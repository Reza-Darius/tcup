use std::net::Ipv4Addr;
use std::{fmt::Display, sync::Arc};

use crate::tcup::TCup;
use crate::{
    error::Result,
    eth::{ETH_P_ARP, Eth_hdr, EthFrame},
    types::{Mac, MockHost},
    utils::mac_to_str,
};
use bytemuck::{Pod, Zeroable};
use tracing::info;

use crate::eth::{ETH_HDR_SIZE, ETH_P_IP, ETH_P_IPV6, ETH_PAY_MIN_SIZE, IP_ADDR_LEN, MAC_ADDR_LEN};

/* ARP protocol opcodes. */
const ARPOP_REQUEST: u16 = 1;
const ARPOP_REPLY: u16 = 2;

/* ARP protocol HARDWARE identifiers. */
const ARP_HRD_ETHER: u16 = 1;
const ARP_PACKET_SIZE: usize = 28;

const ARP_BROADCAST_ADDR: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

#[derive(Default, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct ArpPacket {
    // Header
    pub hwtype: u16,    // (ar$hrd) Hardware address space
    pub prot_type: u16, // (ar$pro) Protocol address space (EtherType field)
    pub hwsize: u8,     // (ar$hln) byte length of each hardware address
    pub prosize: u8,    // (ar$pln) byte length of each protocol address
    pub opcode: u16,    // (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
    // Payload
    pub smac: [u8; 6], // (ar$sha) Hardware address of sender
    pub sip: [u8; 4],  // (ar$spa) Protocol address of sender

    pub dmac: [u8; 6], // (ar$tha) Hardware address of target (if known)
    pub dip: [u8; 4],  // (ar$tpa) Protocol address of target
}

impl ArpPacket {
    /// from network order bytes
    pub fn from_be_bytes(data: &[u8; ARP_PACKET_SIZE]) -> Self {
        let mut arp_packet: ArpPacket = bytemuck::cast(*data);

        arp_packet.hwtype = u16::from_be(arp_packet.hwtype);
        arp_packet.prot_type = u16::from_be(arp_packet.prot_type);
        arp_packet.opcode = u16::from_be(arp_packet.opcode);

        arp_packet
    }

    /// converts into network order bytes
    pub fn into_be_bytes(mut self) -> [u8; ARP_PACKET_SIZE] {
        self.hwtype = u16::to_be(self.hwtype);
        self.prot_type = u16::to_be(self.prot_type);
        self.opcode = u16::to_be(self.opcode);

        bytemuck::cast(self)
    }
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hw_type = match self.hwtype {
            ARP_HRD_ETHER => "ethernet",
            _ => return Err(std::fmt::Error),
        };

        let protocol = match self.prot_type {
            ETH_P_IP => "IPV4",
            ETH_P_IPV6 => "IPV6",
            _ => return Err(std::fmt::Error),
        };

        let op = match self.opcode {
            ARPOP_REPLY => "Reply",
            ARPOP_REQUEST => "Request",
            _ => unreachable!(),
        };

        let src_mac = mac_to_str(&self.smac);
        let dst_mac = mac_to_str(&self.dmac);
        let src_ip = Ipv4Addr::from_octets(self.sip);
        let dst_ip = Ipv4Addr::from_octets(self.dip);

        write!(
            f,
            "\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n",
            "hw type",
            hw_type,
            "protocol",
            protocol,
            "opcode",
            op,
            "src mac",
            src_mac,
            "src ip",
            src_ip,
            "dst mac",
            dst_mac,
        )?;
        writeln!(f, "{:<15} {:>10}", "dst ip", dst_ip)
    }
}

/// in case the ARP request was directed at us, it returns an appropiate response packet
pub async fn handle_arp(mut inc: EthFrame, tcup: TCup, host: &mut MockHost) -> Result<()> {
    info!("handling ARP\n");

    let arp_packet = ArpPacket::from_be_bytes(inc.get_eth_pay()[..ARP_PACKET_SIZE].try_into()?);
    println!("{}\n", &arp_packet);

    if let Some(arp_packet) = run_arp_check(arp_packet, host) {
        let hdr = Eth_hdr::new(arp_packet.dmac.into(), host.mac, ETH_P_ARP);

        inc.set_eth_hdr(hdr);
        inc.set_eth_pay(&arp_packet.into_be_bytes())?;

        println!("reply frame:\n{}\n", inc.get_eth_hdr());

        let n = tcup.write_tap(inc).await?;
        println!("{n} bytes written");
    }
    Ok(())
}

async fn arp_broadcast(tcup: &TCup, ip: Ipv4Addr, host: &MockHost) -> Result<()> {
    const PADDING: usize = ETH_PAY_MIN_SIZE - ARP_PACKET_SIZE;
    let mut buf = [0u8; ETH_HDR_SIZE + ARP_PACKET_SIZE + PADDING];

    let arp = ArpPacket {
        hwtype: ARP_HRD_ETHER,
        prot_type: ETH_P_IP,
        hwsize: MAC_ADDR_LEN as u8,
        prosize: IP_ADDR_LEN as u8,
        opcode: ARPOP_REQUEST,
        smac: host.mac.octets(),
        sip: host.addr.octets(),
        dmac: [0, 0, 0, 0, 0, 0],
        dip: ip.octets(),
    };
    let eth = Eth_hdr {
        dmac: ARP_BROADCAST_ADDR,
        smac: host.mac.octets(),
        prot_type: ETH_P_ARP,
    };

    buf[..ETH_HDR_SIZE].copy_from_slice(&eth.into_be_bytes());
    buf[ETH_HDR_SIZE..ETH_HDR_SIZE + ARP_PACKET_SIZE].copy_from_slice(&arp.into_be_bytes());

    let frame = EthFrame::from_be_bytes(&buf)?;
    tcup.write_tap(frame).await?;
    Ok(())
}

fn run_arp_check(mut arp: ArpPacket, host: &mut MockHost) -> Option<ArpPacket> {
    let sender_mac = Mac::from_octets(arp.smac);
    let sender_ip = Ipv4Addr::from_octets(arp.sip);

    let target_mac = Mac::from_octets(arp.dmac);
    let target_ip = Ipv4Addr::from_octets(arp.dip);

    if arp.hwtype != ARP_HRD_ETHER {
        return None;
    }

    if arp.prot_type != ETH_P_IP {
        return None;
    }

    let mut merge_flag = false;

    // do we have an entry for the sender ip address?
    //      if yes, update ip address with sender mac
    //          set merge_flag = true
    if host.arp_table.insert(sender_ip, sender_mac).is_some() {
        merge_flag = true;
    }

    // am i the target of the ip address?
    if target_ip != host.addr {
        return None;
    }

    // if merge_flag = false add sender ip address with sender mac to table
    if !merge_flag {
        host.arp_table.insert(sender_ip, sender_mac);
    }

    if arp.opcode == ARPOP_REPLY {
        return None;
    }

    // if opcode == request
    //     put my prot address and hw addres in the sender fields
    //     set opcode to reply
    //             send the packet away
    if arp.opcode == ARPOP_REQUEST {
        arp.smac = host.mac.octets();
        arp.sip = host.addr.octets();

        arp.dmac = sender_mac.octets();
        arp.dip = sender_ip.octets();

        arp.opcode = ARPOP_REPLY;

        println!("sending arp:\n{}\n", &arp);
        return Some(arp);
    }
    None
}
