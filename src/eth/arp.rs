use std::fmt::Display;
use std::net::Ipv4Addr;

use crate::ip::IP_ADDR_LEN;
use crate::tcup::TCup;
use crate::{
    error::Result,
    eth::{Eth_hdr, EthFrame},
    utils::Mac,
    utils::mac_to_str,
};
use bytes::BufMut;
use tracing::{Level, info, span, trace, trace_span};
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16, Unaligned};

use crate::eth::{ETH_HDR_SIZE, ETH_PAY_MIN_SIZE, MAC_ADDR_LEN};

const ARP_PACKET_SIZE: usize = 28;
const ARP_BROADCAST_ADDR: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

#[derive(Default, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ArpPacket {
    // Header
    pub hwtype: U16<BE>,    // (ar$hrd) Hardware address space
    pub prot_type: U16<BE>, // (ar$pro) Protocol address space (EtherType field)
    pub hwsize: u8,         // (ar$hln) byte length of each hardware address
    pub prosize: u8,        // (ar$pln) byte length of each protocol address
    pub opcode: U16<BE>,    // (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)

    // Payload
    pub smac: [u8; 6], // (ar$sha) Hardware address of sender
    pub sip: [u8; 4],  // (ar$spa) Protocol address of sender

    pub dmac: [u8; 6], // (ar$tha) Hardware address of target (if known)
    pub dip: [u8; 4],  // (ar$tpa) Protocol address of target
}

impl ArpPacket {
    pub async fn new_broadcast(smac: Mac, sip: Ipv4Addr, target_ip: Ipv4Addr) -> EthFrame {
        const PADDING: usize = ETH_PAY_MIN_SIZE - ARP_PACKET_SIZE;
        const SIZE: usize = ETH_HDR_SIZE + ARP_PACKET_SIZE + PADDING;

        let mut buf = Vec::with_capacity(SIZE);

        let eth = Eth_hdr {
            dmac: ARP_BROADCAST_ADDR,
            smac: smac.octets(),
            prot_type: libc::ETH_P_ARP as u16,
        };

        let arp = ArpPacket {
            hwtype: libc::ARPHRD_ETHER.into(),
            prot_type: (libc::ETH_P_IP as u16).into(),
            hwsize: MAC_ADDR_LEN as u8,
            prosize: IP_ADDR_LEN as u8,
            opcode: libc::ARPOP_REQUEST.into(),
            smac: smac.octets(),
            sip: sip.octets(),
            dmac: [0, 0, 0, 0, 0, 0],
            dip: target_ip.octets(),
        };

        buf.put_slice(&eth.into_be_bytes());
        buf.put_slice(arp.as_bytes());

        debug_assert_eq!(buf.len(), SIZE);

        EthFrame::from_bytes_unchecked(buf)
    }

    /// if we need to reply to the arp packet this function returns Some()
    fn run_arp_check(mut self, host: &mut impl ArpStore) -> Option<ArpPacket> {
        let sender_mac = Mac::from_octets(self.smac);
        let sender_ip = Ipv4Addr::from_octets(self.sip);
        let target_ip = Ipv4Addr::from_octets(self.dip);

        let _span = span!(Level::TRACE, "arp", smac = %sender_mac, sip = %sender_ip, target_ip = %target_ip).entered();
        let (host_mac, host_ip) = host.addr();

        // NOTE: zerocopy's big endian types are overloaded to convert to native endian before
        // comparing

        if self.hwtype != libc::ARPHRD_ETHER {
            return None;
        }

        if self.prot_type != libc::ETH_P_IP as u16 {
            return None;
        }

        let mut merge_flag = false;

        // do we have an entry for the sender ip address?
        //      if yes, update ip address with sender mac
        //          set merge_flag = true
        if host.update_if_present(sender_mac, sender_ip) {
            trace!("updated arp entry");
            merge_flag = true;
        }

        // am i the target of the ip address?
        if target_ip != host_ip {
            trace!("we are not targeted, done");
            return None;
        }

        // if merge_flag = false add sender ip address with sender mac to table
        if !merge_flag {
            host.insert(sender_mac, sender_ip);
            trace!("inserted arp entry");
        }

        if self.opcode == libc::ARPOP_REPLY {
            trace!("arp packet is reply, done");
            return None;
        }

        // if opcode == request
        //     put my prot address and hw addres in the sender fields
        //     set opcode to reply
        //             send the packet away
        if self.opcode == libc::ARPOP_REQUEST {
            self.smac = host_mac.octets();
            self.sip = host_ip.octets();

            self.dmac = sender_mac.octets();
            self.dip = sender_ip.octets();

            self.opcode = libc::ARPOP_REPLY.into();

            trace!("generated arp reply");
            return Some(self);
        }
        None
    }
}

pub trait ArpStore {
    /// if and only if smac and sip are in the store, update it the entry and return true
    fn update_if_present(&mut self, smac: Mac, sip: Ipv4Addr) -> bool;

    /// insert smac and sip as a new entry
    fn insert(&mut self, smac: Mac, sip: Ipv4Addr);

    /// fetch the hosts link and network address
    fn addr(&self) -> (Mac, Ipv4Addr);
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hw_type = match self.hwtype.get() {
            libc::ARPHRD_ETHER => "ethernet",
            _ => return Err(std::fmt::Error),
        };

        let protocol = match self.prot_type.get() as i32 {
            libc::ETH_P_IP => "IPV4",
            libc::ETH_P_IPV6 => "IPV6",
            _ => return Err(std::fmt::Error),
        };

        let op = match self.opcode.get() {
            libc::ARPOP_REPLY => "Reply",
            libc::ARPOP_REQUEST => "Request",
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

// /// in case the ARP request was directed at us, it returns an appropiate response packet
// pub async fn handle_arp(mut inc: EthFrame, tcup: TCup) -> Result<()> {
//     info!("handling ARP\n");
//
//     let arp_packet = ArpPacket::from_be_bytes(inc.get_eth_pay()[..ARP_PACKET_SIZE].try_into()?);
//     println!("{}\n", &arp_packet);
//
//     if let Some(arp_packet) = run_arp_check(arp_packet, &tcup) {
//         let hdr = Eth_hdr::new(arp_packet.dmac.into(), arp_packet.smac.into(), ETH_P_ARP);
//
//         inc.set_eth_hdr(hdr);
//         inc.set_eth_pay(&arp_packet.into_be_bytes())?;
//
//         println!("reply frame:\n{}\n", inc.get_eth_hdr());
//
//         let n = tcup.write_tap(inc).await?;
//         println!("{n} bytes written");
//     }
//     Ok(())
// }
