use std::fmt::Display;
use std::net::Ipv4Addr;

use crate::{
    types::{MAC, MockHost},
    utils::mac_to_str,
};
use bytemuck::{Pod, Zeroable};
use tracing::info;

use crate::eth::{ETH_P_IP, ETH_P_IPV6};

/* ARP protocol opcodes. */
const ARPOP_REQUEST: u16 = 1;
const ARPOP_REPLY: u16 = 2;

/* ARP protocol HARDWARE identifiers. */
const ARP_HRD_ETHER: u16 = 1;
const ARP_PACKET_SIZE: usize = 28;

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
    pub fn from_bytes(data: &[u8; ARP_PACKET_SIZE]) -> Self {
        let mut arp_packet: ArpPacket = bytemuck::cast(*data);

        arp_packet.hwtype = u16::from_be(arp_packet.hwtype);
        arp_packet.prot_type = u16::from_be(arp_packet.prot_type);
        arp_packet.opcode = u16::from_be(arp_packet.opcode);

        arp_packet
    }

    pub fn into_bytes(mut self) -> [u8; ARP_PACKET_SIZE] {
        self.hwtype = u16::to_be(self.hwtype);
        self.prot_type = u16::to_be(self.prot_type);
        self.opcode = u16::to_be(self.opcode);

        bytemuck::cast(self)
    }
}

/// in case the ARP request was directed at us, it returns an appropiate response packet
pub fn handle_arp(frame_payload: &[u8], host: &mut MockHost) -> Option<ArpPacket> {
    let mut arp_packet =
        ArpPacket::from_bytes(frame_payload[..ARP_PACKET_SIZE].try_into().unwrap());

    let sender_mac = MAC::from_octets(arp_packet.smac);
    let sender_ip = Ipv4Addr::from_octets(arp_packet.sip);

    let target_mac = MAC::from_octets(arp_packet.dmac);
    let target_ip = Ipv4Addr::from_octets(arp_packet.dip);

    info!("handling arp\n");
    println!("{}\n", &arp_packet);

    if arp_packet.hwtype != ARP_HRD_ETHER {
        return None;
    }

    if arp_packet.prot_type != ETH_P_IP {
        return None;
    }

    let mut merge_flag = false;

    // do we have an entry for the sender ip address?
    //      if yes, update ip address with sender mac
    //          set merge_flag = true
    if host.table.insert(sender_ip, sender_mac).is_some() {
        merge_flag = true;
    }

    // am i the target of the ip address?
    if target_ip != host.addr {
        return None;
    }

    // if merge_flag = false add sender ip address with sender mac to table
    if !merge_flag {
        host.table.insert(sender_ip, sender_mac);
    }

    if arp_packet.opcode == ARPOP_REPLY {
        return None;
    }

    // if opcode == request
    //     put my prot address and hw addres in the sender fields
    //     set opcode to reply
    //             send the packet away
    if arp_packet.opcode == ARPOP_REQUEST {
        arp_packet.smac = host.mac.octets();
        arp_packet.sip = host.addr.octets();

        arp_packet.dmac = sender_mac.octets();
        arp_packet.dip = sender_ip.octets();

        arp_packet.opcode = ARPOP_REPLY;

        println!("sending arp:\n{}\n", &arp_packet);
        return Some(arp_packet);
    }
    None
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

        write!(f, "hw type: {hw_type}\nprotocol: {protocol}\nop: {op}\n")?;
        write!(
            f,
            "source mac: {}\nsource ip: {}\ntarget mac: {}\ntarget ip: {}\n",
            mac_to_str(&self.smac),
            Ipv4Addr::from_octets(self.sip),
            mac_to_str(&self.dmac),
            Ipv4Addr::from_octets(self.dip),
        )
    }
}
