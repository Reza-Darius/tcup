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
const ARPHRD_ETHER: u16 = 1;

const ARP_PACKET_SIZE: usize = 28;

#[derive(Default, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct ArpPacket {
    pub header: ArpHeader,
    pub payload: ArpIpv4,
}

impl ArpPacket {
    pub fn from_bytes(data: &[u8; ARP_PACKET_SIZE]) -> Self {
        let mut arp_packet: ArpPacket = bytemuck::cast(*data);

        arp_packet.header.hwtype = u16::from_be(arp_packet.header.hwtype);
        arp_packet.header.prot_type = u16::from_be(arp_packet.header.prot_type);
        arp_packet.header.opcode = u16::from_be(arp_packet.header.opcode);

        arp_packet
    }

    pub fn into_bytes(mut self) -> [u8; ARP_PACKET_SIZE] {
        self.header.hwtype = u16::to_be(self.header.hwtype);
        self.header.prot_type = u16::to_be(self.header.prot_type);
        self.header.opcode = u16::to_be(self.header.opcode);
        bytemuck::cast(self)
        // let mut packet = [0u8; ARP_PACKET_SIZE];

        // packet[..2].copy_from_slice(&self.header.hwsize.to_be_bytes());
        // packet[2..4].copy_from_slice(&self.header.prot_type.to_be_bytes());
        // packet[4] = self.header.hwsize;
        // packet[5] = self.header.prosize;
        // packet[6..8].copy_from_slice(&self.header.opcode.to_be_bytes());

        // packet[8..14].copy_from_slice(&self.payload.smac);
        // packet[14..18].copy_from_slice(&self.payload.sip);

        // packet[18..24].copy_from_slice(&self.payload.dmac);
        // packet[24..28].copy_from_slice(&self.payload.dip);

        // packet
    }
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "header:\n{}\npayload:\n{}", self.header, self.payload)
    }
}

#[derive(Default, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct ArpHeader {
    pub hwtype: u16,    // (ar$hrd) Hardware address space
    pub prot_type: u16, // (ar$pro) Protocol address space (EtherType field)
    pub hwsize: u8,     // (ar$hln) byte length of each hardware address
    pub prosize: u8,    // (ar$pln) byte length of each protocol address
    pub opcode: u16,    // (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
}

impl Display for ArpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hw_type = match self.hwtype {
            ARPHRD_ETHER => "ethernet",
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
        write!(f, "hw type: {hw_type}\nprotocol: {protocol}\nop: {op}\n")
    }
}

#[derive(Default, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct ArpIpv4 {
    pub smac: [u8; 6], // (ar$sha) Hardware address of sender
    pub sip: [u8; 4],  // (ar$spa) Protocol address of sender

    pub dmac: [u8; 6], // (ar$tha) Hardware address of target (if known)
    pub dip: [u8; 4],  // (ar$tpa) Protocol address of target
}

impl Display for ArpIpv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

pub fn handle_arp(frame_payload: &[u8], host: &mut MockHost) -> Option<ArpPacket> {
    let mut arp_packet =
        ArpPacket::from_bytes(frame_payload[..ARP_PACKET_SIZE].try_into().unwrap());

    let sender_mac = MAC::from_octets(arp_packet.payload.smac);
    let sender_ip = Ipv4Addr::from_octets(arp_packet.payload.sip);

    let target_mac = MAC::from_octets(arp_packet.payload.dmac);
    let target_ip = Ipv4Addr::from_octets(arp_packet.payload.dip);

    println!("handling arp\n{}\n", &arp_packet);
    info!("parsing ARP packet:\n{}", &arp_packet);

    let header = &arp_packet.header;

    if header.hwtype != ARPHRD_ETHER {
        return None;
    }

    if header.prot_type != ETH_P_IP {
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

    if arp_packet.header.opcode == ARPOP_REPLY {
        return None;
    }

    // if opcode == request
    //     put my prot address and hw addres in the sender fields
    //     set opcode to reply
    //             send the packet away
    if arp_packet.header.opcode == ARPOP_REQUEST {
        arp_packet.payload.smac = host.mac.octets();
        arp_packet.payload.sip = host.addr.octets();

        arp_packet.payload.dmac = sender_mac.octets();
        arp_packet.payload.dip = sender_ip.octets();

        arp_packet.header.opcode = ARPOP_REPLY;

        println!("sending arp:\n{}\n", &arp_packet);
        return Some(arp_packet);
    }
    None
}
