use std::fmt::Display;
use std::net::Ipv4Addr;

use super::mac::*;
use crate::eth::error::EthErr;
use crate::ip::IP_ADDR_LEN;
use crate::utils::packet::*;
use bytes::BufMut;
use tracing::{Level, span, trace};
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16, Unaligned};

use crate::eth::{ETH_HDR_SIZE, ETH_PAY_MIN_SIZE};

const ARP_PACKET_SIZE: usize = std::mem::size_of::<ArpMsg>();

impl Packet<Arp> {
    pub fn parse(eth: Packet<Eth>) -> Result<Self, EthErr> {
        let data = eth.into_vec();
        let arp = ArpMsg::ref_from_prefix(&data[ETH_HDR_SIZE..])
            .map_err(|_| EthErr::ParseError("arp parse error"))?
            .0;

        // we validate fields during arp

        Ok(data.into())
    }

    pub fn hdr(&self) -> ArpMsg {
        ArpMsg::read_from_prefix(&self.data[ETH_HDR_SIZE..])
            .expect("the packet is validated already")
            .0
    }

    pub fn set_hdr(&mut self, hdr: ArpMsg) {
        hdr.write_to_prefix(&mut self.data[ETH_HDR_SIZE..])
            .expect("the packet is validated already")
    }

    /// allocates a new arp message
    pub fn new(packet: ArpMsg) -> Self {
        const PADDING: usize = ETH_PAY_MIN_SIZE - ARP_PACKET_SIZE;
        // we include padding to get to the required minimum ethernet size
        const SIZE: usize = ETH_HDR_SIZE + ARP_PACKET_SIZE + PADDING;

        let mut v = vec![0u8; SIZE];

        v.put_slice(&[0; ETH_HDR_SIZE]);
        v.put_slice(packet.as_bytes());

        v.into()
    }

    pub fn new_request(smac: Mac, sip: Ipv4Addr, target_ip: Ipv4Addr) -> Packet<Eth> {
        let arp = ArpMsg {
            hwtype: libc::ARPHRD_ETHER.into(),
            prot_type: (libc::ETH_P_IP as u16).into(),
            hwsize: MAC_ADDR_LEN as u8,
            prosize: IP_ADDR_LEN as u8,
            opcode: libc::ARPOP_REQUEST.into(),
            smac: smac.octets(),
            sip: sip.octets(),
            dmac: [0; _],
            dip: target_ip.octets(),
        };

        Packet::<Eth>::new(Mac::BROADCAST, smac, Packet::<Arp>::new(arp).into())
            .expect("the values are hard coded")
    }

    pub fn run_arp_check(mut self, host: &mut impl ArpStore) -> Option<Packet<Eth>> {
        let mut arp_packet = self.hdr();

        let sender_mac = Mac::from_octets(arp_packet.smac);
        let sender_ip = Ipv4Addr::from_octets(arp_packet.sip);
        let target_ip = Ipv4Addr::from_octets(arp_packet.dip);
        let mut merge_flag = false;
        let (host_mac, host_ip) = host.addr();

        let _span = span!(Level::TRACE, "arp", smac = %sender_mac, sip = %sender_ip, target_ip = %target_ip).entered();

        // NOTE: zerocopy's big endian types are overloaded to convert to native endian before
        // comparing

        if arp_packet.hwtype != libc::ARPHRD_ETHER {
            trace!("unsupported hw protocol, done");
            return None;
        }

        if arp_packet.prot_type != libc::ETH_P_IP as u16 {
            trace!("unsupported network protocol, done");
            return None;
        }

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

        if arp_packet.opcode == libc::ARPOP_REPLY {
            trace!("arp packet is reply, done");
            return None;
        }

        // if opcode == request
        //     put my prot address and hw addres in the sender fields
        //     set opcode to reply
        //             send the packet away
        if arp_packet.opcode == libc::ARPOP_REQUEST {
            arp_packet.smac = host_mac.octets();
            arp_packet.sip = host_ip.octets();

            arp_packet.dmac = sender_mac.octets();
            arp_packet.dip = sender_ip.octets();

            arp_packet.opcode = libc::ARPOP_REPLY.into();

            trace!("generated arp reply");

            self.set_hdr(arp_packet);

            return Some(
                Packet::<Eth>::new(sender_mac, host_mac, self.into())
                    .expect("the values are hard coded"),
            );
        }
        None
    }
}

#[derive(Default, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ArpMsg {
    // Header
    pub hwtype: U16<BE>,    // (ar$hrd) Hardware address space
    pub prot_type: U16<BE>, // (ar$pro) Protocol address space (EtherType field)
    pub hwsize: u8,         // (ar$hln) byte length of each hardware address
    pub prosize: u8,        // (ar$pln) byte length of each protocol address
    pub opcode: U16<BE>,    // (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)

    // Payload
    pub smac: [u8; MAC_ADDR_LEN], // (ar$sha) Hardware address of sender
    pub sip: [u8; IP_ADDR_LEN],   // (ar$spa) Protocol address of sender
    pub dmac: [u8; MAC_ADDR_LEN], // (ar$tha) Hardware address of target (if known)
    pub dip: [u8; IP_ADDR_LEN],   // (ar$tpa) Protocol address of target
}

impl ArpMsg {}

pub trait ArpStore {
    /// if and only if smac and sip are in the store, update it the entry and return true
    fn update_if_present(&mut self, smac: Mac, sip: Ipv4Addr) -> bool;

    /// insert smac and sip as a new entry
    fn insert(&mut self, smac: Mac, sip: Ipv4Addr);

    /// fetch the hosts link and network address
    fn addr(&self) -> (Mac, Ipv4Addr);
}

impl Display for ArpMsg {
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

        let src_mac = Mac::from_octets(self.smac);
        let dst_mac = Mac::from_octets(self.dmac);
        let src_ip = Ipv4Addr::from_octets(self.sip);
        let dst_ip = Ipv4Addr::from_octets(self.dip);

        write!(f, "hw type: {hw_type}, prot: {protocol}, opcode: {op}, src_mac: {src_mac}, src_ip: {src_ip}, dst_mac {dst_mac}, dst_ip {dst_ip}\n")
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
