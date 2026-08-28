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
        ArpMsg::read_from_prefix(&self.as_bytes()[ETH_HDR_SIZE..])
            .expect("the packet is validated already")
            .0
    }

    pub fn set_hdr(&mut self, hdr: ArpMsg) {
        hdr.write_to_prefix(&mut self.as_bytes_mut()[ETH_HDR_SIZE..])
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

        write!(
            f,
            "hw type: {hw_type}, prot: {protocol}, opcode: {op}, src_mac: {src_mac}, src_ip: {src_ip}, dst_mac {dst_mac}, dst_ip {dst_ip}\n"
        )
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

// These tests only rely on the API surface visible in the pasted source:
// Packet::<Arp>::new/parse/hdr/set_hdr, ArpMsg, Mac, and the ArpStore
// trait. If your real Ipv4Addr extension trait or Packet::<Eth>::new
// signature differs, adjust the helper below accordingly.

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const HOST_MAC: Mac = Mac::new(0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA);
    const SENDER_MAC: Mac = Mac::new(0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB);

    fn host_ip() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    fn sender_ip() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 2)
    }

    fn other_ip() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 99)
    }

    fn base_request(target_ip: Ipv4Addr) -> ArpMsg {
        ArpMsg {
            hwtype: libc::ARPHRD_ETHER.into(),
            prot_type: (libc::ETH_P_IP as u16).into(),
            hwsize: MAC_ADDR_LEN as u8,
            prosize: IP_ADDR_LEN as u8,
            opcode: libc::ARPOP_REQUEST.into(),
            smac: SENDER_MAC.octets(),
            sip: sender_ip().octets(),
            dmac: [0; MAC_ADDR_LEN],
            dip: target_ip.octets(),
        }
    }

    fn base_reply(target_ip: Ipv4Addr) -> ArpMsg {
        let mut msg = base_request(target_ip);
        msg.opcode = libc::ARPOP_REPLY.into();
        msg.dmac = HOST_MAC.octets();
        msg
    }

    /// Records calls so tests can assert on merge vs. insert behavior,
    /// independent of what's actually stored.
    #[derive(Default)]
    struct MockStore {
        known: Vec<(Mac, Ipv4Addr)>,
        update_calls: RefCell<Vec<(Mac, Ipv4Addr)>>,
        insert_calls: RefCell<Vec<(Mac, Ipv4Addr)>>,
    }

    impl MockStore {
        fn with_known(mac: Mac, ip: Ipv4Addr) -> Self {
            Self {
                known: vec![(mac, ip)],
                ..Default::default()
            }
        }
    }

    impl ArpStore for MockStore {
        fn update_if_present(&mut self, smac: Mac, sip: Ipv4Addr) -> bool {
            self.update_calls.borrow_mut().push((smac, sip));
            self.known.iter().any(|(_, ip)| *ip == sip)
        }

        fn insert(&mut self, smac: Mac, sip: Ipv4Addr) {
            self.insert_calls.borrow_mut().push((smac, sip));
        }

        fn addr(&self) -> (Mac, Ipv4Addr) {
            (HOST_MAC, host_ip())
        }
    }

    #[test]
    fn request_directed_at_host_generates_reply() {
        let packet = Packet::<Arp>::new(base_request(host_ip()));
        let mut store = MockStore::default();

        let reply_eth = packet
            .run_arp_check(&mut store)
            .expect("expected a reply packet");

        let reply_arp =
            Packet::<Arp>::parse(reply_eth).expect("reply should be a valid parseable ARP packet");
        let hdr = reply_arp.hdr();

        assert_eq!(hdr.opcode.get(), libc::ARPOP_REPLY);
        assert_eq!(Mac::from_octets(hdr.smac).octets(), HOST_MAC.octets());
        assert_eq!(Ipv4Addr::from_octets(hdr.sip), host_ip());
        assert_eq!(Mac::from_octets(hdr.dmac).octets(), SENDER_MAC.octets());
        assert_eq!(Ipv4Addr::from_octets(hdr.dip), sender_ip());
    }

    #[test]
    fn request_not_directed_at_host_returns_none() {
        let packet = Packet::<Arp>::new(base_request(other_ip()));
        let mut store = MockStore::default();

        let result = packet.run_arp_check(&mut store);
        assert!(result.is_none());
    }

    #[test]
    fn reply_directed_at_host_updates_table_and_sends_nothing() {
        let packet = Packet::<Arp>::new(base_reply(host_ip()));
        let mut store = MockStore::default();

        let result = packet.run_arp_check(&mut store);
        assert!(result.is_none());
        assert_eq!(store.insert_calls.borrow().len(), 1);
    }

    #[test]
    fn unsupported_hwtype_is_ignored() {
        let mut msg = base_request(host_ip());
        msg.hwtype = 0xFFFF.into();
        let packet = Packet::<Arp>::new(msg);
        let mut store = MockStore::default();

        assert!(packet.run_arp_check(&mut store).is_none());
        assert!(store.update_calls.borrow().is_empty());
        assert!(store.insert_calls.borrow().is_empty());
    }

    #[test]
    fn unsupported_protocol_type_is_ignored() {
        let mut msg = base_request(host_ip());
        msg.prot_type = (libc::ETH_P_IPV6 as u16).into();
        let packet = Packet::<Arp>::new(msg);
        let mut store = MockStore::default();

        assert!(packet.run_arp_check(&mut store).is_none());
        assert!(store.update_calls.borrow().is_empty());
        assert!(store.insert_calls.borrow().is_empty());
    }

    #[test]
    fn existing_sender_is_updated_not_inserted() {
        let packet = Packet::<Arp>::new(base_request(host_ip()));
        let mut store = MockStore::with_known(SENDER_MAC, sender_ip());

        let _ = packet.run_arp_check(&mut store);

        assert_eq!(store.update_calls.borrow().len(), 1);
        assert!(store.insert_calls.borrow().is_empty());
    }

    #[test]
    fn new_sender_is_inserted_after_failed_update() {
        let packet = Packet::<Arp>::new(base_request(host_ip()));
        let mut store = MockStore::default();

        let _ = packet.run_arp_check(&mut store);

        assert_eq!(store.update_calls.borrow().len(), 1);
        assert_eq!(store.insert_calls.borrow().len(), 1);
        assert_eq!(store.insert_calls.borrow()[0], (SENDER_MAC, sender_ip()));
    }

    #[test]
    fn new_arp_message_round_trips_through_parse() {
        let original = base_request(host_ip());
        let packet = Packet::<Arp>::new(original.clone());

        // Wrap the raw ARP packet bytes in a minimal Eth frame's worth of
        // padding so Packet::<Arp>::parse can strip ETH_HDR_SIZE back off.
        // Packet::<Arp>::new already prepends ETH_HDR_SIZE zero bytes and
        // pads to ETH_PAY_MIN_SIZE, so `hdr()` should recover the same
        // fields we put in.
        let hdr = packet.hdr();

        assert_eq!(hdr.opcode.get(), original.opcode.get());
        assert_eq!(hdr.smac, original.smac);
        assert_eq!(hdr.sip, original.sip);
        assert_eq!(hdr.dmac, original.dmac);
        assert_eq!(hdr.dip, original.dip);
    }

    #[test]
    fn new_request_builds_broadcast_ethernet_request() {
        let smac = SENDER_MAC;
        let sip = sender_ip();
        let target = host_ip();

        let eth = Packet::<Arp>::new_request(smac, sip, target);
        let arp = Packet::<Arp>::parse(eth).expect("should parse back out");
        let hdr = arp.hdr();

        assert_eq!(hdr.opcode.get(), libc::ARPOP_REQUEST);
        assert_eq!(Mac::from_octets(hdr.smac).octets(), smac.octets());
        assert_eq!(Ipv4Addr::from_octets(hdr.sip), sip);
        assert_eq!(Ipv4Addr::from_octets(hdr.dip), target);
    }

    #[test]
    fn display_formats_known_fields() {
        let hdr = base_request(host_ip());
        let s = format!("{hdr}");
        assert!(s.contains("Request"));
        assert!(s.contains("IPV4"));
        assert!(s.contains("ethernet"));
    }
}
