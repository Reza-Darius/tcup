use std::net::Ipv4Addr;

use bytes::BufMut;
use num_enum::TryFromPrimitive;
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

use crate::eth::Mac;
use crate::ip::IpErr::{BuildError, ParseError};
use crate::utils::packet::*;
use crate::{
    eth::ETH_HDR_SIZE,
    ip::error::IpErr,
    utils::{calc_checksum_be, packet::Packet},
};

pub const IP_HDR_MINSIZE: u8 = 20;
pub const IP_HDR_MAXSIZE: u8 = 60;
pub const IP_ADDR_LEN: u8 = 4;

pub const TOS_BEST_EFFORT: u8 = 0;
pub const TTL_START: u8 = 64;

pub const IPPROTO_ICMP: u8 = libc::IPPROTO_ICMP as u8;
pub const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;

pub const IP_RF: u16 = 0x8000; // reserved
pub const IP_DF: u16 = 0x4000; // don't fragment
pub const IP_MF: u16 = 0x2000; // more fragments
pub const FRAG_OFFSET_MASK: u16 = 0x1FFF;

/// start of the IP header
const IP_HDR_OFFSET: usize = ETH_HDR_SIZE;
/// offset for checkmark byte
const IP_CHECK_OFFSET: usize = ETH_HDR_SIZE + 10;
/// offset for protocol byte
const IP_PROT_OFFSET: usize = ETH_HDR_SIZE + 10;
/// payloard offset without options
const IP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE as usize;

#[derive(TryFromPrimitive, PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum Ipv4Prot {
    Icmp = libc::IPPROTO_ICMP as u8,
    Tcp = libc::IPPROTO_TCP as u8,
}

impl Packet<IP> {
    pub fn parse(pck: Packet<ETH>) -> Result<Self, IpErr> {
        let packet = pck.into_buf();
        let eth_pay = &packet.as_bytes()[IP_HDR_OFFSET..];
        let hdr_size = get_hdr_len(eth_pay[0]);

        let check = calc_checksum_be(&eth_pay[..hdr_size as usize]);
        if check != 0 {
            return Err(ParseError(format!("invalid IP checksum: {check:x}")));
        }

        if eth_pay.len() < IP_HDR_MINSIZE as usize {
            return Err(ParseError("eth_pay is too small for IP header".into()));
        }

        if get_hdr_ver(eth_pay[0]) != libc::IPVERSION {
            return Err(ParseError("not supported IP version".into()));
        }

        if hdr_size as usize > eth_pay.len() {
            return Err(ParseError(
                "frame smaller than declared header length".into(),
            ));
        }

        if hdr_size < IP_HDR_MINSIZE {
            return Err(ParseError("IP header below minimum 20 bytes".into()));
        }

        // options arent supported
        if hdr_size > IP_HDR_MINSIZE {
            return Err(ParseError("IP header above supported 20 bytes".into()));
        }

        let hdr = IPv4Hdr::read_from_prefix(eth_pay)
            .map_err(|e| ParseError(format!("couldnt extract header: {e}")))?
            .0;

        if !hdr.is_fragmented() {
            return Err(ParseError("fragmentation is not supported".into()));
        }

        if hdr.tot_len.get() < hdr_size as u16 {
            return Err(ParseError("total length smaller than header len".into()));
        };

        if (hdr.tot_len.get() as usize) > eth_pay.len() {
            return Err(ParseError("total length exceeds eth_pay length".into()));
        }

        Ok(Packet::from_vec(packet))
    }

    pub fn into_parts(self) -> Result<(IPv4Hdr, Ipv4Payload), IpErr> {
        let hdr = self.hdr().clone();
        match self.prot() {
            Ipv4Prot::Icmp => {
                let packet = Packet::<ICMP>::parse(self)?;
                Ok((hdr, packet.into()))
            }
            Ipv4Prot::Tcp => todo!(),
        }
    }

    pub fn new(
        src_addr: Ipv4Addr,
        dest_addr: Ipv4Addr,
        paylod: Ipv4Payload,
    ) -> Result<Packet<IP>, IpErr> {
        let prot;
        let mut data = match paylod {
            Ipv4Payload::Tcp(packet) => {
                prot = Ipv4Prot::Tcp;
                packet.into_buf()
            }
            Ipv4Payload::Icmp(packet) => {
                prot = Ipv4Prot::Icmp;
                packet.into_buf()
            }
        };

        if data.len() < IP_PAY_OFFSET + IP_HDR_MINSIZE as usize {
            return Err(BuildError(
                "invalid size: data len is lower than required".to_string(),
            ));
        }

        IPv4Hdr::new(src_addr, dest_addr, prot, &data)
            .write_to_prefix(&mut data[IP_HDR_OFFSET..])
            .expect("there should be enough space");

        let mut packet: Packet<IP> = data.into();
        packet.set_checksum();

        Ok(packet)
    }

    #[inline(always)]
    pub fn prot(&self) -> Ipv4Prot {
        self.as_buf()[IP_CHECK_OFFSET]
            .try_into()
            .expect("the packet is parsed")
    }

    /// convenience function
    #[inline(always)]
    pub fn to_eth(self, dmac: impl Into<Mac>, smac: impl Into<Mac>) -> Packet<ETH> {
        Packet::<ETH>::new(dmac, smac, self.into())
    }

    /// reads the header length of the ip packet: 20 byte + options
    #[inline(always)]
    pub fn hdr_len(&self) -> u8 {
        // the len field is in the first byte
        let res = get_hdr_len(self.as_buf()[IP_HDR_OFFSET]);
        debug_assert!(
            (IP_HDR_MINSIZE..=IP_HDR_MAXSIZE).contains(&res),
            "illegal size"
        );
        res
    }

    #[inline(always)]
    pub fn hdr(&self) -> &IPv4Hdr {
        IPv4Hdr::ref_from_prefix(&self.as_buf()[IP_HDR_OFFSET..])
            .expect("get ip hdr: the packet is parsed")
            .0
    }

    /// ip payload
    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        let hdr_len = self.hdr_len();
        let pay_len = self.hdr().tot_len.get() - self.hdr_len() as u16;

        &self.as_buf()[IP_HDR_OFFSET + hdr_len as usize..IP_HDR_OFFSET + hdr_len as usize]
    }

    #[inline(always)]
    fn set_checksum(&mut self) {
        debug_assert!(self.len() > IP_CHECK_OFFSET + 1);

        let offset = IP_CHECK_OFFSET;

        // setting to 0 before calculation
        self.as_buf_mut()[offset] = 0;
        self.as_buf_mut()[offset + 1] = 0;

        let check =
            calc_checksum_be(&self.as_buf()[ETH_HDR_SIZE..ETH_HDR_SIZE + self.hdr_len() as usize]);
        (&mut self.as_buf_mut()[offset..]).put_u16(check);
        // self.data[offset..offset + size_of::<u16>()].copy_from_slice(&u16::to_be_bytes(check));

        debug_assert_eq!(
            0,
            calc_checksum_be(&self.as_buf()[ETH_HDR_SIZE..ETH_HDR_SIZE + self.hdr_len() as usize]),
            "set checksum failed"
        );
    }
}

#[derive(Debug)]
pub enum Ipv4Payload {
    Tcp(Packet<TCP>),
    Icmp(Packet<ICMP>),
}

impl From<Packet<TCP>> for Ipv4Payload {
    fn from(value: Packet<TCP>) -> Self {
        Ipv4Payload::Tcp(value)
    }
}

impl From<Packet<ICMP>> for Ipv4Payload {
    fn from(value: Packet<ICMP>) -> Self {
        Ipv4Payload::Icmp(value)
    }
}

/// IPv4 Header without options
#[derive(Default, Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct IPv4Hdr {
    /// 4 bits for version and IHL (internet header length)
    ver_ihl: u8,
    /// type of service, in newer versiond the first 6 bits are the "differentiated server field" (DS field)
    tos: u8,
    /// length of the whole IP datagram
    tot_len: U16<BE>,
    id: U16<BE>,
    // first 3 bits are flags, rest offset
    frag_off: U16<BE>,
    /// time to live
    ttl: u8,
    prot: u8,
    /// only covers the IP header
    checksum: U16<BE>,

    src_addr: [u8; 4],
    dest_addr: [u8; 4],
}

impl IPv4Hdr {
    pub fn new(src_addr: Ipv4Addr, dest_addr: Ipv4Addr, prot: Ipv4Prot, payload: &[u8]) -> IPv4Hdr {
        let mut hdr = IPv4Hdr {
            ver_ihl: 4 << 4,
            tos: TOS_BEST_EFFORT,
            tot_len: 0.into(),
            id: 0.into(),
            frag_off: IP_DF.into(),
            ttl: TTL_START,
            prot: prot as u8,
            checksum: 0.into(),
            src_addr: src_addr.octets(),
            dest_addr: dest_addr.octets(),
        };

        debug_assert!(payload.len() <= u16::MAX as usize);

        hdr.set_ihl(4, payload.len() as u16 + IP_HDR_MINSIZE as u16);
        hdr.checksum = calc_checksum_be(payload).into();

        hdr
    }

    #[inline(always)]
    pub fn prot(&self) -> Ipv4Prot {
        self.prot.try_into().expect("parsed is always a valid prot")
    }

    /// sets the header size, takes the length in bytes as argument
    #[inline(always)]
    fn set_ihl(&mut self, version: u8, len: u16) {
        self.ver_ihl = (version << 4) | (len as u8 >> 2);
    }

    /// retrieves the size of the IP header in bytes
    #[allow(clippy::len_without_is_empty)]
    #[inline(always)]
    pub fn len(&self) -> u8 {
        get_hdr_len(self.ver_ihl)
    }

    /// retrieves the total size of the IP header in bytes
    #[inline(always)]
    pub fn tot_len(&self) -> u16 {
        self.tot_len.get()
    }

    #[inline(always)]
    pub fn version(&self) -> u8 {
        get_hdr_ver(self.ver_ihl)
    }

    #[inline(always)]
    pub fn is_fragmented(&self) -> bool {
        (self.frag_off & IP_MF == 0) && (self.frag_off & FRAG_OFFSET_MASK == 0)
    }
}

/// retrieves the header len of the first byte of an ipv4 header
#[inline(always)]
fn get_hdr_len(tot_len: u8) -> u8 {
    (tot_len & 0x0F) << 2
}

/// retrieves the version declared in the first header byte
#[inline(always)]
fn get_hdr_ver(byte: u8) -> u8 {
    byte >> 4
}

impl std::fmt::Display for IPv4Hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ver = self.version();
        let len = self.len();
        let tot = self.tot_len;
        let ttl = self.ttl;
        let prot = self.prot;
        let check = self.checksum;
        let src = Ipv4Addr::from_octets(self.src_addr);
        let dest = Ipv4Addr::from_octets(self.dest_addr);

        writeln!(
            f,
            "sip: {src}, \
            dest: {dest}, \
            ver: {ver}, \
            len: {len}, \
            tot_len: {tot}, \
            ttl: {ttl}, \
            prot {prot}, \
            check: {check}"
        )
    }
}
