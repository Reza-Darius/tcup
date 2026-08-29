use std::net::Ipv4Addr;

use bytes::BufMut;
use num_enum::TryFromPrimitive;
use tracing::error;
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

use crate::eth::Mac;
use crate::ip::IpErr::{BuildError, ParseError};
use crate::utils::packet::*;
use crate::{
    eth::ETH_HDR_SIZE,
    ip::error::IpErr,
    utils::{calc_checksum_be, packet::Packet},
};

pub const IP_HDR_MINSIZE: usize = 20;
pub const IP_HDR_MAXSIZE: usize = 60;
pub const IP_ADDR_LEN: usize = 4;
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
const IP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;

#[derive(TryFromPrimitive, PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum Ipv4Prot {
    Icmp = libc::IPPROTO_ICMP as u8,
    Tcp = libc::IPPROTO_TCP as u8,
}

impl Packet<Ipv4> {
    pub fn parse(pck: Packet<Eth>) -> Result<Self, IpErr> {
        let packet = pck.into_vec();
        let eth_pay = &packet.as_bytes()[IP_HDR_OFFSET..];

        if eth_pay.len() < IP_HDR_MINSIZE {
            return Err(ParseError("eth_pay is too small for IP header".into()));
        }

        if get_hdr_ver(eth_pay[0]) != 4 {
            return Err(ParseError("not supported IP version".into()));
        }

        let hdr_size = get_hdr_len(eth_pay[0]);

        if hdr_size > eth_pay.len() {
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

        let check = calc_checksum_be(&eth_pay[..hdr_size]);
        if check != 0 {
            return Err(ParseError(format!("invalid IP checksum: {check:x}")));
        }

        let hdr = IPv4Hdr::read_from_prefix(eth_pay)
            .map_err(|e| ParseError(format!("couldnt extract header: {e}")))?
            .0;

        if !hdr.is_fragmented() {
            let hdr_frag = hdr.frag_off;
            error!("{:b}", hdr_frag);
            return Err(ParseError("fragmentation is not supported".into()));
        }

        if (hdr.tot_len.get() as usize) < hdr_size {
            return Err(ParseError("total length smaller than header len".into()));
        };

        if (hdr.tot_len.get() as usize) > eth_pay.len() {
            return Err(ParseError("total length exceeds eth_pay length".into()));
        }

        Ok(Packet::from_vec(packet))
    }

    pub fn into_parts(self) -> Result<(IPv4Hdr, Ipv4Payload), IpErr> {
        let hdr = self.hdr().clone();
        todo!()
        // match self.prot() {
        //     Ipv4Prot::Icmp => Packet::<Icmp>::parse(),
        //     Ipv4Prot::Tcp => todo!(),
        // }
    }

    pub fn new(
        src_addr: Ipv4Addr,
        dest_addr: Ipv4Addr,
        paylod: Ipv4Payload,
    ) -> Result<Packet<Ipv4>, IpErr> {
        let prot;
        let mut data = match paylod {
            Ipv4Payload::Tcp(packet) => {
                prot = Ipv4Prot::Tcp;
                packet.into_vec()
            }
            Ipv4Payload::Icmp(packet) => {
                prot = Ipv4Prot::Icmp;
                packet.into_vec()
            }
        };

        if data.len() < IP_PAY_OFFSET + IP_HDR_MINSIZE {
            return Err(BuildError(
                "invalid size: data len is lower than required".to_string(),
            ));
        }

        let hdr = IPv4Hdr::new(src_addr, dest_addr, prot, &data);
        hdr.write_to_prefix(&mut data[IP_HDR_OFFSET..])
            .expect("there should be enough space");

        Ok(data.into())
    }

    pub fn prot(&self) -> Ipv4Prot {
        self.as_slice()[IP_CHECK_OFFSET]
            .try_into()
            .expect("the packet is parsed")
    }

    pub fn to_eth(self, dmac: impl Into<Mac>, smac: impl Into<Mac>) -> Result<Packet<Eth>, IpErr> {
        Packet::<Eth>::new(dmac, smac, self.into())
            .map_err(|e| IpErr::ConversionError(format!("failed to create eth packet {e}")))
    }

    /// reads the header length of the ip packet: 20 byte + options
    #[inline(always)]
    pub fn hdr_len(&self) -> usize {
        // the len field is in the first byte
        let res = get_hdr_len(self.as_slice()[IP_HDR_OFFSET]);
        debug_assert!(
            (IP_HDR_MINSIZE..=IP_HDR_MAXSIZE).contains(&res),
            "illegal size"
        );
        res
    }

    #[inline(always)]
    pub fn hdr(&self) -> &IPv4Hdr {
        IPv4Hdr::ref_from_prefix(&self.as_slice()[IP_HDR_OFFSET..])
            .expect("get ip hdr: the packet is parsed")
            .0
    }

    #[inline(always)]
    fn set_hdr(&mut self, hdr: IPv4Hdr) {
        // currently doesnt support IP options
        assert_eq!(
            hdr.len(),
            IP_HDR_MINSIZE,
            "ip options arent supported currently"
        );
        hdr.write_to_prefix(&mut self.as_slice_mut()[IP_HDR_OFFSET..])
            .expect("set ip hdr: the packet is parsed");
    }

    #[inline(always)]
    fn set_ip_check(&mut self) {
        debug_assert!(self.len() < IP_CHECK_OFFSET + 1);

        let offset = IP_CHECK_OFFSET;

        // setting to 0 before calculation
        self.as_slice_mut()[offset] = 0;
        self.as_slice_mut()[offset + 1] = 0;

        let check = calc_checksum_be(&self.as_slice()[ETH_HDR_SIZE..ETH_HDR_SIZE + self.hdr_len()]);
        (&mut self.as_slice_mut()[offset..]).put_u16(check);
        // self.data[offset..offset + size_of::<u16>()].copy_from_slice(&u16::to_be_bytes(check));

        debug_assert_eq!(
            0,
            calc_checksum_be(&self.as_slice()[ETH_HDR_SIZE..ETH_HDR_SIZE + self.hdr_len()]),
            "checksum failed"
        );
    }
}

#[derive(Debug)]
pub enum Ipv4Payload {
    Tcp(Packet<Tcp>),
    Icmp(Packet<Icmp>),
}

impl From<Packet<Tcp>> for Ipv4Payload {
    fn from(value: Packet<Tcp>) -> Self {
        Ipv4Payload::Tcp(value)
    }
}

impl From<Packet<Icmp>> for Ipv4Payload {
    fn from(value: Packet<Icmp>) -> Self {
        Ipv4Payload::Icmp(value)
    }
}

#[derive(Default, Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct IPv4Hdr {
    pub ver_ihl: u8, // 4 bits for version and IHL (internet header length)
    pub tos: u8,     // type of service, in newer versiond the first 6 bits are the
    // "differentiated server field" (DS field)
    pub tot_len: U16<BE>, // length of the whole IP datagram
    pub id: U16<BE>,
    pub frag_off: U16<BE>, // first 3 bits are flags, rest offset
    pub ttl: u8,           // time to live
    pub prot: u8,
    pub checksum: U16<BE>, // only covers the IP header

    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],
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

        hdr.set_ihl(4, payload.len() + IP_HDR_MINSIZE);
        hdr.checksum = calc_checksum_be(payload).into();

        hdr
    }
    /// sets the header size, takes the length in bytes as argument
    fn set_ihl(&mut self, version: u8, len: usize) {
        self.ver_ihl = (version << 4) | (len as u8 >> 2);
    }

    /// retrieves the size of the IP header in bytes
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        get_hdr_len(self.ver_ihl)
    }

    pub fn version(&self) -> u8 {
        get_hdr_ver(self.ver_ihl)
    }

    pub fn is_fragmented(&self) -> bool {
        (self.frag_off & IP_MF == 0) && (self.frag_off & FRAG_OFFSET_MASK == 0)
    }
}

/// retrieves the header len of the first byte of an ipv4 header
#[inline(always)]
fn get_hdr_len(tot_len: u8) -> usize {
    ((tot_len & 0x0F) << 2) as usize
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
            "sip: {src},
            dest: {dest},
            ver: {ver},
            len: {len},
            tot_len: {tot},
            ttl: {ttl},
            prot {prot},
            check: {check}"
        )
    }
}

// pub async fn handle_ip_frame(inc: EthPacket, tcup: TCup) -> Result<()> {
//     let eth_pay = inc.payload();
//     let ip_hdr = check_ip_packet(eth_pay)?;
//
//     debug!("handling IP packet\n{}", ip_hdr);
//
//     match ip_hdr.prot {
//         IPPROTO_ICMP => handle_icmp(inc, tcup).await,
//         IPPROTO_TCP => handle_tcp(inc, tcup).await,
//         _ => Err("IP protocol not supported".into()),
//     }
// }

