use std::net::Ipv4Addr;

use tracing::{debug, error};
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

use crate::eth::EthHdr;
use crate::utils::packet::*;
use crate::{
    eth::ETH_HDR_SIZE,
    ip::{error::IpErr, icmp::*},
    tcp::{TCP_HDR_MINSIZE, handle_tcp},
    utils::{calc_checksum_be, packet::Packet},
};

pub const IP_HDR_MINSIZE: usize = 20;
pub const IP_HDR_MAXSIZE: usize = 60;
pub const IP_ADDR_LEN: usize = 4;
pub const TOS_BEST_EFFORT: u8 = 0;

pub const TTL_START: u8 = 64;

pub const IPPROTO_ICMP: u8 = libc::IPPROTO_ICMP as u8;
pub const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
pub const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;

pub const IP_RF: u16 = 0x8000; // reserved
pub const IP_DF: u16 = 0x4000; // don't fragment
pub const IP_MF: u16 = 0x2000; // more fragments
pub const FRAG_OFFSET_MASK: u16 = 0x1FFF;

const IP_HDR_OFFSET: usize = ETH_HDR_SIZE;
const IP_CHECK_OFFSET: usize = ETH_HDR_SIZE + 10;
/// minimum offset
const IP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;

const TCP_HDR_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE;
const TCP_CHECK_OFFSET_FROM_HDR: usize = 16;
pub const TCP_HDR_DOF_OFF: usize = 12;
/// minimum offset
const TCP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE + TCP_HDR_MINSIZE;

impl Packet<Ipv4> {
    pub fn parse(pck: Packet<Eth>) -> Result<Self, IpErr> {
        todo!()
    }

    pub fn into_parts(self) -> Result<(IP_hdr, Ipv4Payload), IpErr> {
        todo!()
    }

    pub fn to_eth(hdr: EthHdr) -> Packet<Eth> {
        todo!()
    }

    fn iphdr_size(&self) -> usize {
        let res = ((self.data[ETH_HDR_SIZE] & 0x0F) << 2) as usize;
        assert!((IP_HDR_MINSIZE..=IP_HDR_MAXSIZE).contains(&res));
        res
    }

    pub fn hdr(&self) -> IP_hdr {
        IP_hdr::from_be_bytes(
            self.data[IP_HDR_OFFSET..IP_HDR_OFFSET + IP_HDR_MINSIZE].try_into()?,
        )
    }

    pub fn get_ip_hdr(&self) -> IP_hdr {
        if self.data.len() < IP_HDR_OFFSET + IP_HDR_MINSIZE {
            return Err("not enough data to retrieve IP header".into());
        }

        Ok(IP_hdr::from_be_bytes(
            self.0[IP_HDR_OFFSET..IP_HDR_OFFSET + IP_HDR_MINSIZE].try_into()?,
        ))
    }

    pub fn set_ip_hdr(&mut self, hdr: IP_hdr) -> Result<()> {
        let lo = IP_HDR_OFFSET;
        let hi = IP_HDR_OFFSET + IP_HDR_MINSIZE;

        if self.0.len() < hi {
            return Err("data too small to write IP hdr".into());
        }

        // currently doesnt support IP options
        assert_eq!(
            hdr.len(),
            IP_HDR_MINSIZE,
            "ip options arent supported currently"
        );

        self.0.as_mut_slice()[lo..hi].copy_from_slice(&hdr.into_be_bytes());

        Ok(())
    }

    pub fn set_ip_check(&mut self) -> Result<()> {
        if self.len() < IP_CHECK_OFFSET + 1 {
            return Err("cant set ip checksum, len is too small".into());
        }

        let offset = IP_CHECK_OFFSET;

        // setting to 0 before calculation
        self.0[offset] = 0;
        self.0[offset + 1] = 0;

        let check = calc_checksum_be(&self.0[ETH_HDR_SIZE..ETH_HDR_SIZE + self.iphdr_size()]);
        self.0[offset..offset + size_of::<u16>()].copy_from_slice(&u16::to_be_bytes(check));

        assert_eq!(
            0,
            calc_checksum_be(&self.0[ETH_HDR_SIZE..ETH_HDR_SIZE + self.iphdr_size()]),
            "checksum failed"
        );

        Ok(())
    }

    pub fn get_ip_pay(&self) -> Result<&[u8]> {
        let offset = ETH_HDR_SIZE + self.iphdr_size();

        if self.len() < offset {
            return Err("no IP payload found".into());
        }

        Ok(&self.0.as_slice()[offset..])
    }

    pub fn get_ip_pay_mut(&mut self) -> Result<&mut [u8]> {
        let offset = ETH_HDR_SIZE + self.iphdr_size();
        if self.len() < offset {
            return Err("no IP payload found".into());
        }

        Ok(&mut self.0.as_mut_slice()[offset..])
    }

    /// overwrites the IP payload of the frame with data
    pub fn set_ip_pay(&mut self, data: &[u8]) -> Result<()> {
        let offset = ETH_HDR_SIZE + self.iphdr_size();

        if offset + data.len() > ETH_FRAME_MAX_SIZE {
            return Err("data exceeds MTU".into());
        }

        self.0.truncate(offset);
        self.0.extend_from_slice(data);

        Ok(())
    }
}

#[derive(Default, Debug, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct IP_hdr {
    pub ver_ihl: u8,  // 4 bits for version and IHL (internet header length)
    pub tos: u8,      // type of service
    pub tot_len: U16<BE>, // length of the whole IP datagram
    pub id: U16<BE>,
    pub frag_off: U16<BE>, // first 3 bits are flags, rest offset
    pub ttl: u8,       // time to live
    pub prot: u8,
    pub checksum: U16<BE>, // only covers the IP header

    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],
}

impl IP_hdr {
    /// sets the header size, takes the length in bytes as argument
    pub fn set_ihl(&mut self, len: usize) -> Result<()> {
        if len > IP_HDR_MAXSIZE {
            return Err("length exceeding 4 bit capacity".into());
        }
        if len < IP_HDR_MINSIZE {
            return Err("length cant be smaller than 20 bytes".into());
        }

        if len != IP_HDR_MINSIZE {
            return Err("IP options arent supported".into());
        }

        // set version to 4 with len
        self.ver_ihl = (4 << 4) | (len as u8 >> 2);

        Ok(())
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

/// retrieves the size of the IP header in bytes
pub fn get_hdr_len(byte: u8) -> usize {
    ((byte & 0x0F) << 2) as usize
}

/// retrieves the version declared in the first header byte
fn get_hdr_ver(byte: u8) -> u8 {
    byte >> 4
}

impl std::fmt::Display for IP_hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ver = self.version();
        let len = self.len();
        let tot = self.tot_len;
        let ttl = self.ttl;
        let prot = self.prot;
        let check = self.checksum;
        let src = Ipv4Addr::from_octets(self.src_addr);
        let dest = Ipv4Addr::from_octets(self.dest_addr);

        writeln!(f, "┌─────────────────┬───────────────────┐")?;
        writeln!(f, "│ {:<15} │ {:<17} │", "Field", "Value")?;
        writeln!(f, "├─────────────────┼───────────────────┤")?;
        writeln!(f, "│ {:<15} │ {:<17} │", "version", ver)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "hdr len", len)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "total length", tot)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "TTL", ttl)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "protocol", prot)?;
        writeln!(f, "│ {:<15} │ {:#06x}            │", "checksum", check)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "src addr", src)?;
        writeln!(f, "│ {:<15} │ {:<17} │", "dst addr", dest)?;
        write!(f, "└─────────────────┴───────────────────┘")
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

fn check_ip_packet(eth_pay: &[u8]) -> Result<IP_hdr> {
    if eth_pay.len() < IP_HDR_MINSIZE {
        return Err("eth_pay is too small for IP header".into());
    }

    if get_hdr_ver(eth_pay[0]) != 4 {
        return Err("not supported IP version".into());
    }

    let hdr_size = get_hdr_len(eth_pay[0]);

    if hdr_size > eth_pay.len() {
        return Err("frame smaller than declared header length".into());
    }

    if hdr_size < IP_HDR_MINSIZE {
        return Err("IP header below minimum 20 bytes".into());
    }

    // options arent supported
    if hdr_size > IP_HDR_MINSIZE {
        return Err("IP header above supported 20 bytes".into());
    }

    let check = calc_checksum_be(&eth_pay[..hdr_size]);
    if check != 0 {
        return Err(format!("invalid IP checksum: {check:x}").into());
    }

    let hdr = IP_hdr::from_be_bytes(&eth_pay[..IP_HDR_MINSIZE].try_into()?);

    if !hdr.is_fragmented() {
        let hdr_frag = hdr.frag_off;
        error!("{:b}", hdr_frag);
        return Err("fragmentation is not supported".into());
    }

    if (hdr.tot_len as usize) < hdr_size {
        return Err("total length smaller than header len".into());
    };

    if (hdr.tot_len as usize) > eth_pay.len() {
        return Err("total length exceeds eth_pay length".into());
    }
    Ok(hdr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdr_set_len() -> Result<()> {
        let mut hdr = IP_hdr::default();

        assert!(hdr.set_ihl(20).is_ok());
        assert_eq!(hdr.ver_ihl & 0x0F, 5);
        assert_eq!(hdr.len(), 20);

        assert!(hdr.set_ihl(32).is_ok());
        assert_eq!(hdr.len(), 32);

        assert!(hdr.set_ihl(44).is_ok());
        assert_eq!(hdr.len(), 44);

        assert!(hdr.set_ihl(1).is_err());
        assert!(hdr.set_ihl(4).is_err());
        assert!(hdr.set_ihl(u32::MAX as usize).is_err());

        Ok(())
    }
}
