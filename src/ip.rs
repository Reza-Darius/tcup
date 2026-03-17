use std::{
    net::Ipv4Addr,
};

use bytemuck::{Pod, Zeroable};
use tracing::{error, info};

use crate::{
    error::Result, eth::EthFrame, icmp::handle_icmp, tap::TAPDevice, types::MockHost,
    utils::calc_checksum_be,
};

pub const IP_HDR_MINSIZE: usize = 20;
pub const IP_HDR_MAXSIZE: usize = 60;

pub const TOS_BEST_EFFORT: u8 = 0;

pub const TTL_START: u8 = 64;

pub const IPPROTO_ICMP: u8 = libc::IPPROTO_ICMP as u8;
pub const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
pub const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;

#[derive(Default, Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct IP_hdr {
    pub ver_ihl: u8,  // 4 bits for version and IHL (internet header length)
    pub tos: u8,      // type of service
    pub tot_len: u16, // length of the whole IP datagram
    pub id: u16,
    pub frag_off: u16, // first 3 bits are flags, rest offset
    pub ttl: u8,       // time to live
    pub prot: u8,
    pub checksum: u16,

    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],
}

impl IP_hdr {
    /// from network order bytes
    pub fn from_be_bytes(bytes: &[u8; IP_HDR_MINSIZE]) -> Self {
        let mut hdr: IP_hdr = bytemuck::cast(*bytes);

        hdr.tot_len = u16::from_be(hdr.tot_len);
        hdr.id = u16::from_be(hdr.id);
        hdr.checksum = u16::from_be(hdr.checksum);
        hdr.frag_off = u16::from_be(hdr.frag_off);

        hdr
    }

    /// into network order bytes
    pub fn into_be_bytes(mut self) -> [u8; IP_HDR_MINSIZE] {
        self.tot_len = u16::to_be(self.tot_len);
        self.id = u16::to_be(self.id);
        self.checksum = u16::to_be(self.checksum);

        bytemuck::cast(self)
    }

    /// sets the header size, takes the length in bytes as argument
    pub fn set_ihl(&mut self, len: usize) -> Result<()> {
        // number or 32 bit words
        let mut n_32w = len / 4;

        if !len.is_multiple_of(4) {
            n_32w += 1;
        }

        if n_32w > 0b1111 {
            return Err("length exceeding 4 bit capacity".into());
        }
        if n_32w < IP_HDR_MINSIZE / 4 {
            return Err("length cant be smaller than 20 bytes".into());
        }

        // set version to 4 with len
        self.ver_ihl = (4 << 4) | n_32w as u8;
        Ok(())
    }

    /// retrieves the size of the IP header in bytes
    pub fn len(&self) -> usize {
        get_hdr_len(self.ver_ihl)
    }

    pub fn version(&self) -> u8 {
        get_hdr_ver(self.ver_ihl)
    }

    pub fn is_fragmented(&self) -> bool {
        const IP_RF: u16 = 0x8000; // reserved
        const IP_DF: u16 = 0x4000; // don't fragment
        const IP_MF: u16 = 0x2000; // more fragments
        const FRAG_OFFSET_MASK: u16 = 0x1FFF;

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
        let tot = self.tot_len;
        let ttl = self.ttl;
        let prot = self.prot;
        let check = self.checksum;
        let src = Ipv4Addr::from_octets(self.src_addr);
        let dest = Ipv4Addr::from_octets(self.dest_addr);

        write!(
            f,
            "\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n{:<15} {:>10}\n",
            "version",
            ver,
            "total length",
            tot,
            "TTL",
            ttl,
            "protocol",
            prot,
            "checksum",
            check,
            "src addr",
            src,
            "dst addr",
            dest
        )
    }
}

pub fn handle_ip_frame(data: EthFrame, tap: &TAPDevice, host: &mut MockHost) -> Result<()> {
    let eth_pay = data.get_eth_pay();

    let ip_hdr = check_ip_packet(eth_pay)?;

    info!("handling IP packet {}", ip_hdr);

    if ip_hdr.dest_addr != host.addr.octets() {
        return Err("IP packet not directed at me".into());
    }

    match ip_hdr.prot {
        IPPROTO_ICMP => {
            handle_icmp(data, tap, host)?;
            // TODO send packet

            Ok(())
        }
        // IPPROTO_TCP => (),
        // IPPROTO_UDP => (),
        _ => Err("IP protocol not supported".into()),
    }
}

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
