use bytemuck::{Pod, Zeroable};

use crate::error::Result;

const IP_HDR_MINSIZE: usize = 20;
const IP_HDR_MAXSIZE: usize = 60;

const TTL_START: usize = 64;
const IPPROTO_ICMP: u8 = libc::IPPROTO_ICMP as u8;
const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;

const TOS_BEST_EFFORT: u8 = 0;

#[derive(Debug)]
struct IPv4Packet {
    hdr: IPHdr,
    options: Option<Box<[u8]>>, // 3 bytes options, 1 byte padding
    payload: Box<[u8]>,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
struct IPHdr {
    ver_ihl: u8, // 4 bits for version and IHL
    tos: u8,
    tot_len: u16, // length of the whole IP datagram
    id: u16,
    frag_off: FragOff, // first 3 bits are flags, rest offset
    ttl: u8,
    prot: u8,
    checksum: u16,

    src_addr: [u8; 4],
    dest_addr: [u8; 4],
}

impl IPHdr {
    pub fn from_bytes(bytes: &[u8; IP_HDR_MINSIZE]) -> Self {
        let mut hdr: IPHdr = bytemuck::cast(*bytes);

        hdr.tot_len = u16::from_be(hdr.tot_len);
        hdr.id = u16::from_be(hdr.id);
        hdr.checksum = u16::from_be(hdr.checksum);

        hdr
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
    pub fn get_hdr_len(&self) -> usize {
        let ver_mask = 0x0F;
        ((self.ver_ihl & ver_mask) << 2) as usize
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct FragOff(u16); // first 3 bits are flags, rest offset

pub fn handle_ip_frame(frame_payload: &[u8]) -> Result<()> {
    Ok(())
}
