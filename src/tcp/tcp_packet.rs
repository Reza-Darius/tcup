use std::default;
use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::BufMut;
use tracing::warn;
use zerocopy::{BE, FromBytes, Immutable, IntoBytes, KnownLayout, U16, U32};

use crate::eth::{ETH_FRAME_MAX_SIZE, ETH_HDR_SIZE, ETH_PAY_MAX_SIZE};
use crate::ip::{IP_HDR_MINSIZE, IP_HDR_OFFSET, IPPROTO_TCP, IPv4Hdr};
use crate::tcp::error::TCPError::{self, ParseError};
use crate::tcp::opts::TCPOpts;
use crate::tcp::socket::TCPCon;
use crate::utils::calc_checksum_be;
use crate::utils::packet::{IP, Packet, PacketBuf, TCP};

pub const TCP_HDR_MINSIZE: usize = 20;
pub const TCP_HDR_MAXSIZE: usize = 60;
pub const TCP_PSEUDOHDR_SIZE: usize = 12;
pub const TCP_OPT_MAX_SIZE: usize = TCP_HDR_MAXSIZE - TCP_HDR_MINSIZE;
/// start of the TCP segment with a min size IP header in an eth frame buffer
pub const TCP_HDR_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE as usize;
const TCP_CHECK_OFFSET_FROM_HDR: usize = 16;
pub const TCP_HDR_DOF_OFF: usize = 12;
pub const TCP_SEG_MAX_SIZE: usize = ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE as usize - TCP_HDR_MINSIZE;

/// minimum offset
const TCP_PAY_OFFSET: usize = ETH_HDR_SIZE + IP_HDR_MINSIZE as usize + TCP_HDR_MINSIZE;

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Default)]
#[repr(C, packed)]
pub struct TCPHdr {
    pub sport: U16<BE>, // source port
    pub dport: U16<BE>, // destination port
    pub seq: U32<BE>,
    pub ack: U32<BE>,
    /// len of the header including options, the number of 32-bit words in the TCP header
    pub len: u8,
    pub flags: TCPFlags,
    pub win_size: U16<BE>,
    pub check: U16<BE>,
    /// ignored in modern stacks
    pub urg_ptr: U16<BE>,
}

impl TCPHdr {
    pub fn new(sport: u16, dport: u16, seq: u32, ack: u32, flags: TCPFlags) -> Self {
        TCPHdr {
            sport: sport.into(),
            dport: dport.into(),
            seq: seq.into(),
            ack: ack.into(),
            len: 5 << 4,
            flags,
            ..default::Default::default()
        }
    }
}

/// the 13th octet in the header can be used for direct lookup
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Default)]
#[repr(transparent)]
pub struct TCPFlags(u8);

bitflags::bitflags! {
    impl TCPFlags: u8 {
        const CWR = 0b10000000;
        /// ECN Echo (E) informs that the sender received a congestion notification
        const ECE = 0b01000000;
        /// Urgent Pointer (U) indicates that the segment contains prioritized dat
        const URG = 0b00100000;
        /// ACK (A) field is used to communicate the state of the TCP handshake. It stays on for the remainder of the connection.
        const ACK = 0b00010000;
        /// PSH (P) is used to indicate that the receiver should “push” the data to the application as soon as possible.
        const PSH = 0b00001000;
        /// RST (R) resets the TCP connection
        const RST = 0b00000100;
        /// SYN (S) is used to synchronize sequence numbers in the initial handshake
        const SYN = 0b00000010;
        /// FIN (F) indicates that the sender has finished sending data
        const FIN = 0b00000001;

        /// Union of SYN and ACK field
        const SYNACK = Self::SYN.bits() | Self::ACK.bits();
        const RSTACK = Self::RST.bits() | Self::ACK.bits();
    }
}

impl TCPHdr {
    pub fn set_len(&mut self, len: usize) {
        debug_assert!((TCP_HDR_MINSIZE..=TCP_HDR_MAXSIZE).contains(&len));
        self.len = (((len >> 2) & 0xF) << 4) as u8;
    }

    /// doff - data offset
    pub fn len(&self) -> usize {
        (((self.len >> 4) & 0xF) << 2) as usize
    }

    pub fn is_syn(&self) -> bool {
        self.flags & TCPFlags::SYN == TCPFlags::SYN
    }

    pub fn is_syn_only(&self) -> bool {
        self.flags == TCPFlags::SYN
    }

    pub fn is_synack(&self) -> bool {
        self.flags & TCPFlags::SYNACK == TCPFlags::SYNACK
    }

    pub fn set_syn(&mut self) -> &mut Self {
        self.flags |= TCPFlags::SYN;
        self
    }

    pub fn set_ack(&mut self) -> &mut Self {
        self.flags |= TCPFlags::ACK;
        self
    }

    pub fn is_ack(&self) -> bool {
        self.flags & TCPFlags::ACK == TCPFlags::ACK
    }

    pub fn pure_ack(&self) -> bool {
        self.is_ack() && !self.is_syn() && !self.is_fin() && !self.is_rst()
    }

    pub fn is_fin(&self) -> bool {
        self.flags & TCPFlags::FIN == TCPFlags::FIN
    }

    pub fn set_fin(&mut self) -> &mut Self {
        self.flags |= TCPFlags::FIN;
        self
    }

    pub fn is_rst(&self) -> bool {
        self.flags & TCPFlags::RST == TCPFlags::RST
    }

    pub fn set_rst(&mut self) -> &mut Self {
        self.flags |= TCPFlags::RST;
        self
    }
}

#[derive(Default, Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct PseudoHdr {
    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],

    padding: u8,      // padding zero
    prot: u8,         // IPPROTO_TCP = 6
    tcp_len: U16<BE>, // TCP segment length
}

impl PseudoHdr {
    /// tcp_len = tcp header len + payload len
    pub fn new(src_addr: Ipv4Addr, dest_addr: Ipv4Addr, tcp_len: u16) -> Self {
        PseudoHdr {
            src_addr: src_addr.octets(),
            dest_addr: dest_addr.octets(),
            padding: 0,
            prot: IPPROTO_TCP,
            tcp_len: tcp_len.into(),
        }
    }
}

pub struct TCPPayload {
    data: Vec<u8>,
    offset: usize, // the offset of the actual TCP payload, as the buffer retains ETH/IP info
}

impl TCPPayload {
    /// the caller is responsible for placing the payload at the correct offset
    pub fn from_vec(data: Vec<u8>, offset: usize) -> Self{
        TCPPayload { data, offset }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.offset
    }
}

impl Packet<TCP> {
    pub fn parse(packet: Packet<IP>) -> Result<Self, TCPError> {
        if packet.len() < ETH_HDR_SIZE + IP_HDR_MINSIZE as usize + TCP_HDR_MINSIZE {
            warn!(len = packet.len(), "packet len is too small");
            return Err(ParseError);
        }

        if !verify_tcp_checksum(&packet) {
            warn!("invalid checksum");
            return Err(ParseError);
        }

        let tcp_packet = Packet::<TCP>::from_vec(packet.into_buf());
        Ok(tcp_packet)
    }

    pub fn new(
        sip: Ipv4Addr,
        dip: Ipv4Addr,
        mut hdr: TCPHdr,
        opts: TCPOpts,
        payload: &[u8],
    ) -> Packet<IP> {
        hdr.set_len(TCP_HDR_MINSIZE + opts.len());
        let payload_offset = ETH_HDR_SIZE + IP_HDR_MINSIZE as usize + hdr.len();

        debug_assert!(payload_offset + payload.len() <= ETH_FRAME_MAX_SIZE);

        let mut data = Vec::with_capacity(payload_offset + payload.len());

        // make space for all the headers and write the payload
        data.resize(payload_offset, 0);
        data.extend_from_slice(payload);

        let mut packet = Packet::<TCP>::from_vec(data);

        packet.set_hdr(hdr);
        packet.set_options(opts);
        packet.set_checksum(PseudoHdr::new(
            sip,
            dip,
            hdr.len() as u16 + payload.len() as u16,
        ));

        let packet = Packet::<IP>::new(sip, dip, packet.into()).unwrap();

        debug_assert!(
            packet.len() == ETH_HDR_SIZE + IP_HDR_MINSIZE as usize + packet.payload().len()
        );
        debug_assert!(
            packet.hdr().tot_len()
                == IP_HDR_MINSIZE as u16 + hdr.len() as u16 + payload.len() as u16
        );

        packet
    }

    pub fn into_parts(self) -> (TCPHdr, Option<TCPPayload>) {
        let hdr = *self.hdr();

        if self.payload().is_empty() {
            (hdr, None)
        } else {
            let offset = ETH_HDR_SIZE + self.iphdr_size() + self.hdr_size();
            (
                hdr,
                Some(TCPPayload {
                    offset,
                    data: self.into_buf(),
                }),
            )
        }
    }

    fn iphdr_size(&self) -> usize {
        // TODO: dynamic reading of IP header with options
        IP_HDR_MINSIZE as usize
    }

    #[inline(always)]
    pub fn ip_hdr(&self) -> &IPv4Hdr {
        IPv4Hdr::ref_from_prefix(&self.as_buf()[IP_HDR_OFFSET..])
            .expect("get ip hdr: the packet is parsed")
            .0
    }

    /// destination socket addr
    pub fn d_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip_hdr().dip(), self.hdr().dport.get())
    }

    /// source socket addr
    pub fn s_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip_hdr().sip(), self.hdr().sport.get())
    }

    /// retrieves the the IP payload
    fn ip_pay(&self) -> &[u8] {
        let tot_len = self.ip_hdr().tot_len();
        &self.as_buf()[ETH_HDR_SIZE..ETH_HDR_SIZE + tot_len as usize]
    }

    /// retrieves the size of the TCP header including options
    fn hdr_size(&self) -> usize {
        let offset = ETH_HDR_SIZE + self.iphdr_size() + TCP_HDR_DOF_OFF;
        let res = (((self.as_buf()[offset] >> 4) & 0xF) << 2) as usize;
        debug_assert!((TCP_HDR_MINSIZE..=TCP_HDR_MAXSIZE).contains(&res));
        res
    }

    pub fn hdr(&self) -> &TCPHdr {
        let offset = ETH_HDR_SIZE + self.iphdr_size();
        TCPHdr::ref_from_prefix(&self.as_buf()[offset..])
            .expect("the packet is parsed")
            .0
    }

    /// the starting point of the TCP header inside the buffer
    fn tcp_offset(&self) -> usize {
        ETH_HDR_SIZE + self.iphdr_size()
    }

    fn set_hdr(&mut self, hdr: TCPHdr) {
        debug_assert!((TCP_HDR_MINSIZE..=TCP_HDR_MAXSIZE).contains(&hdr.len()));

        let lo = self.tcp_offset();
        let hi = lo + TCP_HDR_MINSIZE;

        self.as_buf_mut()[lo..hi].copy_from_slice(hdr.as_bytes());

        debug_assert_eq!(hdr.len(), self.hdr_size());
    }

    pub fn options(&self) -> Option<TCPOpts> {
        let opt_size = self.hdr_size() - TCP_HDR_MINSIZE;
        if opt_size == 0 {
            return None;
        }

        let lo = self.tcp_offset() + TCP_HDR_MINSIZE;
        let hi = lo + opt_size;
        let opt_slice = &self.as_buf()[lo..hi];

        Some(TCPOpts::from_be_bytes(opt_slice).expect("the packet is parsed"))
    }

    fn set_options(&mut self, opts: TCPOpts) {
        if opts.is_empty() {
            return;
        }

        let opts = opts.into_be_bytes();
        let lo = self.tcp_offset() + TCP_HDR_MINSIZE;
        let hi = lo + opts.len();

        debug_assert!(
            opts.len() <= TCP_OPT_MAX_SIZE,
            "tcp options cant exceed opt max size"
        );

        self.as_buf_mut()[lo..hi].copy_from_slice(&opts);

        debug_assert_eq!(self.hdr_size(), opts.len() + TCP_HDR_MINSIZE);
    }

    /// sets the TCP checksum, breaks on ip header with options
    fn set_checksum(&mut self, phdr: PseudoHdr) {
        // set TCP check to 0
        self.write_checksum(0);

        // populate buffer for checksum calculation
        // TODO: account for IP hdr options
        const BUF_LEN: usize = ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE as usize + TCP_PSEUDOHDR_SIZE;
        let mut buf = [0u8; BUF_LEN];
        let mut cursor = &mut buf[..];

        cursor.put_slice(phdr.as_bytes());
        cursor.put_slice(&self.as_buf()[TCP_HDR_OFFSET..]);
        let buf_off = BUF_LEN - cursor.remaining_mut();

        let check = calc_checksum_be(&buf[..buf_off]);
        self.write_checksum(check);

        #[cfg(debug_assertions)]
        {
            let ctrl_off = TCP_PSEUDOHDR_SIZE + TCP_CHECK_OFFSET_FROM_HDR;
            buf[ctrl_off..ctrl_off + size_of::<u16>()].copy_from_slice(&check.to_be_bytes());
            assert_eq!(0, calc_checksum_be(&buf[..buf_off]));
        }
    }

    fn write_checksum(&mut self, checksum: u16) {
        let check_off = self.tcp_offset() + TCP_CHECK_OFFSET_FROM_HDR;
        (&mut self.as_buf_mut()[check_off..]).put_u16(checksum);
    }

    /// payload of the TCP packet
    pub fn payload(&self) -> &[u8] {
        let lo = self.tcp_offset() + self.hdr_size();
        let hi = lo + self.ip_hdr().tot_len() as usize - self.iphdr_size() - self.hdr_size();

        &self.as_buf()[lo..hi]
    }

    pub fn con(&self) -> TCPCon {
        let ip_hdr = self.ip_hdr();
        let tcp_hdr = self.hdr();

        TCPCon {
            remote_ip: ip_hdr.sip(),
            remote_port: tcp_hdr.sport.get(),
            local_ip: ip_hdr.dip(),
            local_port: tcp_hdr.dport.get(),
        }
    }
}

fn verify_tcp_checksum(packet: &Packet<IP>) -> bool {
    let ip_hdr = packet.hdr();
    let tcp_len = ip_hdr.tot_len() as usize - ip_hdr.len() as usize;
    let tcp_off = ETH_HDR_SIZE + ip_hdr.len() as usize;
    let seg = &packet.as_buf()[tcp_off..tcp_off + tcp_len];

    let phdr = PseudoHdr::new(ip_hdr.sip(), ip_hdr.dip(), tcp_len as u16);

    let mut buf = Vec::with_capacity(TCP_PSEUDOHDR_SIZE + tcp_len);
    buf.extend_from_slice(phdr.as_bytes());
    buf.extend_from_slice(seg);
    calc_checksum_be(&buf) == 0
}

impl std::fmt::Display for TCPHdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flags = [
            (TCPFlags::CWR, "CWR"),
            (TCPFlags::ECE, "ECE"),
            (TCPFlags::URG, "URG"),
            (TCPFlags::ACK, "ACK"),
            (TCPFlags::PSH, "PSH"),
            (TCPFlags::RST, "RST"),
            (TCPFlags::SYN, "SYN"),
            (TCPFlags::FIN, "FIN"),
        ]
        .iter()
        .filter_map(|(flag, name)| self.flags.contains(*flag).then_some(*name))
        .collect::<Vec<_>>()
        .join(", ");

        write!(
            f,
            "sport: {}, dport: {}, seq: {}, ack: {}, len: {}, win_size: {}, check: {:#06x}, urg_ptr: {}, flags: {}",
            self.sport,
            self.dport,
            self.seq,
            self.ack,
            self.len(),
            self.win_size,
            self.check,
            self.urg_ptr,
            flags,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    fn zero_hdr() -> TCPHdr {
        TCPHdr::read_from_bytes(&[0u8; TCP_HDR_MINSIZE]).unwrap()
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(size_of::<TCPHdr>(), TCP_HDR_MINSIZE);
        assert_eq!(size_of::<PseudoHdr>(), TCP_PSEUDOHDR_SIZE);
    }

    #[test]
    fn data_offset_roundtrip() {
        let mut h = zero_hdr();
        for len in (TCP_HDR_MINSIZE..=TCP_HDR_MAXSIZE).step_by(4) {
            h.set_len(len);
            assert_eq!(h.len(), len);
        }
    }

    #[test]
    fn wire_layout() {
        let mut h = zero_hdr();
        h.sport = 0x1234.into();
        h.dport = 80.into();
        h.seq = 0x0102_0304.into();
        h.ack = 0x0a0b_0c0d.into();
        h.set_len(24);
        h.set_syn();
        h.win_size = 0xffff.into();
        let b = h.as_bytes();
        assert_eq!(&b[0..2], &[0x12, 0x34]);
        assert_eq!(&b[2..4], &[0, 80]);
        assert_eq!(&b[4..8], &[1, 2, 3, 4]);
        assert_eq!(&b[8..12], &[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(b[12], 0x60); // doff = 6 words
        assert_eq!(b[13], 0x02); // SYN
        assert_eq!(&b[14..16], &[0xff, 0xff]);
    }

    #[test]
    fn flag_helpers() {
        let mut h = zero_hdr();
        h.set_syn();
        assert!(h.is_syn() && h.is_syn_only() && !h.is_synack());
        h.set_ack();
        assert!(h.is_synack() && h.is_syn() && !h.is_syn_only());
        h.set_fin();
        assert!(h.is_fin());
        h.set_rst();
        assert!(h.is_rst());
    }

    #[test]
    fn pseudo_hdr_bytes() {
        let p = PseudoHdr::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            0x0123,
        );
        assert_eq!(p.as_bytes(), &[10, 0, 0, 1, 10, 0, 0, 2, 0, 6, 0x01, 0x23]);
    }

    /// RFC 1071 example. Assumes calc_checksum_be returns the complemented sum.
    #[test]
    fn checksum_rfc1071_vector() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(calc_checksum_be(&data), 0x220d);
    }

    fn build(opts: TCPOpts, payload: &[u8]) -> Packet<IP> {
        let mut h = zero_hdr();
        h.sport = 40000.into();
        h.dport = 80.into();
        h.seq = 1.into();
        h.set_syn();
        h.win_size = 1024.into();
        h.set_len(TCP_HDR_MINSIZE + opts.len());
        Packet::<TCP>::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            h,
            opts,
            payload,
        )
    }

    // folded ones'-complement sum over pseudo hdr + segment must be 0xffff
    fn verify_checksum(frame: &[u8], sip: [u8; 4], dip: [u8; 4]) {
        let tcp = &frame[TCP_HDR_OFFSET..];
        let mut buf = Vec::new();
        buf.extend_from_slice(PseudoHdr::new(sip.into(), dip.into(), tcp.len() as u16).as_bytes());
        buf.extend_from_slice(tcp);
        assert_eq!(calc_checksum_be(&buf), 0);
    }

    #[test]
    fn new_without_options() {
        let p = build(TCPOpts::default(), b"hello");
        verify_checksum(p.as_buf(), [10, 0, 0, 1], [10, 0, 0, 2]);
    }

    #[allow(clippy::len_zero)]
    #[test]
    fn options_size() {
        let o = TCPOpts::default();
        assert!(o.is_empty());
        assert!(o.len() == 0);
    }

    #[test]
    fn new_with_options_and_odd_payload() {
        let opts = TCPOpts {
            mss: Some(1460),
            wnd_scl: Some(7),
            ..Default::default()
        };
        let p = build(opts, b"abc"); // odd length exercises checksum padding
        verify_checksum(p.as_buf(), [10, 0, 0, 1], [10, 0, 0, 2]);
    }
}
