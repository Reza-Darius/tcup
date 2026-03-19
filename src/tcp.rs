use std::net::Ipv4Addr;
use std::sync::Arc;

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use tokio::sync::mpsc::{Receiver, channel};
use tracing::{info, warn};

use crate::error::Result;
use crate::eth::{ETH_FRAME_MAX_SIZE, ETH_HDR_SIZE, ETH_P_IP, ETH_PAY_MAX_SIZE, Eth_hdr};
use crate::ip::{IP_DF, IP_HDR_MINSIZE, IP_hdr, IPPROTO_TCP, TOS_BEST_EFFORT, TTL_START};
use crate::tcup::TCup;
use crate::types::{ConnectionKey, MAC, Socket};
use crate::utils::calc_checksum_be;
use crate::{eth::EthFrame, types::MockHost};

pub const TCP_HDR_MINSIZE: usize = 20;
pub const TCP_HDR_MAXSIZE: usize = 60;
pub const TCP_PSEUDOHDR_SIZE: usize = 12;
pub const TCP_OPT_MAX_SIZE: usize = TCP_HDR_MAXSIZE - TCP_HDR_MINSIZE;
pub const WRD_SIZE: usize = 4;

/// Retransmission timeout, how long to wait for an ACK before resending the segment in seconds
///
/// double on each retry
pub const RTO: u8 = 1;
pub const RTO_CAP: u8 = 60;

/// After sending the final FIN+ACK, you must linger before fully closing the socket. Prevents old duplicate segments from a dead connection being mistaken for a new one.
pub const TW: u8 = MSL * 2;

/// Maximum segment lifetime
pub const MSL: u8 = 60;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 10;

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct TCP_hdr {
    sport: u16, // source port
    dport: u16, // destination port

    seq: u32,
    ack: u32,

    len: u8, // first 4 bits, last 4 bits are reserved
    flags: TCPFlags,
    win_size: u16,
    check: u16,
    urg_ptr: u16,
}

impl TCP_hdr {
    pub fn from_be_bytes(data: &[u8; TCP_HDR_MINSIZE]) -> Self {
        let mut hdr: TCP_hdr = bytemuck::cast(*data);
        hdr.sport = u16::from_be(hdr.sport);
        hdr.dport = u16::from_be(hdr.dport);

        hdr.seq = u32::from_be(hdr.seq);
        hdr.ack = u32::from_be(hdr.ack);

        hdr.win_size = u16::from_be(hdr.win_size);
        hdr.urg_ptr = u16::from_be(hdr.urg_ptr);

        hdr
    }

    pub fn into_be_bytes(mut self) -> [u8; TCP_HDR_MINSIZE] {
        self.sport = u16::to_be(self.sport);
        self.dport = u16::to_be(self.dport);

        self.seq = u32::to_be(self.seq);
        self.ack = u32::to_be(self.ack);

        self.win_size = u16::to_be(self.win_size);
        self.urg_ptr = u16::to_be(self.urg_ptr);

        bytemuck::cast(self)
    }

    pub fn set_len(&mut self, len: usize) {
        self.len = ((len >> 2) << 4) as u8
    }

    /// doff - data offset
    pub fn len(&self) -> usize {
        ((self.len >> 4) << 2) as usize
    }

    pub fn syn_only(&self) -> bool {
        self.flags == TCPFlags::SYN
    }

    pub fn check_syn(&self) -> bool {
        self.flags & TCPFlags::SYN == TCPFlags::SYN
    }

    pub fn set_syn(&mut self) -> &mut Self {
        self.flags |= TCPFlags::SYN;
        self
    }

    pub fn set_ack(&mut self) -> &mut Self {
        self.flags |= TCPFlags::ACK;
        self
    }

    pub fn check_ack(&self) -> bool {
        self.flags & TCPFlags::ACK == TCPFlags::ACK
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TCP_opts {
    mss: Option<u16>, // max segment size, usually 1460
    wnd_scl: Option<u8>,
    sack_perm: bool,

    time_stamp: Option<(u32, u32)>,
}

// TCP option kinds
const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WSCL: u8 = 3;
const OPT_SACK_PERM: u8 = 4;
const OPT_SACK: u8 = 5;
const OPT_TIME_STMP: u8 = 8;
const OPT_FAST_OPEN: u8 = 34;

impl TCP_opts {
    fn parse(mut tcp_opts: &[u8]) -> Result<Self> {
        let mut opts = TCP_opts::default();

        while !tcp_opts.is_empty() {
            match tcp_opts {
                [OPT_EOL, ..] => return Ok(opts),
                [OPT_NOP, rest @ ..] => tcp_opts = rest,
                [kind, len, rest @ ..] => {
                    let len = *len as usize;
                    if len < 2 || rest.len() < len - 2 {
                        return Err("invalid TCP option length".into());
                    }

                    match *kind {
                        OPT_MSS => {
                            if len != 4 {
                                return Err("invalid MSS length".into());
                            }
                            opts.mss = Some(u16::from_be_bytes([rest[0], rest[1]]))
                        }
                        OPT_WSCL => {
                            if len != 3 {
                                return Err("invalid window scale length".into());
                            }
                            opts.wnd_scl = Some(rest[0]);
                        }
                        OPT_SACK_PERM => {
                            opts.sack_perm = true;
                        }
                        OPT_TIME_STMP => {
                            if len != 10 {
                                return Err("invalid window scale length".into());
                            }

                            let ts_val = u32::from_be_bytes(rest[..4].try_into()?);
                            let ts_ecr = u32::from_be_bytes(rest[4..8].try_into()?);

                            opts.time_stamp = Some((ts_val, ts_ecr));
                        }

                        _ => return Err("unsupported TCP options".into()),
                    }

                    tcp_opts = &tcp_opts[len..];
                }
                _ => return Err("unsupported TCP option".into()),
            }
        }
        Err("option slice ended before EOL".into())
    }

    fn into_be_bytes(self) -> [u8; TCP_OPT_MAX_SIZE] {
        todo!()
    }
}

/// socket control block
#[derive(Debug)]
pub struct SkCb {
    rcv_chan: Receiver<EthFrame>,
    snd_chan: Arc<TCup>,

    buf: Vec<u8>, // buffer for the output message
    status: TCPState,
    tcb: Tcb,

    // host information, will be replaced by socket API
    s_addr: Ipv4Addr,
    s_mac: MAC,
    s_port: u16,

    // connection info
    d_addr: Ipv4Addr,
    d_mac: MAC,
}

impl SkCb {
    fn new(
        rx: Receiver<EthFrame>,
        tcup: Arc<TCup>,
        host: &MockHost,
        d_addr: Ipv4Addr,
        d_mac: MAC,
    ) -> Self {
        SkCb {
            rcv_chan: rx,
            snd_chan: tcup,

            buf: vec![],
            status: TCPState::Closed,
            tcb: Tcb::default(),

            s_addr: host.addr,
            s_mac: host.mac,
            s_port: host.port,

            d_addr,
            d_mac,
        }
    }

    fn send_packet(&self, tcp_hdr: TCP_hdr, opts: Option<TCP_opts>, tcp_pay: &[u8]) -> Result<()> {
        let ip_tot_len = IP_HDR_MINSIZE + tcp_hdr.len() + tcp_pay.len();
        let mut ip_hdr = IP_hdr {
            ver_ihl: 0,
            tos: TOS_BEST_EFFORT,
            tot_len: ip_tot_len as u16,
            id: 0,
            frag_off: IP_DF,
            ttl: TTL_START,
            prot: IPPROTO_TCP,
            checksum: 0,
            src_addr: self.s_addr.octets(),
            dest_addr: self.d_addr.octets(),
        };

        ip_hdr.set_ihl(IP_HDR_MINSIZE)?;

        let mut packet = EthFrame {
            data: Vec::with_capacity(ETH_HDR_SIZE + ip_tot_len),
        };

        let eth_hdr = Eth_hdr::new(self.d_mac, self.s_mac, ETH_P_IP);

        packet.set_eth_hdr(eth_hdr);
        packet.set_ip_hdr(ip_hdr)?;
        packet.set_tcp_hdr(tcp_hdr)?;
        packet.set_tcp_pay(tcp_pay)?;
        packet.set_tcp_check(PseudoHdr::new(
            ip_hdr.src_addr,
            ip_hdr.dest_addr,
            tcp_hdr.len() + tcp_pay.len(),
        ))?;
        packet.set_ip_check()?;

        Ok(())
    }
}

/// transmission control block
#[derive(Debug, Clone, Default)]
pub struct Tcb {
    snd_una: u32, // unacknowledged data
    snd_nxt: u32, // sent bytes
    snd_wnd: u32, // window size (upper limit)

    rcv_nxt: u32, // next byte to receive
    rcv_wnd: u32, // future seq number not yet allowed (upper limit)

    iss: u32, // initial send sequence number
    irs: u32, // initial receive sequence number

    seg_seq: u32,
    seg_ack: u32,
    seg_len: u32,
    seg_wnd: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum TCPState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,

    #[default]
    Closed,
}

bitflags! {
    /// the 13th octet in the header can be used for direct lookup
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Pod, Zeroable, Default)]
    #[repr(C)]
    struct TCPFlags: u8 {
        /// Congestion Window Reduced (C) is used for informing that the sender reduced its sending rate
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
    }
}

#[derive(Default, Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct PseudoHdr {
    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],

    res: u8,      // zero
    prot: u8,     // IPPROTO_TCP = 6
    tcp_len: u16, // TCP segment length
}

impl PseudoHdr {
    fn new(src_addr: [u8; 4], dest_addr: [u8; 4], tcp_len: usize) -> Self {
        PseudoHdr {
            src_addr,
            dest_addr,
            res: 0,
            prot: IPPROTO_TCP,
            tcp_len: tcp_len as u16,
        }
    }
    pub fn into_be_bytes(mut self) -> [u8; TCP_PSEUDOHDR_SIZE] {
        self.tcp_len = self.tcp_len.to_be();
        bytemuck::cast(self)
    }
}

pub async fn handle_tcp(inc: EthFrame, tcup: Arc<TCup>, host: &mut MockHost) -> Result<()> {
    let eth_hdr = inc.get_eth_hdr();
    let ip_hdr = inc.get_ip_hdr()?;
    let tcp_hdr = inc.get_tcp_hdr()?;

    let con_k = ConnectionKey {
        source_ip: Ipv4Addr::from_octets(ip_hdr.src_addr),
        source_port: tcp_hdr.sport,
        destination_ip: Ipv4Addr::from_octets(ip_hdr.dest_addr),
        destination_port: tcp_hdr.dport,
    };

    let sock = tcup.con_table.read().get(&con_k).cloned();

    if let Some(sock) = sock {
        // hand off frame
        info!("handing off packet to connection");

        return sock.tx.send(inc).await.map_err(Into::into);
    } else {
        if !tcp_hdr.syn_only() {
            warn!("discarding TCP packetj");
            return Ok(());
        }

        info!("new connection!");

        // register new connection and spawn worker
        let (tx, rx) = channel::<EthFrame>(CHAN_BUF_SIZE);
        tcup.con_table.write().insert(con_k, Socket { tx });

        let skcb = SkCb::new(
            rx,
            tcup.clone(),
            host,
            con_k.source_ip,
            MAC::from_octets(eth_hdr.smac),
        );
        tokio::spawn(handshake(inc, skcb));

        Ok(())
    }
}

async fn handshake(inc: EthFrame, mut skcb: SkCb) -> Result<()> {
    let req_ip_hdr = inc.get_ip_hdr()?;
    let req_tcp_hdr = inc.get_tcp_hdr()?;

    skcb.status = TCPState::SynReceived;

    // send off SYNACK

    todo!()
}

async fn tcp_loop() {}

fn parse_options(framge: EthFrame) -> Option<TCP_opts> {
    todo!()
}

fn new_isn() -> u32 {
    todo!()
}

fn tcp_checksum(phdr: PseudoHdr, mut hdr: TCP_hdr, opts: Option<TCP_opts>, pay: &[u8]) -> u16 {
    let mut buf = [0u8; ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE + TCP_PSEUDOHDR_SIZE];
    let mut offset = 0;
    hdr.check = 0;

    buf[..TCP_PSEUDOHDR_SIZE].copy_from_slice(&phdr.into_be_bytes());
    offset += TCP_PSEUDOHDR_SIZE;

    buf[offset..offset + TCP_HDR_MINSIZE].copy_from_slice(&hdr.into_be_bytes());
    offset += TCP_HDR_MINSIZE;

    if let Some(opts) = opts {
        let opt_size = hdr.len() - TCP_HDR_MINSIZE;
        buf[offset..offset + opt_size].copy_from_slice(&opts.into_be_bytes());
        offset += opt_size;
    }

    buf[offset..offset + pay.len()].copy_from_slice(pay);

    calc_checksum_be(&buf)
}
