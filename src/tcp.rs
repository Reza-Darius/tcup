use std::net::Ipv4Addr;
use std::sync::Arc;

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, channel};
use tracing::debug;

use crate::error::Result;
use crate::eth::ETH_FRAME_MAX_SIZE;
use crate::types::{ConnectionKey, Socket, TCup};
use crate::{eth::EthFrame, tap::TAPDevice, types::MockHost};

pub const TCP_HDR_MINSIZE: usize = 20;
pub const TCP_HDR_MAXSIZE: usize = 60;
pub const TCP_PSEUDOHDR_SIZE: usize = 12;
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

    pub fn is_syn_only(&self) -> bool {
        // check syn flag
        let syn = self.flags & TCPFlags::SYN;
        if syn.bits() == 0 {
            return false;
        }
        // check for only syn flag
        let syn_only = self.flags | TCPFlags::SYN;
        if syn_only != TCPFlags::SYN {
            return false;
        }
        true
    }
}

/// socket control block
#[derive(Debug)]
pub struct TCP_SK_CB {
    inc: Receiver<EthFrame>,
    out: Arc<RwLock<TAPDevice>>,

    tcb: Tcb,
}

/// transmission control block
#[derive(Debug, Clone, Default)]
pub struct Tcb {
    status: TCPState,

    snd_una: u32,
    snd_next: u32,
    snd_wnd: u32,

    rcv_next: u32,
    rcv_wnd: u32,

    snd_isn: u32,
    rcv_isn: u32,

    seg_seq: u32,
    seg_ack: u32,
    seg_len: u32,
    seg_wnd: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum TCPState {
    Listen,
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
    pub res: u8,      // zero
    pub prot: u8,     // IPPROTO_TCP = 6
    pub tcp_len: u16, // TCP segment length
}

pub async fn handle_tcp(inc: EthFrame, tcup: Arc<TCup>, host: &mut MockHost) -> Result<()> {
    let ip_hdr = inc.get_ip_hdr()?;
    let tcp_hdr = inc.get_tcp_hdr()?;

    let con_k = ConnectionKey {
        source_ip: Ipv4Addr::from_octets(ip_hdr.src_addr),
        source_port: tcp_hdr.sport,
        destination_ip: Ipv4Addr::from_octets(ip_hdr.dest_addr),
        destination_port: tcp_hdr.dport,
    };

    if let Some(sock) = tcup.con_table.read().get(&con_k) {
        // hand off frame
        return sock.tx.send(inc).await.map_err(Into::into);
    } else {
        if !tcp_hdr.is_syn_only() {
            debug!("discarding TCP packetj");
            return Ok(());
        }

        // register new connection and spawn worker
        let (tx, rx) = channel::<EthFrame>(CHAN_BUF_SIZE);
        tcup.con_table.write().insert(con_k, Socket { tx });

        let tcup = tcup.clone();
        tokio::spawn(new_tcp(rx, tcup));

        Ok(())
    }
}

async fn new_tcp(rx: Receiver<EthFrame>, tcup: Arc<TCup>) -> Result<()> {
    todo!()
}

async fn tcp_loop() {}

fn new_isn() -> u32 {
    todo!()
}

fn tcp_checksum(phdr: &PseudoHdr, hrd: &TCP_hdr, tcp_pay: &[u8]) -> usize {
    todo!()
}
