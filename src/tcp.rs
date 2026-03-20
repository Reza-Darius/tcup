pub mod hdr;
pub mod opts;

use core::hash::Hasher;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use siphasher::sip::SipHasher13;
use tokio::select;
use tokio::sync::mpsc::{Receiver, channel};
use tracing::{debug, info, instrument, warn};

use crate::error::Result;
use crate::eth::{ETH_FRAME_MAX_SIZE, ETH_HDR_SIZE, ETH_P_IP, Eth_hdr};
use crate::ip::{IP_DF, IP_HDR_MINSIZE, IP_hdr, IPPROTO_TCP, TOS_BEST_EFFORT, TTL_START};
use crate::tcp::hdr::TCP_hdr;
use crate::tcp::opts::TCP_opts;
use crate::tcup::{CLOCK, TCup};
use crate::types::{Mac, Socket, TCPCon};
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

/// socket control block
#[derive(Debug)]
pub struct SkCb {
    rcv_chan: Receiver<EthFrame>,
    snd_chan: Arc<TCup>,

    buf: Vec<u8>, // buffer for the output message
    status: TCPState,
    tcb: Tcb,

    con: TCPCon,
    eth_hdr: Eth_hdr, // header to be attached to outgoing messages, need to deprecate this
}

impl SkCb {
    fn new(rx: Receiver<EthFrame>, tcup: Arc<TCup>, eth_hdr: Eth_hdr, con: TCPCon) -> Self {
        SkCb {
            rcv_chan: rx,
            snd_chan: tcup,

            buf: vec![],
            status: TCPState::Closed,
            tcb: Tcb::default(),

            eth_hdr: Eth_hdr::new(
                Mac::from_octets(eth_hdr.smac),
                Mac::from_octets(eth_hdr.dmac),
                ETH_P_IP,
            ),
            con,
        }
    }

    /// sends a packet through the open connection
    async fn reply(&self, tcp_hdr: TCP_hdr, opts: TCP_opts, tcp_pay: &[u8]) -> Result<()> {
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
            src_addr: self.con.dip.octets(),
            dest_addr: self.con.sip.octets(),
        };

        ip_hdr.set_ihl(IP_HDR_MINSIZE)?;

        // debug!("ip tot len {}", ip_tot_len);
        // debug!("tcp hdr len {}", tcp_hdr.len());

        let mut packet = EthFrame::with_cap(ETH_HDR_SIZE + ip_tot_len)?;

        packet.set_eth_hdr(self.eth_hdr);
        packet.set_ip_hdr(ip_hdr)?;
        packet.set_tcp_hdr(tcp_hdr)?;
        packet.set_tcp_opts(opts)?;
        packet.set_tcp_pay(tcp_pay)?;
        packet.set_tcp_check(PseudoHdr::new(
            ip_hdr.src_addr,
            ip_hdr.dest_addr,
            tcp_hdr.len() + tcp_pay.len(),
        ))?;
        packet.set_ip_check()?;

        info!("sending reply");
        println!("reply ETH:\n{}", self.eth_hdr);
        println!("reply IP:\n{}", ip_hdr);
        println!("reply TCP:\n{}", tcp_hdr);

        // do we need a timeout?
        let n = self.snd_chan.write_tap(packet).await?;

        assert_eq!(n, ETH_HDR_SIZE + ip_hdr.tot_len as usize);

        println!("{n} bytes written");
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

impl std::fmt::Display for Tcb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\n{:<12} {:>10}\n{:<12} {:>10}\n{:<12} {:>10}\
             \n{:<12} {:>10}\n{:<12} {:>10}\
             \n{:<12} {:>10}\n{:<12} {:>10}\
             \n{:<12} {:>10}\n{:<12} {:>10}\n{:<12} {:>10}",
            "snd_una",
            self.snd_una,
            "snd_nxt",
            self.snd_nxt,
            "snd_wnd",
            self.snd_wnd,
            "rcv_nxt",
            self.rcv_nxt,
            "rcv_wnd",
            self.rcv_wnd,
            "iss",
            self.iss,
            "irs",
            self.irs,
            "seg_seq",
            self.seg_seq,
            "seg_ack",
            self.seg_ack,
            "seg_len",
            self.seg_len,
        )
    }
}

impl Tcb {
    fn ridx(&self) -> usize {
        (self.rcv_nxt - self.irs) as usize
    }

    fn sidx(&self) -> usize {
        (self.snd_nxt - self.iss) as usize
    }
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
    pub struct TCPFlags: u8 {
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
    // TODO: check tcp checksum
    //
    //
    let eth_hdr = inc.get_eth_hdr();
    let ip_hdr = inc.get_ip_hdr()?;
    let tcp_hdr = inc.get_tcp_hdr()?;

    let con_k = TCPCon {
        sip: Ipv4Addr::from_octets(ip_hdr.src_addr),
        sport: tcp_hdr.sport,
        dip: Ipv4Addr::from_octets(ip_hdr.dest_addr),
        dport: tcp_hdr.dport,
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

        info!("new SYN packet received!");

        // register new connection and spawn worker
        let (tx, rx) = channel::<EthFrame>(CHAN_BUF_SIZE);
        tcup.con_table.write().insert(con_k, Socket { tx });

        let mut skcb = SkCb::new(rx, tcup.clone(), eth_hdr, con_k);

        // priming the TCP loops
        skcb.status = TCPState::SynReceived;

        tokio::spawn(tcp_processing(inc, skcb));

        Ok(())
    }
}

#[instrument(skip_all, err)]
async fn tcp_processing(inc: EthFrame, mut skcb: SkCb) -> Result<()> {
    loop {
        match skcb.status {
            TCPState::SynSent => todo!(),
            TCPState::SynReceived => handshake(&inc, &mut skcb).await?,
            TCPState::Established => todo!(),
            TCPState::FinWait1 => todo!(),
            TCPState::FinWait2 => todo!(),
            TCPState::CloseWait => todo!(),
            TCPState::Closing => todo!(),
            TCPState::LastAck => todo!(),
            TCPState::Closed => todo!(),
        };
    }
}

async fn handshake(inc: &EthFrame, skcb: &mut SkCb) -> Result<()> {
    let req_ip_hdr = inc.get_ip_hdr()?;
    let req_tcp_hdr = inc.get_tcp_hdr()?;

    println!("req IP:\n{}", req_ip_hdr);
    println!("req TCP:\n{}", req_tcp_hdr);

    // send off SYNACK

    skcb.tcb.iss = req_tcp_hdr.seq;
    skcb.tcb.irs = new_isn(&skcb.con);

    let mut tcp_hdr = TCP_hdr {
        sport: skcb.con.dport,
        dport: skcb.con.sport,
        seq: skcb.tcb.irs,
        ack: req_tcp_hdr.seq + 1,
        flags: TCPFlags::default(),
        win_size: 10000,
        ..Default::default()
    };

    let opts = TCP_opts {
        mss: Some(1460),
        ..Default::default()
    };

    tcp_hdr.set_syn();
    tcp_hdr.set_ack();
    tcp_hdr.set_len(TCP_HDR_MINSIZE + opts.len())?;

    skcb.reply(tcp_hdr, opts, &[]).await?;

    // wait for response or timeout
    select! {
        _ = tokio::time::sleep(Duration::new(10, 0)) =>  {
            warn!("handshake timed out");

            skcb.status = TCPState::Closed;
            Ok(())
        }
        Some(resp) = skcb.rcv_chan.recv() => {
            println!("SYNACK received!\n{}\n", resp.get_tcp_hdr()?);

            // check ACK flag and seq
            let resp_hdr = resp.get_tcp_hdr()?;
            if resp_hdr.check_ack() && resp_hdr.ack == skcb.tcb.irs + 1 {
                info!("connection established!");
                // populate control block
                skcb.status = TCPState::Established;
                Ok(())
            } else {
                Err("handshake failes".into())
            }
        }
    }
}

fn parse_options(framge: EthFrame) -> Option<TCP_opts> {
    todo!()
}

// TODO: implement 4 microsecond clock
fn new_isn(con: &TCPCon) -> u32 {
    let key: &[u8; 16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut hasher = SipHasher13::new_with_key(key);

    CLOCK
        .load(std::sync::atomic::Ordering::Relaxed)
        .hash(&mut hasher);
    con.hash(&mut hasher);

    hasher.finish() as u32
}
