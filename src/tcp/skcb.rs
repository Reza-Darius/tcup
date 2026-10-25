use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, trace, warn};

use super::sock::TCPCon;
use crate::eth::ETH_FRAME_MAX_SIZE;
use crate::ip::IPv4Hdr;
use crate::tcp::buffer::{RecvBuf, SendBuf};
use crate::tcp::error::TCPError::{self, SKCBError};
use crate::tcp::handler::seg_handler;
use crate::tcp::skcb::TCPState::{Listen, SynReceived};
use crate::tcp::{
    opts::TCPOpts,
    rto::RTO,
    seq::*,
    sock::*,
    tcp_packet::{TCP_HDR_MINSIZE, TCPFlags, TCPHdr},
    timer::TIME_WAIT,
};
use crate::utils::packet::{IP, Packet, TCP};

pub const WRD_SIZE: usize = 4;
pub const WND_SIZE: u16 = 10000;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 100;
pub const SYN_ACK_RETRIES: u64 = 5;

pub const SND_RCV_BUF_SIZE: usize = 512;

type Result<T> = std::result::Result<T, TCPError>;

// this is just a wrapper, see below for the real meat and potatoes
#[derive(Debug)]
pub struct SKCB {
    inner: Box<SKCBInner>,
}

impl Deref for SKCB {
    type Target = SKCBInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SKCB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Debug)]
pub struct SKCBInner {
    pub con: TCPCon,
    pub status: TCPState,
    pub tcb: Tcb,
    pub open: Open,

    /// communication channel for receiving TCP data and user calls
    pub in_chan: Receiver<SocketMessage>,
    /// sender for giving out IP packets to be handled by lower layer
    pub out_chan: Sender<Packet<IP>>,

    /// buffer for outgoing data
    pub snd_buf: SendBuf,
    /// buffer for incoming data
    pub rcv_buf: RecvBuf,
}

#[derive(Debug)]
pub enum Open {
    Passive,
    Active,
}

impl SKCB {
    pub(super) fn new(rx: Receiver<SocketMessage>, tx: Sender<Packet<IP>>, con: TCPCon) -> Self {
        SKCB {
            inner: Box::new(SKCBInner {
                tcb: Tcb::default(),
                open: Open::Passive,

                in_chan: rx,
                out_chan: tx,

                snd_buf: SendBuf::new(SND_RCV_BUF_SIZE),
                rcv_buf: RecvBuf::new(SND_RCV_BUF_SIZE),
                status: TCPState::Closed,
                con,
            }),
        }
    }

    /// event loop listening for user calls, data segments and timers
    pub async fn run(mut self) -> Result<()> {
        // we need to linger after closing the socket before reopening it as to not confuse
        // packets for the old connection
        //
        // maybe we need some way to circumvent this?
        if matches!(self.status, TCPState::TimeWait) {
            tokio::time::sleep(Duration::new(TIME_WAIT, 0)).await;
            return Ok(());
        }

        loop {
            if matches!(self.status, TCPState::Closed) {
                return Ok(());
            }

            // TODO: we probably want to poll the timoeut first
            tokio::select! {
                res = self.inner.in_chan.recv() => {
                    trace!("message recieved");
                    let msg = res.expect("assert: the channel cant be closed");
                    if let Err(e) = self.handle_user_call(msg).await {
                        error!(%e);
                    };
                }
                _ = &mut self.inner.tcb.rto => {
                    // self.inner.tcb.rto.clear();
                    trace!("RTO expired");
                }
            }
        }
    }

    async fn handle_user_call(&mut self, message: SocketMessage) -> Result<()> {
        let event = match message {
            SocketMessage::Close => todo!(),
            SocketMessage::Segment(packet) => {
                self.update_tcb(&packet);
                TCPEvent::Seg(packet)
            }
            SocketMessage::Receive(sender) => todo!(),
            SocketMessage::Send(data) => todo!(),
        };

        match event {
            TCPEvent::Timeout => todo!(),
            TCPEvent::Seg(packet) => seg_handler(self, packet).await,
            TCPEvent::Send(items) => todo!(),
            TCPEvent::Close => todo!(),
            TCPEvent::Abort => todo!(),
        }
    }

    fn hdr_t(&self) -> TCPHdr {
        TCPHdr {
            sport: self.con.local_port.into(),
            dport: self.con.remote_port.into(),
            seq: self.tcb.snd_nxt.into(),
            ack: self.tcb.rcv_nxt.into(),
            flags: TCPFlags::default(),
            win_size: WND_SIZE.into(),
            ..Default::default()
        }
    }

    /// updates the control block
    fn update_tcb(&mut self, eth: &Packet<TCP>) {
        let inc_ip_hdr = eth.ip_hdr();
        let inc_tcp_hdr = *eth.hdr();

        // populate control block
        self.update(inc_ip_hdr, &inc_tcp_hdr);
    }

    /// updates the TCB with the values of a packet
    fn update(&mut self, ip_hdr: &IPv4Hdr, tcp_hdr: &TCPHdr) {
        let tcb = &mut self.inner.tcb;

        tcb.seg_seq = tcp_hdr.seq.get();
        tcb.seg_ack = tcp_hdr.ack.get();
        tcb.seg_wnd = tcp_hdr.win_size.get();
        tcb.last_seq = tcb.seg_seq + tcb.seg_len - 1;

        tcb.seg_len = ip_hdr.tot_len() as u32 - ip_hdr.len() as u32 - tcp_hdr.len() as u32;
        if tcp_hdr.is_syn() {
            tcb.seg_len += 1;
        }
        if tcp_hdr.is_fin() {
            tcb.seg_len += 1;
        }
    }

    /// sends a packet out through the open connection
    pub(super) async fn output(
        &self,
        tcp_hdr: TCPHdr,
        opts: TCPOpts,
        tcp_pay: &[u8],
    ) -> Result<()> {
        // TODO: maybe we send outstanding data here?
        let packet = Packet::<TCP>::new(
            self.con.local_ip,
            self.con.remote_ip,
            tcp_hdr,
            opts,
            tcp_pay,
        );
        self.out_chan.send(packet).await.unwrap();
        Ok(())
    }

    /// sends a naked ack based on current control block values
    ///
    /// can also serve as challenge ack?
    pub(super) async fn send_ack(&self) -> Result<()> {
        trace!("sending ack");

        // TODO: aggregate ACKs

        let inner = &self.inner;
        let mut tcp_hdr = TCPHdr {
            sport: inner.con.local_port.into(),
            dport: inner.con.remote_port.into(),
            seq: inner.tcb.snd_nxt.into(),
            ack: inner.tcb.rcv_nxt.into(),
            flags: TCPFlags::default(),
            win_size: WND_SIZE.into(),
            ..Default::default()
        };

        tcp_hdr.set_ack();
        tcp_hdr.set_len(TCP_HDR_MINSIZE);
        self.output(tcp_hdr, TCPOpts::default(), &[]).await
    }

    pub(super) async fn send_rst(&self, tcp_hdr: &TCPHdr) -> Result<()> {
        trace!("sending reset");

        let inner = &self.inner;

        if tcp_hdr.is_rst() {
            warn!("cant respond to RST with RST");
            return Ok(());
        }

        let mut tcp_hdr = TCPHdr {
            sport: inner.con.local_port.into(),
            dport: inner.con.remote_port.into(),
            ..Default::default()
        };

        tcp_hdr.set_rst();
        tcp_hdr.set_len(TCP_HDR_MINSIZE);

        match self.status {
            TCPState::Listen => {
                tcp_hdr.seq = self.tcb.seg_ack.into();
            }
            _ => {
                if tcp_hdr.is_ack() {
                    tcp_hdr.seq = tcp_hdr.ack;
                } else {
                    tcp_hdr.seq = 0.into();
                    tcp_hdr.ack = tcp_hdr.seq.get().wrapping_add(inner.tcb.seg_len).into();
                    tcp_hdr.set_ack();
                }
            }
        }

        self.output(tcp_hdr, TCPOpts::default(), &[]).await
    }

    /// checks for acceptable ACK
    pub(super) fn check_ack(&self, tcp_hdr: &TCPHdr) -> bool {
        if !tcp_hdr.is_ack() {
            return true;
        }

        let inner = &self.inner;

        let snd_una = inner.tcb.snd_una;
        let seg_ack = inner.tcb.seg_ack;
        let snd_nxt = inner.tcb.snd_nxt;

        seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt)
    }

    // Segment Receive  Test
    // Length  Window
    // ------- -------  -------------------------------------------
    //
    //    0       0     SEG.SEQ = RCV.NXT
    //
    //    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //
    //   >0       0     not acceptable
    //
    //   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    /// checks for acceptable segment, and sends a reply
    pub(super) async fn check_seg(&self) -> Result<()> {
        match self.status {
            TCPState::Listen | TCPState::SynSent => {
                panic!("seg check triggered in unacceptable state")
            }
            _ => {}
        };

        let check = {
            let tcb = &self.inner.tcb;

            let seg_seq = tcb.seg_seq;
            let seg_len = tcb.seg_len;
            let rcv_nxt = tcb.rcv_nxt;
            let rcv_wnd = tcb.rcv_wnd;

            if seg_len == 0 {
                match rcv_wnd {
                    0 => seg_seq == rcv_nxt,
                    _ => seq_lte(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt + rcv_wnd),
                }
            } else {
                match rcv_wnd {
                    0 => false,
                    _ => {
                        seq_lte(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt + rcv_wnd)
                            || seq_lte(rcv_nxt, seg_seq + seg_len - 1)
                                && seq_lt(seg_seq + seg_len - 1, rcv_nxt + rcv_wnd)
                    }
                }
            }
        };

        if !check {
            self.send_ack().await?;
            Err(SKCBError("unacceptable segment".to_string()))
        } else {
            Ok(())
        }
    }

    // pub fn update_rto(&mut self, seg: &TCPSegment) -> Result<()> {
    //     // we only update RTQ/RTO if the segment advances the windows (SND.UNA) and is ack
    //     match self.status {
    //         TCPState::SynSent => todo!(),
    //         TCPState::SynReceived => todo!(),
    //         _ => todo!(),
    //     }
    // }
    //
    // fn retransmit(&mut self) -> Result<()> {
    //     // pop seg from queue
    //     // call send()
    //     // dont take measurement
    //     Ok(())
    // }

    pub fn clear_rto(&mut self) {
        // TODO: impl
    }
}

/// transmission control block
#[derive(Debug, Default)]
pub struct Tcb {
    /// unacknowledged data in flight
    pub snd_una: u32,
    /// data that could be sent
    pub snd_nxt: u32,
    /// window size (upper limit) = UNA + window size
    pub snd_wnd: u32,
    /// segment sequence number used for last window update
    pub snd_wl1: u32,
    /// segment acknowledgment number used for last window update
    pub snd_wl2: u32,

    /// next byte to receive
    pub rcv_nxt: u32,
    /// future seq number not yet allowed (upper limit)
    pub rcv_wnd: u32,

    /// initial send sequence number
    pub iss: u32,
    /// initial receive sequence number
    pub irs: u32,

    /// sequence number of the current segment
    pub seg_seq: u32,
    /// acknowledgment number of the current segment
    pub seg_ack: u32,
    /// len of the payload of the current segment
    pub seg_len: u32,
    /// advertised window of the current segment
    pub seg_wnd: u16,

    /// last sequence number of a segment
    pub last_seq: u32,

    pub snd_opts: TCPOpts,
    pub rcv_opts: TCPOpts,

    pub last_snd: Option<Instant>,
    pub last_rcv: Option<Instant>,
    pub rto: RTO,
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

// https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview
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
    Listen,
    TimeWait,

    #[default]
    Closed,
}

/// event type that the TCP loop reacts to
#[derive(Debug)]
pub enum TCPEvent {
    Timeout,
    Seg(Packet<TCP>),

    Send(Vec<u8>),
    Close,
    Abort,
}
