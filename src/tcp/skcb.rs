use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Receiver;
use tracing::{debug, error, trace, warn};

use crate::error::{Error, Result};
use crate::eth::{ETH_P_IP, Eth_hdr, EthFrame};
use crate::ip::{IP_DF, IP_HDR_MINSIZE, IP_hdr, IPPROTO_TCP, TOS_BEST_EFFORT, TTL_START};
use crate::tcp::{
    TCP_HDR_MINSIZE, WND_SIZE,
    buffer::RCV_BUF_SIZE,
    hdr::{TCP_hdr, TCPFlags},
    opts::TCP_opts,
    rto::RTO,
    rtq::RTQ,
    seq::*,
    sock::*,
    tcp_check,
    timer::TIME_WAIT,
};
use crate::tcup::TCup;
use crate::types::TCPCon;

// this is just a wrapper, see below for the real meat and potatoes
#[derive(Debug)]
pub struct SkCb {
    inner: Box<SkCbInner>,
}

impl Deref for SkCb {
    type Target = SkCbInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SkCb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Debug)]
pub struct SkCbInner {
    pub con: TCPCon,
    pub status: TCPState,
    pub tcb: Tcb,
    pub open: Open,

    pub rcv_chan: Receiver<SocketWorkerMsg>,
    // TODO: out of order, and in order buffer
    /// buffer for the output message
    pub rcv_buffer: Vec<u8>,

    pub tcup: TCup,
    /// buffer for the input message
    pub snd_buf: Vec<u8>,
    /// retransmission queue
    pub rtq: RTQ,
}

#[derive(Debug)]
pub enum Open {
    Passive,
    Active,
}

impl SkCb {
    pub fn new(rx: Receiver<SocketWorkerMsg>, tcup: TCup, con: TCPCon) -> Self {
        SkCb {
            inner: Box::new(SkCbInner {
                tcb: Tcb::default(),
                open: Open::Passive,
                rcv_chan: rx,
                rcv_buffer: Vec::with_capacity(RCV_BUF_SIZE),
                tcup,
                snd_buf: vec![],
                rtq: RTQ::new(),
                // rt_queue: RTQ(VecDeque::new()),
                status: TCPState::Closed,
                con,
            }),
        }
    }

    /// updates the control block
    pub fn parse_frame(&mut self, eth: EthFrame) -> Result<TCPSegment> {
        let inc_ip_hdr = eth.get_ip_hdr()?;
        let inc_tcp_hdr = eth.get_tcp_hdr()?;

        if !tcp_check(&inc_ip_hdr, eth.get_ip_pay()?) {
            return Err(Error::Tcp("TCP checksum error".to_string()));
        };

        // populate control block
        self.update(&inc_ip_hdr, &inc_tcp_hdr);

        Ok(TCPSegment {
            hdr: inc_tcp_hdr,
            opts: eth.get_tcp_opt()?,
            seg: eth,
        })
    }

    /// updates the TCB with the values of a frame
    pub fn update(&mut self, ip_hdr: &IP_hdr, tcp_hdr: &TCP_hdr) {
        let tcb = &mut self.inner.tcb;

        tcb.seg_seq = tcp_hdr.seq;
        tcb.seg_ack = tcp_hdr.ack;
        tcb.seg_wnd = tcp_hdr.win_size;
        tcb.last_seq = tcb.seg_seq + tcb.seg_len - 1;

        tcb.seg_len = ip_hdr.tot_len as u32 - ip_hdr.len() as u32 - tcp_hdr.len() as u32;
        if tcp_hdr.check_syn() {
            tcb.seg_len += 1;
        }
        if tcp_hdr.check_fin() {
            tcb.seg_len += 1;
        }
    }

    /// sends a packet through the open connection
    pub async fn send(&self, tcp_hdr: TCP_hdr, opts: TCP_opts, tcp_pay: &[u8]) -> Result<()> {
        let ip_tot_len = IP_HDR_MINSIZE + tcp_hdr.len() + tcp_pay.len();
        let inner = &self.inner;

        assert!(ip_tot_len >= IP_HDR_MINSIZE + TCP_HDR_MINSIZE);

        let mut ip_hdr = IP_hdr {
            ver_ihl: 0,
            tos: TOS_BEST_EFFORT,
            tot_len: ip_tot_len as u16,
            id: 1,
            frag_off: IP_DF,
            ttl: TTL_START,
            prot: IPPROTO_TCP,
            checksum: 0,
            src_addr: inner.con.local_ip.octets(),
            dest_addr: inner.con.remote_ip.octets(),
        };

        ip_hdr.set_ihl(IP_HDR_MINSIZE)?;

        // TODO: if this fails, close the socket
        let dmac = self.tcup.resolve_with_arp(inner.con.remote_ip).await?;
        let eth_hdr = Eth_hdr::new(dmac, self.tcup.mac(), ETH_P_IP);
        let frame = EthFrame::new_tcp(eth_hdr, ip_hdr, tcp_hdr, opts, tcp_pay)?;

        debug!(
            "sending frame:\nETH:\nIP:{}\nTCP:{}\n{}\n",
            frame.get_eth_hdr(),
            frame.get_ip_hdr()?,
            frame.get_tcp_hdr()?
        );

        let n = inner.tcup.write_tap(frame).await?;

        trace!("{n} bytes written");
        Ok(())
    }

    /// sends a naked ack based on current control block values
    pub async fn send_ack(&self) -> Result<()> {
        trace!("sending ack");

        // TODO: aggregate ACKs

        let inner = &self.inner;
        let mut tcp_hdr = TCP_hdr {
            sport: inner.con.local_port,
            dport: inner.con.remote_port,
            seq: inner.tcb.snd_nxt,
            ack: inner.tcb.rcv_nxt,
            flags: TCPFlags::default(),
            win_size: WND_SIZE,
            ..Default::default()
        };

        tcp_hdr.set_ack();
        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;
        self.send(tcp_hdr, TCP_opts::default(), &[]).await
    }

    pub async fn send_rst(&self, tcp_hdr: &TCP_hdr) -> Result<()> {
        trace!("sending reset");

        let inner = &self.inner;

        if tcp_hdr.check_rst() {
            warn!("cant respond to RST with RST");
            return Ok(());
        }

        let mut tcp_hdr = TCP_hdr {
            sport: inner.con.local_port,
            dport: inner.con.remote_port,
            ..Default::default()
        };

        tcp_hdr.set_rst();
        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

        match self.status {
            TCPState::Listen => {
                tcp_hdr.seq = self.tcb.seg_ack;
            }
            _ => {
                if tcp_hdr.check_ack() {
                    tcp_hdr.seq = tcp_hdr.ack;
                } else {
                    tcp_hdr.seq = 0;
                    tcp_hdr.ack = tcp_hdr.seq.wrapping_add(inner.tcb.seg_len);
                    tcp_hdr.set_ack();
                }
            }
        }

        self.send(tcp_hdr, TCP_opts::default(), &[]).await
    }

    pub async fn close_socket(self) {
        let inner = &self.inner;

        inner.tcup.remove_sock(&inner.con);
    }

    /// checks for acceptable ACK
    pub fn check_ack(&self, tcp_hdr: &TCP_hdr) -> bool {
        if !tcp_hdr.check_ack() {
            return true;
        }

        let inner = &self.inner;

        let snd_una = inner.tcb.snd_una;
        let seg_ack = inner.tcb.seg_ack;
        let snd_nxt = inner.tcb.snd_nxt;

        seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt)
    }

    /*
    Segment Receive  Test
    Length  Window
    ------- -------  -------------------------------------------

       0       0     SEG.SEQ = RCV.NXT

       0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

      >0       0     not acceptable

      >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                  or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    */

    /// checks for acceptable segment, and sends a reply
    pub async fn check_seg(&self) -> Result<()> {
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
            Err(Error::Tcp("unacceptable segment".to_string()))
        } else {
            Ok(())
        }
    }

    pub async fn event_listen(&mut self) -> TCPEvent {
        // we need to linger after closing the socket before reopening it as to not confuse
        // packets for the old connection
        //
        // maybe we need some way to circumvent this?
        if self.status == TCPState::TimeWait {
            tokio::time::sleep(Duration::new(TIME_WAIT, 0)).await;
            return TCPEvent::Timeout;
        }

        loop {
            tokio::select! {
                res = self.inner.rcv_chan.recv() => {
                    trace!("message recieved");
                    let msg = res.expect("the channel cant be closed");

                    match self.handle_worker_msg(msg) {
                        Ok(event) => return event,
                        Err(e) => {
                            error!(?e, "event rcv error");
                            continue;
                        }
                    }
                }
                _ = &mut self.inner.tcb.rto => {
                    trace!("RTO expired");
                    return TCPEvent::Timeout
                }
            }
        }
    }

    fn handle_worker_msg(&mut self, message: SocketWorkerMsg) -> Result<TCPEvent> {
        match message {
            SocketWorkerMsg::Frame(eth_frame) => {
                let seg = self.parse_frame(eth_frame)?;
                Ok(TCPEvent::Seg(seg))
            }
            SocketWorkerMsg::Close => Ok(TCPEvent::Close),
            SocketWorkerMsg::Send => todo!(),
        }
    }

    pub fn update_rto(&mut self, seg: &TCPSegment) -> Result<()> {
        // we only update RTQ/RTO if the segment advances the windows (SND.UNA) and is ack
        match self.status {
            TCPState::SynSent => todo!(),
            TCPState::SynReceived => todo!(),
            _ => todo!(),
        }
    }

    fn retransmit(&mut self) -> Result<()> {
        // pop seg from queue
        // call send()
        // dont take measurement
        Ok(())
    }

    /// return true if the loop should skip, i.e the segment gets dropped
    pub fn handle_rst(&mut self, seg: &TCPSegment) -> bool {
        if !seg.hdr.check_rst() {
            return false;
        }
        match self.status {
            TCPState::SynSent => {
                if self.check_ack(&seg.hdr) {
                    self.status = TCPState::Closed;
                    false // we drop the segment, but through the loop we cancel
                } else {
                    true
                }
            }
            TCPState::Listen | TCPState::Closed => true,
            TCPState::SynReceived => {
                match self.open {
                    Open::Passive => {
                        self.status = TCPState::Listen;
                        // TODO: flush buffer
                        true
                    }
                    // our connection was refused
                    Open::Active => {
                        self.status = TCPState::Closed;
                        // TODO: flush buffer
                        true
                    }
                }
            }
            _ => {
                let seg_seq = seg.hdr.seq;
                if seq_gt(seg_seq, self.tcb.rcv_wnd) {
                    return true;
                }
                if seg_seq == self.tcb.rcv_nxt {
                    match self.open {
                        Open::Passive => {
                            self.status = TCPState::Listen;
                            // TODO: flush buffer
                            return true;
                        }
                        // our connection was refused
                        Open::Active => {
                            self.status = TCPState::Closed;
                            // TODO: flush buffer
                            return true;
                        }
                    }
                };
                true
                /*
                * If the RST bit is set and the sequence number does not exactly match the next expected sequence value, yet is within the current receive window, TCP endpoints MUST send an acknowledgment (challenge ACK):

                <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                After sending the challenge ACK, TCP endpoints MUST drop the unacceptable segment and stop processing the incoming packet further. Note that RFC 5961 and Errata ID 4772 [99] contain additional considerations for ACK throttling in an implementation.
                */
            }
        }
    }

    /// returns true if the segment should be dropped
    pub fn handle_syn(&mut self, seg: &TCPSegment) -> bool {
        false
        // if !seg.hdr.check_syn() {
        //     return false;
        // }
        // match self.status {
        //     TCPState::SynSent => todo!(),
        //     TCPState::SynReceived => todo!(),
        //     TCPState::Established => todo!(),
        //     TCPState::FinWait1 => todo!(),
        //     TCPState::FinWait2 => todo!(),
        //     TCPState::CloseWait => todo!(),
        //     TCPState::Closing => todo!(),
        //     TCPState::LastAck => todo!(),
        //     TCPState::Listen => todo!(),
        //     TCPState::TimeWait => todo!(),
        //     TCPState::Closed => todo!(),
        // }
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

    // values of the last received segment
    pub seg_seq: u32,
    pub seg_ack: u32,
    pub seg_len: u32,
    pub seg_wnd: u16,

    /// last sequence number of a segment
    pub last_seq: u32,

    pub snd_opts: TCP_opts,
    pub rcv_opts: TCP_opts,

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
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
    Seg(TCPSegment),

    Send(Vec<u8>),
    Close,
    Abort,
}

/// parsed and validated TCP segment
#[derive(Debug)]
pub struct TCPSegment {
    pub hdr: TCP_hdr,
    pub opts: Option<TCP_opts>,
    seg: EthFrame, // we pass the ethernet frame to reuse the allocation
}

impl TCPSegment {
    pub fn get_pay(&self) -> &[u8] {
        self.seg.get_tcp_pay().expect("we already validated this")
    }
}
