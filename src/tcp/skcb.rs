use std::net::SocketAddrV4;
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot;
use tracing::{debug, error, instrument, trace};

use super::socket::TCPCon;
use crate::eth::ETH_FRAME_MAX_SIZE;
use crate::server::services::arp_svc::ARPServiceHandle;
use crate::tcp::buffer::{RecvBuf, SendBuf};
use crate::tcp::error::TCPError::{self};
use crate::tcp::handler::seg_handler;
use crate::tcp::{
    opts::TCPOpts,
    rto::RTO,
    seq::*,
    socket::*,
    tcp_packet::{TCPFlags, TCPHdr},
    timer::TIME_WAIT,
};
use crate::utils::packet::{Packet, TCP};

pub const WRD_SIZE: usize = 4;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 100;
pub const SYN_ACK_RETRIES: u64 = 5;

pub const SND_RCV_BUF_SIZE: u16 = 10000;

type Result<T> = std::result::Result<T, TCPError>;

// this is just a wrapper, see below for the real meat and potatoes
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

pub struct SKCBInner {
    /// local address
    pub l_addr: SocketAddrV4,
    /// remote address for a connection, which is absent in the LISTEN state
    pub r_addr: Option<SocketAddrV4>,

    pub status: TCPState,
    pub tcb: TCB,
    pub open: Open,

    /// communication channel for receiving TCP data and user calls
    pub in_chan: Receiver<SocketMessage>,
    /// sender for giving out IP packets to be handled by lower layer
    pub out_chan: ARPServiceHandle,

    /// buffer for outgoing data
    pub snd_buf: SendBuf,
    /// buffer for incoming data
    pub rcv_buf: RecvBuf,

    pub pending_req: Option<oneshot::Sender<Vec<u8>>>,
}

#[derive(Debug)]
pub enum Open {
    Passive,
    Active,
}

/// transmission control block
#[derive(Debug, Default)]
pub struct TCB {
    /// unacknowledged data in flight
    pub snd_una: u32,
    /// data that could be sent, usually the seq in the reply
    pub snd_nxt: u32,
    /// window size (upper limit) = UNA + window size
    pub snd_wnd: u16,
    /// segment sequence number used for last window update
    pub snd_wl1: u32,
    /// segment acknowledgment number used for last window update
    pub snd_wl2: u32,

    /// next byte to receive, incrementing this is equivalent to ACKing data in the response
    pub rcv_nxt: u32,
    /// future seq number not yet allowed (upper limit)
    pub rcv_wnd: u16,

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

impl SKCB {
    pub(super) fn new(
        rx: Receiver<SocketMessage>,
        tx: ARPServiceHandle,
        addr: SocketAddrV4,
    ) -> Self {
        let mut skcb = SKCB {
            inner: Box::new(SKCBInner {
                tcb: TCB::default(),
                open: Open::Passive,

                in_chan: rx,
                out_chan: tx,

                snd_buf: SendBuf::new(SND_RCV_BUF_SIZE as usize),
                rcv_buf: RecvBuf::new(SND_RCV_BUF_SIZE as usize),
                status: TCPState::Closed,

                l_addr: addr,
                r_addr: None,

                pending_req: None,
            }),
        };

        skcb.tcb.rcv_wnd = SND_RCV_BUF_SIZE;
        skcb
    }

    /// event loop listening for user calls, data segments and timers
    #[instrument(name = "TCP", skip_all, fields(state = ?self.status))]
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
                debug!("closing socket");
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
        match message {
            SocketMessage::Close => todo!(),
            SocketMessage::Segment(packet) => {
                self.update_tcb(&packet);
                seg_handler(self, packet).await?;
            }
            // TODO: how do we deal with multiple receive calls?
            SocketMessage::Receive(sender) => {
                if !self.is_synchronized() {
                    self.pending_req = Some(sender);
                    return Ok(());
                }

                if let Some(data) = self.rcv_buf.pop_first() {
                    sender.send(data);
                } else {
                    self.pending_req = Some(sender);
                    debug!("cant service receive request")
                }
            }
            SocketMessage::Send(data) => todo!(),
            SocketMessage::Status(sender) => {
                sender.send(self.status).expect("the rcv cant be closed");
            }
        };

        Ok(())
    }

    /// a template for a header
    #[inline(always)]
    fn hdr_t(&self) -> TCPHdr {
        TCPHdr {
            sport: self.l_addr.port().into(),
            dport: self.r_addr.unwrap().port().into(),
            seq: self.tcb.snd_nxt.into(),
            ack: self.tcb.rcv_nxt.into(),
            flags: TCPFlags::default(),
            win_size: self.tcb.rcv_wnd.into(),
            ..Default::default()
        }
    }

    pub fn con(&self) -> TCPCon {
        TCPCon {
            local_ip: *self.l_addr.ip(),
            local_port: self.l_addr.port(),
            remote_ip: *self.r_addr.unwrap().ip(),
            remote_port: self.r_addr.unwrap().port(),
        }
    }

    /// calculates the currently usable send window
    pub(super) fn usable_window(&self) -> u32 {
        self.tcb
            .snd_una
            .wrapping_add(self.tcb.snd_wnd as u32)
            .wrapping_sub(self.tcb.snd_nxt)
            .min(self.tcb.snd_wnd as u32)
    }

    pub(super) fn is_synchronized(&self) -> bool {
        !matches!(
            self.status,
            TCPState::Listen | TCPState::SynSent | TCPState::Closed
        )
    }

    fn try_send(&mut self) -> Result<Option<u16>> {
        if !matches!(self.status, TCPState::Established | TCPState::CloseWait) {
            return Ok(None);
        }
        todo!()
    }

    /// updates the control block
    fn update_tcb(&mut self, seg: &Packet<TCP>) {
        let ip_hdr = seg.ip_hdr();
        let tcp_hdr = *seg.hdr();

        // populate control block

        let tcb = &mut self.inner.tcb;
        tcb.seg_seq = tcp_hdr.seq.get();
        tcb.seg_ack = tcp_hdr.ack.get();
        // tcb.seg_wnd = tcp_hdr.win_size.get();
        // tcb.snd_wnd = tcb.seg_wnd;

        tcb.seg_len = ip_hdr.tot_len() as u32 - ip_hdr.len() as u32 - tcp_hdr.len() as u32;
    }

    /// sends a packet out through the open connection
    pub(super) async fn output(
        &self,
        tcp_hdr: TCPHdr,
        opts: TCPOpts,
        tcp_pay: &[u8],
    ) -> Result<()> {
        let con = self.con();
        let packet = Packet::<TCP>::new(con.local_ip, con.remote_ip, tcp_hdr, opts, tcp_pay);

        debug!(%tcp_hdr, "sending packet out"); // this prints incomplete information about the header but thats fine
        self.out_chan.send(packet.into()).await;
        Ok(())
    }

    /// sends an ack based on current control block values
    ///
    /// can also serve as challenge ack
    pub(super) async fn send_ack(&self) -> Result<()> {
        let mut tcp_hdr = self.hdr_t();
        tcp_hdr.set_ack();
        self.output(tcp_hdr, TCPOpts::default(), &[]).await
    }

    pub(super) async fn send_fin(&mut self) -> Result<()> {
        let mut tcp_hdr = self.hdr_t();

        // FIN takes one seq number
        self.tcb.snd_nxt = self.tcb.snd_nxt.wrapping_add(1);

        tcp_hdr.set_fin();
        self.output(tcp_hdr, TCPOpts::default(), &[]).await
    }

    pub(super) async fn send_fin_ack(&mut self) -> Result<()> {
        let mut tcp_hdr = self.hdr_t();

        // FIN takes one seq number
        self.tcb.snd_nxt = self.tcb.snd_nxt.wrapping_add(1);

        tcp_hdr.set_fin();
        tcp_hdr.set_ack();

        self.output(tcp_hdr, TCPOpts::default(), &[]).await
    }

    pub(super) async fn send_rst(&self) -> Result<()> {
        let inner = &self.inner;
        let mut tcp_hdr = self.hdr_t();

        tcp_hdr.set_rst();

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
            return false;
        }

        let inner = &self.inner;

        let snd_una = inner.tcb.snd_una;
        let seg_ack = inner.tcb.seg_ack;
        let snd_nxt = inner.tcb.snd_nxt;

        seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt)
    }

    /// checks for acceptable segment, i.e a segment that respects our receive window
    pub(super) fn check_seq(&self) -> bool {
        match self.status {
            TCPState::Listen | TCPState::SynSent => {
                panic!("seg check triggered in unacceptable state")
            }
            _ => {}
        };

        // TODO:
        // If the RCV.WND is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs, and RSTs.

        let tcb = &self.inner.tcb;

        let seg_seq = tcb.seg_seq;
        let seg_len = tcb.seg_len;
        let rcv_nxt = tcb.rcv_nxt;
        let rcv_wnd = tcb.rcv_wnd as u32;

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

        if rcv_wnd == 0 {
            seg_seq == rcv_nxt
        } else if seg_len == 0 {
            seq_lte(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt + rcv_wnd)
        } else {
            seq_lte(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt + rcv_wnd)
                || seq_lte(rcv_nxt, seg_seq + seg_len - 1)
                    && seq_lt(seg_seq + seg_len - 1, rcv_nxt + rcv_wnd)
        }
    }

    // fn retransmit(&mut self) -> Result<()> {
    //     // pop seg from queue
    //     // call send()
    //     // dont take measurement
    //     Ok(())
    // }

    pub fn clear_rto(&mut self) {
        // TODO: impl
    }

    #[inline(always)]
    pub(super) fn change_state(&mut self, to: TCPState) {
        #[cfg(debug_assertions)]
        {
            // TODO: check illegal state transitions?
        }

        trace!(from = ?self.status, to = ?to, "changing state");
        self.status = to;
    }

    /// tries to pull bytes out of the rcv buffer if we have a pending request
    pub(super) fn try_empty_rcv_buffer(&mut self) {
        if !self.is_synchronized() {
            return;
        }

        if let Some(sender) = self.pending_req.take()
            && let Some(data) = self.rcv_buf.pop_first()
        {
            let _ = sender.send(data);
        }
    }
}

impl std::fmt::Display for TCB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snd_una: {}, snd_nxt: {}, snd_wnd: {}, rcv_nxt: {}, rcv_wnd: {}, iss: {}, irs: {}, seg_seq: {}, seg_ack: {}, seg_len: {}",
            self.snd_una,
            self.snd_nxt,
            self.snd_wnd,
            self.rcv_nxt,
            self.rcv_wnd,
            self.iss,
            self.irs,
            self.seg_seq,
            self.seg_ack,
            self.seg_len,
        )
    }
}
