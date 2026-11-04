use std::collections::VecDeque;
use std::net::SocketAddrV4;
use std::ops::{Deref, DerefMut};
use std::time::Instant;

use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot;
use tracing::{debug, error, instrument, trace, warn};

use crate::eth::ETH_FRAME_MAX_SIZE;
use crate::server::services::arp_svc::ARPServiceHandle;
use crate::tcp::TCPError::{ChannelError, SKCBError};
use crate::tcp::TCPState::{Closing, LastAck};
use crate::tcp::buffer::{RecvBuf, SendBuf};
use crate::tcp::error::TCPError::{self};
use crate::tcp::handler::{TCP_HDR_MINSIZE, seg_handler};
use crate::tcp::tcp_packet::{TCP_HDR_OFFSET, TCP_SEG_MAX_SIZE, TCPPayload};
use crate::tcp::timer::{CONNECTION_LIFETIME_LIMIT, TCPTimerCBHandle, TimerKind};
use crate::tcp::{
    opts::TCPOpts,
    rto::RTO,
    seq::*,
    socket::*,
    tcp_packet::{TCPFlags, TCPHdr},
};
use crate::utils::packet::{Packet, TCP};

pub const WRD_SIZE: usize = 4;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 100;
pub const SYN_ACK_RETRIES: u64 = 5;

pub const SND_RCV_BUF_SIZE: u16 = 10000;
pub const SND_MAX_TRIES: u8 = 5;

const SYN_RETRY_LIMIT: u8 = 6;
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
    pub in_chan: Receiver<SKCBMessage>,
    /// sender for giving out IP packets to be handled by lower layer
    pub out_chan: ARPServiceHandle,

    /// buffer for outgoing data
    pub snd_buf: SendBuf,
    /// buffer for incoming data
    pub rcv_buf: RecvBuf,

    /// pending RECEIVE user calls
    pub pending_rcv: VecDeque<oneshot::Sender<Result<Vec<u8>>>>,

    pub timer_chan: TCPTimerCBHandle,
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

    /// remembers the last segment to take measurements against
    pub rtt_probe: Option<SentSegment>,
    pub rto: RTO,
    pub rto_set: bool,

    pub syn_retries: u8,
    /// this timestamp is recorded whenever SND_UNA is advanced to see whether the connection timed
    /// out
    pub last_received_ack: Option<Instant>,

    pub shutdown_init: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SentSegment {
    pub seq_start: u32,
    pub seq_end: u32,
    pub sent: Instant,
    pub retransmission: bool,
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
        rx: Receiver<SKCBMessage>,
        tx: ARPServiceHandle,
        local_addr: SocketAddrV4,
        timer_tx: TCPTimerCBHandle,
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

                l_addr: local_addr,
                r_addr: None,

                pending_rcv: VecDeque::new(),
                timer_chan: timer_tx,
            }),
        };

        skcb.tcb.rcv_wnd = SND_RCV_BUF_SIZE;
        skcb
    }

    /// event loop listening for user calls, data segments and timers
    pub async fn run(mut self) -> Result<()> {
        loop {
            trace!("waiting for event...");
            if matches!(self.status, TCPState::Closed) {
                break;
            }

            // this select is biased as to not cause a race between an incoming packet
            // changing a packet then reacting to a fired timer
            tokio::select! {biased;
                timer = self.inner.timer_chan.recv() => {
                    trace!("timer fired");

                    if let Err(e) = self.handle_timer(timer).await {
                        error!(%e);
                    };
                }
                res = self.inner.in_chan.recv() => {
                    let Some(msg) = res else {
                        self.init_close().await?;
                        break;
                    };
                    if let Err(e) = self.handle_user_call(msg).await {
                        error!(%e);
                    };
                }
            }
        }

        debug!("closing socket");
        Ok(())
    }

    #[instrument(name = "TCP", skip_all, fields(state = ?self.status, timer))]
    async fn handle_timer(&mut self, timer: TimerKind) -> Result<()> {
        match timer {
            TimerKind::RTO => {
                trace!("RTO fired");

                if matches!(self.status, TCPState::SynSent | TCPState::SynReceived)
                    && self.tcb.syn_retries > SYN_RETRY_LIMIT
                {
                    warn!("SYN retry limit reached");
                    self.change_state(TCPState::Closed);
                }

                if let Some(last) = self.tcb.last_received_ack
                    && last.elapsed() >= CONNECTION_LIFETIME_LIMIT
                {
                    warn!("connection timed out");
                    self.change_state(TCPState::Closed);
                    return Ok(());
                }

                // - retransmit segment
                self.retransmit().await?;

                // - start new RTO with backoff
                self.tcb.rto.backoff();
                self.start_rto().await;
            }
            TimerKind::TimeWait => todo!(),
        }
        Ok(())
    }

    #[instrument(name = "TCP", skip_all, fields(state = ?self.status, call = %message))]
    async fn handle_user_call(&mut self, message: SKCBMessage) -> Result<()> {
        trace!("message recieved");

        match message {
            SKCBMessage::Close => {
                self.init_close().await?;
            }
            SKCBMessage::Segment(packet) => {
                if let Some(remote_addr) = self.r_addr
                    && remote_addr != packet.s_addr()
                {
                    trace!(packet_addr = %packet.s_addr(), ?self.r_addr, "addr mismatch, dropping segment");
                    return Ok(());
                }

                self.update_tcb(&packet);
                seg_handler(self, packet).await?;
            }
            // TODO: how do we deal with multiple receive calls?
            SKCBMessage::Receive { resp } => {
                if !self.is_synchronized() {
                    self.pending_rcv.push_back(resp);
                    return Ok(());
                }

                if let Some(data) = self.rcv_buf.pop_first() {
                    resp.send(Ok(data)).map_err(|_| ChannelError)?;
                    self.tcb.rcv_wnd = self.rcv_buf.available_cap();
                } else {
                    self.pending_rcv.push_back(resp);
                    trace!("cant service receive request, queueing it")
                }
            }
            SKCBMessage::Send { data, resp } => {
                if data.is_empty() {
                    resp.send(Err(TCPError::SocketError(
                        "send call error: empty data buffer".to_string(),
                    )))
                    .map_err(|_| ChannelError)?;
                    return Ok(());
                };

                let result = match self.status {
                    // queue up data to be sent later
                    TCPState::SynSent | TCPState::SynReceived => {
                        trace!("queueing send request for later");
                        self.snd_buf.insert(data)
                    }

                    // send some data if we can
                    TCPState::Established | TCPState::CloseWait => {
                        match self.snd_buf.insert(data) {
                            Err(e) => Err(e),
                            Ok(_) => {
                                let window = self.usable_window();
                                if window > 0 {
                                    trace!("window permits sending data immediately");
                                    self.send_ack().await?;
                                } else {
                                    trace!(window, "cant send data right now: window is closed")
                                }
                                Ok(())
                            }
                        }
                    }

                    _ => Err(TCPError::SocketError(
                        "cant send data: connection closing".into(),
                    )),
                };

                resp.send(result).map_err(|_| ChannelError)?;
            }
            SKCBMessage::Status(sender) => {
                sender.send(self.status);
            }
        };

        Ok(())
    }

    /// get a header based on current TCB values
    #[inline(always)]
    fn hdr_template(&self) -> TCPHdr {
        TCPHdr {
            sport: self.l_addr.port().into(),
            dport: self.r_addr.unwrap().port().into(),
            seq: self.tcb.snd_nxt.into(),
            ack: self.tcb.rcv_nxt.into(),
            flags: TCPFlags::default(),
            win_size: self.rcv_buf.available_cap().into(),
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
        // .min(self.tcb.snd_wnd as u32)
    }

    pub(super) fn is_synchronized(&self) -> bool {
        !matches!(
            self.status,
            TCPState::Listen | TCPState::SynSent | TCPState::Closed
        )
    }

    /// checks the snd buffer for data to send
    ///
    /// pass the size of the lenght of TCP options for the correct offset
    fn check_snd_data(&mut self, opt_len: usize) -> Option<TCPPayload> {
        if !matches!(self.status, TCPState::Established | TCPState::CloseWait) {
            return None;
        }

        if seq_gt(self.tcb.snd_nxt, self.tcb.snd_una) {
            return None;
        }

        // we request at most mss - opt len bytes for the payload
        let n_send_bytes = u32::min(
            self.usable_window(),
            self.tcb
                .snd_opts
                .mss
                .expect("we need to know the MSS at this point") as u32
                - opt_len as u32,
        );

        let data = self.snd_buf.get_una_seg(n_send_bytes)?;
        let offset = TCP_HDR_OFFSET + TCP_HDR_MINSIZE + opt_len;
        let data_len = data.len() as u32;

        let mut v = vec![0; offset]; // get a vec with room for incoming header
        v.extend_from_slice(data); // write payload

        // advance window
        self.tcb.snd_nxt = self.tcb.snd_nxt.wrapping_add(data_len);

        Some(TCPPayload::from_vec(v, offset))
    }

    /// updates the control block with a new segment
    fn update_tcb(&mut self, seg: &Packet<TCP>) {
        let ip_hdr = seg.ip_hdr();
        let tcp_hdr = *seg.hdr();

        let tcb = &mut self.inner.tcb;
        tcb.seg_seq = tcp_hdr.seq.get();
        tcb.seg_ack = tcp_hdr.ack.get();
        tcb.seg_wnd = tcp_hdr.win_size.get();
        tcb.seg_len = ip_hdr.tot_len() as u32 - ip_hdr.len() as u32 - tcp_hdr.len() as u32;
    }

    /// starts the RTO timer
    pub(super) async fn start_rto(&mut self) {
        self.tcb.rto_set = true;
        let deadline = self.tcb.rto.deadline();

        trace!(rto = ?self.tcb.rto.rto(), "setting RTO");
        self.timer_chan.set_timer(TimerKind::RTO, deadline).await;
    }

    /// updates the RTO with a RTT measruement, must only be called for a non retransmission
    pub(super) fn update_rto(&mut self, sent: Instant) {
        self.tcb.rto.update(sent, Instant::now());
    }

    /// disables the RTO timer
    pub(super) async fn stop_rto(&mut self) {
        trace!(rto = ?self.tcb.rto.rto(), "stopping RTO");
        self.tcb.rto_set = false;
        self.timer_chan.remove_timer(TimerKind::RTO).await;
    }

    pub(super) async fn retransmit(&mut self) -> Result<()> {
        let mut hdr = self.hdr_template();
        let con = self.con();

        // get a payload
        let mut seg_len = self.tcb.snd_nxt.wrapping_sub(self.tcb.snd_una);

        match self.status {
            TCPState::SynSent => {
                hdr.set_syn();
                self.tcb.syn_retries += 1;
                seg_len -= 1;
            }
            TCPState::SynReceived => {
                hdr.set_syn();
                hdr.set_ack();
                seg_len -= 1;
            }
            TCPState::FinWait1 | Closing | LastAck => {
                hdr.set_fin();
                hdr.set_ack();
                seg_len -= 1;
            }
            TCPState::Listen | TCPState::Closed => {
                return Err(SKCBError("retransmit called in LISTEN state".into()));
            }
            _ => {}
        }

        hdr.seq = self.tcb.snd_una.into();

        let offset = TCP_HDR_OFFSET + TCP_HDR_MINSIZE;
        let payload = self
            .snd_buf
            .get_una_seg(seg_len)
            .map(|bytes| TCPPayload::from_vec(bytes.into(), offset));

        // bookkeeping for RTO
        let seq_start = hdr.seq.get();
        let seq_end = seq_start.wrapping_add(
            payload.as_ref().map(|payload| payload.len()).unwrap_or(0) as u32
                + u32::from(hdr.is_syn())
                + u32::from(hdr.is_fin()),
        );

        self.inner.tcb.rtt_probe = Some(SentSegment {
            seq_start,
            seq_end,
            sent: Instant::now(),
            retransmission: true,
        });

        let packet = Packet::<TCP>::new(
            con.local_ip,
            con.remote_ip,
            hdr,
            TCPOpts::default(),
            payload,
        );

        debug!(%hdr, "retransmitting packet"); // this prints incomplete information about the header but thats fine
        self.out_chan.send(packet.into()).await;
        Ok(())
    }

    /// sends a packet out through the open connection
    pub(super) async fn output(
        &mut self,
        mut hdr: TCPHdr,
        opts: TCPOpts,
        payload: Option<TCPPayload>,
    ) -> Result<()> {
        let con = self.con();

        if matches!(self.status, TCPState::Established | TCPState::CloseWait)
            && self.tcb.shutdown_init
            && self.snd_buf.is_empty()
        {
            if matches!(self.status, TCPState::Established) {
                self.change_state(TCPState::FinWait1);
            }
            if matches!(self.status, TCPState::CloseWait) {
                self.change_state(TCPState::LastAck);
            }

            hdr.set_fin();
            self.tcb.snd_nxt = self.tcb.snd_nxt.wrapping_add(1);
            self.tcb.shutdown_init = false;
        }

        // prepare a new RTT probe for RTO
        if self.inner.tcb.rtt_probe.is_none() {
            let seq_start = hdr.seq.get();
            let seq_end = seq_start.wrapping_add(
                payload.as_ref().map(|payload| payload.len()).unwrap_or(0) as u32
                    + u32::from(hdr.is_syn())
                    + u32::from(hdr.is_fin()),
            );
            self.inner.tcb.rtt_probe = Some(SentSegment {
                seq_start,
                seq_end,
                sent: Instant::now(),
                retransmission: false,
            });
        }

        // make sure we dont overrwite an running rto
        if !self.tcb.rto_set && (payload.is_some() || hdr.is_fin() || hdr.is_syn()) {
            self.start_rto().await;
        }

        if hdr.is_syn() {
            self.tcb.syn_retries += 1;
        }

        let packet = Packet::<TCP>::new(con.local_ip, con.remote_ip, hdr, opts, payload);

        debug!(%hdr, "sending packet out"); // this prints incomplete information about the header but thats fine
        self.out_chan.send(packet.into()).await;
        Ok(())
    }

    /// sends an ack based on current control block values
    ///
    /// can also serve as challenge ack
    pub(super) async fn send_ack(&mut self) -> Result<()> {
        let mut tcp_hdr = self.hdr_template();
        let payload = self.check_snd_data(0);

        tcp_hdr.set_ack();
        self.output(tcp_hdr, TCPOpts::default(), payload).await
    }

    pub(super) async fn send_fin(&mut self) -> Result<()> {
        let mut tcp_hdr = self.hdr_template();
        let payload = self.check_snd_data(0);

        // FIN takes one seq number
        self.tcb.snd_nxt = self.tcb.snd_nxt.wrapping_add(1);

        tcp_hdr.set_fin();
        self.output(tcp_hdr, TCPOpts::default(), payload).await
    }

    pub(super) async fn send_fin_ack(&mut self) -> Result<()> {
        let mut tcp_hdr = self.hdr_template();
        let payload = self.check_snd_data(0);

        // FIN takes one seq number
        self.tcb.snd_nxt = self.tcb.snd_nxt.wrapping_add(1);

        tcp_hdr.set_fin();
        tcp_hdr.set_ack();

        self.output(tcp_hdr, TCPOpts::default(), payload).await
    }

    pub(super) async fn send_rst(&mut self) -> Result<()> {
        let inner = &self.inner;
        let mut tcp_hdr = self.hdr_template();

        tcp_hdr.set_rst();

        match self.status {
            TCPState::Listen => {
                tcp_hdr.seq = self.tcb.seg_ack.into();
            }
            _ => {
                if self.check_ack() {
                    tcp_hdr.seq = tcp_hdr.ack;
                } else {
                    tcp_hdr.seq = 0.into();
                    tcp_hdr.ack = tcp_hdr.seq.get().wrapping_add(inner.tcb.seg_len).into();
                    tcp_hdr.set_ack();
                }
            }
        }

        self.output(tcp_hdr, TCPOpts::default(), None).await
    }

    /// checks for acceptable ACK
    pub(super) fn check_ack(&self) -> bool {
        let inner = &self.inner;

        let snd_una = inner.tcb.snd_una;
        let seg_ack = inner.tcb.seg_ack;
        let snd_nxt = inner.tcb.snd_nxt;

        // SND_UNA < SEG_ACK <= SND_NXT
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
        if !self.pending_rcv.is_empty() // we dont pop front to not lose the sender
            && let Some(data) = self.rcv_buf.pop_first()
        {
            trace!("servicing queued receive request");

            self.pending_rcv
                .pop_front()
                .expect("we just checked")
                .send(Ok(data))
                .expect("the receiver should block on this call");
            self.tcb.rcv_wnd = self.rcv_buf.available_cap();
        }
    }

    /// initiates the closing routine
    pub(super) async fn init_close(&mut self) -> Result<()> {
        debug_assert!(!self.tcb.shutdown_init);
        trace!("closing initiated");
        match self.status {
            TCPState::Established => {
                if self.snd_buf.is_empty() {
                    self.send_fin_ack().await?;
                    self.change_state(TCPState::FinWait1);
                } else {
                    self.tcb.shutdown_init = true;
                }
            }
            TCPState::Listen => {
                self.change_state(TCPState::Closed);
            }
            TCPState::SynReceived => {
                if self.snd_buf.is_empty() {
                    self.send_fin().await?;
                    self.change_state(TCPState::FinWait1);
                } else {
                    self.tcb.shutdown_init = true;
                }
            }

            TCPState::FinWait1 | TCPState::FinWait2 => {}
            _ => {}
        }
        Ok(())
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
