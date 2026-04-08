use std::collections::VecDeque;
use std::fmt::Display;
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tracing::{debug, info, trace, warn};

use crate::error::{Error, Result};
use crate::eth::EthFrame;
use crate::eth::{ETH_P_IP, Eth_hdr};
use crate::ip::{IP_DF, IP_HDR_MINSIZE, IP_hdr, IPPROTO_TCP, TOS_BEST_EFFORT, TTL_START};
use crate::tcp::hdr::{TCP_hdr, TCPFlags};
use crate::tcp::opts::TCP_opts;
use crate::tcp::{TCP_HDR_MINSIZE, TW, WND_SIZE, seq_lt, seq_lte, tcp_check};
use crate::tcup::TCup;
use crate::types::{Mac, TCPCon};

const RCV_BUF_SIZE: usize = 512 << 10; // 512 * 1024 = 512 KiB

/// socket control block
#[derive(Debug)]
pub struct SkCb {
    pub rcv_chan: Receiver<EthFrame>,
    // TODO: out of order, and in order buffer
    pub rcv_buffer: Vec<u8>, // buffer for the output message

    pub snd_chan: TCup,
    pub snd_buf: Vec<u8>, // buffer for the input message
    pub rt_queue: TransmissionQueue,

    pub msg: EthFrame, // the last message received on the connection

    pub status: TCPState,
    pub tcb: Tcb,

    pub con: TCPCon,
    pub eth_hdr: Eth_hdr, // header to be attached to outgoing messages, need to deprecate this
}

impl SkCb {
    pub fn new(inc: EthFrame, rx: Receiver<EthFrame>, tcup: TCup, con: TCPCon) -> Box<Self> {
        let eth_hdr = inc.get_eth_hdr();

        Box::new(SkCb {
            rcv_chan: rx,
            rcv_buffer: Vec::with_capacity(RCV_BUF_SIZE),
            snd_chan: tcup,
            snd_buf: vec![],
            msg: inc,
            rt_queue: TransmissionQueue(VecDeque::new()),
            status: TCPState::Closed,
            tcb: Tcb::default(),

            eth_hdr: Eth_hdr::new(
                Mac::from_octets(eth_hdr.smac),
                Mac::from_octets(eth_hdr.dmac),
                ETH_P_IP,
            ),
            con,
        })
    }

    /// listens for a packet on the receiver
    pub async fn receive(&mut self) -> Result<TCP_hdr> {
        let new_packet = if let Some(packet) = self.rcv_chan.recv().await {
            packet
        } else {
            return Err("channel unexpectedly closed".into());
        };

        self.ingest_frame(new_packet)
    }

    /// updates the control block
    pub fn ingest_frame(&mut self, eth: EthFrame) -> Result<TCP_hdr> {
        let inc_ip_hdr = eth.get_ip_hdr()?;
        let inc_tcp_hdr = eth.get_tcp_hdr()?;

        // checksum
        tcp_check(inc_ip_hdr, eth.get_ip_pay()?);

        // populate control block
        self.update(&inc_ip_hdr, &inc_tcp_hdr);
        self.msg = eth;

        Ok(inc_tcp_hdr)
    }

    /// sends a packet through the open connection
    pub async fn send(&self, tcp_hdr: TCP_hdr, opts: TCP_opts, tcp_pay: &[u8]) -> Result<()> {
        let ip_tot_len = IP_HDR_MINSIZE + tcp_hdr.len() + tcp_pay.len();

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
            src_addr: self.con.dip.octets(),
            dest_addr: self.con.sip.octets(),
        };

        ip_hdr.set_ihl(IP_HDR_MINSIZE)?;

        let packet = EthFrame::new_tcp(self.eth_hdr, ip_hdr, tcp_hdr, opts, tcp_pay)?;

        debug!(
            "sending frame:\nETH:\nIP:{}\nTCP:{}\n{}\n",
            packet.get_eth_hdr(),
            packet.get_ip_hdr()?,
            packet.get_tcp_hdr()?
        );

        let n = self.snd_chan.write_tap(packet).await?;

        trace!("{n} bytes written");
        Ok(())
    }

    /// sends a naked ack based on current control block values
    pub async fn send_ack(&self) -> Result<()> {
        let mut tcp_hdr = TCP_hdr {
            sport: self.con.dport,
            dport: self.con.sport,
            seq: self.tcb.snd_nxt,
            ack: self.tcb.rcv_nxt,
            flags: TCPFlags::default(),
            win_size: WND_SIZE,
            ..Default::default()
        };

        tcp_hdr.set_ack();
        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;
        self.send(tcp_hdr, TCP_opts::default(), &[]).await
    }

    pub async fn close_socket(&self) {
        // waiting until we close the socket: TIME WAIT TIMEOUT
        tokio::time::sleep(Duration::new(TW, 0)).await;
        self.snd_chan.remove_sock(&self.con);
    }

    pub async fn send_rst(&self, tcp_hdr: &TCP_hdr) -> Result<()> {
        debug!("sending reset");
        if tcp_hdr.check_rst() {
            // never respond to rst with rst
            warn!("cant respond to RST with RST");
            return Ok(());
        }

        let mut tcp_hdr = TCP_hdr {
            sport: self.con.dport,
            dport: self.con.sport,
            ..Default::default()
        };

        tcp_hdr.set_rst();

        if tcp_hdr.check_ack() {
            tcp_hdr.seq = tcp_hdr.ack;
        } else {
            tcp_hdr.seq = 0;
            tcp_hdr.ack = tcp_hdr.seq.wrapping_add(self.tcb.seg_len);
            tcp_hdr.set_ack();
        }

        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

        self.send(tcp_hdr, TCP_opts::default(), &[]).await
    }

    /// checks for acceptable ACK
    pub fn acc_ack(&self, tcp_hdr: &TCP_hdr) -> bool {
        if !tcp_hdr.check_ack() {
            return true;
        }

        let snd_una = self.tcb.snd_una;
        let seg_ack = self.tcb.seg_ack;
        let snd_nxt = self.tcb.snd_nxt;

        seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt)
    }

    /// updates the TCB with the values of a frame
    pub fn update(&mut self, ip_hdr: &IP_hdr, tcp_hdr: &TCP_hdr) {
        self.tcb.seg_seq = tcp_hdr.seq;
        self.tcb.seg_ack = tcp_hdr.ack;
        self.tcb.seg_wnd = tcp_hdr.win_size;
        self.tcb.last_seq = self.tcb.seg_seq + self.tcb.seg_len - 1;

        self.tcb.seg_len = ip_hdr.tot_len as u32 - ip_hdr.len() as u32 - tcp_hdr.len() as u32;
        if tcp_hdr.check_syn() {
            self.tcb.seg_len += 1;
        }
        if tcp_hdr.check_fin() {
            self.tcb.seg_len += 1;
        }
    }

    /// checks for acceptable segment
    pub fn acc_seg(&self) -> bool {
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
        let seg_seq = self.tcb.seg_seq;
        let seg_len = self.tcb.seg_len;
        let rcv_nxt = self.tcb.rcv_nxt;
        let rcv_wnd = self.tcb.rcv_wnd;

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
    }
}

/// transmission control block
#[derive(Debug, Clone, Default)]
pub struct Tcb {
    pub snd_una: u32, // unacknowledged data in flight
    pub snd_nxt: u32, // data that could be sent
    pub snd_wnd: u32, // window size (upper limit) = UNA + window size
    pub snd_wl1: u32, // segment sequence number used for last window update
    pub snd_wl2: u32, // segment acknowledgment number used for last window update

    pub rcv_nxt: u32, // next byte to receive
    pub rcv_wnd: u32, // future seq number not yet allowed (upper limit)

    /// initial send sequence number
    pub iss: u32,
    /// initial receive sequence number
    pub irs: u32,

    pub seg_seq: u32,
    pub seg_ack: u32,
    pub seg_len: u32,
    pub seg_wnd: u16,
    /// last sequence number of a segment
    pub last_seq: u32,

    pub snd_opts: TCP_opts,
    pub rcv_opts: TCP_opts,
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

    #[default]
    Closed,
}

/*
 A segment on the retransmission queue is fully acknowledged if the sum of its sequence number and length is less than or equal to the acknowledgment value in the incoming segment.

 Only segments that advance SND.NXT (i.e., consume sequence space) are tracked for retransmission.
*/

#[derive(Debug, Default)]
pub struct TransmissionQueue(VecDeque<QEntry>);

impl TransmissionQueue {
    pub fn push(&mut self, elem: QEntry) {
        self.0.push_back(elem);
    }
    pub fn pop(&mut self) -> Option<QEntry> {
        self.0.pop_front()
    }
    pub fn peek(&self) -> Option<&QEntry> {
        self.0.front()
    }
    pub fn match_front(&self, seg: u32) -> bool {
        if let Some(elem) = self.peek() {
            return elem.seg == seg;
        }
        false
    }
}

#[derive(Debug, Default)]
pub struct QEntry {
    pub seg: u32,
    pub data: usize,
    pub len: u16,
}

#[derive(Debug, Default)]
pub struct RcvBuffer(Vec<u8>);

impl RcvBuffer {
    pub fn new() -> Self {
        RcvBuffer(vec![0u8; RCV_BUF_SIZE])
    }

    pub fn insert(&mut self, data: &[u8], seq: u32, isn: u32) -> Result<()> {
        let idx = (isn - seq) as usize;
        if idx + data.len() > self.0.len() {
            return Err(Error::Socket(
                "rcv buffer insert exceeds capacity".to_string(),
            ));
        }
        let slice = self.0.as_mut_slice();

        slice[idx..idx + data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::replace(&mut self.0, vec![0u8; RCV_BUF_SIZE])
    }
}
