pub mod hdr;
pub mod opts;
pub mod sock;

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
use tracing::{debug, error, info, instrument, warn};

use crate::error::Result;
use crate::eth::{ETH_FRAME_MAX_SIZE, ETH_P_IP, ETH_PAY_MAX_SIZE, Eth_hdr};
use crate::ip::{IP_DF, IP_HDR_MINSIZE, IP_hdr, IPPROTO_TCP, TOS_BEST_EFFORT, TTL_START};
use crate::tcp::hdr::TCP_hdr;
use crate::tcp::opts::TCP_opts;
use crate::tcup::{CLOCK, TCup};
use crate::types::{Mac, Socket, TCPCon};
use crate::utils::calc_checksum_be;
use crate::{eth::EthFrame, types::MockHost};

pub const TCP_HDR_MINSIZE: usize = 20;
pub const TCP_HDR_MAXSIZE: usize = 60;
pub const TCP_PSEUDOHDR_SIZE: usize = 12;
pub const TCP_OPT_MAX_SIZE: usize = TCP_HDR_MAXSIZE - TCP_HDR_MINSIZE;
pub const WRD_SIZE: usize = 4;
pub const WND_SIZE: u16 = 10000;

/// Retransmission timeout, how long to wait for an ACK before resending the segment in seconds
///
/// double on each retry
pub const RTO_START: u64 = 1;
pub const RTO_CAP: u64 = 60;

/// After sending the final FIN+ACK, you must linger before fully closing the socket. Prevents old duplicate segments from a dead connection being mistaken for a new one.
pub const TW: u64 = MSL * 2;

/// Maximum segment lifetime
pub const MSL: u64 = 60;
pub const FIN_TIMEOUT: u64 = 60;
pub const SYN_ACK_RETRIES: u64 = 5;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 10;

/// socket control block
#[derive(Debug)]
pub struct SkCb {
    rcv_chan: Receiver<EthFrame>,
    rcv_buffer: Vec<u8>, // buffer for the output message
    msg: EthFrame,       // the last message received on the connection

    snd_chan: Arc<TCup>,
    snd_buf: Vec<u8>, // buffer for the output message

    status: TCPState,
    tcb: Tcb,

    con: TCPCon,
    eth_hdr: Eth_hdr, // header to be attached to outgoing messages, need to deprecate this
}

impl SkCb {
    fn new(
        inc: EthFrame,
        rx: Receiver<EthFrame>,
        tcup: Arc<TCup>,
        eth_hdr: Eth_hdr,
        con: TCPCon,
    ) -> Self {
        // TODO: fixed buffer sizes
        SkCb {
            rcv_chan: rx,
            rcv_buffer: vec![],
            snd_chan: tcup,
            msg: inc,

            snd_buf: vec![],
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

    /// listens for a packet on the receiver
    async fn listen(&mut self) -> Result<TCP_hdr> {
        let new_packet = if let Some(packet) = self.rcv_chan.recv().await {
            packet
        } else {
            return Err("channel unexpectedly closed".into());
        };

        let inc_ip_hdr = new_packet.get_ip_hdr()?;
        let inc_tcp_hdr = new_packet.get_tcp_hdr()?;

        // checksum
        tcp_check(inc_ip_hdr, new_packet.get_ip_pay()?);

        // populate control block
        self.update(&inc_ip_hdr, &inc_tcp_hdr);
        self.msg = new_packet;

        Ok(inc_tcp_hdr)
    }

    /// sends a packet through the open connection
    async fn reply(&self, tcp_hdr: TCP_hdr, opts: TCP_opts, tcp_pay: &[u8]) -> Result<()> {
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

        info!("sending reply");
        println!("reply ETH:\n{}", packet.get_eth_hdr());
        println!("reply IP:\n{}", packet.get_ip_hdr()?);
        println!("reply TCP:\n{}", packet.get_tcp_hdr()?);

        // do we need a timeout?
        let n = self.snd_chan.write_tap(packet).await?;

        println!("{n} bytes written");
        Ok(())
    }

    async fn close_socket(&self) {
        // waiting until we close the socket: TIME WAIT TIMEOUT
        tokio::time::sleep(Duration::new(TW, 0)).await;
        self.snd_chan.con_table.write().remove(&self.con);
    }

    async fn send_rst(&self, tcp_hdr: &TCP_hdr) -> Result<()> {
        warn!("sending reset");
        if tcp_hdr.check_rst() {
            // never respond to rst with rst
            debug!("cant respond to RST with RST");
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

        self.reply(tcp_hdr, TCP_opts::default(), &[]).await
    }

    /// checks for acceptable ACK
    fn acc_ack(&self, tcp_hdr: &TCP_hdr) -> bool {
        if !tcp_hdr.check_ack() {
            return true;
        }

        let snd_una = self.tcb.snd_una;
        let seg_ack = self.tcb.seg_ack;
        let snd_nxt = self.tcb.snd_nxt;

        seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt)
    }

    /// updates the TCB with the values of a frame
    fn update(&mut self, ip_hdr: &IP_hdr, tcp_hdr: &TCP_hdr) {
        self.tcb.seg_seq = tcp_hdr.seq;
        self.tcb.seg_ack = tcp_hdr.ack;
        self.tcb.seg_wnd = tcp_hdr.win_size;

        self.tcb.seg_len = ip_hdr.tot_len as u32 - ip_hdr.len() as u32 - tcp_hdr.len() as u32;
        if tcp_hdr.check_syn() {
            self.tcb.seg_len += 1;
        }
        if tcp_hdr.check_fin() {
            self.tcb.seg_len += 1;
        }
    }

    /// checks for acceptable segment
    fn acc_seg(&self) -> bool {
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
    snd_una: u32, // unacknowledged data in flight
    snd_nxt: u32, // data that could be sent
    snd_wnd: u32, // window size (upper limit) = UNA + window size

    rcv_nxt: u32, // next byte to receive
    rcv_wnd: u32, // future seq number not yet allowed (upper limit)

    iss: u32, // initial send sequence number
    irs: u32, // initial receive sequence number

    seg_seq: u32,
    seg_ack: u32,
    seg_len: u32,
    seg_wnd: u16,

    snd_opts: TCP_opts,
    rcv_opts: TCP_opts,
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
    pub fn new(src_addr: [u8; 4], dest_addr: [u8; 4], tcp_len: usize) -> Self {
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
    let ip_hdr = inc.get_ip_hdr()?;

    if !tcp_check(ip_hdr, inc.get_ip_pay()?) {
        return Err("TCP checksum error".into());
    }

    let eth_hdr = inc.get_eth_hdr();
    let tcp_hdr = inc.get_tcp_hdr()?;

    let con = TCPCon {
        sip: Ipv4Addr::from_octets(ip_hdr.src_addr),
        sport: tcp_hdr.sport,
        dip: Ipv4Addr::from_octets(ip_hdr.dest_addr),
        dport: tcp_hdr.dport,
    };

    let sock = tcup.con_table.read().get(&con).cloned();

    if let Some(sock) = sock {
        // hand off frame
        info!("handing off packet to connection");

        return sock.tx.send(inc).await.map_err(Into::into);
    } else {
        if !tcp_hdr.syn_only() {
            warn!("discarding TCP packet");
            // TODO: send reset
            return Ok(());
        }

        info!("new SYN packet received!");

        // register new connection and spawn worker
        let (tx, rx) = channel::<EthFrame>(CHAN_BUF_SIZE);
        tcup.con_table.write().insert(con, Socket { tx });

        let mut skcb = SkCb::new(inc, rx, tcup.clone(), eth_hdr, con);

        // priming the TCP loops
        skcb.status = TCPState::SynReceived;

        tokio::spawn(tcp_processing(tcup.clone(), skcb));

        Ok(())
    }
}

#[instrument(skip_all, err)]
async fn tcp_processing(tcup: Arc<TCup>, mut skcb: SkCb) -> Result<()> {
    loop {
        match skcb.status {
            TCPState::SynSent => todo!(),
            TCPState::SynReceived => syn_received(&mut skcb).await?,
            TCPState::Established => established(&mut skcb).await?,
            TCPState::FinWait1 => todo!(),
            TCPState::FinWait2 => todo!(),
            TCPState::CloseWait => close_wait(&mut skcb).await?,
            TCPState::Closing => todo!(),
            TCPState::LastAck => last_ack(&mut skcb).await?,
            TCPState::Listen => todo!(),

            TCPState::Closed => break,
        };
    }
    skcb.close_socket().await;
    Ok(())
}

/*
    TCP A                                                TCP B

1.  CLOSED                                               LISTEN

2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED

5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED

        Basic 3-Way Handshake for Connection Synchronization

                              Figure 7.
*/
// TODO: seperate LISTEN from SYN RECEIVED state
async fn syn_received(skcb: &mut SkCb) -> Result<()> {
    let req_ip_hdr = skcb.msg.get_ip_hdr()?;
    let req_tcp_hdr = skcb.msg.get_tcp_hdr()?;

    println!("req IP:\n{}", req_ip_hdr);
    println!("req TCP:\n{}", req_tcp_hdr);

    // configure initial sequence numbers
    skcb.update(&req_ip_hdr, &req_tcp_hdr);
    skcb.tcb.iss = new_isn(&skcb.con);
    skcb.tcb.irs = skcb.tcb.seg_seq;

    // building SYN ACK response
    // SYN consumes 1 seq number!
    skcb.tcb.rcv_nxt = skcb.tcb.seg_seq + 1;

    skcb.tcb.snd_una = skcb.tcb.iss;
    skcb.tcb.snd_nxt = skcb.tcb.iss + 1;

    let mut tcp_hdr = TCP_hdr {
        sport: skcb.con.dport,
        dport: skcb.con.sport,
        seq: skcb.tcb.iss,
        ack: skcb.tcb.rcv_nxt, // ACKing the irs
        flags: TCPFlags::default(),
        win_size: WND_SIZE,
        ..Default::default()
    };

    let opts = TCP_opts {
        mss: Some(1460),
        ..Default::default()
    };

    skcb.tcb.rcv_opts = opts;

    tcp_hdr.set_syn();
    tcp_hdr.set_ack();
    tcp_hdr.set_len(TCP_HDR_MINSIZE + opts.len())?;

    skcb.reply(tcp_hdr, opts, &[]).await?;

    let mut rto = RTO_START;
    let mut retries = 0;

    loop {
        if rto == SYN_ACK_RETRIES {
            skcb.status = TCPState::Listen;
            return Err("handshake timed out".into());
        }

        select! {
                _ = tokio::time::sleep(Duration::from_secs(rto)) =>  {
                    rto <<= 1;

                    skcb.reply(tcp_hdr, opts, &[]).await?;
                    retries += 1;
                    continue;
                }

                r = skcb.listen() => {
                    let resp = r?;

                    if !skcb.acc_seg() {
                        let mut tcp_hdr = TCP_hdr {
                            sport: skcb.con.dport,
                            dport: skcb.con.sport,
                            seq: skcb.tcb.snd_nxt,
                            ack: skcb.tcb.rcv_nxt,
                            flags: TCPFlags::default(),
                            win_size: WND_SIZE,
                            ..Default::default()
                        };

                        tcp_hdr.set_ack();
                        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

                        skcb.reply(tcp_hdr, TCP_opts::default(), &[]).await?;

                        return Err("invalid segment, state: syn_received".into());
                    }

                    if resp.check_rst() {
                        skcb.snd_buf.clear();
                        skcb.status = TCPState::Listen;
                        return Err("RST received, state: syn_received, returning to listen".into());
                    }

                    if resp.check_syn() {
                        skcb.status = TCPState::Closed;
                        return Err("SYN packet received, status: syn_received, terminating connection".into());
                    }

                    if !resp.check_ack() {
                        skcb.status = TCPState::Closed;
                        return Err("no ACK set, status: syn_received, terminating connection".into());
                    }

                    if seq_lte(skcb.tcb.snd_una, skcb.tcb.seg_ack) && seq_lte(skcb.tcb.seg_ack, skcb.tcb.snd_nxt) {
                        // ACK packets dont carry data so the windows doesnt advance
                        skcb.tcb.snd_wnd = skcb.tcb.seg_wnd as u32;
                        skcb.tcb.rcv_wnd = WND_SIZE as u32;
                        skcb.tcb.snd_opts = skcb.msg.get_tcp_opts()?;

                        info!("connection established!");
                        skcb.status = TCPState::Established;

                        return Ok(())
                    } else {
                        let mut tcp_hdr = TCP_hdr {
                            sport: skcb.con.dport,
                            dport: skcb.con.sport,
                            seq: skcb.tcb.seg_ack,
                            ack: skcb.tcb.rcv_nxt,
                            flags: TCPFlags::default(),
                            win_size: WND_SIZE,
                            ..Default::default()
                        };

                        tcp_hdr.set_rst();
                        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

                        skcb.reply(tcp_hdr, TCP_opts::default(), &[]).await?;

                        continue;
                    }

                }
        }
    }
}

async fn established(skcb: &mut SkCb) -> Result<()> {
    // listen for new packets
    info!(
        "listening on connection: {}:{}",
        skcb.con.sip, skcb.con.sport
    );

    let resp = skcb.listen().await?;

    if !skcb.acc_seg() && !resp.check_rst() {
        let mut tcp_hdr = TCP_hdr {
            sport: skcb.con.dport,
            dport: skcb.con.sport,
            seq: skcb.tcb.snd_nxt,
            ack: skcb.tcb.rcv_nxt,
            flags: TCPFlags::default(),
            win_size: WND_SIZE,
            ..Default::default()
        };

        tcp_hdr.set_ack();
        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

        skcb.reply(tcp_hdr, TCP_opts::default(), &[]).await?;

        return Err("err: segment wasnt acceptable, status: established".into());
    }

    if resp.check_rst() {
        skcb.status = TCPState::Closed;
        return Err("RST packet received, status: established, terminating connection".into());
    }

    if resp.check_syn() {
        skcb.status = TCPState::Closed;
        return Err("SYN packet received, status: established, terminating connection".into());
    }

    if !resp.check_ack() {
        return Err("ACK not set, status: established, returning".into());
    }

    // fifth check the ACK field

    // shorthand variables
    let snd_una = skcb.tcb.snd_una;
    let seg_ack = skcb.tcb.seg_ack;
    let snd_nxt = skcb.tcb.snd_nxt;

    if seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt) {
        // the sequences was acknowledged within our send window
        // we can move the send window forward
        skcb.tcb.snd_una = skcb.tcb.seg_ack;
    };

    if seq_gt(seg_ack, snd_nxt) {
        // we got an ACK for a segment we havent sent yet
        let mut tcp_hdr = TCP_hdr {
            sport: skcb.con.dport,
            dport: skcb.con.sport,
            seq: skcb.tcb.snd_nxt,
            ack: skcb.tcb.rcv_nxt,
            flags: TCPFlags::default(),
            win_size: WND_SIZE,
            ..Default::default()
        };

        tcp_hdr.set_ack();
        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

        skcb.reply(tcp_hdr, TCP_opts::default(), &[]).await?;

        return Err("ACK for unseen segment received".into());
    }
    // TODO: update window
    /*
    If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
    updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
    SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
    SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.

    Note that SND.WND is an offset from SND.UNA, that SND.WL1
    records the sequence number of the last segment used to update
    SND.WND, and that SND.WL2 records the acknowledgment number of
    the last segment used to update SND.WND.  The check here
    prevents using old segments to update the window.
     */

    // TODO: return SEND buffer

    // TODO: sixth, check URG

    // seventh, process the segment text,
    let tcp_pay = skcb.msg.get_tcp_pay()?;
    // we can advance the window here and write to the buffer
    info!("got {} bytes of data, advancing rcv_nxt", tcp_pay.len());

    skcb.snd_buf.extend_from_slice(tcp_pay);
    println!(
        "\nsent via tcup: {}",
        str::from_utf8(skcb.snd_buf.as_slice()).unwrap()
    );
    skcb.tcb.rcv_nxt += tcp_pay.len() as u32;

    let mut tcp_hdr = TCP_hdr {
        sport: skcb.con.dport,
        dport: skcb.con.sport,
        seq: skcb.tcb.snd_nxt,
        ack: skcb.tcb.rcv_nxt,
        flags: TCPFlags::default(),
        win_size: WND_SIZE,
        ..Default::default()
    };

    tcp_hdr.set_ack();
    tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

    // TODO: retransmission queue
    skcb.reply(tcp_hdr, TCP_opts::default(), &[]).await?;

    // eighth, check the FIN bit,
    if resp.check_fin() {
        skcb.tcb.rcv_nxt += 1;
        skcb.status = TCPState::CloseWait;
    }

    Ok(())
}

async fn close_wait(skcb: &mut SkCb) -> Result<()> {
    // let resp = skcb.msg_buf.get_tcp_hdr()?;
    // if resp.check_rst() {
    //     info!("RST packet received, status: close-wait, terminating connection");

    //     skcb.status = TCPState::Closed;
    //     return Ok(());
    // }

    // ACKing their FIN and sending our own FIN
    let mut tcp_hdr = TCP_hdr {
        sport: skcb.con.dport,
        dport: skcb.con.sport,
        seq: skcb.tcb.snd_nxt,
        ack: skcb.tcb.rcv_nxt,
        flags: TCPFlags::default(),
        win_size: WND_SIZE,
        ..Default::default()
    };

    // FIN takes one seq number
    skcb.tcb.snd_una += 1;
    skcb.tcb.snd_nxt += 1;

    tcp_hdr.set_ack();
    tcp_hdr.set_fin();
    tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

    skcb.reply(tcp_hdr, TCP_opts::default(), &[]).await?;

    skcb.status = TCPState::LastAck;
    Ok(())
}

async fn last_ack(skcb: &mut SkCb) -> Result<()> {
    // waiting for our FIN to be ACKed before closing
    let resp: TCP_hdr;

    select! {
        _ = tokio::time::sleep(Duration::new(FIN_TIMEOUT, 0)) => {
            skcb.status = TCPState::Closed;
            return Ok(())
        }
        r = skcb.listen() => {
            resp = r?;
        }
    };

    let resp = skcb.listen().await?;

    if !skcb.acc_seg() && !resp.check_rst() {
        let mut tcp_hdr = TCP_hdr {
            sport: skcb.con.dport,
            dport: skcb.con.sport,
            seq: skcb.tcb.snd_nxt,
            ack: skcb.tcb.rcv_nxt,
            flags: TCPFlags::default(),
            win_size: WND_SIZE,
            ..Default::default()
        };

        tcp_hdr.set_ack();
        tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

        skcb.reply(tcp_hdr, TCP_opts::default(), &[]).await?;
    }

    if resp.ack == skcb.tcb.snd_nxt {
        skcb.status = TCPState::Closed;
        Ok(())
    } else {
        Err("error when waiting for last ACK".into())
    }
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

/// validates TCP checksum
fn tcp_check(ip_hdr: IP_hdr, ip_pay: &[u8]) -> bool {
    if ip_hdr.tot_len as usize > ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE {
        return false;
    }
    if ip_pay.len() > ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE {
        return false;
    }

    // TODO: account for IP hdr options
    let mut buf = [0u8; ETH_PAY_MAX_SIZE - IP_HDR_MINSIZE + TCP_PSEUDOHDR_SIZE];
    let mut buf_off = 0;

    let phdr = PseudoHdr::new(
        ip_hdr.src_addr,
        ip_hdr.dest_addr,
        ip_hdr.tot_len as usize - ip_hdr.len(),
    );

    buf[..TCP_PSEUDOHDR_SIZE].copy_from_slice(&phdr.into_be_bytes());
    buf_off += TCP_PSEUDOHDR_SIZE;

    buf[buf_off..buf_off + ip_pay.len()].copy_from_slice(ip_pay);
    buf_off += ip_pay.len();

    0 == calc_checksum_be(&buf[..buf_off])
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_lte(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn seq_gte(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}
