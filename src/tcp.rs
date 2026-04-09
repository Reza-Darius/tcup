pub mod hdr;
pub mod heap;
pub mod opts;
pub mod rto;
pub mod skcb;
pub mod sock;
pub mod timer;

use core::hash::Hasher;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::time::Duration;

use siphasher::sip::SipHasher13;
use tokio::sync::mpsc::channel;
use tokio::{pin, select};
use tracing::{error, info, instrument, warn};

use crate::eth::{ETH_FRAME_MAX_SIZE, ETH_PAY_MAX_SIZE};
use crate::ip::{IP_HDR_MINSIZE, IP_hdr};
use crate::tcp::hdr::{PseudoHdr, TCP_hdr, TCPFlags};
use crate::tcp::opts::TCP_opts;
use crate::tcp::rto::RTO;
use crate::tcp::skcb::{SkCb, TCPState};
use crate::tcp::sock::Socket;
use crate::tcp::timer::*;
use crate::tcup::TCup;
use crate::types::TCPCon;
use crate::utils::calc_checksum_be;
use crate::{Error, Result};
use crate::{eth::EthFrame, types::MockHost};

pub const TCP_HDR_MINSIZE: usize = 20;
pub const TCP_HDR_MAXSIZE: usize = 60;
pub const TCP_PSEUDOHDR_SIZE: usize = 12;
pub const TCP_OPT_MAX_SIZE: usize = TCP_HDR_MAXSIZE - TCP_HDR_MINSIZE;
pub const WRD_SIZE: usize = 4;
pub const WND_SIZE: u16 = 10000;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 10;
pub const SYN_ACK_RETRIES: u64 = 5;

pub async fn handle_tcp(inc: EthFrame, tcup: TCup, host: &mut MockHost) -> Result<()> {
    let ip_hdr = inc.get_ip_hdr()?;

    if !tcp_check(&ip_hdr, inc.get_ip_pay()?) {
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

    let sock = tcup.get_sock(&con);

    // TODO: refactor all this
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
        tcup.insert_sock(&con, Socket { tx });

        let mut skcb = SkCb::new(inc, rx, tcup.clone(), con);

        // priming the TCP loops
        skcb.status = TCPState::SynReceived;

        tokio::spawn(tcp_input(skcb));

        Ok(())
    }
}

/// main TCP loop running on a dedicated tokio task
#[instrument(skip_all)]
async fn tcp_input(mut skcb: Box<SkCb>) -> Result<()> {
    loop {
        // TODO: listen on receiver for events then go into state functions
        let mut rto = RTO::new();

        select! {
                msg = skcb.recv_message() => {
                    todo!()
                }
                _ =  &mut rto => {
                    // send segment in queue if any
                    rto.backoff();
                }
        }

        if let Err(e) = match skcb.status {
            TCPState::SynSent => syn_sent(&mut skcb).await,
            TCPState::SynReceived => syn_received(&mut skcb).await,
            TCPState::Established => established(&mut skcb).await,
            TCPState::FinWait1 => todo!(),
            TCPState::FinWait2 => todo!(),
            TCPState::CloseWait => close_wait(&mut skcb).await,
            TCPState::Closing => todo!(),
            TCPState::LastAck => last_ack(&mut skcb).await,
            TCPState::Listen => todo!(),

            TCPState::Closed => break,
        } {
            error!(?e, "error")
        };
    }
    skcb.close_socket().await;
    Ok(())
}

async fn seg_handoff(inc: EthFrame, con: TCPCon, tcup: TCup) -> Result<()> {
    let sock = tcup.get_sock(&con);

    match sock {
        Some(sock) => sock.tx.send(inc).await.map_err(Into::into),
        None => todo!(),
    }
}

fn register_socket(inc: EthFrame, con: TCPCon, tcup: TCup) -> Result<Box<SkCb>> {
    let sock = tcup.get_sock(&con);

    if sock.is_some() {
        return Err(Error::Socket(
            "attempting to register existing socket".to_string(),
        ));
    }

    let (tx, rx) = channel::<EthFrame>(CHAN_BUF_SIZE);
    tcup.insert_sock(&con, Socket { tx });

    Ok(SkCb::new(inc, rx, tcup.clone(), con))
}

fn listen(mut skcb: Box<SkCb>) -> Result<()> {
    skcb.status = TCPState::Listen;
    tokio::spawn(tcp_input(skcb));

    Ok(())
}

async fn active_open(mut skcb: Box<SkCb>) -> Result<()> {
    // configure initial sequence numbers
    skcb.tcb.iss = new_isn(&skcb.con);
    skcb.tcb.irs = 0;

    // building SYN packet
    // SYN consumes 1 seq number! seg_len = 1
    skcb.tcb.rcv_nxt = 0;
    skcb.tcb.rcv_wnd = 0;

    skcb.tcb.snd_una = skcb.tcb.iss;
    skcb.tcb.snd_nxt = skcb.tcb.iss + 1;

    let mut tcp_hdr = TCP_hdr {
        sport: skcb.con.dport,
        dport: skcb.con.sport,
        seq: skcb.tcb.iss,
        ack: 0,
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
    tcp_hdr.set_len(TCP_HDR_MINSIZE + opts.len())?;

    skcb.send(tcp_hdr, opts, &[]).await?;

    skcb.status = TCPState::SynSent;
    tokio::spawn(tcp_input(skcb));

    Ok(())
}

async fn syn_sent(skcb: &mut SkCb) -> Result<()> {
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
#[instrument(fields(state = ?skcb.status))]
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
    // SYN consumes 1 seq number! seg_len = 1
    skcb.tcb.rcv_nxt = skcb.tcb.seg_seq + 1;
    skcb.tcb.rcv_wnd = WND_SIZE as u32;

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

    skcb.send(tcp_hdr, opts, &[]).await?;

    let mut rto = RTO_START;
    let mut retries = 0;

    loop {
        if retries == SYN_ACK_RETRIES {
            skcb.status = TCPState::Listen;
            return Err("handshake timed out".into());
        }

        select! {
                _ = tokio::time::sleep(Duration::from_secs(rto)) =>  {
                    rto <<= 1;

                    skcb.send(tcp_hdr, opts, &[]).await?;
                    retries += 1;
                    continue;
                }

                r = skcb.receive() => {
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

                        skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;

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

                    if seq_lt(skcb.tcb.snd_una, skcb.tcb.seg_ack) && seq_lte(skcb.tcb.seg_ack, skcb.tcb.snd_nxt) {
                        // ACK packets dont carry data so the windows doesnt advance
                        skcb.tcb.snd_wnd = skcb.tcb.seg_wnd as u32;
                        skcb.tcb.snd_wl1 = skcb.tcb.seg_seq;
                        skcb.tcb.snd_wl2 = skcb.tcb.seg_ack;
                        skcb.tcb.snd_opts = skcb.msg.get_tcp_opts()?;

                        // TODO:
                        // If an MSS Option is not received at connection setup, TCP implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).

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

                        skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;

                        continue;
                    }

                }
        }
    }
}

#[instrument(fields(state = ?skcb.status))]
async fn established(skcb: &mut SkCb) -> Result<()> {
    // listen for new packets
    info!(
        "listening on connection: {}:{}",
        skcb.con.sip, skcb.con.sport
    );

    // TODO: react to SEND calls

    let resp = skcb.receive().await?;

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

        skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;

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
    let seg_seq = skcb.tcb.seg_seq;
    let snd_nxt = skcb.tcb.snd_nxt;

    if seq_lte(seg_ack, snd_una) {
        return Err("duplicate ack received, returning...".into());
    }

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

        skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;

        return Err("ACK for unseen segment received".into());
    }

    // update window
    if seq_lte(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt) && seq_lt(skcb.tcb.snd_wl1, seg_seq)
        || (skcb.tcb.snd_wl1 == seg_seq && seq_lte(skcb.tcb.snd_wl2, seg_ack))
    {
        skcb.tcb.snd_wnd = skcb.tcb.seg_wnd as u32;
        skcb.tcb.snd_wl1 = seg_seq;
        skcb.tcb.snd_wl2 = seg_ack;
    }

    // TODO: return SEND buffer

    // TODO: sixth, check URG

    // seventh, process the segment text,
    // TODO: queue, RTO
    let seg_data = skcb.msg.get_tcp_pay()?;
    info!("got {} bytes of data, advancing rcv_nxt", seg_data.len());

    skcb.snd_buf.extend_from_slice(seg_data);
    println!(
        "\nsent via tcup:\n{}",
        str::from_utf8(skcb.snd_buf.as_slice()).unwrap()
    );

    if skcb.tcb.seg_seq == skcb.tcb.rcv_nxt {
        skcb.tcb.rcv_nxt += skcb.tcb.seg_len
    } else {
        // TODO: out of order segments (duplicate acknowledgment)
    }

    // eighth, check the FIN bit,
    if resp.check_fin() {
        skcb.tcb.rcv_nxt += 1;
        skcb.status = TCPState::CloseWait;
    }

    // building response
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

    // TODO: retransmission queue if we sent data
    skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;

    Ok(())
}

async fn established_seg_arrives() {}
async fn established_send() {}

#[instrument(fields(state = ?skcb.status))]
async fn close_wait(skcb: &mut SkCb) -> Result<()> {
    // let resp = skcb.msg_buf.get_tcp_hdr()?;
    // if resp.check_rst() {
    //     info!("RST packet received, status: close-wait, terminating connection");

    //     skcb.status = TCPState::Closed;
    //     return Ok(());
    // }

    // sending our own FIN
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
    skcb.tcb.snd_nxt += 1;

    tcp_hdr.set_fin();
    tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

    // TODO: requeue
    skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;

    skcb.status = TCPState::LastAck;
    Ok(())
}

#[instrument(fields(state = ?skcb.status))]
async fn last_ack(skcb: &mut SkCb) -> Result<()> {
    // waiting for our FIN to be ACKed before closing
    let resp: TCP_hdr;

    select! {
        _ = tokio::time::sleep(Duration::new(FIN_TIMEOUT, 0)) => {
            skcb.status = TCPState::Closed;
            return Ok(())
        }
        r = skcb.receive() => {
            resp = r?;
        }
    };

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

        skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;
    }

    if skcb.acc_ack(&resp) {
        skcb.status = TCPState::Closed;
        Ok(())
    } else {
        Err("error when waiting for last ACK".into())
    }
}

// TODO: implement 4 microsecond clock, and make this nice
fn new_isn(con: &TCPCon) -> u32 {
    let key: &[u8; 16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut hasher = SipHasher13::new_with_key(key);

    TICK.load(std::sync::atomic::Ordering::Relaxed)
        .hash(&mut hasher);
    con.hash(&mut hasher);

    hasher.finish() as u32
}

/// returns true on valid checksum
fn tcp_check(ip_hdr: &IP_hdr, ip_pay: &[u8]) -> bool {
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

pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn seq_lte(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

pub fn seq_gte(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}
