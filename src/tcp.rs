pub mod buffer;
pub mod hdr;
pub mod heap;
pub mod opts;
pub mod rto;
pub mod rtq;
pub mod seq;
pub(crate) mod skcb;
pub mod sock;
pub mod timer;

use std::net::Ipv4Addr;

use tokio::sync::mpsc::channel;
use tracing::{debug, error, info, instrument, warn};

use crate::error::SocketError;
use crate::eth::EthFrame;
use crate::eth::{ETH_FRAME_MAX_SIZE, ETH_PAY_MAX_SIZE};
use crate::ip::{IP_HDR_MINSIZE, IP_hdr};
use crate::tcp::{
    hdr::{PseudoHdr, TCP_hdr, TCPFlags},
    opts::TCP_opts,
    seq::*,
    skcb::{Open, SkCb, TCPEvent, TCPSegment, TCPState},
    sock::{Socket, SocketWorkerMsg},
};
use crate::tcup::TCup;
use crate::types::TCPCon;
use crate::utils::calc_checksum_be;
use crate::{Error, Result};

pub const TCP_HDR_MINSIZE: usize = 20;
pub const TCP_HDR_MAXSIZE: usize = 60;
pub const TCP_PSEUDOHDR_SIZE: usize = 12;
pub const TCP_OPT_MAX_SIZE: usize = TCP_HDR_MAXSIZE - TCP_HDR_MINSIZE;
pub const WRD_SIZE: usize = 4;
pub const WND_SIZE: u16 = 10000;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 100;
pub const SYN_ACK_RETRIES: u64 = 5;

pub async fn handle_tcp(inc: EthFrame, tcup: TCup) -> Result<()> {
    let ip_hdr = inc.get_ip_hdr()?;
    let tcp_hdr = inc.get_tcp_hdr()?;

    let con = TCPCon {
        remote_ip: Ipv4Addr::from_octets(ip_hdr.src_addr),
        remote_port: tcp_hdr.sport,
        local_ip: Ipv4Addr::from_octets(ip_hdr.dest_addr),
        local_port: tcp_hdr.dport,
    };

    // hand off segment
    let sock = tcup.get_sock(&con);
    let msg = SocketWorkerMsg::Frame(inc);

    match sock {
        Some(sock) => sock.tx.send(msg).await.map_err(Into::into),
        None => {
            /*
            TODO: receiving message in CLOSED state

            all data in the incoming segment is discarded. An incoming segment containing a RST is discarded. An incoming segment not containing a RST causes a RST to be sent in response. The acknowledgment and sequence field values are selected to make the reset sequence acceptable to the TCP endpoint that sent the offending segment.
            If the ACK bit is off, sequence number zero is used,

            <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            If the ACK bit is on,

            <SEQ=SEG.ACK><CTL=RST>
            Return.

            */
            warn!(?con, "cant find socket for connection");
            Err(Error::Tcp("cant find socket for connection".to_string()))
        }
    }
}

fn register_socket(tcup: TCup, con: TCPCon) -> Result<SkCb> {
    let sock = tcup.get_sock(&con);

    if sock.is_some() {
        error!("attempted to register socket for existing connection");
        return Err(SocketError::SocketInUse(con).into());
    }

    let (tx, rx) = channel::<SocketWorkerMsg>(CHAN_BUF_SIZE);
    tcup.insert_sock(&con, Socket { tx });

    Ok(SkCb::new(rx, tcup.clone(), con))
}

fn passive_open(mut skcb: SkCb) -> Result<()> {
    skcb.status = TCPState::Listen;
    skcb.open = Open::Passive;

    tokio::spawn(tcp_input(skcb));

    Ok(())
}

async fn active_open(mut skcb: SkCb) -> Result<()> {
    // configure initial sequence numbers
    skcb.tcb.iss = new_isn(&skcb.con);
    skcb.tcb.irs = 0;

    // building SYN packet
    // SYN consumes 1 seq number!
    skcb.tcb.rcv_nxt = 0;
    skcb.tcb.rcv_wnd = 0;

    skcb.tcb.snd_una = skcb.tcb.iss;
    skcb.tcb.snd_nxt = skcb.tcb.iss + 1;

    let mut tcp_hdr = TCP_hdr {
        sport: skcb.con.local_port,
        dport: skcb.con.remote_port,
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
    skcb.open = Open::Active;

    tokio::spawn(tcp_input(skcb));

    Ok(())
}

/// main TCP loop running on a dedicated tokio task
#[instrument(skip_all, fields(state = ?skcb.status), err)]
async fn tcp_input(mut skcb: SkCb) -> Result<()> {
    loop {
        if skcb.status == TCPState::Closed {
            skcb.close_socket().await;
            return Ok(());
        }

        let event = skcb.event_listen().await;

        // these behaviours are mostly the same across states so we can handle them right here
        if let TCPEvent::Seg(ref seg) = event {
            if skcb.handle_rst(seg) {
                continue;
            };
            // currently a noop
            if skcb.handle_syn(seg) {
                continue;
            }
        }

        if let Err(e) = match skcb.status {
            TCPState::Listen => listen(&mut skcb, event).await,
            TCPState::SynSent => syn_sent(&mut skcb, event).await,
            TCPState::SynReceived => syn_received(&mut skcb, event).await,
            TCPState::Established => established(&mut skcb, event).await,
            TCPState::FinWait1 => finwait1(&mut skcb, event).await,
            TCPState::FinWait2 => finwait2(&mut skcb, event).await,
            TCPState::CloseWait => close_wait(&mut skcb, event).await,
            TCPState::Closing => closing(&mut skcb, event).await,
            TCPState::LastAck => last_ack(&mut skcb, event).await,

            TCPState::TimeWait => timewait(&mut skcb, event).await,

            TCPState::Closed => unreachable!(),
        } {
            error!(?e, "error")
        };
    }
}

async fn listen(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    match event {
        TCPEvent::Seg(seg) => {
            if seg.hdr.check_ack() {
                skcb.send_rst(&seg.hdr).await?;
                return Err(Error::Tcp("ACK received".to_string()));
            }

            if seg.hdr.check_fin() {
                return Err(Error::Tcp("cant process fin segment".to_string()));
            }

            // probably unneccessary
            if !seg.hdr.check_syn() {
                return Err(Error::Tcp("received seg without SYN".to_string()));
            }

            let req_tcp_hdr = seg.hdr;

            debug!("req TCP:\n{}", req_tcp_hdr);

            // configure initial sequence numbers
            skcb.tcb.iss = new_isn(&skcb.con);
            skcb.tcb.irs = skcb.tcb.seg_seq;

            // building SYN ACK response
            // SYN consumes 1 seq number! seg_len = 1
            skcb.tcb.rcv_nxt = skcb.tcb.seg_seq + 1;
            skcb.tcb.rcv_wnd = WND_SIZE as u32;

            skcb.tcb.snd_una = skcb.tcb.iss;
            skcb.tcb.snd_nxt = skcb.tcb.iss + 1;

            let mut tcp_hdr = TCP_hdr {
                sport: skcb.con.local_port,

                dport: skcb.con.remote_port,
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
            skcb.status = TCPState::SynReceived;

            Ok(())
        }
        _ => todo!(),
    }
}

async fn syn_sent(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    todo!()
}
async fn finwait1(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    todo!()
}
async fn finwait2(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    todo!()
}
async fn closing(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    todo!()
}
async fn timewait(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    match event {
        TCPEvent::Timeout => skcb.status = TCPState::Closed,
        _ => todo!(),
    }
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

async fn syn_received(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    match event {
        TCPEvent::Seg(seg) => {
            skcb.check_seg().await?;

            if seg.hdr.check_rst() {
                skcb.snd_buf.clear();
                skcb.status = TCPState::Listen;
                return Err(Error::Tcp("RST received, returning to listen".to_string()));
            }

            if seg.hdr.check_syn() {
                skcb.status = TCPState::Closed;
                return Err(Error::Tcp(
                    "SYN packet received, terminating connection".to_string(),
                ));
            }

            if !seg.hdr.check_ack() {
                skcb.status = TCPState::Closed;
                return Err(Error::Tcp("no ACK set, terminating connection".to_string()));
            }

            // SND.UNA < SEG.ACK <= SND.NXT
            if seq_lt(skcb.tcb.snd_una, skcb.tcb.seg_ack)
                && seq_lte(skcb.tcb.seg_ack, skcb.tcb.snd_nxt)
            {
                // ACK packets dont carry data so the windows doesnt advance
                skcb.tcb.snd_wnd = skcb.tcb.seg_wnd as u32;
                skcb.tcb.snd_wl1 = skcb.tcb.seg_seq;
                skcb.tcb.snd_wl2 = skcb.tcb.seg_ack;

                // If an MSS Option is not received at connection setup, TCP implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).
                skcb.tcb.snd_opts = seg.opts.unwrap_or_else(|| TCP_opts {
                    mss: Some(536),
                    ..Default::default()
                });

                debug!("connection established!");
                skcb.status = TCPState::Established;

                return Ok(());
            } else {
                let mut tcp_hdr = TCP_hdr {
                    sport: skcb.con.local_port,
                    dport: skcb.con.remote_port,
                    seq: skcb.tcb.seg_ack,
                    ack: skcb.tcb.rcv_nxt,
                    flags: TCPFlags::default(),
                    win_size: WND_SIZE,
                    ..Default::default()
                };

                tcp_hdr.set_rst();
                tcp_hdr.set_len(TCP_HDR_MINSIZE)?;

                skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;
            }

            if seg.hdr.check_fin() {
                skcb.tcb.rcv_nxt += 1;
                skcb.status = TCPState::CloseWait;
                skcb.send_ack().await?;
            }
        }
        _ => todo!(),
    }
    Ok(())
}

async fn established(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    match event {
        TCPEvent::Seg(seg) => established_seg(skcb, seg).await,
        _ => todo!(),
    }
}

async fn established_seg(skcb: &mut SkCb, seg: TCPSegment) -> Result<()> {
    skcb.check_seg().await?;

    if seg.hdr.check_syn() {
        skcb.send_ack().await?;
        return Err(Error::Tcp(
            "SYN packet received in synchronized state".to_string(),
        ));
    }

    if !seg.hdr.check_ack() {
        return Err(Error::Tcp("ACK not set".to_string()));
    }

    // shorthand variables
    let snd_una = skcb.tcb.snd_una;
    let seg_ack = skcb.tcb.seg_ack;
    let seg_seq = skcb.tcb.seg_seq;
    let snd_nxt = skcb.tcb.snd_nxt;

    if seq_lte(seg_ack, snd_una) {
        return Err(Error::Tcp("duplicate ACK received".to_string()));
    }

    if seq_gt(seg_ack, snd_nxt) {
        // we got an ACK for a segment we havent sent yet
        skcb.send_ack().await?;
        return Err("ACK for unseen segment received".into());
    }

    if seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt) {
        // the sequences was acknowledged within our send window
        // we can move the send window forward
        // TODO: pop from retransmission queue here
        // TODO: if the buffer has been acknowledged, return OK response to user
        skcb.tcb.snd_una = skcb.tcb.seg_ack;

        // update window
        if seq_lt(skcb.tcb.snd_wl1, seg_seq)
            || (skcb.tcb.snd_wl1 == seg_seq && seq_lte(skcb.tcb.snd_wl2, seg_ack))
        {
            skcb.tcb.snd_wnd = skcb.tcb.seg_wnd as u32;
            skcb.tcb.snd_wl1 = seg_seq;
            skcb.tcb.snd_wl2 = seg_ack;
        }
    };

    // TODO: sixth, check URG

    // seventh, process the segment text,

    let seg_data = seg.get_pay();
    info!("got {} bytes of data, advancing rcv_nxt", seg_data.len());

    skcb.snd_buf.extend_from_slice(seg_data);
    println!(
        "\nsent via tcup:\n{}",
        str::from_utf8(skcb.snd_buf.as_slice()).unwrap()
    );

    if skcb.tcb.seg_seq == skcb.tcb.rcv_nxt {
        skcb.tcb.rcv_nxt += skcb.tcb.seg_len;
        skcb.tcb.rcv_wnd += skcb.tcb.seg_len;
    } else {
        // TODO: out of order segments (duplicate acknowledgment)
    }

    // eighth, check the FIN bit,
    if seg.hdr.check_fin() {
        skcb.tcb.rcv_nxt += 1;
        skcb.status = TCPState::CloseWait;
    }

    // This acknowledgment should be piggybacked on a segment being transmitted if possible without incurring undue delay.
    skcb.send_ack().await?;

    Ok(())
}

async fn established_send() {}

async fn close_wait(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    // TODO: send remaining data

    // sending our own FIN
    let mut tcp_hdr = TCP_hdr {
        sport: skcb.con.local_port,
        dport: skcb.con.remote_port,
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

    skcb.send(tcp_hdr, TCP_opts::default(), &[]).await?;

    skcb.status = TCPState::LastAck;
    Ok(())
}

async fn last_ack(skcb: &mut SkCb, event: TCPEvent) -> Result<()> {
    // waiting for our FIN to be ACKed before closing
    match event {
        TCPEvent::Seg(seg) => {
            if skcb.check_ack(&seg.hdr) {
                skcb.status = TCPState::Closed;
                Ok(())
            } else {
                Err(Error::Tcp("invalid ACK".to_string()))
            }
        }
        TCPEvent::Timeout => todo!(),
        TCPEvent::Send(items) => todo!(),
        TCPEvent::Close => todo!(),
        TCPEvent::Abort => todo!(),
    }
}

/// returns true on valid checksum
pub fn tcp_check(ip_hdr: &IP_hdr, ip_pay: &[u8]) -> bool {
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
