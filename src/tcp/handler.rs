use std::assert_matches;

use tracing::{debug, instrument};

use super::error::TCPError;
use crate::eth::ETH_FRAME_MAX_SIZE;
use crate::tcp::error::TCPError::HandlerError;
use crate::tcp::seq::*;
use crate::tcp::skcb::TCPState::{Listen, SynReceived};
use crate::tcp::tcp_packet::TCP_SEG_MAX_SIZE;
use crate::tcp::{
    opts::TCPOpts,
    skcb::{Open, SKCB, TCPState},
    tcp_packet::{TCPFlags, TCPHdr},
};
use crate::utils::packet::{Packet, TCP};

pub const TCP_HDR_MINSIZE: usize = 20;
pub const TCP_HDR_MAXSIZE: usize = 60;
pub const TCP_PSEUDOHDR_SIZE: usize = 12;
pub const TCP_OPT_MAX_SIZE: usize = TCP_HDR_MAXSIZE - TCP_HDR_MINSIZE;
pub const WRD_SIZE: usize = 4;
pub const WND_SIZE: u16 = 10000;

pub const CHAN_BUF_SIZE: usize = ETH_FRAME_MAX_SIZE * 100;
pub const SYN_ACK_RETRIES: u64 = 5;

type Result<T> = std::result::Result<T, TCPError>;

/// dispatch the correct handler for a segment event
#[instrument(skip_all, fields(state = ?skcb.status))]
pub async fn seg_handler(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // these behaviours are mostly the same across states so we can handle them right here
    // what to do when we get a syn rst packet?
    let hdr = seg.hdr();

    if handle_rst(skcb, hdr).await || handle_syn(skcb, hdr).await {
        return Ok(());
    };

    match skcb.status {
        TCPState::Listen => listen(skcb, seg).await?,
        TCPState::SynSent => syn_sent(skcb, seg).await?,
        TCPState::SynReceived => syn_received(skcb, seg).await?,
        TCPState::Established => established(skcb, seg).await?,
        TCPState::FinWait1 => finwait1(skcb, seg).await?,
        TCPState::FinWait2 => finwait2(skcb, seg).await?,
        TCPState::CloseWait => close_wait(skcb, seg).await?,
        TCPState::Closing => closing(skcb, seg).await?,
        TCPState::LastAck => last_ack(skcb, seg).await?,
        TCPState::TimeWait => timewait(skcb, seg).await?,

        TCPState::Closed => unreachable!(),
    };
    Ok(())
}

/// determines whether the segment should be dropped and possible state change
async fn handle_rst(skcb: &mut SKCB, hdr: &TCPHdr) -> bool {
    if !hdr.is_rst() {
        return false;
    }
    match skcb.status {
        TCPState::SynSent => {
            if skcb.check_ack(hdr) {
                skcb.status = TCPState::Closed;
                true
            } else {
                false
            }
        }
        TCPState::TimeWait => {
            skcb.status = TCPState::Closed;
            true
        }
        TCPState::Listen | TCPState::Closed => true,
        TCPState::SynReceived => {
            match skcb.open {
                Open::Passive => {
                    skcb.status = TCPState::Listen;
                }
                // our connection was refused
                Open::Active => {
                    skcb.status = TCPState::Closed;
                }
            };
            skcb.snd_buf.clear();
            skcb.rcv_buf.clear();
            true
        }
        _ => {
            let seg_seq = hdr.seq.get();
            if seq_gt(seg_seq, skcb.tcb.rcv_wnd) {
                return true;
            }
            if seg_seq == skcb.tcb.rcv_nxt {
                match skcb.open {
                    Open::Passive => {
                        skcb.status = TCPState::Listen;
                    }
                    // our connection was refused
                    Open::Active => {
                        skcb.status = TCPState::Closed;
                    }
                };
                skcb.snd_buf.clear();
                skcb.rcv_buf.clear();
                return true;
            };
            /*
            * If the RST bit is set and the sequence number does not exactly match the next expected sequence value, yet is within the current receive window, TCP endpoints MUST send an acknowledgment (challenge ACK):

            <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

            After sending the challenge ACK, TCP endpoints MUST drop the unacceptable segment and stop processing the incoming packet further. Note that RFC 5961 and Errata ID 4772 [99] contain additional considerations for ACK throttling in an implementation.
            */
            skcb.send_ack().await.unwrap();
            true
        }
    }
}

/// returns true if the segment should be dropped
async fn handle_syn(skcb: &mut SKCB, hdr: &TCPHdr) -> bool {
    if !hdr.is_syn() {
        return false;
    }
    if matches!(skcb.status, TCPState::SynSent | SynReceived | Listen) {
        // in synchronized state: send challenge ack and drop the segment
        skcb.send_ack().await.unwrap();
        true
    } else {
        false
    }
}

/// response to connect call, actively opening a connection
pub async fn active_open(skcb: &mut SKCB) -> Result<()> {
    assert_matches!(
        skcb.status,
        TCPState::Closed,
        "active open can only be called from closed state"
    );

    skcb.open = Open::Active;

    // configure initial sequence numbers
    skcb.tcb.iss = new_isn(&skcb.con);
    skcb.tcb.irs = 0;

    // building SYN packet
    // SYN consumes 1 seq number!
    skcb.tcb.rcv_nxt = 0;
    skcb.tcb.rcv_wnd = 0;

    skcb.tcb.snd_una = skcb.tcb.iss;
    skcb.tcb.snd_nxt = skcb.tcb.iss + 1;

    let mut tcp_hdr = TCPHdr {
        sport: skcb.con.local_port.into(),
        dport: skcb.con.remote_port.into(),
        seq: skcb.tcb.iss.into(),
        ack: 0.into(),
        flags: TCPFlags::default(),
        win_size: WND_SIZE.into(),
        ..Default::default()
    };

    let opts = TCPOpts {
        mss: Some(TCP_SEG_MAX_SIZE as u16),
        ..Default::default()
    };

    skcb.tcb.rcv_opts = opts;

    tcp_hdr.set_syn();
    skcb.output(tcp_hdr, opts, &[]).await?;

    skcb.status = TCPState::SynSent;
    skcb.open = Open::Active;

    Ok(())
}

async fn listen(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    let req_tcp_hdr = seg.hdr();

    if req_tcp_hdr.is_ack() {
        skcb.send_rst(req_tcp_hdr).await?;
        return Err(HandlerError("ACK received".to_string()));
    }

    if req_tcp_hdr.is_fin() {
        return Err(HandlerError("cant process fin segment".to_string()));
    }

    // probably unneccessary
    if !req_tcp_hdr.is_syn() {
        return Err(HandlerError("received seg without SYN".to_string()));
    }

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

    let mut tcp_hdr = TCPHdr {
        sport: skcb.con.local_port.into(),
        dport: skcb.con.remote_port.into(),
        seq: skcb.tcb.iss.into(),
        ack: skcb.tcb.rcv_nxt.into(), // ACKing the irs
        flags: TCPFlags::default(),
        win_size: WND_SIZE.into(),
        ..Default::default()
    };

    let opts = TCPOpts {
        mss: Some(1460),
        ..Default::default()
    };

    skcb.tcb.rcv_opts = opts;

    tcp_hdr.set_syn();
    tcp_hdr.set_ack();
    tcp_hdr.set_len(TCP_HDR_MINSIZE + opts.len());

    skcb.output(tcp_hdr, opts, &[]).await?;
    skcb.status = TCPState::SynReceived;

    Ok(())
}

/// event handler for SYN SENT TCP state
async fn syn_sent(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    todo!()
}

/// event handler for FIN WAIT1 TCP state
async fn finwait1(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    todo!()
}

/// event handler for FIN WAIT2 TCP state
async fn finwait2(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    todo!()
}

/// event handler for CLOSING TCP state
async fn closing(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    todo!()
}

/// event handler for TIME WAIT TCP state
async fn timewait(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // match event {
    //     TCPEvent::Timeout => skcb.status = TCPState::Closed,
    //     _ => todo!(),
    // }
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

/// event handler for SYN RECEIVED TCP state
async fn syn_received(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    skcb.check_seg().await?;
    let hdr = seg.hdr();
    if hdr.is_rst() {
        skcb.rcv_buf.clear();

        // If this connection was initiated with a passive OPEN (i.e., came from the LISTEN state),
        // then return this connection to LISTEN state and return. The user need not be informed.
        // If this connection was initiated with an active OPEN (i.e., came from SYN-SENT state),
        // then the connection was refused; signal the user "connection refused".
        // In either case, the retransmission queue should be flushed.
        // And in the active OPEN case, enter the CLOSED state and delete the TCB, and return.

        skcb.status = match skcb.open {
            Open::Passive => TCPState::Listen,
            Open::Active => TCPState::Closed,
        };

        return Err(HandlerError(format!(
            "RST received, returning to {:?}",
            skcb.status
        )));
    }

    if hdr.is_syn() {
        skcb.status = TCPState::Closed;
        return Err(HandlerError(
            "SYN packet received, terminating connection".to_string(),
        ));
    }

    if !hdr.is_ack() {
        skcb.status = TCPState::Closed;
        return Err(HandlerError(
            "no ACK set, terminating connection".to_string(),
        ));
    }

    // SND.UNA < SEG.ACK <= SND.NXT
    if seq_lt(skcb.tcb.snd_una, skcb.tcb.seg_ack) && seq_lte(skcb.tcb.seg_ack, skcb.tcb.snd_nxt) {
        // ACK packets dont carry data so the windows doesnt advance
        skcb.tcb.snd_wnd = skcb.tcb.seg_wnd as u32;
        skcb.tcb.snd_wl1 = skcb.tcb.seg_seq;
        skcb.tcb.snd_wl2 = skcb.tcb.seg_ack;

        // If an MSS Option is not received at connection setup, TCP implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).
        skcb.tcb.snd_opts = seg.options().unwrap_or_else(|| TCPOpts {
            mss: Some(536),
            ..Default::default()
        });

        debug!("connection established!");
        skcb.status = TCPState::Established;

        // TODO: place any data that accompanies this ack into the buffer
        return Ok(());
    } else {
        let mut tcp_hdr = TCPHdr {
            sport: skcb.con.local_port.into(),
            dport: skcb.con.remote_port.into(),
            seq: skcb.tcb.seg_ack.into(),
            ack: skcb.tcb.rcv_nxt.into(),
            flags: TCPFlags::default(),
            win_size: WND_SIZE.into(),
            ..Default::default()
        };

        tcp_hdr.set_rst();
        tcp_hdr.set_len(TCP_HDR_MINSIZE);

        skcb.output(tcp_hdr, TCPOpts::default(), &[]).await?;
    }

    if hdr.is_fin() {
        skcb.tcb.rcv_nxt += 1;
        skcb.status = TCPState::CloseWait;
        skcb.send_ack().await?;
    }
    Ok(())
}

/// handler for segment event in ESTABLISHED state
async fn established(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    skcb.check_seg().await?;
    let seg_hdr = seg.hdr();

    // syn and rst case are handled already

    if !seg_hdr.is_ack() {
        return Err(HandlerError("ACK not set".to_string()));
    }

    // shorthand variables
    let snd_una = skcb.tcb.snd_una;
    let seg_ack = skcb.tcb.seg_ack;
    let seg_seq = skcb.tcb.seg_seq;
    let snd_nxt = skcb.tcb.snd_nxt;

    // check segment for ACKs to our sent data
    if seq_lte(seg_ack, snd_una) {
        return Err(HandlerError("duplicate ACK received".to_string()));
    }

    if seq_gt(seg_ack, snd_nxt) {
        // we got an ACK for a segment we havent sent yet
        skcb.send_ack().await?;
        return Err(HandlerError("ACK for unseen segment received".into()));
    }
    // check for snd window = seg window, advertised window hasnt changed
    if seq_lt(snd_una, seg_ack) && seq_lte(seg_ack, snd_nxt) {
        // we got an ACK within our send window, we can move it forward

        // - pop data from sendbuffer/retransmission queue
        skcb.snd_buf.free_n(snd_una.abs_diff(seg_ack) as usize);

        // - If the received segment acknowledges all outstanding data (snd_una equals snd_max), the
        //   retransmission timer is turned off. Otherwise, if the persist timer is off, the retransmit timer is restarted
        if skcb.snd_buf.is_empty() {
            skcb.clear_rto();
        }

        skcb.tcb.snd_una = seg_ack;

        // TODO::
        // - if the buffer has been fully acknowledged, return OK response to user

        // update window
        if seq_lt(skcb.tcb.snd_wl1, seg_seq)
            || (skcb.tcb.snd_wl1 == seg_seq && seq_lte(skcb.tcb.snd_wl2, seg_ack))
        {
            skcb.tcb.snd_wnd = skcb.tcb.seg_wnd as u32;
            skcb.tcb.snd_wl1 = seg_seq;
            skcb.tcb.snd_wl2 = seg_ack;
        }
    };

    // check segment for received data

    // segment is next expected data so we move the window
    if skcb.tcb.seg_seq == skcb.tcb.rcv_nxt {
        // TODO: consume the package to avoid another allocation
        let seg_data = seg.payload();

        debug!("got {} bytes of data, advancing rcv_nxt", seg_data.len());
        debug_assert!(seg_data.len() as u32 == skcb.tcb.seg_len);

        let rcv_nxt = skcb.tcb.rcv_nxt;
        skcb.rcv_buf.insert(seg_data, rcv_nxt);

        skcb.tcb.rcv_nxt += skcb.tcb.seg_len;
        skcb.tcb.rcv_wnd += skcb.tcb.seg_len;
    } else {
        // TODO:
        // If this test is false, then the received segment is
        // either a retransmission or a segment beyond the one expected
        // right now we just drop the packet
    }

    // eighth, check the FIN bit,
    if seg_hdr.is_fin() {
        skcb.tcb.rcv_nxt += 1;
        skcb.status = TCPState::CloseWait;
    }

    // This acknowledgment should be piggybacked on a segment being transmitted if possible without incurring undue delay.
    skcb.send_ack().await?;

    Ok(())
}

/// handler for send event in ESTABLISHED TCP state
async fn established_send() {}

/// event handler for CLOSE WAIT TCP state
async fn close_wait(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // TODO: send remaining data

    // sending our own FIN
    let mut tcp_hdr = TCPHdr {
        sport: skcb.con.local_port.into(),
        dport: skcb.con.remote_port.into(),
        seq: skcb.tcb.snd_nxt.into(),
        ack: skcb.tcb.rcv_nxt.into(),
        flags: TCPFlags::default(),
        win_size: WND_SIZE.into(),
        ..Default::default()
    };

    // FIN takes one seq number
    skcb.tcb.snd_nxt += 1;

    tcp_hdr.set_fin();
    tcp_hdr.set_len(TCP_HDR_MINSIZE);

    skcb.output(tcp_hdr, TCPOpts::default(), &[]).await?;

    skcb.status = TCPState::LastAck;
    Ok(())
}

async fn last_ack(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // waiting for our FIN to be ACKed before closing
    if skcb.check_ack(seg.hdr()) {
        skcb.status = TCPState::Closed;
        Ok(())
    } else {
        Err(HandlerError("invalid ACK".to_string()))
    }
}
