use std::assert_matches;
use std::net::SocketAddrV4;

use tracing::{instrument, trace};

use super::error::TCPError;
use crate::eth::ETH_FRAME_MAX_SIZE;
use crate::tcp::error::TCPError::HandlerError;
use crate::tcp::seq::*;
use crate::tcp::tcp_packet::{TCP_SEG_MAX_SIZE, TCPPayload};
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
pub async fn seg_handler(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    let hdr = seg.hdr();

    // in synchronized states we can handle step 1 (seq check), step 2 (rst check) and step 3 (ack check)
    // right here
    if skcb.is_synchronized() {
        if !skcb.check_seq() {
            if !hdr.is_rst() {
                skcb.send_ack().await?;
            }
            return Ok(());
        }

        if handle_sync_rst(skcb, hdr).await || handle_sync_syn(skcb, hdr).await || !hdr.is_ack() {
            return Ok(());
        };
    }

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
        TCPState::Closed => {}
    };
    Ok(())
}

/// determines whether the segment should be dropped and possible state change
async fn handle_sync_rst(skcb: &mut SKCB, hdr: &TCPHdr) -> bool {
    trace!("chcking rst in sync state");

    if !hdr.is_rst() {
        return false;
    }

    if matches!(skcb.status, TCPState::SynReceived) {
        match skcb.open {
            Open::Passive => {
                skcb.change_state(TCPState::Listen);
            }
            Open::Active => {
                skcb.change_state(TCPState::Closed);
            }
        };
    } else {
        skcb.change_state(TCPState::Closed);
    }
    true
}

/// returns true if the segment should be dropped
async fn handle_sync_syn(skcb: &mut SKCB, hdr: &TCPHdr) -> bool {
    trace!("chcking syn in sync state");

    if !hdr.is_syn() {
        return false;
    }

    if matches!(skcb.status, TCPState::SynReceived) {
        match skcb.open {
            Open::Passive => {
                skcb.change_state(TCPState::Listen);
                true
            }
            Open::Active => false,
        }
    } else {
        // challenge ACK
        skcb.send_ack().await.unwrap();
        true
    }
}

/// response to connect call, actively opening a connection
pub async fn active_open(skcb: &mut SKCB, remote_addr: SocketAddrV4) -> Result<()> {
    assert_matches!(
        skcb.status,
        TCPState::Closed,
        "active open can only be called from closed state"
    );

    skcb.open = Open::Active;
    skcb.r_addr = Some(remote_addr);

    // configure initial sequence numbers
    skcb.tcb.iss = new_isn(&skcb.con());
    skcb.tcb.irs = 0;

    // building SYN packet
    // SYN consumes 1 seq number!
    skcb.tcb.rcv_nxt = 0;
    skcb.tcb.rcv_wnd = 0;

    skcb.tcb.snd_una = skcb.tcb.iss;
    skcb.tcb.snd_nxt = skcb.tcb.iss + 1;

    let mut tcp_hdr = TCPHdr {
        sport: skcb.l_addr.port().into(),
        dport: skcb.r_addr.unwrap().port().into(),
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

    skcb.change_state(TCPState::SynSent);
    skcb.open = Open::Active;

    Ok(())
}

/// event handler for LISTEN state
async fn listen(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    let seg_hdr = seg.hdr();

    if seg_hdr.is_rst() {
        trace!("dropping segment: rst check failed");

        return Err(HandlerError("got rst in listen".to_string()));
    }

    if seg_hdr.is_ack() {
        trace!("dropping segment: ack check failed");

        return skcb.send_rst().await;
    }

    if !seg_hdr.is_syn() {
        trace!("dropping segment: syn check failed");

        return Err(HandlerError("didnt get syn in listen".to_string()));
    }

    // passive open:

    let con = seg.con();
    skcb.r_addr = Some(SocketAddrV4::new(con.remote_ip, con.remote_port));

    // configure initial sequence numbers
    skcb.tcb.iss = new_isn(&skcb.con());
    skcb.tcb.irs = skcb.tcb.seg_seq;

    // building SYN ACK response
    // SYN consumes 1 seq number! seg_len = 1
    skcb.tcb.rcv_nxt = skcb.tcb.seg_seq.wrapping_add(1);
    skcb.tcb.rcv_wnd = skcb.rcv_buf.available_cap();

    skcb.tcb.snd_una = skcb.tcb.iss;
    skcb.tcb.snd_nxt = skcb.tcb.iss.wrapping_add(1);

    let mut tcp_hdr = TCPHdr {
        sport: skcb.l_addr.port().into(),
        dport: skcb.r_addr.unwrap().port().into(),
        seq: skcb.tcb.iss.into(),
        ack: skcb.tcb.rcv_nxt.into(), // ACKing the irs
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
    tcp_hdr.set_ack();
    tcp_hdr.set_len(TCP_HDR_MINSIZE + opts.len());

    skcb.output(tcp_hdr, opts, &[]).await?;
    skcb.change_state(TCPState::SynReceived);

    Ok(())
}

//    TCP A                                                TCP B
//
//1.  CLOSED                                               LISTEN
//
//2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED
//
//3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED
//
//4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED
//
//5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
//
//        Basic 3-Way Handshake for Connection Synchronization
//
//                              Figure 7.

/// event handler for SYN RECEIVED state
async fn syn_received(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    let hdr = seg.hdr();

    // SND.UNA < SEG.ACK <= SND.NXT
    if seq_lt(skcb.tcb.snd_una, skcb.tcb.seg_ack) && seq_lte(skcb.tcb.seg_ack, skcb.tcb.snd_nxt) {
        skcb.tcb.snd_wnd = skcb.tcb.seg_wnd;
        skcb.tcb.snd_wl1 = skcb.tcb.seg_seq;
        skcb.tcb.snd_wl2 = skcb.tcb.seg_ack;

        // If an MSS Option is not received at connection setup, TCP implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).
        skcb.tcb.snd_opts = seg.options().unwrap_or_else(|| TCPOpts {
            mss: Some(536),
            ..Default::default()
        });

        skcb.change_state(TCPState::Established);

        // our syn got acked, we move the window
        skcb.tcb.snd_una = skcb.tcb.seg_ack;
        return established(skcb, seg).await;
    } else {
        let mut tcp_hdr = TCPHdr {
            sport: skcb.l_addr.port().into(),
            dport: skcb.r_addr.unwrap().port().into(),
            seq: skcb.tcb.seg_ack.into(),
            ack: skcb.tcb.rcv_nxt.into(),
            flags: TCPFlags::default(),
            win_size: WND_SIZE.into(),
            ..Default::default()
        };

        tcp_hdr.set_rst();
        skcb.output(tcp_hdr, TCPOpts::default(), &[]).await?;
    }

    if hdr.is_fin() {
        skcb.tcb.rcv_nxt = skcb.tcb.rcv_nxt.wrapping_add(1);

        skcb.change_state(TCPState::CloseWait);
        skcb.send_ack().await?;
    }
    Ok(())
}

/// event handler for SYN SENT state
async fn syn_sent(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    let seg_hdr = seg.hdr();

    if seg_hdr.is_ack() {
        if seg_hdr.is_rst() {
            return Ok(());
        }

        if seq_lte(skcb.tcb.seg_ack, skcb.tcb.iss) || seq_gt(skcb.tcb.seg_ack, skcb.tcb.snd_nxt) {
            skcb.send_rst().await.unwrap();
        }
        // we dont support data on SYN
        return Ok(());
    }

    if seg_hdr.is_rst() {
        if skcb.check_ack(seg_hdr) {
            skcb.change_state(TCPState::Closed);
        }
        return Ok(());
    }

    if seg_hdr.is_fin() {
        return Err(HandlerError("cant process fin segment".to_string()));
    }

    if seg_hdr.is_syn() {
        skcb.tcb.rcv_nxt = skcb.tcb.seg_seq.wrapping_add(1);
        skcb.tcb.irs = skcb.tcb.seg_seq;

        if seg_hdr.is_ack() {
            skcb.tcb.snd_una = skcb.tcb.seg_ack;
            debug_assert_eq!(skcb.tcb.snd_una, skcb.tcb.snd_nxt);

            if seq_gt(skcb.tcb.snd_una, skcb.tcb.iss) {
                skcb.change_state(TCPState::Established);
                skcb.send_ack().await?;
            }
        } else {
            // simultaneous open path: we got a syn but not ack in response to our syn
            skcb.tcb.snd_wnd = skcb.tcb.seg_wnd;
            skcb.tcb.snd_wl1 = skcb.tcb.seg_seq;
            skcb.tcb.snd_wl2 = skcb.tcb.seg_ack;

            let mut tcp_hdr = TCPHdr {
                sport: skcb.l_addr.port().into(),
                dport: skcb.r_addr.unwrap().port().into(),
                seq: skcb.tcb.iss.into(),
                ack: skcb.tcb.rcv_nxt.into(), // ACKing the irs
                flags: TCPFlags::default(),
                win_size: WND_SIZE.into(),
                ..Default::default()
            };

            tcp_hdr.set_syn();
            tcp_hdr.set_ack();

            skcb.output(tcp_hdr, TCPOpts::default(), &[]).await?;
            skcb.change_state(TCPState::SynReceived);

            // TODO:
            // If there are other controls or text in the segment, queue them for processing after the ESTABLISHED state has been reached, return.
        }
    }

    todo!()
}

/// event handler for FIN WAIT1 state
async fn finwait1(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // we sent a FIN so we only have to take in data
    // TODO: we need a timer here in case the other side doesnt respond
    let (seg_hdr, seg_payload) = seg.into_parts();

    check_ack(skcb).await?;

    let data_accepted = accept_data(skcb, &seg_hdr, seg_payload);
    let sent_fin_accepted = skcb.tcb.snd_una == skcb.tcb.snd_nxt;

    match data_accepted {
        AcceptResult::Fin => {
            skcb.tcb.rcv_nxt = skcb.tcb.rcv_nxt.wrapping_add(1);

            if sent_fin_accepted {
                // we accepted a fin, and our fin was accepted
                skcb.change_state(TCPState::TimeWait)
            } else {
                // we accepted a fin, but our fin wasnt acked
                skcb.change_state(TCPState::Closing)
            }
        }
        // we didnt get a fin, but our fin was accepted
        _ if sent_fin_accepted => skcb.change_state(TCPState::FinWait2),
        _ => {}
    };

    skcb.send_ack().await
}

/// event handler for FIN WAIT2 state
async fn finwait2(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    let (seg_hdr, seg_payload) = seg.into_parts();

    // In addition to the processing for the ESTABLISHED state,
    // if the retransmission queue is empty, the user's CLOSE can be acknowledged ("ok") but do not delete the TCB.

    check_ack(skcb).await?;
    let accepted = accept_data(skcb, &seg_hdr, seg_payload);

    if matches!(accepted, AcceptResult::Fin) {
        skcb.tcb.rcv_nxt = skcb.tcb.rcv_nxt.wrapping_add(1);
        skcb.change_state(TCPState::TimeWait);
    }
    skcb.send_ack().await
}

/// event handler for CLOSING state
///
/// here we sent a fin and received a fin, but didnt have our fin acked yet
async fn closing(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    check_ack(skcb).await?;
    let sent_fin_accepted = skcb.tcb.snd_una == skcb.tcb.snd_nxt;

    if sent_fin_accepted {
        skcb.change_state(TCPState::TimeWait);
    }
    Ok(())
}

/// event handler for CLOSE WAIT state
///
/// this is the state for the other side sent a FIN which we ackd
/// so we can still send data, and want to empty our snd buffer
async fn close_wait(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // TODO: empty send buffer and send FIN packet

    check_ack(skcb).await?;

    if skcb.snd_buf.is_empty() {
        skcb.send_fin().await?;
        skcb.change_state(TCPState::LastAck);
    }
    Ok(())
}

/// event handler for LAST ACK state
///
/// we are watiting for an ack for our fin
async fn last_ack(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // TODO: handle inc ACKs, sender is done sending
    // TODO: account for sent FIN flag

    // waiting for our FIN to be ACKed before closing
    if skcb.check_ack(seg.hdr()) {
        skcb.change_state(TCPState::Closed);
        Ok(())
    } else {
        Err(HandlerError("invalid ACK".to_string()))
    }
}

/// event handler for TIME WAIT state
///
/// this is the lingering stage after the connection terminated
async fn timewait(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    // TODO: deal with retrasnmitted FIN
    Ok(())
}

/// handler for segment event in ESTABLISHED state
async fn established(skcb: &mut SKCB, seg: Packet<TCP>) -> Result<()> {
    let (seg_hdr, seg_payload) = seg.into_parts();

    if !seg_hdr.is_ack() {
        return Err(HandlerError("ACK not set".to_string()));
    }

    check_ack(skcb).await?;

    let accepted = accept_data(skcb, &seg_hdr, seg_payload);

    if matches!(accepted, AcceptResult::Fin) {
        skcb.tcb.rcv_nxt = skcb.tcb.rcv_nxt.wrapping_add(1);

        if skcb.snd_buf.is_empty() {
            skcb.send_fin_ack().await?;
            skcb.change_state(TCPState::LastAck);
            return Ok(());
        } else {
            skcb.change_state(TCPState::CloseWait);
        }
    }

    skcb.send_ack().await?;
    Ok(())
}

/// helper function to check if the segment ACKd outstanding data. True indicates new data was ACKd
async fn check_ack(skcb: &mut SKCB) -> Result<bool> {
    // shorthand variables
    let snd_una = skcb.tcb.snd_una;
    let seg_ack = skcb.tcb.seg_ack;
    let seg_seq = skcb.tcb.seg_seq;
    let snd_nxt = skcb.tcb.snd_nxt;

    let ackd;

    // does the segment ACK in flight data (snd_una)?
    if seq_gt(seg_ack, snd_una) {
        // does the ACK lie inside our sent data (snd_nxt)?
        if seq_lte(seg_ack, snd_nxt) {
            // we got an ACK within our send window, we can move it forward

            // - pop data from sendbuffer/retransmission queue
            let mut acked = seg_ack.wrapping_sub(snd_una) as usize;

            // we have to handle the case where a FIN takes up a sequence number but doesnt mess
            // with our buffer
            if matches!(skcb.status, TCPState::FinWait1 | TCPState::LastAck) {
                acked -= 1;
            }

            skcb.snd_buf.free(acked);

            // - If the received segment acknowledges all outstanding data (snd_una equals snd_max), the
            //   retransmission timer is turned off. Otherwise, if the persist timer is off, the retransmit timer is restarted
            if skcb.snd_buf.is_empty() {
                skcb.clear_rto();
            }

            skcb.tcb.snd_una = seg_ack;

            // TODO::
            // - if the buffer has been fully acknowledged, return OK response to user
            ackd = true;
        } else {
            skcb.send_ack().await?;
            return Err(HandlerError("ACK lies beyond snd next".into()));
        }
    } else {
        ackd = false
    };

    // update send window
    if seq_lt(skcb.tcb.snd_wl1, seg_seq)
        || (skcb.tcb.snd_wl1 == seg_seq && seq_lte(skcb.tcb.snd_wl2, seg_ack))
    {
        skcb.tcb.snd_wnd = skcb.tcb.seg_wnd;
        skcb.tcb.snd_wl1 = seg_seq;
        skcb.tcb.snd_wl2 = seg_ack;
    }

    Ok(ackd)
}

enum AcceptResult {
    Not,
    /// might also be a pure ACK (ACK without any new data)
    Data,
    Fin,
}

/// helper functon for handling receiving data, returns true if the data was accepted
fn accept_data(skcb: &mut SKCB, seg_hdr: &TCPHdr, seg_payload: Option<TCPPayload>) -> AcceptResult {
    // shorthand variables
    let snd_una = skcb.tcb.snd_una;
    let seg_ack = skcb.tcb.seg_ack;
    let seg_seq = skcb.tcb.seg_seq;
    let snd_nxt = skcb.tcb.snd_nxt;

    // TODO:
    // If this test is false, then the received segment is
    // either a retransmission or a segment beyond the one expected
    // right now we just drop the packet

    if skcb.tcb.seg_seq != skcb.tcb.rcv_nxt {
        return AcceptResult::Not;
    }

    // since this routine runs after check_seg() the only possible case left is seg_seq == rcv_next

    // segment is next expected data so we move the window
    if let Some(seg_data) = seg_payload {
        let rcv_nxt = skcb.tcb.rcv_nxt;

        skcb.rcv_buf.insert(seg_data.as_bytes(), rcv_nxt);
        skcb.tcb.rcv_nxt = rcv_nxt.wrapping_add(skcb.tcb.seg_len);
        skcb.tcb.rcv_wnd = skcb.rcv_buf.available_cap();
    };

    if seg_hdr.is_fin() {
        AcceptResult::Fin
    } else {
        AcceptResult::Data
    }
}
