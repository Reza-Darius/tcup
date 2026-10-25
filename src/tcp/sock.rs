use std::net::Ipv4Addr;
use tokio::sync::{mpsc::Sender, oneshot};

use crate::{
    tcp::{
        error::TCPError::{self, SocketError}, handler::active_open, opts::TCPOpts, skcb::{Open, SKCB, TCPState}, tcp_packet::{TCPFlags, TCPHdr},
    }, utils::packet::{IP, Packet, TCP},
};

// TODO: when a packet arrives for a non existing socket
// all data in the incoming segment is discarded. An incoming segment containing a RST is discarded. An incoming segment not containing a RST causes a RST to be sent in response. The acknowledgment and sequence field values are selected to make the reset sequence acceptable to the TCP endpoint that sent the offending segment.
//
// If the ACK bit is off, sequence number zero is used,
// <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
//
// If the ACK bit is on,
// <SEQ=SEG.ACK><CTL=RST>

/// use this for getting a packet addressed to a non existing socket
pub async fn no_sock_found(seg: Packet<TCP>, sender: &Sender<Packet<IP>>) {
    let ip_hdr = seg.ip_hdr();
    let hdr = seg.hdr();

    if hdr.is_rst() {
        return;
    }

    let (seq, ack, flags) = if hdr.is_ack() {
        (hdr.ack.get(), 0, TCPFlags::RST)
    } else {
        (
            0,
            hdr.seq.get() + seg.payload().len() as u32,
            TCPFlags::RSTACK,
        )
    };

    let mut resp_hdr = TCPHdr::new(hdr.dport.get(), hdr.sport.get(), seq, hdr.seq.get(), flags);
    resp_hdr.ack = ack.into();

    sender
        .send(Packet::<TCP>::new(
            ip_hdr.dip(),
            ip_hdr.sip(),
            resp_hdr,
            TCPOpts::default(),
            &[],
        ))
        .await
        .unwrap();
}

pub struct Socket {
    sender: Sender<SocketMessage>,
    worker_handle: tokio::task::JoinHandle<()>,
}

impl Socket {
    /// creates a new listening socket
    pub fn listen(tx: Sender<Packet<IP>>, con: TCPCon, chan_size: usize) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(chan_size);
        let mut skcb = SKCB::new(s_rx, tx, con);

        let handle = tokio::spawn(async move {
            skcb.status = TCPState::Listen;
            skcb.open = Open::Passive;

            skcb.run().await.unwrap();
        });

        Socket {
            sender: s_tx,
            worker_handle: handle,
        }
    }

    /// creates a new connection socket
    pub fn connect(tx: Sender<Packet<IP>>, con: TCPCon, chan_size: usize) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(chan_size);
        let mut skcb = SKCB::new(s_rx, tx, con);

        let handle = tokio::spawn(async move {
            active_open(&mut skcb).await.unwrap();
            skcb.run().await.unwrap();
        });

        Socket {
            sender: s_tx,
            worker_handle: handle,
        }
    }

    pub async fn call(&self, message: SocketMessage) -> Result<(), TCPError> {
        self.sender
            .send(message)
            .await
            .map_err(|e| SocketError(format!("error when calling socket: {e}")))
    }
}

/// a TCP connection identifier
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TCPCon {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}

/// user facing interface
#[derive(Debug)]
pub enum TCPCall {
    Connect(((Ipv4Addr, u16), oneshot::Sender<TCPCon>)),
    Listen(((Ipv4Addr, u16), oneshot::Sender<TCPCon>)),
    Close,

    Send((TCPCon, Vec<u8>)),
    Receive((TCPCon, oneshot::Sender<Vec<u8>>)),
    Segment(Packet<TCP>),
}

/// messages for a TCP connection worker
#[derive(Debug)]
pub enum SocketMessage {
    /// user calls
    Close,
    Send(Vec<u8>),
    Receive(oneshot::Sender<Vec<u8>>),

    /// incoming packet
    Segment(Packet<TCP>),
}
