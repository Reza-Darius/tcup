use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::sync::{mpsc::Sender, oneshot};
use tracing::error;

use crate::{
    server::services::arp_svc::ARPServiceHandle,
    tcp::{
        error::TCPError::{self, SocketError},
        handler::active_open,
        opts::TCPOpts,
        skcb::{Open, SKCB, TCPState},
        tcp_packet::{TCPFlags, TCPHdr},
    },
    utils::packet::{IP, Packet, TCP},
};

/// call this for getting a packet addressed to a non existing socket
pub async fn no_socket_found(seg: Packet<TCP>) -> Option<Packet<IP>> {
    // when a packet arrives for a non existing socket
    // all data in the incoming segment is discarded. An incoming segment containing a RST is discarded. An incoming segment not containing a RST causes a RST to be sent in response. The acknowledgment and sequence field values are selected to make the reset sequence acceptable to the TCP endpoint that sent the offending segment.
    //
    // If the ACK bit is off, sequence number zero is used,
    // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
    //
    // If the ACK bit is on,
    // <SEQ=SEG.ACK><CTL=RST>

    let ip_hdr = seg.ip_hdr();
    let hdr = seg.hdr();

    if hdr.is_rst() {
        return None;
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

    Some(Packet::<TCP>::new(
        ip_hdr.dip(),
        ip_hdr.sip(),
        resp_hdr,
        TCPOpts::default(),
        None,
    ))
}

pub struct SocketUserHandler {
    sender: Sender<SocketMessage>,
}

/// a handle to a socket
pub struct Socket {
    sender: Sender<SocketMessage>,
    worker_handle: tokio::task::JoinHandle<()>,
}

impl Socket {
    /// creates a new listening socket
    pub fn listen(tx: ARPServiceHandle, addr: SocketAddrV4, chan_size: usize) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(chan_size);
        let mut skcb = SKCB::new(s_rx, tx, addr);

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
    pub fn connect(
        tx: ARPServiceHandle,
        s_addr: SocketAddrV4,
        r_addr: SocketAddrV4,
        chan_size: usize,
    ) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(chan_size);
        let mut skcb = SKCB::new(s_rx, tx, s_addr);

        let handle = tokio::spawn(async move {
            active_open(&mut skcb, r_addr).await.unwrap();
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
            .inspect_err(|e| error!(%e, "error when calling socket"))
            .map_err(|e| SocketError(format!("error when calling socket: {e}")))
    }

    /// if this returns true the socket should be deallocated
    pub fn is_closed(&self) -> bool {
        self.worker_handle.is_finished()
    }

    pub async fn close(self) {
        if self.sender.send(SocketMessage::Close).await.is_err() {
            self.worker_handle.abort();
        };
    }

    pub async fn status(&self) -> TCPState {
        if self.is_closed() {
            return TCPState::Closed;
        }

        let (tx, rx) = oneshot::channel();

        let Ok(_) = self.sender.send(SocketMessage::Status(tx)).await else {
            return TCPState::Closed;
        };

        rx.await.unwrap_or(TCPState::Closed)
    }

    pub async fn send_seg(&self, segment: Packet<TCP>) -> TCPState {
        let Ok(_) = self.call(SocketMessage::Segment(segment)).await else {
            return TCPState::Closed;
        };
        self.status().await
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

impl TCPCon {
    pub fn local(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.local_ip, self.local_port)
    }

    pub fn remote(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.remote_ip, self.remote_port)
    }
}

/// user facing interface
#[derive(Debug)]
pub enum TCPCall {
    Connect((SocketAddrV4, oneshot::Sender<TCPCon>)),
    Listen(SocketAddrV4),
    Close,
    Send {
        con: TCPCon,
        data: Vec<u8>,
        resp: oneshot::Sender<Result<(), TCPError>>,
    },
    Receive {
        con: TCPCon,
        resp: oneshot::Sender<Result<Vec<u8>, TCPError>>,
    },
    Segment(Packet<TCP>),
}

impl From<Packet<TCP>> for TCPCall {
    fn from(value: Packet<TCP>) -> Self {
        TCPCall::Segment(value)
    }
}

/// messages for a TCP connection worker
#[derive(Debug)]
pub enum SocketMessage {
    /// user calls
    Close,
    Send {
        data: Vec<u8>,
        resp: oneshot::Sender<Result<(), TCPError>>,
    },
    Receive {
        resp: oneshot::Sender<Result<Vec<u8>, TCPError>>,
    },
    Status(oneshot::Sender<TCPState>),

    /// incoming packet
    Segment(Packet<TCP>),
}
