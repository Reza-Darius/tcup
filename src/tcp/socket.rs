use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::sync::{mpsc::Sender, oneshot};
use tracing::{error, warn};

use crate::{
    server::services::arp_svc::ARPServiceHandle,
    tcp::{
        TCPError::ChannelError,
        error::TCPError::{self, SocketError},
        handler::active_open,
        opts::TCPOpts,
        skcb::{Open, SKCB, TCPState},
        tcp_packet::{TCPFlags, TCPHdr},
        timer::TCPTimerCBHandle,
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

#[derive(Debug, Clone)]
pub struct SocketUserHandle {
    socket_key: usize,
    sender: Sender<SKCBMessage>,
}

impl SocketUserHandle {
    pub async fn send(&mut self, data: impl Into<Vec<u8>>) -> Result<(), TCPError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(SKCBMessage::Send {
                data: data.into(),
                resp: tx,
            })
            .await
            .map_err(|_| ChannelError)?;
        rx.await.map_err(|_| ChannelError).flatten()
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>, TCPError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(SKCBMessage::Receive { resp: tx })
            .await
            .map_err(|_| ChannelError)?;
        rx.await.map_err(|_| ChannelError).flatten()
    }

    pub fn key(&self) -> usize {
        self.socket_key
    }
}

/// a handle to a socket for the transport service
#[derive(Debug)]
pub struct SocketInternalHandle {
    sender: Sender<SKCBMessage>,
    worker_handle: tokio::task::JoinHandle<()>,
}

impl SocketInternalHandle {
    /// creates a new listening socket
    pub fn listen(
        ip_tx: ARPServiceHandle,
        local_addr: SocketAddrV4,
        chan_size: usize,
        timer_tx: TCPTimerCBHandle,
    ) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(chan_size);
        let mut skcb = SKCB::new(s_rx, ip_tx, local_addr, timer_tx);

        let handle = tokio::spawn(async move {
            skcb.status = TCPState::Listen;
            skcb.open = Open::Passive;
            skcb.run().await.unwrap();
        });

        SocketInternalHandle {
            sender: s_tx,
            worker_handle: handle,
        }
    }

    pub fn user_handle(&self, socket_key: usize) -> SocketUserHandle {
        SocketUserHandle {
            socket_key,
            sender: self.sender.clone(),
        }
    }

    /// creates a new connection socket
    pub fn connect(
        ip_tx: ARPServiceHandle,
        local_address: SocketAddrV4,
        remote_address: SocketAddrV4,
        chan_size: usize,
        timer_tx: TCPTimerCBHandle,
    ) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(chan_size);
        let mut skcb = SKCB::new(s_rx, ip_tx, local_address, timer_tx);

        let handle = tokio::spawn(async move {
            active_open(&mut skcb, remote_address).await.unwrap();
            skcb.run().await.unwrap();
        });

        SocketInternalHandle {
            sender: s_tx,
            worker_handle: handle,
        }
    }

    pub async fn call(&self, message: SKCBMessage) -> Result<(), TCPError> {
        self.sender
            .send(message)
            .await
            .map_err(|e| SocketError(format!("error when calling socket: {e}")))
    }

    /// if this returns true the socket should be deallocated
    pub fn is_closed(&self) -> bool {
        self.worker_handle.is_finished()
    }

    pub async fn close(self) {
        if self.sender.send(SKCBMessage::Close).await.is_err() {
            warn!("couldnt send close message, aborting socket handle");
            self.worker_handle.abort();
        };
    }

    pub async fn status(&self) -> TCPState {
        if self.is_closed() {
            return TCPState::Closed;
        }

        let (tx, rx) = oneshot::channel();

        let Ok(_) = self.sender.send(SKCBMessage::Status(tx)).await else {
            return TCPState::Closed;
        };

        rx.await.unwrap_or(TCPState::Closed)
    }

    pub async fn send_seg(&self, segment: Packet<TCP>) -> TCPState {
        let Ok(_) = self.call(SKCBMessage::Segment(segment)).await else {
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

/// calls for the service worker, like allocating new sockets
///
/// data transfer between user and socket is handled by SKCBMessages below
#[derive(Debug)]
pub enum SocketServiceCall {
    Connect {
        local_addr: Ipv4Addr,
        remote_addr: SocketAddrV4,
        resp: oneshot::Sender<Result<SocketUserHandle, TCPError>>,
    },

    Listen {
        listen_addr: SocketAddrV4,
        resp: oneshot::Sender<Result<SocketUserHandle, TCPError>>,
    },

    Close {
        socket_key: usize,
    },
    Segment(Packet<TCP>),
}

impl std::fmt::Display for SocketServiceCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect { remote_addr, .. } => {
                write!(f, "Connect({remote_addr})")
            }
            Self::Listen { listen_addr, .. } => {
                write!(f, "Listen({listen_addr})")
            }
            Self::Close { socket_key } => {
                write!(f, "Close(socket={socket_key})")
            }
            Self::Segment(packet) => {
                write!(f, "Segment({packet})",)
            }
        }
    }
}
impl From<Packet<TCP>> for SocketServiceCall {
    fn from(value: Packet<TCP>) -> Self {
        SocketServiceCall::Segment(value)
    }
}

/// messages for a TCP connection worker
#[derive(Debug)]
pub enum SKCBMessage {
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

impl std::fmt::Display for SKCBMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Close => write!(f, "Close"),
            Self::Send { data, .. } => {
                write!(f, "Send({} bytes)", data.len())
            }
            Self::Receive { .. } => write!(f, "Receive"),
            Self::Status(_) => write!(f, "Status"),
            Self::Segment(packet) => write!(f, "Segment({packet})"),
        }
    }
}
