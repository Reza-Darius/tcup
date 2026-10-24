use std::net::Ipv4Addr;
use tokio::sync::oneshot;

use crate::utils::packet::{Packet, TCP};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TCPCon {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}

/// user facing interface
#[derive(Debug)]
pub enum SocketCall {
    Open((Ipv4Addr, u16)),
    Connect((Ipv4Addr, u16)),
    Listen((Ipv4Addr, u16)),
    Close((Ipv4Addr, u16)),

    Send(Vec<u8>),
    Receive(oneshot::Sender<Vec<u8>>),
    Segment(Packet<TCP>),

    Status,
}

/// messages for a TCP connection worker
#[derive(Debug)]
pub enum TCBMessage {
    /// user calls
    Close,
    Segment(Packet<TCP>),
    Receive(oneshot::Sender<Vec<u8>>),
    Status,
    /// incoming segment
    Send(Vec<u8>),
}
