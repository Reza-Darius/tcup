use std::net::Ipv4Addr;
use futures::channel::mpsc::Sender;
use tokio::sync::oneshot;

use crate::utils::packet::{Packet, TCP};

pub fn alloc_socket() -> Sender<TCBMessage> {
    todo!()
}

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
    Connect((Ipv4Addr, u16)),
    Listen((Ipv4Addr, u16)),
    Close,

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

    /// incoming segment
    Send(Vec<u8>),
    Receive(oneshot::Sender<Vec<u8>>),
    Segment(Packet<TCP>),

    Status,
}
