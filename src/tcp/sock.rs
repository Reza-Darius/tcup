use std::net::Ipv4Addr;

use crate::eth::EthFrame;

use bincode::{Decode, Encode};
use tokio::sync::mpsc::Sender;

#[derive(Debug)]
pub struct SocketCall {
    id: SocketId,
    call: Call,
}

#[derive(Debug, Decode, Encode)]
pub enum Call {
    Open(Ipv4Addr),
    Connect(Ipv4Addr),
    Listen(Ipv4Addr),
    Close(SocketId),

    Send(u32),
    Receive(u32),

    Status(SocketId),
}

#[derive(Debug)]
pub enum SocketWorkerMsg {
    Close,
    Send,
    Frame(EthFrame),
}

#[derive(Debug, Encode, Decode)]
pub struct SocketId(i32);

#[derive(Debug, Clone)]
pub struct Socket {
    pub tx: Sender<SocketWorkerMsg>,
}

trait DataBus {
    async fn send();
    async fn recv();
}
