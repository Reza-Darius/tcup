use crate::error::Error;
use crate::eth::EthFrame;

use bincode::{Decode, Encode};
use tokio::sync::mpsc::Sender;

enum SocketCalls {
    Open,
    Connect,
    Listen,
    Close(SocketId),

    Send(Vec<u8>),
    Receive,

    Status(SocketId),
}

enum SocketWorkerMsg {
    Close,
    Error(Error),
    Send,
    Seg,
}

#[derive(Debug, Encode, Decode)]
pub struct SocketId(i32);

#[derive(Debug, Clone)]
pub struct Socket {
    pub tx: Sender<EthFrame>,
    // // connection
    // pub con: TCPCon,
    // // status
    // pub status: SocketStatus,
}

#[derive(Debug, Clone)]
enum SocketStatus {
    Closed,
    Open,
}
