use crate::{error::Error, eth::EthFrame, types::SocketId};

enum SocketCalls {
    Open,
    Connect,
    Listen,
    Close(SocketId),

    Send(Vec<u8>),
    Receive(EthFrame),

    Abort,
    Status(SocketId),
}

enum SocketWorkerMsg {
    Close,
    Error(Error),
    Send(Vec<u8>),
    Seg(EthFrame),
}
