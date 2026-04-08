use std::net::IpAddr;

use bincode::{Decode, Encode, config};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::select;
use tracing::error;

use crate::error::Result;
use crate::tcp::sock::SocketId;

const IPC_MSG_BUF: usize = 512; // buffer for the ipc message loop

#[derive(Debug, Encode, Decode)]
pub enum TcupCall {
    Open,
    Connect(IpAddr),
    Listen(IpAddr),
    Close(SocketId),
}

pub fn setup_uds_sock(addr: &str) -> Result<UnixListener> {
    UnixListener::bind(addr).map_err(|e| e.into())
}

pub async fn ipc_loop(listener: &UnixListener) -> TcupCall {
    let mut buf = [0u8; IPC_MSG_BUF];
    let config = config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    select! {
        Ok((mut stream, _)) = listener.accept() => {
            if let Err(e) = stream.read(&mut buf).await {
                error!(%e, "error when reading from uds socket");
            };
            let (msg, _): (TcupCall, usize) = bincode::decode_from_slice(&buf[..], config).unwrap();
            msg
        }
    }
}
