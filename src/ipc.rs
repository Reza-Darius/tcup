use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use bincode::config;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::select;
use tokio::sync::mpsc::Sender;
use tracing::error;

use crate::error::{Error, Result};
use crate::eth::ETH_FRAME_MAX_SIZE;
use crate::ip::IP_HDR_MINSIZE;
use crate::tcp::TCP_HDR_MAXSIZE;
use crate::tcp::sock::{Call, SocketCall, SocketId};

// the length of a message is capped by the maximum
const IPC_MSG_PAY_MAX: usize = ETH_FRAME_MAX_SIZE - IP_HDR_MINSIZE - TCP_HDR_MAXSIZE;

// this might be a problem depending on the fields of the Call
const IPC_HDR_LEN: usize = std::mem::size_of::<Call>();

#[derive(Debug)]
pub enum TCupResp {
    Ok,
    Error,
    Data(Vec<u8>),
}

pub fn setup_uds_sock(addr: impl AsRef<Path>) -> Result<UnixListener> {
    UnixListener::bind(addr.as_ref()).map_err(|e| e.into())
}

pub async fn ipc_loop(listener: &UnixListener) {
    select! {
        Ok((stream, _)) = listener.accept() => {
            tokio::spawn(handle_client(stream));
        }
    }
}

struct UdsClient {
    stream: UnixStream,
}

async fn handle_client(stream: UnixStream) {
    let mut reader = BufReader::new(stream);
    loop {
        match read_message(&mut reader).await {
            Ok(msg) => match msg {
                Call::Open(ipv4_addr) => todo!(),
                Call::Connect(ipv4_addr) => todo!(),
                Call::Listen(ipv4_addr) => todo!(),
                Call::Close(socket_id) => todo!(),
                Call::Send(len) => todo!(),
                Call::Receive(len) => todo!(),
                Call::Status(socket_id) => todo!(),
            },
            Err(e) => error!(%e, "message error"),
        };
    }
}

async fn read_message<R>(reader: &mut R) -> Result<Call>
where
    R: AsyncRead + Unpin,
{
    let msg_len = reader.read_u16().await?;

    let mut msg_buf = [0u8; IPC_HDR_LEN];

    reader.read_exact(&mut msg_buf[..msg_len as usize]).await?;

    let config = config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    bincode::decode_from_slice(&msg_buf, config)
        .map(|r| r.0)
        .map_err(Into::into)
}

#[derive(Debug, Clone)]
struct UdsCtrlBusHandler {
    inner: Arc<UdsControlBusInner>,
}

#[derive(Debug)]
struct UdsControlBusInner {
    ctrl_map: Mutex<HashMap<SocketId, Sender<TCupResp>>>,
}

struct DebugCtrlBus;

/// interface for acting with applications
trait ControlBus {
    async fn send(&self, id: SocketId, resp: TCupResp);
    async fn recv(&self) -> SocketCall;
}
