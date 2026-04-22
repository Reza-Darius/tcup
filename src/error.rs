use std::array::TryFromSliceError;

use bincode::error::DecodeError;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

use crate::{tcp::sock::SocketWorkerMsg, types::TCPCon};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Unknown(String),
    #[error("{0}")]
    Ip(String),
    #[error("{0}")]
    Tcp(String),
    #[error("{0}")]
    Eth(String),
    #[error("{0}")]
    Ipc(String),
    #[error("{0}")]
    Arp(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Caps(#[from] caps::errors::CapsError),
    #[error("{0}")]
    Errno(#[from] rustix::io::Errno),
    #[error("{0}")]
    Conversion(#[from] TryFromSliceError),
    #[error("{0}")]
    Net(#[from] std::net::AddrParseError),
    #[error("{0}")]
    TxSend(#[from] SendError<SocketWorkerMsg>),
    #[error("{0}")]
    Socket(#[from] SocketError),
    #[error("{0}")]
    Decode(#[from] DecodeError),
}

#[derive(Error, Debug)]
pub enum SocketError {
    #[error("Error")]
    Error,
    #[error("{0:?}")]
    SocketInUse(TCPCon),
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Error::Unknown(value.to_string())
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::Unknown(value)
    }
}
