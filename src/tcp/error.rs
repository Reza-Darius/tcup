use thiserror::Error;

#[derive(Error, Debug)]
pub enum TCPError {
    #[error("failed to parse TCP packet")]
    ParseError,
    #[error("{0}")]
    OptionError(String),
    #[error("{0}")]
    SocketError(String),
    #[error("{0}")]
    HandlerError(String),
    #[error("{0}")]
    SKCBError(String),
}
