use thiserror::Error;

use crate::ip::IpErr;

#[derive(Error, Debug)]
pub enum EthErr {
    #[error("{0}")]
    ParseError(&'static str),
    #[error("{0}")]
    BuildError(&'static str),
    #[error("{0}")]
    MacError(String),
    #[error("{0}")]
    IpError(#[from] IpErr),
    #[error("unsupported eternet protocol")]
    InvalidProtError,
    #[error("{0}")]
    ConversionError(String),
}
