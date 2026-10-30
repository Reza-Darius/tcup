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
    IpError(String),
    #[error("unsupported eternet protocol")]
    UnsupportedProtocol,
    #[error("{0}")]
    ConversionError(String),
}

impl From<IpErr> for EthErr {
    fn from(value: IpErr) -> Self {
        match value {
            IpErr::UnsupportedProtocol => EthErr::UnsupportedProtocol,
            _ => EthErr::IpError(value.to_string()),
        }
    }
}
