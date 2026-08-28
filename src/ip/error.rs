use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpErr {
    #[error("{0}")]
    ParseError(String),
    #[error("unsupported protocol")]
    InvalidProtError,
    #[error("{0}")]
    HeaderError(String),
    #[error("{0}")]
    ConversionError(String),
}
