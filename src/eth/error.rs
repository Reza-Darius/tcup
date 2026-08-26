use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthErr {
    #[error("{0}")]
    ParseError(&'static str),
    #[error("unsupported protocol")]
    InvalidProtError,
}
