use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpErr {
    #[error("{0}")]
    ParseError(String),
    #[error("unsupported protocol")]
    InvalidProtError,
}
