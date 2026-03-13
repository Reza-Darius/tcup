use std::array::TryFromSliceError;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Unknown(String),
    #[error("{0}")]
    Ip(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Caps(#[from] caps::errors::CapsError),
    #[error("{0}")]
    Errno(#[from] rustix::io::Errno),
    #[error("{0}")]
    Conversion(#[from] TryFromSliceError),
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
