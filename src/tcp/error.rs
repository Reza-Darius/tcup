use thiserror::Error;

#[derive(Error, Debug)]
pub enum TCPError {
    #[error("failed to parse TCP packet")]
    ParseError,
    #[error("{0}")]
    OptionError(String)
}
