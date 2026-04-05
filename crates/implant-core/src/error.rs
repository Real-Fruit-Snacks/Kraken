//! Implant error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ImplantError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("task error: {0}")]
    Task(String),

    #[error("exit requested")]
    ExitRequested,
}

impl From<common::KrakenError> for ImplantError {
    fn from(e: common::KrakenError) -> Self {
        match e {
            common::KrakenError::Crypto(msg) => ImplantError::Crypto(msg),
            common::KrakenError::Protocol(msg) => ImplantError::Protocol(msg),
            e => ImplantError::Transport(e.to_string()),
        }
    }
}

pub type ImplantResult<T> = Result<T, ImplantError>;
