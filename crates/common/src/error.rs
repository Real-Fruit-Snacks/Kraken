//! Error types for Kraken

use thiserror::Error;

#[derive(Error, Debug)]
pub enum KrakenError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("all transports failed")]
    AllTransportsFailed,

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("module not found: {0}")]
    ModuleNotFound(String),

    #[error("invalid module blob")]
    InvalidModuleBlob,

    #[error("unknown task type: {0}")]
    UnknownTaskType(String),

    #[error("module error: {0}")]
    Module(String),

    #[error("no route to destination")]
    NoRoute,

    #[error("database error: {0}")]
    Database(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl KrakenError {
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::Transport(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    pub fn database(msg: impl Into<String>) -> Self {
        Self::Database(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}
