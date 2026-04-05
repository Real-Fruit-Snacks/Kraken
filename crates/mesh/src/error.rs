//! Mesh error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MeshError {
    #[error("no route to destination")]
    NoRoute,

    #[error("TTL expired")]
    TtlExpired,

    #[error("unknown peer: {0}")]
    UnknownPeer(String),

    #[error("peer already connected")]
    AlreadyConnected,

    #[error("cannot relay: not a relay node")]
    NotRelay,

    #[error("routing error: {0}")]
    Routing(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("invalid message: {0}")]
    InvalidMessage(String),
}
