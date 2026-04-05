//! Server error types

use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("database error: {0}")]
    Database(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl From<common::KrakenError> for ServerError {
    fn from(e: common::KrakenError) -> Self {
        match e {
            common::KrakenError::Database(msg) => ServerError::Database(msg),
            common::KrakenError::NotFound(msg) => ServerError::NotFound(msg),
            common::KrakenError::Protocol(msg) => ServerError::Protocol(msg),
            common::KrakenError::Crypto(msg) => ServerError::Crypto(msg),
            common::KrakenError::PermissionDenied(msg) => ServerError::PermissionDenied(msg),
            common::KrakenError::InvalidState(msg) => ServerError::InvalidState(msg),
            e => ServerError::Internal(e.to_string()),
        }
    }
}

impl From<ServerError> for Status {
    fn from(e: ServerError) -> Self {
        match e {
            ServerError::NotFound(msg) => Status::not_found(msg),
            ServerError::InvalidRequest(msg) => Status::invalid_argument(msg),
            ServerError::PermissionDenied(msg) => Status::permission_denied(msg),
            ServerError::InvalidState(msg) => Status::failed_precondition(msg),
            ServerError::Database(msg) => Status::internal(format!("database error: {}", msg)),
            ServerError::Crypto(msg) => Status::internal(format!("crypto error: {}", msg)),
            ServerError::Protocol(msg) => Status::internal(format!("protocol error: {}", msg)),
            ServerError::Internal(msg) => Status::internal(msg),
        }
    }
}

pub type ServerResult<T> = Result<T, ServerError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // From<KrakenError> for ServerError
    // ------------------------------------------------------------------

    #[test]
    fn from_kraken_database_error() {
        let e = common::KrakenError::Database("db fail".to_string());
        let se: ServerError = e.into();
        assert!(matches!(se, ServerError::Database(_)));
        assert!(se.to_string().contains("db fail"));
    }

    #[test]
    fn from_kraken_not_found_error() {
        let e = common::KrakenError::NotFound("missing".to_string());
        let se: ServerError = e.into();
        assert!(matches!(se, ServerError::NotFound(_)));
    }

    #[test]
    fn from_kraken_protocol_error() {
        let e = common::KrakenError::Protocol("bad proto".to_string());
        let se: ServerError = e.into();
        assert!(matches!(se, ServerError::Protocol(_)));
    }

    #[test]
    fn from_kraken_crypto_error() {
        let e = common::KrakenError::Crypto("bad key".to_string());
        let se: ServerError = e.into();
        assert!(matches!(se, ServerError::Crypto(_)));
    }

    #[test]
    fn from_kraken_permission_denied_error() {
        let e = common::KrakenError::PermissionDenied("nope".to_string());
        let se: ServerError = e.into();
        assert!(matches!(se, ServerError::PermissionDenied(_)));
    }

    #[test]
    fn from_kraken_invalid_state_error() {
        let e = common::KrakenError::InvalidState("wrong state".to_string());
        let se: ServerError = e.into();
        assert!(matches!(se, ServerError::InvalidState(_)));
    }

    #[test]
    fn from_kraken_other_variants_become_internal() {
        // Transport is not explicitly matched — should become Internal
        let e = common::KrakenError::Transport("timeout".to_string());
        let se: ServerError = e.into();
        assert!(matches!(se, ServerError::Internal(_)));
    }

    // ------------------------------------------------------------------
    // From<ServerError> for tonic::Status
    // ------------------------------------------------------------------

    #[test]
    fn server_error_not_found_maps_to_status_not_found() {
        let se = ServerError::NotFound("thing".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::NotFound);
        assert!(s.message().contains("thing"));
    }

    #[test]
    fn server_error_invalid_request_maps_to_invalid_argument() {
        let se = ServerError::InvalidRequest("bad".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn server_error_permission_denied_maps_to_permission_denied() {
        let se = ServerError::PermissionDenied("denied".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn server_error_invalid_state_maps_to_failed_precondition() {
        let se = ServerError::InvalidState("bad state".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn server_error_database_maps_to_internal_with_prefix() {
        let se = ServerError::Database("conn refused".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::Internal);
        assert!(s.message().contains("database error"));
    }

    #[test]
    fn server_error_crypto_maps_to_internal_with_prefix() {
        let se = ServerError::Crypto("aes fail".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::Internal);
        assert!(s.message().contains("crypto error"));
    }

    #[test]
    fn server_error_protocol_maps_to_internal_with_prefix() {
        let se = ServerError::Protocol("bad frame".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::Internal);
        assert!(s.message().contains("protocol error"));
    }

    #[test]
    fn server_error_internal_maps_to_internal() {
        let se = ServerError::Internal("oops".to_string());
        let s: tonic::Status = se.into();
        assert_eq!(s.code(), tonic::Code::Internal);
        assert!(s.message().contains("oops"));
    }

    // ------------------------------------------------------------------
    // Display / Debug
    // ------------------------------------------------------------------

    #[test]
    fn server_error_display_includes_message() {
        let se = ServerError::NotFound("my-resource".to_string());
        let msg = se.to_string();
        assert!(msg.contains("my-resource"), "display: {}", msg);
    }
}
