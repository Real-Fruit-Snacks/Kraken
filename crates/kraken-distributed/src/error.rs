use thiserror::Error;

#[derive(Debug, Error)]
pub enum DistributedError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Node unhealthy: {0}")]
    NodeUnhealthy(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Consensus error: {0}")]
    ConsensusError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}
