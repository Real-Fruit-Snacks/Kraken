//! Peer link types and statistics

use common::ImplantId;
use crypto::SymmetricKey;

/// A live link to a peer implant
#[derive(Debug, Clone)]
pub struct PeerLink {
    /// Remote implant's identifier
    pub peer_id: ImplantId,

    /// Underlying transport used for this link
    pub transport: MeshTransport,

    /// Current state of the link
    pub state: PeerLinkState,

    /// Symmetric key shared with the peer (derived from X25519 handshake)
    pub session_key: SymmetricKey,

    /// Monotonically increasing counter used to generate AES-GCM nonces
    pub nonce_counter: u64,

    /// Per-link traffic statistics
    pub stats: LinkStats,

    /// Unix timestamp (milliseconds) of the last activity on this link
    pub last_activity: i64,
}

/// Lifecycle state of a peer link
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLinkState {
    /// TCP/SMB connection being established
    Connecting,

    /// Transport connected; key exchange in progress
    Handshaking,

    /// Fully operational
    Active,

    /// Link experiencing errors but still functional
    Degraded,

    /// Link is unusable and should be removed
    Failed,
}

/// Transport protocol used for a peer link
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTransport {
    /// Windows named pipe (SMB)
    Smb,

    /// Raw TCP socket
    Tcp,
}

/// Traffic counters for a single peer link
#[derive(Debug, Clone, Default)]
pub struct LinkStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors: u64,
    /// Exponential moving average of round-trip latency in milliseconds
    pub latency_ms_avg: u32,
}
