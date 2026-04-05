//! Stager error types

use core::fmt;

/// Stager error types
#[derive(Debug)]
pub enum StagerError {
    /// Network error during fetch
    Network(NetworkError),
    /// Cryptographic error
    Crypto(CryptoError),
    /// Execution error
    Execution(ExecutionError),
    /// Configuration error
    Config(&'static str),
}

/// Network-related errors
#[derive(Debug)]
pub enum NetworkError {
    /// Connection failed
    ConnectionFailed,
    /// All C2 servers unreachable
    AllServersFailed,
    /// Invalid response from server
    InvalidResponse,
    /// Timeout during fetch
    Timeout,
    /// HTTP error status
    HttpError(u16),
}

/// Cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    /// Key exchange failed
    KeyExchangeFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Invalid signature
    InvalidSignature,
    /// Invalid key material
    InvalidKey,
}

/// Execution errors
#[derive(Debug)]
pub enum ExecutionError {
    /// Memory allocation failed
    AllocationFailed,
    /// Invalid PE/ELF format
    InvalidFormat,
    /// Import resolution failed
    ImportResolutionFailed,
    /// Execution transfer failed
    ExecutionFailed,
    /// Platform not supported
    UnsupportedPlatform,
}

impl fmt::Display for StagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StagerError::Network(e) => write!(f, "network: {:?}", e),
            StagerError::Crypto(e) => write!(f, "crypto: {:?}", e),
            StagerError::Execution(e) => write!(f, "execution: {:?}", e),
            StagerError::Config(msg) => write!(f, "config: {}", msg),
        }
    }
}

impl From<NetworkError> for StagerError {
    fn from(e: NetworkError) -> Self {
        StagerError::Network(e)
    }
}

impl From<CryptoError> for StagerError {
    fn from(e: CryptoError) -> Self {
        StagerError::Crypto(e)
    }
}

impl From<ExecutionError> for StagerError {
    fn from(e: ExecutionError) -> Self {
        StagerError::Execution(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StagerError {}
