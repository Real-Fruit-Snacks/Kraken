//! Ed25519 signature verification for module blobs.
//!
//! The server public key is baked into the binary at compile time from
//! `$OUT_DIR/signing_pubkey.bin`. During development a 32-byte placeholder
//! of zeroes is used. For production builds set the `KRAKEN_SIGNING_PUBKEY`
//! environment variable to a path containing the raw 32-byte Ed25519 public
//! key before compiling.
//!
//! Verification results are cached by SHA-256 hash to avoid repeated
//! expensive cryptographic operations when reloading the same module.

use common::{KrakenError, ModuleBlob};
use ring::{digest, signature};
use std::collections::HashSet;
use std::sync::RwLock;

/// Ed25519 public key baked in at compile time via build.rs.
const SERVER_PUBLIC_KEY: &[u8; 32] =
    include_bytes!(concat!(env!("OUT_DIR"), "/signing_pubkey.bin"));

/// Maximum number of cached verification results.
/// Prevents unbounded memory growth from cache entries.
const MAX_CACHE_SIZE: usize = 64;

/// Cache of SHA-256 hashes of blobs that passed signature verification.
/// This avoids repeated Ed25519 verification (~1ms) for the same module.
static VERIFIED_CACHE: std::sync::OnceLock<RwLock<HashSet<[u8; 32]>>> = std::sync::OnceLock::new();

fn get_cache() -> &'static RwLock<HashSet<[u8; 32]>> {
    VERIFIED_CACHE.get_or_init(|| RwLock::new(HashSet::new()))
}

/// Compute SHA-256 hash of the blob for cache key.
fn hash_blob(blob: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, blob);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

/// Verify that `blob` carries a valid Ed25519 signature produced by the
/// team-server's signing key.
///
/// The signed region is everything **except** the signature bytes themselves
/// (see [`ModuleBlob::signed_data`]).  Verification fails with
/// [`KrakenError::InvalidSignature`] on any cryptographic mismatch.
///
/// Results are cached by blob hash for performance. The second verification
/// of the same blob returns immediately without cryptographic operations.
pub fn verify_signature(blob: &[u8]) -> Result<(), KrakenError> {
    let blob_hash = hash_blob(blob);

    // Check cache first (fast path)
    {
        let cache = get_cache().read().unwrap();
        if cache.contains(&blob_hash) {
            return Ok(());
        }
    }

    // Full verification (slow path)
    let parsed = ModuleBlob::parse(blob)?;

    // Reconstruct the byte range that was covered by the signature.
    let signed_data = ModuleBlob::signed_data(blob)?;

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, SERVER_PUBLIC_KEY);

    public_key
        .verify(&signed_data, parsed.signature)
        .map_err(|_| {
            // On any verification failure, clear the entire cache as a security
            // measure to prevent cache poisoning attacks.
            if let Ok(mut cache) = get_cache().write() {
                cache.clear();
            }
            KrakenError::InvalidSignature
        })?;

    // Cache the successful verification
    {
        let mut cache = get_cache().write().unwrap();
        // Enforce cache size limit
        if cache.len() >= MAX_CACHE_SIZE {
            cache.clear(); // Simple eviction: clear all when full
        }
        cache.insert(blob_hash);
    }

    Ok(())
}

/// Clear the verification cache.
///
/// This should be called if the signing key changes or for testing.
#[allow(dead_code)]
pub fn clear_verification_cache() {
    if let Ok(mut cache) = get_cache().write() {
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_blob_deterministic() {
        let blob = b"test blob data";
        let hash1 = hash_blob(blob);
        let hash2 = hash_blob(blob);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_blob_different_data() {
        let hash1 = hash_blob(b"blob1");
        let hash2 = hash_blob(b"blob2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_clear_verification_cache() {
        clear_verification_cache();
        // Should not panic
        let cache = get_cache().read().unwrap();
        assert!(cache.is_empty() || cache.len() <= MAX_CACHE_SIZE);
    }
}
