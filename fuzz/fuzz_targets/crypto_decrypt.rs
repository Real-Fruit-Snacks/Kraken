#![no_main]
//! Fuzz target for crypto decryption
//!
//! Tests that arbitrary ciphertext/key/nonce combinations never cause panics.

use libfuzzer_sys::fuzz_target;
use crypto::types::{Nonce, SymmetricKey};

fuzz_target!(|data: &[u8]| {
    // Need at least key (32) + nonce (12) + tag (16) + some ciphertext
    if data.len() < 60 {
        return;
    }

    // Try to construct valid types from fuzzed data
    if let (Ok(key), Ok(nonce)) = (
        SymmetricKey::from_bytes(&data[0..32]),
        Nonce::from_bytes(&data[32..44]),
    ) {
        let ciphertext = &data[44..];
        let aad = &[];  // Empty AAD for fuzzing

        // Attempt decryption - should never panic, only return Result
        let _ = crypto::aes_gcm::decrypt(&key, &nonce, ciphertext, aad);
    }
});
