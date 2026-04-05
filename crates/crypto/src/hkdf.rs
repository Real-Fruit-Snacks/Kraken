//! HKDF-SHA256 key derivation

use common::KrakenError;
use ring::hkdf::{self, Salt, HKDF_SHA256};

/// Derive key material using HKDF-SHA256
pub fn derive(
    input_key_material: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, KrakenError> {
    // Use empty salt (will use zero-filled salt internally)
    let salt = Salt::new(HKDF_SHA256, &[]);

    let prk = salt.extract(input_key_material);

    let mut output = vec![0u8; output_len];

    prk.expand(&[info], HkdfLen(output_len))
        .map_err(|_| KrakenError::Crypto("HKDF expansion failed".into()))?
        .fill(&mut output)
        .map_err(|_| KrakenError::Crypto("HKDF fill failed".into()))?;

    Ok(output)
}

/// Custom type for HKDF output length
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive a session key from shared secret
pub fn derive_session_key(shared_secret: &[u8], context: &str) -> Result<[u8; 32], KrakenError> {
    let info = format!("kraken-{}", context);
    let output = derive(shared_secret, info.as_bytes(), 32)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&output);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive() {
        let ikm = b"input key material";
        let info = b"application info";

        let output = derive(ikm, info, 32).unwrap();
        assert_eq!(output.len(), 32);

        // Same inputs should produce same output
        let output2 = derive(ikm, info, 32).unwrap();
        assert_eq!(output, output2);

        // Different info should produce different output
        let output3 = derive(ikm, b"different info", 32).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    fn test_derive_session_key() {
        let shared_secret = [0x42u8; 32];

        let key = derive_session_key(&shared_secret, "session").unwrap();
        assert_eq!(key.len(), 32);
    }
}
