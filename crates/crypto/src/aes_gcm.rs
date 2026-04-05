//! AES-256-GCM authenticated encryption

use crate::types::{Nonce, SymmetricKey};
use common::KrakenError;
use ring::aead::{Aad, LessSafeKey, Nonce as RingNonce, UnboundKey, AES_256_GCM};

/// Encrypt plaintext using AES-256-GCM
pub fn encrypt(
    key: &SymmetricKey,
    nonce: &Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KrakenError> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key.as_bytes())
        .map_err(|_| KrakenError::Crypto("invalid AES key".into()))?;

    let sealing_key = LessSafeKey::new(unbound_key);

    let ring_nonce = RingNonce::assume_unique_for_key(*nonce.as_bytes());

    let mut in_out = plaintext.to_vec();
    // Reserve space for the auth tag (16 bytes for AES-GCM)
    in_out.reserve(16);

    sealing_key
        .seal_in_place_append_tag(ring_nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| KrakenError::Crypto("AES-GCM encryption failed".into()))?;

    Ok(in_out)
}

/// Decrypt ciphertext using AES-256-GCM
pub fn decrypt(
    key: &SymmetricKey,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KrakenError> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key.as_bytes())
        .map_err(|_| KrakenError::Crypto("invalid AES key".into()))?;

    let opening_key = LessSafeKey::new(unbound_key);

    let ring_nonce = RingNonce::assume_unique_for_key(*nonce.as_bytes());

    let mut in_out = ciphertext.to_vec();

    let plaintext = opening_key
        .open_in_place(ring_nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| KrakenError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let rng = SystemRandom::new();

        // Generate random key
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes).unwrap();
        let key = SymmetricKey(key_bytes);

        // Generate random nonce
        let nonce = Nonce::random().unwrap();

        let plaintext = b"Hello, Kraken!";
        let aad = b"additional data";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let rng = SystemRandom::new();

        let mut key1_bytes = [0u8; 32];
        let mut key2_bytes = [0u8; 32];
        rng.fill(&mut key1_bytes).unwrap();
        rng.fill(&mut key2_bytes).unwrap();

        let key1 = SymmetricKey(key1_bytes);
        let key2 = SymmetricKey(key2_bytes);
        let nonce = Nonce::random().unwrap();

        let plaintext = b"secret message";
        let ciphertext = encrypt(&key1, &nonce, plaintext, b"").unwrap();

        let result = decrypt(&key2, &nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let rng = SystemRandom::new();

        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes).unwrap();
        let key = SymmetricKey(key_bytes);
        let nonce = Nonce::random().unwrap();

        let plaintext = b"secret message";
        let ciphertext = encrypt(&key, &nonce, plaintext, b"correct aad").unwrap();

        let result = decrypt(&key, &nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }
}
