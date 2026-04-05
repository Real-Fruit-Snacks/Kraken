//! Payload encryption primitives.
//!
//! Provides XOR-based encryption for embedding payloads inside shellcode stubs
//! and DLL templates. The XOR key is either caller-supplied or randomly
//! generated.
//!
//! ## Detection (Blue Team)
//! - XOR-encrypted blobs show high entropy but uniform byte distribution
//! - Rolling XOR leaves statistical artefacts detectable by entropy analysis
//! - Adjacent key material is a strong indicator

use crate::BuilderError;
use rand::Rng;

/// XOR-encrypt `data` with a rolling multi-byte `key`.
///
/// The operation is symmetric: encrypting twice with the same key yields the
/// original plaintext.
pub fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Convenience alias — XOR decryption is the same operation.
pub fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    xor_encrypt(data, key)
}

/// Generate a cryptographically random key of `len` bytes.
pub fn generate_random_key(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

/// Encrypt `data` using the configured encryption type.
pub fn encrypt_payload(
    data: &[u8],
    encryption: crate::EncryptionType,
    key: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), BuilderError> {
    match encryption {
        crate::EncryptionType::Xor => {
            let key = match key {
                Some(k) => k.to_vec(),
                None => generate_random_key(16),
            };
            let encrypted = xor_encrypt(data, &key);
            Ok((encrypted, key))
        }
        crate::EncryptionType::None => Ok((data.to_vec(), vec![])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_roundtrip_single_byte() {
        let data = b"Hello, World!";
        let key = vec![0x42];
        let encrypted = xor_encrypt(data, &key);
        assert_ne!(&encrypted, data);
        let decrypted = xor_decrypt(&encrypted, &key);
        assert_eq!(&decrypted, data);
    }

    #[test]
    fn test_xor_roundtrip_multi_byte() {
        let data = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let key = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let encrypted = xor_encrypt(&data, &key);
        let decrypted = xor_decrypt(&encrypted, &key);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_xor_empty_key_passthrough() {
        let data = b"no change";
        let encrypted = xor_encrypt(data, &[]);
        assert_eq!(&encrypted, data);
    }

    #[test]
    fn test_generate_random_key_length() {
        let key = generate_random_key(32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_generate_random_key_not_all_zeros() {
        let key = generate_random_key(32);
        // Probability of all zeros is 2^-256 — effectively impossible.
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encrypt_payload_xor() {
        let data = b"test payload data";
        let (encrypted, key) = encrypt_payload(data, crate::EncryptionType::Xor, None).unwrap();
        assert_ne!(&encrypted, &data[..]);
        assert!(!key.is_empty());
        let decrypted = xor_decrypt(&encrypted, &key);
        assert_eq!(&decrypted, &data[..]);
    }

    #[test]
    fn test_encrypt_payload_none() {
        let data = b"plaintext";
        let (result, key) = encrypt_payload(data, crate::EncryptionType::None, None).unwrap();
        assert_eq!(&result, &data[..]);
        assert!(key.is_empty());
    }
}
