//! Kraken Crypto - Cryptographic primitives

pub mod aes_gcm;
pub mod hkdf;
pub mod implant;
pub mod mtls;
pub mod server;
pub mod tests;
pub mod types;
pub mod x25519;

pub use aes_gcm::*;
pub use hkdf::*;
pub use implant::ImplantCrypto;
pub use server::ServerCrypto;
pub use types::*;
pub use x25519::*;

use common::KrakenError;

/// Compute SHA256 hash of input data
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use ring::digest::{digest, SHA256};
    let d = digest(&SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Fill buffer with cryptographically secure random bytes
pub fn random_bytes(buf: &mut [u8]) -> Result<(), KrakenError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    rng.fill(buf)
        .map_err(|_| KrakenError::Crypto("random generation failed".into()))
}

/// Crypto provider trait for abstraction
pub trait CryptoProvider: Send + Sync {
    fn generate_x25519_keypair(&self) -> Result<(X25519PublicKey, X25519PrivateKey), KrakenError>;
    fn x25519_diffie_hellman(
        &self,
        our_private: &X25519PrivateKey,
        their_public: &X25519PublicKey,
    ) -> Result<SharedSecret, KrakenError>;
    fn hkdf_derive(
        &self,
        shared_secret: &SharedSecret,
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, KrakenError>;
    fn aes_gcm_encrypt(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, KrakenError>;
    fn aes_gcm_decrypt(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, KrakenError>;
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), KrakenError>;
}

/// Default implementation using ring
pub struct RingCryptoProvider;

impl CryptoProvider for RingCryptoProvider {
    fn generate_x25519_keypair(&self) -> Result<(X25519PublicKey, X25519PrivateKey), KrakenError> {
        x25519::generate_keypair()
    }

    fn x25519_diffie_hellman(
        &self,
        our_private: &X25519PrivateKey,
        their_public: &X25519PublicKey,
    ) -> Result<SharedSecret, KrakenError> {
        x25519::diffie_hellman(our_private, their_public)
    }

    fn hkdf_derive(
        &self,
        shared_secret: &SharedSecret,
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, KrakenError> {
        hkdf::derive(shared_secret.as_bytes(), info, output_len)
    }

    fn aes_gcm_encrypt(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, KrakenError> {
        aes_gcm::encrypt(key, nonce, plaintext, aad)
    }

    fn aes_gcm_decrypt(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, KrakenError> {
        aes_gcm::decrypt(key, nonce, ciphertext, aad)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), KrakenError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        rng.fill(buf)
            .map_err(|_| KrakenError::Crypto("random generation failed".into()))
    }
}
