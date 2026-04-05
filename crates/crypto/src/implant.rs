//! Implant-side cryptographic operations

use crate::{
    aes_gcm, hkdf,
    types::{Nonce, SharedSecret, SymmetricKey, X25519PrivateKey, X25519PublicKey},
    x25519,
};
use common::{ImplantId, KrakenError};
use std::sync::atomic::{AtomicU64, Ordering};

/// Implant crypto context
pub struct ImplantCrypto {
    /// Baked server public key
    server_public_key: X25519PublicKey,
    /// Session key (established after registration)
    session_key: Option<SymmetricKey>,
    /// Nonce counter for encryption
    nonce_counter: AtomicU64,
}

impl ImplantCrypto {
    /// Create new implant crypto with baked server public key
    pub fn new(server_public_key: X25519PublicKey) -> Self {
        Self {
            server_public_key,
            session_key: None,
            nonce_counter: AtomicU64::new(0),
        }
    }

    /// Create implant crypto with restored nonce counter (for reconnection)
    pub fn with_nonce_counter(server_public_key: X25519PublicKey, initial_counter: u64) -> Self {
        Self {
            server_public_key,
            session_key: None,
            nonce_counter: AtomicU64::new(initial_counter),
        }
    }

    /// Get current nonce counter value (for persistence)
    pub fn nonce_counter(&self) -> u64 {
        self.nonce_counter.load(Ordering::SeqCst)
    }

    /// Generate ephemeral keypair for registration
    pub fn generate_keypair(&self) -> Result<(X25519PublicKey, X25519PrivateKey), KrakenError> {
        x25519::generate_keypair()
    }

    /// Get the baked server public key
    pub fn server_public_key(&self) -> &X25519PublicKey {
        &self.server_public_key
    }

    /// Perform key exchange with server
    pub fn key_exchange(
        &self,
        our_private: &X25519PrivateKey,
        server_ephemeral_public: &X25519PublicKey,
    ) -> Result<SharedSecret, KrakenError> {
        x25519::diffie_hellman(our_private, server_ephemeral_public)
    }

    /// Derive and store session key
    pub fn derive_session_key(&mut self, shared_secret: &SharedSecret) -> Result<(), KrakenError> {
        let key_bytes = hkdf::derive_session_key(shared_secret.as_bytes(), "session")?;
        self.session_key = Some(SymmetricKey(key_bytes));
        Ok(())
    }

    /// Get next nonce (counter-based)
    fn next_nonce(&self) -> Nonce {
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        Nonce::from_counter(counter)
    }

    /// Encrypt message for check-in
    pub fn encrypt_message(
        &self,
        plaintext: &[u8],
        implant_id: ImplantId,
    ) -> Result<Vec<u8>, KrakenError> {
        let session_key = self
            .session_key
            .as_ref()
            .ok_or_else(|| KrakenError::Crypto("session key not established".into()))?;

        let nonce = self.next_nonce();
        let ciphertext = aes_gcm::encrypt(session_key, &nonce, plaintext, implant_id.as_bytes())?;

        // Format: implant_id (16) + nonce (12) + ciphertext
        let mut result = Vec::with_capacity(16 + 12 + ciphertext.len());
        result.extend_from_slice(implant_id.as_bytes());
        result.extend_from_slice(nonce.as_bytes());
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt server response
    pub fn decrypt_message(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        let session_key = self
            .session_key
            .as_ref()
            .ok_or_else(|| KrakenError::Crypto("session key not established".into()))?;

        if data.len() < 12 {
            return Err(KrakenError::Crypto("response too short".into()));
        }

        let nonce = Nonce::from_bytes(&data[..12])?;
        let ciphertext = &data[12..];

        aes_gcm::decrypt(session_key, &nonce, ciphertext, b"")
    }

    /// Check if session is established
    pub fn is_session_established(&self) -> bool {
        self.session_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_establishment() {
        // Simulate server and implant
        let (server_pub, _server_priv) = x25519::generate_keypair().unwrap();
        let mut implant_crypto = ImplantCrypto::new(server_pub);

        assert!(!implant_crypto.is_session_established());

        // Simulate key exchange
        let (_implant_pub, implant_priv) = implant_crypto.generate_keypair().unwrap();
        let (server_ephemeral_pub, _) = x25519::generate_keypair().unwrap();

        let shared = implant_crypto
            .key_exchange(&implant_priv, &server_ephemeral_pub)
            .unwrap();
        implant_crypto.derive_session_key(&shared).unwrap();

        assert!(implant_crypto.is_session_established());
    }

    #[test]
    fn test_message_encryption() {
        let (server_pub, _) = x25519::generate_keypair().unwrap();
        let mut implant_crypto = ImplantCrypto::new(server_pub);

        // Establish session
        let (_, priv_key) = implant_crypto.generate_keypair().unwrap();
        let (server_eph_pub, _) = x25519::generate_keypair().unwrap();
        let shared = implant_crypto
            .key_exchange(&priv_key, &server_eph_pub)
            .unwrap();
        implant_crypto.derive_session_key(&shared).unwrap();

        let implant_id = ImplantId::new();
        let plaintext = b"check-in data";

        let encrypted = implant_crypto
            .encrypt_message(plaintext, implant_id)
            .unwrap();
        // Encrypted format: 16 (id) + 12 (nonce) + ciphertext
        assert!(encrypted.len() > 16 + 12);
    }

    #[test]
    fn test_encrypt_without_session_fails() {
        let (server_pub, _) = x25519::generate_keypair().unwrap();
        let implant_crypto = ImplantCrypto::new(server_pub);
        let implant_id = ImplantId::new();

        let result = implant_crypto.encrypt_message(b"data", implant_id);
        assert!(result.is_err());
    }
}
