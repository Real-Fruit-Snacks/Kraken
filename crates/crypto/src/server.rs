//! Server-side cryptographic operations

use crate::{
    aes_gcm, hkdf,
    types::{Nonce, SharedSecret, SymmetricKey, X25519PrivateKey, X25519PublicKey},
    x25519,
};
use common::KrakenError;

/// Server crypto context
pub struct ServerCrypto {
    /// Master key for encrypting stored secrets
    master_key: SymmetricKey,
}

impl ServerCrypto {
    /// Initialize server crypto (generate or load master key)
    pub fn new(master_key: SymmetricKey) -> Self {
        Self { master_key }
    }

    /// Generate a new master key
    pub fn generate_master_key() -> Result<SymmetricKey, KrakenError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .map_err(|_| KrakenError::Crypto("failed to generate master key".into()))?;
        Ok(SymmetricKey(key))
    }

    /// Get reference to master key
    pub fn master_key(&self) -> &SymmetricKey {
        &self.master_key
    }

    /// Generate X25519 keypair for key exchange
    pub fn generate_keypair(&self) -> Result<(X25519PublicKey, X25519PrivateKey), KrakenError> {
        x25519::generate_keypair()
    }

    /// Perform key exchange
    pub fn key_exchange(
        &self,
        our_private: &X25519PrivateKey,
        their_public: &X25519PublicKey,
    ) -> Result<SharedSecret, KrakenError> {
        x25519::diffie_hellman(our_private, their_public)
    }

    /// Derive session key from shared secret
    pub fn derive_session_key(
        &self,
        shared_secret: &SharedSecret,
    ) -> Result<SymmetricKey, KrakenError> {
        let key_bytes = hkdf::derive_session_key(shared_secret.as_bytes(), "session")?;
        Ok(SymmetricKey(key_bytes))
    }

    /// Encrypt data for storage
    pub fn encrypt_for_storage(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        let nonce = Nonce::random()?;
        let ciphertext = aes_gcm::encrypt(&self.master_key, &nonce, data, b"storage")?;

        // Prepend nonce to ciphertext
        let mut result = nonce.as_bytes().to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    /// Decrypt data from storage
    pub fn decrypt_from_storage(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        if data.len() < 12 {
            return Err(KrakenError::Crypto(
                "data too short for storage decryption".into(),
            ));
        }

        let nonce = Nonce::from_bytes(&data[..12])?;
        let ciphertext = &data[12..];

        aes_gcm::decrypt(&self.master_key, &nonce, ciphertext, b"storage")
    }

    /// Encrypt session key for database storage
    pub fn encrypt_session_key(&self, session_key: &SymmetricKey) -> Result<Vec<u8>, KrakenError> {
        self.encrypt_for_storage(session_key.as_bytes())
    }

    /// Decrypt session key from database
    pub fn decrypt_session_key(&self, encrypted: &[u8]) -> Result<SymmetricKey, KrakenError> {
        let decrypted = self.decrypt_from_storage(encrypted)?;
        SymmetricKey::from_bytes(&decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_encryption_roundtrip() {
        let master_key = ServerCrypto::generate_master_key().unwrap();
        let crypto = ServerCrypto::new(master_key);

        let data = b"secret session key data";
        let encrypted = crypto.encrypt_for_storage(data).unwrap();
        let decrypted = crypto.decrypt_from_storage(&encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_session_key_storage() {
        let master_key = ServerCrypto::generate_master_key().unwrap();
        let crypto = ServerCrypto::new(master_key);

        // Simulate storing/retrieving session key
        let session_key = SymmetricKey([0x42u8; 32]);
        let encrypted = crypto.encrypt_session_key(&session_key).unwrap();
        let decrypted = crypto.decrypt_session_key(&encrypted).unwrap();

        assert_eq!(session_key.as_bytes(), decrypted.as_bytes());
    }
}
