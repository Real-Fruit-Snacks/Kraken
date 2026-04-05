//! Cryptographic type definitions

use common::KrakenError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 public key (32 bytes)
#[derive(Clone)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KrakenError> {
        if bytes.len() != 32 {
            return Err(KrakenError::Crypto(format!(
                "invalid public key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PublicKey([...])")
    }
}

/// X25519 private key (32 bytes) - zeroized on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519PrivateKey(pub [u8; 32]);

impl X25519PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KrakenError> {
        if bytes.len() != 32 {
            return Err(KrakenError::Crypto(format!(
                "invalid private key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PrivateKey([REDACTED])")
    }
}

/// Shared secret from ECDH (32 bytes) - zeroized on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KrakenError> {
        if bytes.len() != 32 {
            return Err(KrakenError::Crypto(format!(
                "invalid shared secret length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

/// AES-256 symmetric key (32 bytes) - zeroized on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KrakenError> {
        if bytes.len() != 32 {
            return Err(KrakenError::Crypto(format!(
                "invalid symmetric key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey([REDACTED])")
    }
}

/// AES-GCM nonce (12 bytes)
#[derive(Clone)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KrakenError> {
        if bytes.len() != 12 {
            return Err(KrakenError::Crypto(format!(
                "invalid nonce length: expected 12, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 12];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn from_counter(counter: u64) -> Self {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
        Self(nonce)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Extract counter value from nonce (assumes counter is in bytes 4..12)
    pub fn to_counter(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.0[4..12]);
        u64::from_be_bytes(bytes)
    }

    pub fn random() -> Result<Self, KrakenError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce)
            .map_err(|_| KrakenError::Crypto("failed to generate random nonce".into()))?;
        Ok(Self(nonce))
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({})", hex::encode(self.0))
    }
}

/// Ed25519 public key (32 bytes) - for module signing
#[derive(Clone)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KrakenError> {
        if bytes.len() != 32 {
            return Err(KrakenError::Crypto(format!(
                "invalid Ed25519 public key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Clone)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Ed25519Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KrakenError> {
        if bytes.len() != 64 {
            return Err(KrakenError::Crypto(format!(
                "invalid signature length: expected 64, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}
