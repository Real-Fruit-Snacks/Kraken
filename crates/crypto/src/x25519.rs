//! X25519 key exchange using x25519-dalek
//!
//! This module provides proper static key Diffie-Hellman using x25519-dalek,
//! which allows storing and reusing private keys (unlike ring's ephemeral-only API).

use crate::types::{SharedSecret, X25519PrivateKey, X25519PublicKey};
use common::KrakenError;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a new X25519 keypair.
///
/// Returns (public_key, private_key). The private key can be stored and reused
/// for multiple DH operations.
pub fn generate_keypair() -> Result<(X25519PublicKey, X25519PrivateKey), KrakenError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(secret.as_bytes());

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(public.as_bytes());

    Ok((X25519PublicKey(pub_bytes), X25519PrivateKey(priv_bytes)))
}

/// Perform X25519 Diffie-Hellman key exchange.
///
/// Both parties compute the same shared secret:
/// - Alice: diffie_hellman(alice_private, bob_public)
/// - Bob: diffie_hellman(bob_private, alice_public)
///
/// The shared secret can then be used with HKDF to derive session keys.
pub fn diffie_hellman(
    our_private: &X25519PrivateKey,
    their_public: &X25519PublicKey,
) -> Result<SharedSecret, KrakenError> {
    // Reconstruct the StaticSecret from stored bytes
    let secret = StaticSecret::from(*our_private.as_bytes());

    // Parse their public key
    let their_pub = PublicKey::from(*their_public.as_bytes());

    // Perform the DH operation
    let shared = secret.diffie_hellman(&their_pub);

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(shared.as_bytes());

    Ok(SharedSecret(secret_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (pub_key, priv_key) = generate_keypair().unwrap();
        assert_eq!(pub_key.as_bytes().len(), 32);
        assert_eq!(priv_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_exchange_produces_same_secret() {
        let (alice_pub, alice_priv) = generate_keypair().unwrap();
        let (bob_pub, bob_priv) = generate_keypair().unwrap();

        // Both parties derive the same shared secret
        let secret1 = diffie_hellman(&alice_priv, &bob_pub).unwrap();
        let secret2 = diffie_hellman(&bob_priv, &alice_pub).unwrap();

        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_dh_deterministic() {
        let (_alice_pub, alice_priv) = generate_keypair().unwrap();
        let (bob_pub, _bob_priv) = generate_keypair().unwrap();

        // Same inputs produce same output
        let secret1 = diffie_hellman(&alice_priv, &bob_pub).unwrap();
        let secret2 = diffie_hellman(&alice_priv, &bob_pub).unwrap();

        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let (_alice_pub, alice_priv) = generate_keypair().unwrap();
        let (bob_pub, _) = generate_keypair().unwrap();
        let (carol_pub, _) = generate_keypair().unwrap();

        let secret_ab = diffie_hellman(&alice_priv, &bob_pub).unwrap();
        let secret_ac = diffie_hellman(&alice_priv, &carol_pub).unwrap();

        assert_ne!(secret_ab.as_bytes(), secret_ac.as_bytes());
    }
}
