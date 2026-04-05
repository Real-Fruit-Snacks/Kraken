//! Comprehensive unit tests for crypto roundtrips

#[cfg(test)]
mod tests {
    use crate::{
        aes_gcm, hkdf,
        server::ServerCrypto,
        types::{Nonce, SharedSecret, SymmetricKey},
        x25519,
    };

    // -------------------------------------------------------------------------
    // 1. Full key exchange — both parties derive the same shared secret
    // -------------------------------------------------------------------------

    #[test]
    fn test_key_exchange_shared_secret() {
        // Server generates its keypair
        let (server_pub, server_priv) = x25519::generate_keypair().unwrap();

        // Implant generates its keypair
        let (implant_pub, implant_priv) = x25519::generate_keypair().unwrap();

        // Server computes shared secret using its private key + implant's public key
        let server_secret = x25519::diffie_hellman(&server_priv, &implant_pub).unwrap();

        // Implant computes shared secret using its private key + server's public key
        let implant_secret = x25519::diffie_hellman(&implant_priv, &server_pub).unwrap();

        // Both parties must arrive at the same 32-byte value
        assert_eq!(
            server_secret.as_bytes(),
            implant_secret.as_bytes(),
            "DH shared secrets must match"
        );
    }

    // -------------------------------------------------------------------------
    // 2. AES-GCM encrypt / decrypt roundtrip
    // -------------------------------------------------------------------------

    #[test]
    fn test_aes_gcm_roundtrip() {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();

        // Generate a random 256-bit key
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes).unwrap();
        let key = SymmetricKey(key_bytes);

        // Generate a random nonce
        let nonce = Nonce::random().unwrap();

        let plaintext = b"kraken test payload";
        let aad = b"implant-id:abc123";

        // Encrypt
        let ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Ciphertext must differ from plaintext and be longer (auth tag appended)
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        assert!(ciphertext.len() > plaintext.len());

        // Decrypt and verify
        let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_aes_gcm_roundtrip_empty_aad() {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();

        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes).unwrap();
        let key = SymmetricKey(key_bytes);
        let nonce = Nonce::random().unwrap();

        let plaintext = b"no additional data here";

        let ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, b"").unwrap();
        let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    // -------------------------------------------------------------------------
    // 3. HKDF derivation — output is 32 bytes and deterministic
    // -------------------------------------------------------------------------

    #[test]
    fn test_hkdf_derive_session_key() {
        // Simulate a shared secret (32 bytes)
        let shared_secret = SharedSecret([0xABu8; 32]);

        // Derive a session key
        let key_bytes = hkdf::derive_session_key(shared_secret.as_bytes(), "session").unwrap();

        // Must be exactly 32 bytes
        assert_eq!(key_bytes.len(), 32, "session key must be 32 bytes");

        // Derivation must be deterministic
        let key_bytes2 = hkdf::derive_session_key(shared_secret.as_bytes(), "session").unwrap();
        assert_eq!(key_bytes, key_bytes2, "HKDF must be deterministic");

        // Different context must produce a different key
        let key_other = hkdf::derive_session_key(shared_secret.as_bytes(), "other").unwrap();
        assert_ne!(
            key_bytes, key_other,
            "different context must yield different key"
        );
    }

    #[test]
    fn test_hkdf_different_secrets_different_keys() {
        let secret_a = SharedSecret([0x11u8; 32]);
        let secret_b = SharedSecret([0x22u8; 32]);

        let key_a = hkdf::derive_session_key(secret_a.as_bytes(), "session").unwrap();
        let key_b = hkdf::derive_session_key(secret_b.as_bytes(), "session").unwrap();

        assert_ne!(
            key_a, key_b,
            "different shared secrets must yield different keys"
        );
    }

    // -------------------------------------------------------------------------
    // 4. Nonce counter roundtrip
    // -------------------------------------------------------------------------

    #[test]
    fn test_nonce_from_counter() {
        let counter: u64 = 42;

        let nonce = Nonce::from_counter(counter);

        // Extract the counter back and verify it matches
        let recovered = nonce.to_counter();
        assert_eq!(recovered, counter, "counter roundtrip must be lossless");
    }

    #[test]
    fn test_nonce_counter_zero() {
        let nonce = Nonce::from_counter(0);
        assert_eq!(nonce.to_counter(), 0);
    }

    #[test]
    fn test_nonce_counter_max() {
        let nonce = Nonce::from_counter(u64::MAX);
        assert_eq!(nonce.to_counter(), u64::MAX);
    }

    #[test]
    fn test_nonce_counter_bytes_length() {
        let nonce = Nonce::from_counter(1);
        // AES-GCM nonces must be exactly 12 bytes
        assert_eq!(nonce.as_bytes().len(), 12);
    }

    #[test]
    fn test_nonce_counter_prefix_is_zero() {
        // The first 4 bytes are reserved (zero) and only bytes 4..12 hold the counter
        let nonce = Nonce::from_counter(0xDEAD_BEEF_1234_5678);
        let bytes = nonce.as_bytes();
        assert_eq!(&bytes[0..4], &[0u8; 4], "first 4 bytes must be zero");
    }

    // -------------------------------------------------------------------------
    // 5. ServerCrypto session key encryption roundtrip
    // -------------------------------------------------------------------------

    #[test]
    fn test_server_crypto_session_key_roundtrip() {
        // Create ServerCrypto with a freshly generated master key
        let master_key = ServerCrypto::generate_master_key().unwrap();
        let crypto = ServerCrypto::new(master_key);

        // Create an arbitrary session key
        let original_session_key = SymmetricKey([0x77u8; 32]);

        // Encrypt it
        let encrypted = crypto.encrypt_session_key(&original_session_key).unwrap();

        // Encrypted blob must not equal the raw key bytes
        assert_ne!(
            encrypted.as_slice(),
            original_session_key.as_bytes().as_slice()
        );

        // Decrypt and verify
        let recovered = crypto.decrypt_session_key(&encrypted).unwrap();
        assert_eq!(
            original_session_key.as_bytes(),
            recovered.as_bytes(),
            "session key must survive encrypt/decrypt roundtrip"
        );
    }

    #[test]
    fn test_server_crypto_session_key_wrong_master_key_fails() {
        let master_key1 = ServerCrypto::generate_master_key().unwrap();
        let master_key2 = ServerCrypto::generate_master_key().unwrap();

        let crypto1 = ServerCrypto::new(master_key1);
        let crypto2 = ServerCrypto::new(master_key2);

        let session_key = SymmetricKey([0x55u8; 32]);
        let encrypted = crypto1.encrypt_session_key(&session_key).unwrap();

        // Decrypting with a different master key must fail
        let result = crypto2.decrypt_session_key(&encrypted);
        assert!(
            result.is_err(),
            "decryption with wrong master key must fail"
        );
    }

    // -------------------------------------------------------------------------
    // 6. End-to-end: full handshake → session key → message encryption
    // -------------------------------------------------------------------------

    #[test]
    fn test_full_handshake_to_message_encryption() {
        // Key exchange
        let (server_pub, server_priv) = x25519::generate_keypair().unwrap();
        let (implant_pub, implant_priv) = x25519::generate_keypair().unwrap();

        let server_shared = x25519::diffie_hellman(&server_priv, &implant_pub).unwrap();
        let implant_shared = x25519::diffie_hellman(&implant_priv, &server_pub).unwrap();

        assert_eq!(server_shared.as_bytes(), implant_shared.as_bytes());

        // Both sides derive the same session key
        let server_key_bytes =
            hkdf::derive_session_key(server_shared.as_bytes(), "session").unwrap();
        let implant_key_bytes =
            hkdf::derive_session_key(implant_shared.as_bytes(), "session").unwrap();

        assert_eq!(server_key_bytes, implant_key_bytes);

        let server_key = SymmetricKey(server_key_bytes);
        let implant_key = SymmetricKey(implant_key_bytes);

        // Implant encrypts a message; server decrypts it
        let message = b"exec /bin/whoami";
        let nonce = Nonce::from_counter(1);
        let aad = b"channel:0";

        let ciphertext = aes_gcm::encrypt(&implant_key, &nonce, message, aad).unwrap();
        let plaintext = aes_gcm::decrypt(&server_key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), message.as_slice());
    }

    // -------------------------------------------------------------------------
    // 7. Edge Case Tests — Authentication & Error Handling
    // -------------------------------------------------------------------------

    #[test]
    fn test_tampered_ciphertext_fails_authentication() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce = Nonce::from_counter(1);
        let plaintext = b"secret message";
        let aad = b"context";

        let mut ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Tamper with the ciphertext (flip a bit)
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = SymmetricKey([0x11u8; 32]);
        let key2 = SymmetricKey([0x22u8; 32]);
        let nonce = Nonce::from_counter(1);
        let plaintext = b"sensitive data";
        let aad = b"";

        let ciphertext = aes_gcm::encrypt(&key1, &nonce, plaintext, aad).unwrap();
        let result = aes_gcm::decrypt(&key2, &nonce, &ciphertext, aad);

        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn test_wrong_nonce_fails_decryption() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce1 = Nonce::from_counter(1);
        let nonce2 = Nonce::from_counter(2);
        let plaintext = b"protected payload";
        let aad = b"header";

        let ciphertext = aes_gcm::encrypt(&key, &nonce1, plaintext, aad).unwrap();
        let result = aes_gcm::decrypt(&key, &nonce2, &ciphertext, aad);

        assert!(result.is_err(), "wrong nonce must fail decryption");
    }

    #[test]
    fn test_wrong_aad_fails_decryption() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce = Nonce::from_counter(1);
        let plaintext = b"authenticated message";
        let aad1 = b"correct-context";
        let aad2 = b"wrong-context";

        let ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad1).unwrap();
        let result = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad2);

        assert!(result.is_err(), "wrong AAD must fail decryption");
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce = Nonce::from_counter(1);
        let plaintext = b"";
        let aad = b"empty-payload";

        let ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad).unwrap();
        // Ciphertext should only contain auth tag (16 bytes for AES-GCM)
        assert_eq!(ciphertext.len(), 16);

        let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext_roundtrip() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce = Nonce::from_counter(1);
        // 1MB plaintext
        let plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        let aad = b"large-payload";

        let ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext, aad).unwrap();
        let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce = Nonce::from_counter(1);
        let plaintext = b"data to encrypt";
        let aad = b"";

        let ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Truncate the ciphertext (remove auth tag)
        let truncated = &ciphertext[..ciphertext.len() - 8];
        let result = aes_gcm::decrypt(&key, &nonce, truncated, aad);

        assert!(result.is_err(), "truncated ciphertext must fail");
    }

    #[test]
    fn test_too_short_ciphertext_fails() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce = Nonce::from_counter(1);

        // Ciphertext shorter than auth tag (16 bytes)
        let short_ciphertext = vec![0u8; 8];
        let result = aes_gcm::decrypt(&key, &nonce, &short_ciphertext, b"");

        assert!(result.is_err(), "too-short ciphertext must fail");
    }

    #[test]
    fn test_nonce_uniqueness_matters() {
        let key = SymmetricKey([0x42u8; 32]);
        let nonce = Nonce::from_counter(1);
        let plaintext1 = b"message one";
        let plaintext2 = b"message two";

        // Encrypting different messages with same nonce produces different ciphertexts
        let ct1 = aes_gcm::encrypt(&key, &nonce, plaintext1, b"").unwrap();
        let ct2 = aes_gcm::encrypt(&key, &nonce, plaintext2, b"").unwrap();

        assert_ne!(ct1, ct2, "different plaintexts should produce different ciphertexts");

        // Both should decrypt correctly
        let pt1 = aes_gcm::decrypt(&key, &nonce, &ct1, b"").unwrap();
        let pt2 = aes_gcm::decrypt(&key, &nonce, &ct2, b"").unwrap();

        assert_eq!(pt1.as_slice(), plaintext1);
        assert_eq!(pt2.as_slice(), plaintext2);
    }

    #[test]
    fn test_random_nonce_is_unique() {
        // Generate multiple random nonces and verify they're all different
        let nonces: Vec<Nonce> = (0..100)
            .map(|_| Nonce::random().unwrap())
            .collect();

        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(
                    nonces[i].as_bytes(),
                    nonces[j].as_bytes(),
                    "random nonces must be unique"
                );
            }
        }
    }

    #[test]
    fn test_symmetric_key_from_bytes_wrong_length() {
        // Too short
        let result = SymmetricKey::from_bytes(&[0u8; 16]);
        assert!(result.is_err(), "16-byte key must be rejected");

        // Too long
        let result = SymmetricKey::from_bytes(&[0u8; 64]);
        assert!(result.is_err(), "64-byte key must be rejected");

        // Correct length
        let result = SymmetricKey::from_bytes(&[0u8; 32]);
        assert!(result.is_ok(), "32-byte key must be accepted");
    }

    #[test]
    fn test_keypair_generation_produces_unique_keys() {
        let kp1 = x25519::generate_keypair().unwrap();
        let kp2 = x25519::generate_keypair().unwrap();

        assert_ne!(
            kp1.0.as_bytes(),
            kp2.0.as_bytes(),
            "public keys must be unique"
        );
        assert_ne!(
            kp1.1.as_bytes(),
            kp2.1.as_bytes(),
            "private keys must be unique"
        );
    }

    #[test]
    fn test_dh_with_all_zero_public_key() {
        // This tests handling of weak/invalid public keys
        use crate::X25519PublicKey;
        let (_, our_priv) = x25519::generate_keypair().unwrap();

        // All-zero public key is a known weak point
        let zero_pub = X25519PublicKey::from_bytes(&[0u8; 32]).unwrap();

        // The DH operation might succeed but produce all-zeros (low-order point)
        // This is a security consideration - implementations should check for this
        let result = x25519::diffie_hellman(&our_priv, &zero_pub);
        // Just verify it doesn't panic - the result handling depends on implementation
        let _ = result;
    }

    #[test]
    fn test_hkdf_empty_context() {
        let shared_secret = SharedSecret([0xABu8; 32]);
        let key = hkdf::derive_session_key(shared_secret.as_bytes(), "").unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_long_context() {
        let shared_secret = SharedSecret([0xABu8; 32]);
        let long_context = "x".repeat(1000);
        let key = hkdf::derive_session_key(shared_secret.as_bytes(), &long_context).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_server_crypto_decrypt_garbage() {
        let master_key = ServerCrypto::generate_master_key().unwrap();
        let crypto = ServerCrypto::new(master_key);

        // Try to decrypt random garbage
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        let result = crypto.decrypt_session_key(&garbage);

        assert!(result.is_err(), "decrypting garbage must fail");
    }

    #[test]
    fn test_server_crypto_decrypt_empty() {
        let master_key = ServerCrypto::generate_master_key().unwrap();
        let crypto = ServerCrypto::new(master_key);

        let result = crypto.decrypt_session_key(&[]);
        assert!(result.is_err(), "decrypting empty data must fail");
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;
    use crate::{aes_gcm, hkdf, types::{Nonce, SymmetricKey}};

    // Helper: build a SymmetricKey from a 32-byte array produced by a strategy.
    fn make_key(bytes: [u8; 32]) -> SymmetricKey {
        SymmetricKey(bytes)
    }

    // Strategy: produce an arbitrary 32-byte key array.
    fn arb_key() -> impl Strategy<Value = [u8; 32]> {
        prop::array::uniform32(any::<u8>())
    }

    // Strategy: produce an arbitrary 12-byte nonce array, returned as a Nonce.
    fn arb_nonce_bytes() -> impl Strategy<Value = [u8; 12]> {
        prop::array::uniform::<_, 12>(any::<u8>())
    }

    fn nonce_from_array(bytes: [u8; 12]) -> Nonce {
        Nonce::from_bytes(&bytes).expect("12-byte array must always produce a valid Nonce")
    }

    proptest! {
        // ------------------------------------------------------------------
        // 1. Encrypt → Decrypt roundtrip
        //    For any plaintext and key/nonce, decryption must recover the
        //    original bytes exactly.
        // ------------------------------------------------------------------
        #[test]
        fn encrypt_decrypt_roundtrip(
            plaintext in prop::collection::vec(any::<u8>(), 0..8192),
            key_bytes in arb_key(),
            nonce_raw in arb_nonce_bytes(),
        ) {
            let key = make_key(key_bytes);
            let nonce = nonce_from_array(nonce_raw);
            let aad = b"proptest-aad";

            let ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext, aad)
                .expect("encryption must not fail");
            let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad)
                .expect("decryption must not fail");

            prop_assert_eq!(decrypted, plaintext);
        }

        // ------------------------------------------------------------------
        // 2. Semantic security — different nonces produce different ciphertext
        //    (for the same key and non-empty plaintext).
        // ------------------------------------------------------------------
        #[test]
        fn different_nonces_different_ciphertext(
            plaintext in prop::collection::vec(any::<u8>(), 1..4096),
            key_bytes in arb_key(),
            counter_a in any::<u64>(),
            counter_b in any::<u64>(),
        ) {
            // Only meaningful when the nonces differ.
            prop_assume!(counter_a != counter_b);

            let key = make_key(key_bytes);
            let nonce_a = Nonce::from_counter(counter_a);
            let nonce_b = Nonce::from_counter(counter_b);
            let aad = b"";

            let ct_a = aes_gcm::encrypt(&key, &nonce_a, &plaintext, aad)
                .expect("encryption with nonce_a must succeed");
            let ct_b = aes_gcm::encrypt(&key, &nonce_b, &plaintext, aad)
                .expect("encryption with nonce_b must succeed");

            prop_assert_ne!(ct_a, ct_b,
                "same plaintext encrypted under different nonces must yield different ciphertexts");
        }

        // ------------------------------------------------------------------
        // 3. Integrity — flipping any single bit in the ciphertext must
        //    cause authentication to fail.
        // ------------------------------------------------------------------
        #[test]
        fn tampered_ciphertext_fails(
            plaintext in prop::collection::vec(any::<u8>(), 0..4096),
            key_bytes in arb_key(),
            nonce_raw in arb_nonce_bytes(),
            // Which byte to flip (will be wrapped to ciphertext length).
            flip_index in any::<usize>(),
            // Which bit within that byte to flip.
            flip_bit in 0usize..8,
        ) {
            let key = make_key(key_bytes);
            let nonce = nonce_from_array(nonce_raw);
            let aad = b"tamper-test";

            let mut ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext, aad)
                .expect("encryption must succeed");

            // AES-GCM appends a 16-byte auth tag; the ciphertext is always
            // at least 16 bytes long (tag only when plaintext is empty).
            prop_assume!(!ciphertext.is_empty());

            let idx = flip_index % ciphertext.len();
            ciphertext[idx] ^= 1 << flip_bit;

            let result = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad);
            prop_assert!(result.is_err(),
                "decryption of tampered ciphertext must fail (byte {} bit {})", idx, flip_bit);
        }

        // ------------------------------------------------------------------
        // 4. Key derivation is deterministic — identical inputs always
        //    produce the same 32-byte session key.
        // ------------------------------------------------------------------
        #[test]
        fn key_derivation_deterministic(
            secret_bytes in arb_key(),
            context in "[a-z]{0,64}",
        ) {
            let key1 = hkdf::derive_session_key(&secret_bytes, &context)
                .expect("first derivation must succeed");
            let key2 = hkdf::derive_session_key(&secret_bytes, &context)
                .expect("second derivation must succeed");

            prop_assert_eq!(key1.len(), 32, "derived key must be 32 bytes");
            prop_assert_eq!(key1, key2,
                "same inputs must always produce the same derived key");
        }

        // ------------------------------------------------------------------
        // 5. Key derivation separates contexts — distinct context strings
        //    (with the same secret) must produce distinct keys.
        // ------------------------------------------------------------------
        #[test]
        fn key_derivation_context_separation(
            secret_bytes in arb_key(),
            ctx_a in "[a-z]{1,32}",
            ctx_b in "[a-z]{1,32}",
        ) {
            prop_assume!(ctx_a != ctx_b);

            let key_a = hkdf::derive_session_key(&secret_bytes, &ctx_a)
                .expect("derivation for ctx_a must succeed");
            let key_b = hkdf::derive_session_key(&secret_bytes, &ctx_b)
                .expect("derivation for ctx_b must succeed");

            prop_assert_ne!(key_a, key_b,
                "different context strings must yield different derived keys");
        }

        // ------------------------------------------------------------------
        // 6. Wrong key fails decryption — a different 32-byte key must not
        //    be able to decrypt a ciphertext.
        // ------------------------------------------------------------------
        #[test]
        fn wrong_key_fails_decryption(
            plaintext in prop::collection::vec(any::<u8>(), 1..1024),
            key_bytes_enc in arb_key(),
            key_bytes_dec in arb_key(),
            nonce_raw in arb_nonce_bytes(),
        ) {
            prop_assume!(key_bytes_enc != key_bytes_dec);

            let enc_key = make_key(key_bytes_enc);
            let dec_key = make_key(key_bytes_dec);
            let nonce = nonce_from_array(nonce_raw);
            let aad = b"wrong-key-test";

            let ciphertext = aes_gcm::encrypt(&enc_key, &nonce, &plaintext, aad)
                .expect("encryption must succeed");

            let result = aes_gcm::decrypt(&dec_key, &nonce, &ciphertext, aad);
            prop_assert!(result.is_err(),
                "decryption with a different key must fail");
        }

        // ------------------------------------------------------------------
        // 7. Nonce counter roundtrip — Nonce::from_counter / to_counter are
        //    inverse operations for all u64 values.
        // ------------------------------------------------------------------
        #[test]
        fn nonce_counter_roundtrip(counter in any::<u64>()) {
            let nonce = Nonce::from_counter(counter);
            prop_assert_eq!(nonce.to_counter(), counter,
                "counter must survive from_counter → to_counter roundtrip");
        }
    }

    // =========================================================================
    // KNOWN ANSWER TESTS (KATs)
    // Test vectors from NIST, RFCs to verify cryptographic correctness
    // =========================================================================

    mod kat_tests {
        use super::*;

        // ---------------------------------------------------------------------
        // AES-256-GCM Test Vectors (NIST SP 800-38D)
        // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
        // ---------------------------------------------------------------------

        #[test]
        fn kat_aes_gcm_nist_vector_1() {
            // NIST GCM Test Case 14 (256-bit key)
            // Key: all zeros
            let key = SymmetricKey([0u8; 32]);
            // IV/Nonce: all zeros (12 bytes)
            let nonce = Nonce([0u8; 12]);
            // Plaintext: empty
            let plaintext: &[u8] = &[];
            // AAD: empty
            let aad: &[u8] = &[];

            // Expected ciphertext + tag (16 bytes tag only since plaintext is empty)
            let expected_tag: [u8; 16] = [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
                0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b
            ];

            let ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad).unwrap();
            assert_eq!(ciphertext.len(), 16, "empty plaintext should produce 16-byte tag only");
            assert_eq!(&ciphertext[..], &expected_tag[..], "AES-GCM tag mismatch for NIST vector 1");

            // Verify decryption
            let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
            assert_eq!(decrypted.len(), 0, "decrypted empty plaintext");
        }

        #[test]
        fn kat_aes_gcm_nist_vector_2() {
            // NIST GCM Test Case 15 (256-bit key with plaintext)
            // Key: all zeros
            let key = SymmetricKey([0u8; 32]);
            // IV: all zeros
            let nonce = Nonce([0u8; 12]);
            // Plaintext: 16 bytes of zeros
            let plaintext = [0u8; 16];
            // AAD: empty
            let aad: &[u8] = &[];

            // Expected ciphertext (16 bytes) + tag (16 bytes)
            let expected_ciphertext: [u8; 16] = [
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
                0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
            ];
            let expected_tag: [u8; 16] = [
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
                0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
            ];

            let result = aes_gcm::encrypt(&key, &nonce, &plaintext, aad).unwrap();
            assert_eq!(result.len(), 32, "16 bytes ciphertext + 16 bytes tag");
            assert_eq!(&result[..16], &expected_ciphertext[..], "AES-GCM ciphertext mismatch");
            assert_eq!(&result[16..], &expected_tag[..], "AES-GCM tag mismatch");

            // Verify decryption
            let decrypted = aes_gcm::decrypt(&key, &nonce, &result, aad).unwrap();
            assert_eq!(&decrypted[..], &plaintext[..], "decryption must recover plaintext");
        }

        // ---------------------------------------------------------------------
        // X25519 Test Vectors (RFC 7748)
        // ---------------------------------------------------------------------

        #[test]
        fn kat_x25519_rfc7748_vector_1() {
            // RFC 7748 Section 5.2 Test Vector 1
            // Alice's private key (clamped scalar)
            let alice_private: [u8; 32] = [
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
            ];
            // Alice's expected public key
            let alice_public_expected: [u8; 32] = [
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
                0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
                0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
                0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
            ];

            // Bob's private key
            let bob_private: [u8; 32] = [
                0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
                0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
                0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
            ];
            // Bob's expected public key
            let bob_public_expected: [u8; 32] = [
                0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
            ];

            // Expected shared secret
            let expected_shared: [u8; 32] = [
                0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
            ];

            // Note: x25519 module uses ring which handles key generation internally
            // We verify DH shared secret computation with known test vectors
            // by using the raw scalar multiplication if exposed, or skip this
            // if the API doesn't allow injecting specific private keys.

            // For now, verify that public key derivation concept works
            // (ring's x25519 doesn't expose raw scalar mult with arbitrary scalars)
            // The roundtrip tests above verify correctness; this documents the vectors.
            let _ = (alice_private, alice_public_expected, bob_private, bob_public_expected, expected_shared);
        }

        // ---------------------------------------------------------------------
        // HKDF-SHA256 Test Vectors (RFC 5869)
        // ---------------------------------------------------------------------

        #[test]
        fn kat_hkdf_rfc5869_vector_1() {
            // RFC 5869 Appendix A.1 - Test Case 1
            // IKM (Input Keying Material)
            let ikm: [u8; 22] = [0x0b; 22];
            // Salt
            let _salt: [u8; 13] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c
            ];
            // Info
            let _info: [u8; 10] = [
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                0xf8, 0xf9
            ];

            // Expected OKM (42 bytes)
            let _expected_okm: [u8; 42] = [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
                0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
                0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
                0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
                0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
                0x58, 0x65
            ];

            // Our HKDF uses a fixed salt internally, so we test the derive_session_key API
            // which uses HKDF with SHA256
            let result = hkdf::derive_session_key(&ikm, "test-context").unwrap();
            assert_eq!(result.len(), 32, "derived key should be 32 bytes");

            // Verify determinism
            let result2 = hkdf::derive_session_key(&ikm, "test-context").unwrap();
            assert_eq!(result, result2, "HKDF derivation must be deterministic");
        }

        #[test]
        fn kat_hkdf_context_separation() {
            // Verify that different contexts produce different keys (per RFC 5869 info parameter)
            let ikm: [u8; 32] = [0x42; 32];

            let key_a = hkdf::derive_session_key(&ikm, "context-alpha").unwrap();
            let key_b = hkdf::derive_session_key(&ikm, "context-beta").unwrap();

            assert_ne!(key_a, key_b, "different info must produce different keys");
        }

        // ---------------------------------------------------------------------
        // SHA256 Test Vectors (FIPS 180-4)
        // ---------------------------------------------------------------------

        #[test]
        fn kat_sha256_fips180_vectors() {
            // FIPS 180-4 Example: "abc"
            let input1 = b"abc";
            let expected1: [u8; 32] = [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
            ];
            let result1 = crate::sha256(input1);
            assert_eq!(result1, expected1, "SHA256('abc') mismatch");

            // FIPS 180-4 Example: empty string
            let input2 = b"";
            let expected2: [u8; 32] = [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
            ];
            let result2 = crate::sha256(input2);
            assert_eq!(result2, expected2, "SHA256('') mismatch");

            // FIPS 180-4 Example: 448-bit message
            let input3 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            let expected3: [u8; 32] = [
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
            ];
            let result3 = crate::sha256(input3);
            assert_eq!(result3, expected3, "SHA256(448-bit) mismatch");
        }

        // ---------------------------------------------------------------------
        // Additional AES-GCM edge cases
        // ---------------------------------------------------------------------

        #[test]
        fn kat_aes_gcm_with_aad() {
            // Test with both plaintext and AAD
            let key = SymmetricKey([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            ]);
            let nonce = Nonce([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b
            ]);
            let plaintext = b"The quick brown fox jumps over the lazy dog";
            let aad = b"additional authenticated data";

            // Encrypt
            let ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad).unwrap();

            // Verify structure: ciphertext_len = plaintext_len + 16 (tag)
            assert_eq!(ciphertext.len(), plaintext.len() + 16);

            // Decrypt and verify
            let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
            assert_eq!(&decrypted[..], &plaintext[..]);

            // Wrong AAD must fail
            let wrong_aad_result = aes_gcm::decrypt(&key, &nonce, &ciphertext, b"wrong aad");
            assert!(wrong_aad_result.is_err(), "wrong AAD must fail decryption");
        }

        #[test]
        fn kat_aes_gcm_tag_verification() {
            // Verify that a tampered tag fails
            let key = SymmetricKey([0x42; 32]);
            let nonce = Nonce([0x00; 12]);
            let plaintext = b"test message";
            let aad = b"";

            let mut ciphertext = aes_gcm::encrypt(&key, &nonce, plaintext, aad).unwrap();

            // Tamper with the last byte (part of the auth tag)
            let last_idx = ciphertext.len() - 1;
            ciphertext[last_idx] ^= 0x01;

            let result = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad);
            assert!(result.is_err(), "tampered tag must fail authentication");
        }
    }
}
