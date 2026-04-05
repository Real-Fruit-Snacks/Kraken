//! X25519 key exchange handshake for mesh peer links
//!
//! Protocol:
//! 1. Initiator sends: ephemeral public key (32 bytes)
//! 2. Responder sends: ephemeral public key (32 bytes)
//! 3. Both derive shared secret via X25519
//! 4. Session key = HKDF(shared_secret, salt="kraken-mesh-v1")

use common::KrakenError;
use crypto::{SymmetricKey, X25519PrivateKey, X25519PublicKey};

/// Result of a completed handshake.
pub struct HandshakeResult {
    pub session_key: SymmetricKey,
    pub peer_public_key: X25519PublicKey,
}

/// Transport trait for handshake I/O — abstracts SMB named pipe / TCP stream.
pub trait Transport {
    fn send(&mut self, data: &[u8]) -> Result<(), KrakenError>;
    fn recv(&mut self) -> Result<Vec<u8>, KrakenError>;
}

/// Perform handshake as the initiator side.
///
/// 1. Send our ephemeral public key.
/// 2. Receive peer's ephemeral public key.
/// 3. Optionally verify key matches `expected_peer_pubkey`.
/// 4. Derive shared secret via X25519 DH.
/// 5. Derive session key via HKDF-SHA256 with info `b"kraken-mesh-v1"`.
pub fn initiate_handshake<T: Transport>(
    transport: &mut T,
    our_keypair: &(X25519PublicKey, X25519PrivateKey),
    expected_peer_pubkey: Option<&X25519PublicKey>,
) -> Result<HandshakeResult, KrakenError> {
    // 1. Send our ephemeral public key
    transport.send(our_keypair.0.as_bytes())?;

    // 2. Receive peer's ephemeral public key
    let peer_pubkey_bytes = transport.recv()?;
    if peer_pubkey_bytes.len() != 32 {
        return Err(KrakenError::Protocol(format!(
            "invalid peer public key length: expected 32, got {}",
            peer_pubkey_bytes.len()
        )));
    }
    let peer_pubkey = X25519PublicKey::from_bytes(&peer_pubkey_bytes)?;

    // 3. Verify against expected key if provided
    if let Some(expected) = expected_peer_pubkey {
        if peer_pubkey.as_bytes() != expected.as_bytes() {
            return Err(KrakenError::Protocol(
                "peer public key mismatch".into(),
            ));
        }
    }

    // 4. Derive shared secret via X25519 DH
    let shared_secret = crypto::diffie_hellman(&our_keypair.1, &peer_pubkey)?;

    // 5. Derive 32-byte session key via HKDF-SHA256
    let key_bytes = crypto::derive(shared_secret.as_bytes(), b"kraken-mesh-v1", 32)?;
    let session_key = SymmetricKey::from_bytes(&key_bytes)?;

    Ok(HandshakeResult {
        session_key,
        peer_public_key: peer_pubkey,
    })
}

/// Perform handshake as the responder side.
///
/// 1. Receive initiator's ephemeral public key.
/// 2. Send our ephemeral public key.
/// 3. Derive shared secret via X25519 DH.
/// 4. Derive session key via HKDF-SHA256 with info `b"kraken-mesh-v1"`.
pub fn respond_handshake<T: Transport>(
    transport: &mut T,
    our_keypair: &(X25519PublicKey, X25519PrivateKey),
) -> Result<HandshakeResult, KrakenError> {
    // 1. Receive initiator's ephemeral public key
    let peer_pubkey_bytes = transport.recv()?;
    if peer_pubkey_bytes.len() != 32 {
        return Err(KrakenError::Protocol(format!(
            "invalid peer public key length: expected 32, got {}",
            peer_pubkey_bytes.len()
        )));
    }
    let peer_pubkey = X25519PublicKey::from_bytes(&peer_pubkey_bytes)?;

    // 2. Send our ephemeral public key
    transport.send(our_keypair.0.as_bytes())?;

    // 3. Derive shared secret via X25519 DH
    let shared_secret = crypto::diffie_hellman(&our_keypair.1, &peer_pubkey)?;

    // 4. Derive 32-byte session key via HKDF-SHA256
    let key_bytes = crypto::derive(shared_secret.as_bytes(), b"kraken-mesh-v1", 32)?;
    let session_key = SymmetricKey::from_bytes(&key_bytes)?;

    Ok(HandshakeResult {
        session_key,
        peer_public_key: peer_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct PairedTransport {
        outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
        inbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    fn make_pair() -> (PairedTransport, PairedTransport) {
        let a_to_b: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let initiator = PairedTransport {
            outbox: Arc::clone(&a_to_b),
            inbox: Arc::clone(&b_to_a),
        };
        let responder = PairedTransport {
            outbox: Arc::clone(&b_to_a),
            inbox: Arc::clone(&a_to_b),
        };
        (initiator, responder)
    }

    impl Transport for PairedTransport {
        fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
            self.outbox.lock().unwrap().push_back(data.to_vec());
            Ok(())
        }
        fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            // Spin until the peer thread delivers data, yielding each iteration
            // so the OS can schedule the other thread.
            loop {
                if let Some(msg) = self.inbox.lock().unwrap().pop_front() {
                    return Ok(msg);
                }
                std::thread::yield_now();
            }
        }
    }

    #[test]
    fn test_handshake_produces_same_session_key() {
        let initiator_kp = crypto::generate_keypair().unwrap();
        let responder_kp = crypto::generate_keypair().unwrap();

        let (mut init_t, mut resp_t) = make_pair();

        let resp_kp_copy = (
            X25519PublicKey::from_bytes(responder_kp.0.as_bytes()).unwrap(),
            X25519PrivateKey::from_bytes(responder_kp.1.as_bytes()).unwrap(),
        );

        let (init_result, resp_result) = std::thread::scope(|s| {
            let ih = s.spawn(|| initiate_handshake(&mut init_t, &initiator_kp, None).unwrap());
            let rh = s.spawn(|| respond_handshake(&mut resp_t, &resp_kp_copy).unwrap());
            (ih.join().unwrap(), rh.join().unwrap())
        });

        assert_eq!(
            init_result.session_key.as_bytes(),
            resp_result.session_key.as_bytes(),
            "both sides must derive identical session keys"
        );
        assert_eq!(
            init_result.peer_public_key.as_bytes(),
            responder_kp.0.as_bytes(),
            "initiator must see responder's public key as peer"
        );
        assert_eq!(
            resp_result.peer_public_key.as_bytes(),
            initiator_kp.0.as_bytes(),
            "responder must see initiator's public key as peer"
        );
    }

    #[test]
    fn test_initiator_rejects_wrong_peer_key() {
        let initiator_kp = crypto::generate_keypair().unwrap();
        let responder_kp = crypto::generate_keypair().unwrap();
        let wrong_kp = crypto::generate_keypair().unwrap();

        let (mut init_t, mut resp_t) = make_pair();

        let resp_kp_copy = (
            X25519PublicKey::from_bytes(responder_kp.0.as_bytes()).unwrap(),
            X25519PrivateKey::from_bytes(responder_kp.1.as_bytes()).unwrap(),
        );

        std::thread::scope(|s| {
            s.spawn(|| respond_handshake(&mut resp_t, &resp_kp_copy));
            let result = initiate_handshake(&mut init_t, &initiator_kp, Some(&wrong_kp.0));
            assert!(result.is_err(), "should reject mismatched peer key");
        });
    }

    #[test]
    fn test_handshake_concurrent_sessions() {
        use std::sync::Barrier;

        const N: usize = 10;

        // Barrier gates all 20 threads so every handshake starts simultaneously.
        let barrier = Arc::new(Barrier::new(N * 2));

        // Per-pair slot stores (initiator_key, responder_key) once both threads finish.
        let slots: Vec<Arc<Mutex<([u8; 32], [u8; 32])>>> =
            (0..N).map(|_| Arc::new(Mutex::new(([0u8; 32], [0u8; 32])))).collect();

        std::thread::scope(|s| {
            for i in 0..N {
                let initiator_kp = crypto::generate_keypair().unwrap();
                let responder_kp = crypto::generate_keypair().unwrap();

                let (mut init_t, mut resp_t) = make_pair();

                let b_i = Arc::clone(&barrier);
                let b_r = Arc::clone(&barrier);
                let slot_i = Arc::clone(&slots[i]);
                let slot_r = Arc::clone(&slots[i]);

                // Responder thread: wait at barrier, run handshake, store key.
                s.spawn(move || {
                    b_r.wait();
                    let r = respond_handshake(&mut resp_t, &responder_kp).unwrap();
                    let key: [u8; 32] = *r.session_key.as_bytes();
                    slot_r.lock().unwrap().1 = key;
                });

                // Initiator thread: wait at barrier, run handshake, store key.
                s.spawn(move || {
                    b_i.wait();
                    let r = initiate_handshake(&mut init_t, &initiator_kp, None).unwrap();
                    let key: [u8; 32] = *r.session_key.as_bytes();
                    slot_i.lock().unwrap().0 = key;
                });
            }
        }); // scope join — all threads have completed here

        let pairs: Vec<([u8; 32], [u8; 32])> = slots
            .iter()
            .map(|slot| *slot.lock().unwrap())
            .collect();

        // 1. All 10 handshakes succeeded (panics above would have propagated otherwise).
        assert_eq!(pairs.len(), N, "all 10 handshakes must complete");

        // 2. All session keys are 32 bytes (type guarantees it, but assert explicitly).
        for (i, (ik, rk)) in pairs.iter().enumerate() {
            assert_eq!(ik.len(), 32, "pair {i}: initiator key must be 32 bytes");
            assert_eq!(rk.len(), 32, "pair {i}: responder key must be 32 bytes");
        }

        // 3. Within each pair the two sides derive identical session keys.
        for (i, (ik, rk)) in pairs.iter().enumerate() {
            assert_eq!(
                ik, rk,
                "pair {i}: initiator and responder must derive identical session keys"
            );
        }

        // 4. Session keys across different pairs are all distinct (no collisions).
        let all_keys: Vec<[u8; 32]> = pairs.iter().map(|(ik, _)| *ik).collect();
        for i in 0..all_keys.len() {
            for j in (i + 1)..all_keys.len() {
                assert_ne!(
                    all_keys[i], all_keys[j],
                    "pairs {i} and {j} must not share a session key"
                );
            }
        }
    }

    #[test]
    fn test_different_peer_pairs_produce_different_keys() {
        let kp_a = crypto::generate_keypair().unwrap();
        let kp_b = crypto::generate_keypair().unwrap();
        let kp_c = crypto::generate_keypair().unwrap();

        let (mut t_ab_i, mut t_ab_r) = make_pair();
        let (mut t_ac_i, mut t_ac_r) = make_pair();

        let kp_b_copy = (
            X25519PublicKey::from_bytes(kp_b.0.as_bytes()).unwrap(),
            X25519PrivateKey::from_bytes(kp_b.1.as_bytes()).unwrap(),
        );
        let kp_c_copy = (
            X25519PublicKey::from_bytes(kp_c.0.as_bytes()).unwrap(),
            X25519PrivateKey::from_bytes(kp_c.1.as_bytes()).unwrap(),
        );
        let kp_a2 = (
            X25519PublicKey::from_bytes(kp_a.0.as_bytes()).unwrap(),
            X25519PrivateKey::from_bytes(kp_a.1.as_bytes()).unwrap(),
        );

        let (ab, ac) = std::thread::scope(|s| {
            let h1 = s.spawn(|| respond_handshake(&mut t_ab_r, &kp_b_copy).unwrap());
            let h2 = s.spawn(|| respond_handshake(&mut t_ac_r, &kp_c_copy).unwrap());
            let h3 = s.spawn(|| initiate_handshake(&mut t_ab_i, &kp_a, None).unwrap());
            let h4 = s.spawn(|| initiate_handshake(&mut t_ac_i, &kp_a2, None).unwrap());
            h1.join().unwrap();
            h2.join().unwrap();
            (h3.join().unwrap(), h4.join().unwrap())
        });

        assert_ne!(
            ab.session_key.as_bytes(),
            ac.session_key.as_bytes(),
            "different peer pairs must produce different session keys"
        );
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    /// Transport that returns a fixed response, useful for testing error conditions.
    struct MockTransport {
        recv_data: Vec<u8>,
        sent: Vec<Vec<u8>>,
    }

    impl MockTransport {
        fn new(recv_data: Vec<u8>) -> Self {
            Self { recv_data, sent: Vec::new() }
        }
    }

    impl Transport for MockTransport {
        fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
            self.sent.push(data.to_vec());
            Ok(())
        }
        fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            Ok(self.recv_data.clone())
        }
    }

    /// Transport that fails on recv
    struct FailingRecvTransport;

    impl Transport for FailingRecvTransport {
        fn send(&mut self, _data: &[u8]) -> Result<(), KrakenError> {
            Ok(())
        }
        fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            Err(KrakenError::internal("network error"))
        }
    }

    /// Transport that fails on send
    struct FailingSendTransport;

    impl Transport for FailingSendTransport {
        fn send(&mut self, _data: &[u8]) -> Result<(), KrakenError> {
            Err(KrakenError::internal("send failed"))
        }
        fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            Ok(vec![0u8; 32])
        }
    }

    #[test]
    fn test_invalid_public_key_length_too_short() {
        let our_kp = crypto::generate_keypair().unwrap();
        let mut transport = MockTransport::new(vec![0u8; 16]); // Too short

        let result = initiate_handshake(&mut transport, &our_kp, None);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("invalid peer public key length"));
        }
    }

    #[test]
    fn test_invalid_public_key_length_too_long() {
        let our_kp = crypto::generate_keypair().unwrap();
        let mut transport = MockTransport::new(vec![0u8; 64]); // Too long

        let result = initiate_handshake(&mut transport, &our_kp, None);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("invalid peer public key length"));
        }
    }

    #[test]
    fn test_empty_public_key() {
        let our_kp = crypto::generate_keypair().unwrap();
        let mut transport = MockTransport::new(vec![]); // Empty

        let result = initiate_handshake(&mut transport, &our_kp, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_responder_invalid_key_length() {
        let our_kp = crypto::generate_keypair().unwrap();
        let mut transport = MockTransport::new(vec![0xAB; 31]); // One byte short

        let result = respond_handshake(&mut transport, &our_kp);
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_recv_failure_initiator() {
        let our_kp = crypto::generate_keypair().unwrap();
        let mut transport = FailingRecvTransport;

        let result = initiate_handshake(&mut transport, &our_kp, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_recv_failure_responder() {
        let our_kp = crypto::generate_keypair().unwrap();
        let mut transport = FailingRecvTransport;

        let result = respond_handshake(&mut transport, &our_kp);
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_send_failure_initiator() {
        let our_kp = crypto::generate_keypair().unwrap();
        let mut transport = FailingSendTransport;

        let result = initiate_handshake(&mut transport, &our_kp, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_key_verification_exact_match() {
        let our_kp = crypto::generate_keypair().unwrap();
        let peer_kp = crypto::generate_keypair().unwrap();

        // Transport returns the expected peer key
        let mut transport = MockTransport::new(peer_kp.0.as_bytes().to_vec());

        // Should succeed when we expect the exact key we receive
        let result = initiate_handshake(&mut transport, &our_kp, Some(&peer_kp.0));
        assert!(result.is_ok());
    }

    #[test]
    fn test_initiator_sends_correct_public_key() {
        let our_kp = crypto::generate_keypair().unwrap();
        let peer_kp = crypto::generate_keypair().unwrap();

        let mut transport = MockTransport::new(peer_kp.0.as_bytes().to_vec());

        let _ = initiate_handshake(&mut transport, &our_kp, None);

        // Verify we sent our public key
        assert_eq!(transport.sent.len(), 1);
        assert_eq!(transport.sent[0].as_slice(), our_kp.0.as_bytes());
    }

    #[test]
    fn test_responder_sends_correct_public_key() {
        let our_kp = crypto::generate_keypair().unwrap();
        let peer_kp = crypto::generate_keypair().unwrap();

        let mut transport = MockTransport::new(peer_kp.0.as_bytes().to_vec());

        let _ = respond_handshake(&mut transport, &our_kp);

        // Verify we sent our public key
        assert_eq!(transport.sent.len(), 1);
        assert_eq!(transport.sent[0].as_slice(), our_kp.0.as_bytes());
    }

    #[test]
    fn test_session_key_is_32_bytes() {
        let our_kp = crypto::generate_keypair().unwrap();
        let peer_kp = crypto::generate_keypair().unwrap();

        let mut transport = MockTransport::new(peer_kp.0.as_bytes().to_vec());

        let result = initiate_handshake(&mut transport, &our_kp, None).unwrap();

        assert_eq!(result.session_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_all_zero_peer_key_handling() {
        // All-zero public key is a low-order point edge case
        let our_kp = crypto::generate_keypair().unwrap();
        let zero_key = vec![0u8; 32];

        let mut transport = MockTransport::new(zero_key);

        // The handshake may succeed but produces a weak key
        // This test verifies the code doesn't panic
        let _ = initiate_handshake(&mut transport, &our_kp, None);
    }

    #[test]
    fn test_handshake_result_contains_peer_key() {
        let our_kp = crypto::generate_keypair().unwrap();
        let peer_kp = crypto::generate_keypair().unwrap();

        let mut transport = MockTransport::new(peer_kp.0.as_bytes().to_vec());

        let result = initiate_handshake(&mut transport, &our_kp, None).unwrap();

        assert_eq!(
            result.peer_public_key.as_bytes(),
            peer_kp.0.as_bytes(),
            "result must contain the peer's public key"
        );
    }
}
