//! Encrypted mesh connection wrapper
//!
//! Wraps a Transport with AES-256-GCM encryption using the session key
//! derived during handshake.

use std::sync::atomic::{AtomicU64, Ordering};

use common::KrakenError;
use crypto::{aes_gcm, Nonce, SymmetricKey};

use crate::handshake::Transport;

/// Direction indicator for nonce construction to prevent reuse
const NONCE_DIR_SEND: u8 = 0x01;
#[allow(dead_code)]
const NONCE_DIR_RECV: u8 = 0x02;

/// Encrypted connection wrapper that provides AES-256-GCM encryption
/// over any Transport implementation.
pub struct EncryptedConnection<T: Transport> {
    inner: T,
    session_key: SymmetricKey,
    send_counter: AtomicU64,
    recv_counter: AtomicU64,
    /// Unique connection ID to include in AAD
    connection_id: [u8; 8],
}

impl<T: Transport> EncryptedConnection<T> {
    /// Create a new encrypted connection wrapper.
    ///
    /// # Arguments
    /// * `inner` - The underlying transport
    /// * `session_key` - The shared session key from handshake
    /// * `is_initiator` - Whether we initiated the connection (affects nonce direction)
    pub fn new(inner: T, session_key: SymmetricKey, is_initiator: bool) -> Self {
        // Derive connection ID from session key so both sides have same value
        let hash = crypto::sha256(session_key.as_bytes());
        let mut connection_id = [0u8; 8];
        connection_id.copy_from_slice(&hash[..8]);

        // Initiator uses odd counters for send, responder uses even
        // This prevents any chance of nonce collision
        let (send_start, recv_start) = if is_initiator {
            (1u64, 0u64)  // Initiator sends on odd, expects even from peer
        } else {
            (0u64, 1u64)  // Responder sends on even, expects odd from peer
        };

        Self {
            inner,
            session_key,
            send_counter: AtomicU64::new(send_start),
            recv_counter: AtomicU64::new(recv_start),
            connection_id,
        }
    }

    /// Build a nonce from counter and direction
    fn build_nonce(counter: u64, direction: u8) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0] = direction;
        // Bytes 1-3 reserved
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        Nonce::from_bytes(&nonce_bytes).expect("valid nonce size")
    }

    /// Build AAD (Additional Authenticated Data) for a message
    fn build_aad(&self, counter: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16);
        aad.extend_from_slice(&self.connection_id);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad
    }

    /// Send encrypted data
    pub fn send_encrypted(&mut self, plaintext: &[u8]) -> Result<(), KrakenError> {
        // Get and increment counter (by 2 to stay in our lane)
        let counter = self.send_counter.fetch_add(2, Ordering::SeqCst);

        // Build nonce and AAD
        let nonce = Self::build_nonce(counter, NONCE_DIR_SEND);
        let aad = self.build_aad(counter);

        // Encrypt
        let ciphertext = aes_gcm::encrypt(&self.session_key, &nonce, plaintext, &aad)?;

        // Prepend counter to ciphertext so receiver can derive nonce
        let mut message = Vec::with_capacity(8 + ciphertext.len());
        message.extend_from_slice(&counter.to_be_bytes());
        message.extend_from_slice(&ciphertext);

        // Send via underlying transport
        self.inner.send(&message)
    }

    /// Receive and decrypt data
    pub fn recv_encrypted(&mut self) -> Result<Vec<u8>, KrakenError> {
        // Receive from underlying transport
        let message = self.inner.recv()?;

        if message.len() < 8 {
            return Err(KrakenError::Protocol("encrypted message too short".into()));
        }

        // Extract counter
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&message[..8]);
        let counter = u64::from_be_bytes(counter_bytes);

        // Verify counter is >= expected (prevents replay)
        let expected = self.recv_counter.load(Ordering::SeqCst);
        if counter < expected {
            return Err(KrakenError::Protocol(format!(
                "replay detected: got counter {}, expected >= {}",
                counter, expected
            )));
        }

        // Update expected counter
        self.recv_counter.store(counter + 2, Ordering::SeqCst);

        // Extract ciphertext
        let ciphertext = &message[8..];

        // Build nonce and AAD (using RECV direction since we're receiving)
        // Note: sender used SEND, but we need to match what sender built
        let nonce = Self::build_nonce(counter, NONCE_DIR_SEND);
        let aad = self.build_aad(counter);

        // Decrypt
        aes_gcm::decrypt(&self.session_key, &nonce, ciphertext, &aad)
    }

    /// Get reference to inner transport
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get mutable reference to inner transport
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume and return inner transport
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// Implement Transport trait for EncryptedConnection
impl<T: Transport> Transport for EncryptedConnection<T> {
    fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
        self.send_encrypted(data)
    }

    fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
        self.recv_encrypted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Mock transport for testing
    struct MockTransport {
        outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
        inbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    fn make_pair() -> (MockTransport, MockTransport) {
        let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a = Arc::new(Mutex::new(VecDeque::new()));

        let a = MockTransport {
            outbox: Arc::clone(&a_to_b),
            inbox: Arc::clone(&b_to_a),
        };
        let b = MockTransport {
            outbox: Arc::clone(&b_to_a),
            inbox: Arc::clone(&a_to_b),
        };
        (a, b)
    }

    impl Transport for MockTransport {
        fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
            self.outbox.lock().unwrap().push_back(data.to_vec());
            Ok(())
        }

        fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            self.inbox
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| KrakenError::Transport("no data".into()))
        }
    }

    fn make_test_key() -> SymmetricKey {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = 0x42; // Just needs to be non-zero for testing
        SymmetricKey::from_bytes(&key_bytes).unwrap()
    }

    #[test]
    fn test_encrypted_roundtrip() {
        let (t_a, t_b) = make_pair();
        let key = make_test_key();

        let mut enc_a = EncryptedConnection::new(t_a, key.clone(), true);
        let mut enc_b = EncryptedConnection::new(t_b, key, false);

        let plaintext = b"Hello, encrypted mesh!";

        // A sends to B
        enc_a.send_encrypted(plaintext).unwrap();
        let received = enc_b.recv_encrypted().unwrap();
        assert_eq!(received, plaintext);

        // B sends to A
        let response = b"Hello back!";
        enc_b.send_encrypted(response).unwrap();
        let received = enc_a.recv_encrypted().unwrap();
        assert_eq!(received, response);
    }

    #[test]
    fn test_multiple_messages() {
        let (t_a, t_b) = make_pair();
        let key = make_test_key();

        let mut enc_a = EncryptedConnection::new(t_a, key.clone(), true);
        let mut enc_b = EncryptedConnection::new(t_b, key, false);

        for i in 0..10 {
            let msg = format!("Message {}", i);
            enc_a.send_encrypted(msg.as_bytes()).unwrap();
            let received = enc_b.recv_encrypted().unwrap();
            assert_eq!(received, msg.as_bytes());
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let (t_a, t_b) = make_pair();
        let key_a = make_test_key();
        let mut key_b_bytes = [0u8; 32];
        key_b_bytes[0] = 0x99; // Different key
        let key_b = SymmetricKey::from_bytes(&key_b_bytes).unwrap();

        let mut enc_a = EncryptedConnection::new(t_a, key_a, true);
        let mut enc_b = EncryptedConnection::new(t_b, key_b, false);

        enc_a.send_encrypted(b"secret").unwrap();
        let result = enc_b.recv_encrypted();
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_concurrent_send_recv() {
        use std::sync::Barrier;
        use std::thread;

        const NUM_THREADS: usize = 10;
        const MSGS_PER_THREAD: usize = 5;
        const TOTAL_MSGS: usize = NUM_THREADS * MSGS_PER_THREAD;

        let (t_a, t_b) = make_pair();
        let key = make_test_key();

        // Wrap both sides in Arc<Mutex<>> so threads can share them
        let enc_a = Arc::new(Mutex::new(EncryptedConnection::new(t_a, key.clone(), true)));
        let enc_b = Arc::new(Mutex::new(EncryptedConnection::new(t_b, key, false)));

        // Barrier to synchronize all sender threads starting at the same time
        let barrier = Arc::new(Barrier::new(NUM_THREADS));

        // Spawn sender threads — each sends MSGS_PER_THREAD messages from A
        let mut handles = Vec::with_capacity(NUM_THREADS);
        for tid in 0..NUM_THREADS {
            let enc_a_clone = Arc::clone(&enc_a);
            let barrier_clone = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier_clone.wait(); // synchronized start
                for msg_idx in 0..MSGS_PER_THREAD {
                    let payload = format!("thread={} msg={}", tid, msg_idx);
                    enc_a_clone
                        .lock()
                        .unwrap()
                        .send_encrypted(payload.as_bytes())
                        .expect("send failed");
                }
            }));
        }

        // Wait for all senders to finish
        for h in handles {
            h.join().expect("sender thread panicked");
        }

        // Receive all messages on B side — collect into a set to verify completeness
        let mut received: Vec<String> = Vec::with_capacity(TOTAL_MSGS);
        let mut enc_b_guard = enc_b.lock().unwrap();
        for _ in 0..TOTAL_MSGS {
            let data = enc_b_guard
                .recv_encrypted()
                .expect("recv failed");
            received.push(String::from_utf8(data).expect("invalid utf8"));
        }
        drop(enc_b_guard);

        // All TOTAL_MSGS messages must have arrived without corruption
        assert_eq!(received.len(), TOTAL_MSGS, "wrong number of messages received");

        // Every received string must match the expected payload format
        for msg in &received {
            assert!(
                msg.starts_with("thread=") && msg.contains(" msg="),
                "unexpected message content: {}",
                msg
            );
        }

        // Verify the full expected set arrived (order may vary due to concurrency)
        let mut expected_set: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for tid in 0..NUM_THREADS {
            for msg_idx in 0..MSGS_PER_THREAD {
                expected_set.insert(format!("thread={} msg={}", tid, msg_idx));
            }
        }
        let received_set: std::collections::HashSet<String> =
            received.into_iter().collect();
        assert_eq!(
            received_set, expected_set,
            "received set does not match expected set"
        );
    }

    #[test]
    fn test_encrypted_high_volume_messages() {
        const MSG_COUNT: usize = 150;

        let (t_a, t_b) = make_pair();
        let key = make_test_key();

        let mut enc_a = EncryptedConnection::new(t_a, key.clone(), true);
        let mut enc_b = EncryptedConnection::new(t_b, key, false);

        // Send all messages first, then receive — exercises nonce increment across bulk traffic
        let mut sent_payloads: Vec<Vec<u8>> = Vec::with_capacity(MSG_COUNT);
        for i in 0..MSG_COUNT {
            let payload = format!("high-volume message {}", i).into_bytes();
            enc_a.send_encrypted(&payload).expect("send failed");
            sent_payloads.push(payload);
        }

        // Verify the raw outbox counters embedded in messages increment by 2 each time
        // (initiator starts at 1 and increments by 2: 1, 3, 5, …)
        {
            let outbox = enc_a.inner().outbox.lock().unwrap();
            for (idx, raw_msg) in outbox.iter().enumerate() {
                let mut counter_bytes = [0u8; 8];
                counter_bytes.copy_from_slice(&raw_msg[..8]);
                let counter = u64::from_be_bytes(counter_bytes);
                let expected_counter = 1u64 + (idx as u64) * 2;
                assert_eq!(
                    counter, expected_counter,
                    "nonce counter mismatch at message {}: got {}, want {}",
                    idx, counter, expected_counter
                );
            }
            // Confirm no two messages share the same counter (no collision)
            let counters: Vec<u64> = outbox
                .iter()
                .map(|m| {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&m[..8]);
                    u64::from_be_bytes(b)
                })
                .collect();
            let unique: std::collections::HashSet<u64> =
                counters.iter().cloned().collect();
            assert_eq!(
                unique.len(),
                MSG_COUNT,
                "nonce collision detected among {} messages",
                MSG_COUNT
            );
        }

        // Decrypt all messages on B side and verify they match what was sent
        for (i, expected) in sent_payloads.iter().enumerate() {
            let received = enc_b
                .recv_encrypted()
                .unwrap_or_else(|e| panic!("recv failed on message {}: {}", i, e));
            assert_eq!(
                &received, expected,
                "message {} payload mismatch",
                i
            );
        }
    }

    #[test]
    fn test_ciphertext_differs() {
        let (t_a, _t_b) = make_pair();
        let key = make_test_key();

        let mut enc_a = EncryptedConnection::new(t_a, key, true);

        let plaintext = b"Same message";

        // Send same message twice
        enc_a.send_encrypted(plaintext).unwrap();
        enc_a.send_encrypted(plaintext).unwrap();

        // Get the raw ciphertexts from outbox
        let outbox = enc_a.into_inner().outbox;
        let mut guard = outbox.lock().unwrap();
        let ct1 = guard.pop_front().unwrap();
        let ct2 = guard.pop_front().unwrap();

        // Ciphertexts should differ due to different nonces
        assert_ne!(ct1, ct2);
    }
}
