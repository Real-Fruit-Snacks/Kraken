//! TransportChain - Resilient transport with automatic fallback
//!
//! Manages multiple transports and automatically fails over to the next
//! available transport when one fails. Wraps around to retry from the
//! beginning after cycling through all transports.

use common::{KrakenError, Transport};
use tracing::{debug, warn};

/// Chain of transports with automatic fallback
///
/// Tries each transport in order. On failure, advances to the next transport.
/// After a full cycle with no success, returns `AllTransportsFailed`.
pub struct TransportChain {
    transports: Vec<Box<dyn Transport>>,
    current_index: usize,
    /// Number of consecutive failures on current transport before switching
    failure_threshold: usize,
    /// Current consecutive failure count
    consecutive_failures: usize,
}

impl TransportChain {
    /// Create a new transport chain from a list of transports
    ///
    /// # Arguments
    /// * `transports` - Ordered list of transports (first = primary)
    ///
    /// # Panics
    /// Panics if `transports` is empty
    pub fn new(transports: Vec<Box<dyn Transport>>) -> Self {
        assert!(
            !transports.is_empty(),
            "TransportChain requires at least one transport"
        );

        Self {
            transports,
            current_index: 0,
            failure_threshold: 3,
            consecutive_failures: 0,
        }
    }

    /// Create a transport chain with custom failure threshold
    #[cfg(test)]
    pub fn with_threshold(transports: Vec<Box<dyn Transport>>, threshold: usize) -> Self {
        let mut chain = Self::new(transports);
        chain.failure_threshold = threshold;
        chain
    }

    /// Exchange data with the server, with automatic fallback
    ///
    /// Tries the current transport first. On failure, advances through the
    /// chain until success or all transports have been tried.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Response data on success
    /// * `Err(AllTransportsFailed)` - All transports failed after full cycle
    pub fn exchange(&mut self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        let num_transports = self.transports.len();
        let mut transports_exhausted = 0; // Count of transports that hit threshold

        loop {
            let transport = &self.transports[self.current_index];
            let transport_id = transport.id();

            // Check if transport reports itself as available
            if !transport.is_available() {
                debug!(
                    transport = transport_id,
                    "transport not available, skipping"
                );
                transports_exhausted += 1;
                self.advance_transport();

                if transports_exhausted >= num_transports {
                    warn!("all transports unavailable");
                    return Err(KrakenError::AllTransportsFailed);
                }
                continue;
            }

            // Attempt exchange
            match transport.exchange(data) {
                Ok(response) => {
                    debug!(
                        transport = transport_id,
                        response_len = response.len(),
                        "transport exchange successful"
                    );
                    self.consecutive_failures = 0;
                    return Ok(response);
                }
                Err(e) => {
                    warn!(
                        transport = transport_id,
                        error = %e,
                        consecutive = self.consecutive_failures + 1,
                        "transport exchange failed"
                    );

                    self.consecutive_failures += 1;

                    // Only advance after threshold failures
                    if self.consecutive_failures >= self.failure_threshold {
                        transports_exhausted += 1;
                        self.advance_transport();
                        self.consecutive_failures = 0;

                        // Check if we've exhausted all transports
                        if transports_exhausted >= num_transports {
                            warn!(
                                transports_tried = num_transports,
                                "all transports failed after full cycle"
                            );
                            return Err(KrakenError::AllTransportsFailed);
                        }
                    }
                }
            }
        }
    }

    /// Advance to the next transport in the chain (wraps around)
    fn advance_transport(&mut self) {
        let old_index = self.current_index;
        self.current_index = (self.current_index + 1) % self.transports.len();

        // Reset the old transport's state
        if let Some(transport) = self.transports.get_mut(old_index) {
            transport.reset();
        }

        debug!(
            from = old_index,
            to = self.current_index,
            transport = self.transports[self.current_index].id(),
            "advanced to next transport"
        );
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Mock transport for testing
    struct MockTransport {
        id: &'static str,
        should_fail: Arc<AtomicBool>,
        call_count: Arc<AtomicUsize>,
        available: Arc<AtomicBool>,
    }

    impl MockTransport {
        fn new(id: &'static str) -> Self {
            Self {
                id,
                should_fail: Arc::new(AtomicBool::new(false)),
                call_count: Arc::new(AtomicUsize::new(0)),
                available: Arc::new(AtomicBool::new(true)),
            }
        }

        fn set_fail(&self, fail: bool) {
            self.should_fail.store(fail, Ordering::SeqCst);
        }

        fn set_available(&self, available: bool) {
            self.available.store(available, Ordering::SeqCst);
        }
    }

    impl Transport for MockTransport {
        fn id(&self) -> &'static str {
            self.id
        }

        fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);

            if self.should_fail.load(Ordering::SeqCst) {
                Err(KrakenError::transport("mock failure"))
            } else {
                // Echo back with prefix
                let mut response = b"OK:".to_vec();
                response.extend_from_slice(data);
                Ok(response)
            }
        }

        fn is_available(&self) -> bool {
            self.available.load(Ordering::SeqCst)
        }

        fn reset(&mut self) {
            // No state to reset
        }
    }

    #[test]
    fn test_single_transport_success() {
        let transport = Box::new(MockTransport::new("http"));
        let mut chain = TransportChain::new(vec![transport]);

        let result = chain.exchange(b"hello");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"OK:hello");
    }

    #[test]
    fn test_fallback_on_failure() {
        let t1 = MockTransport::new("http");
        t1.set_fail(true);
        let t1_calls = t1.call_count.clone();

        let t2 = MockTransport::new("https");
        let t2_calls = t2.call_count.clone();

        let mut chain = TransportChain::with_threshold(
            vec![Box::new(t1), Box::new(t2)],
            1, // Fail over after 1 failure
        );

        let result = chain.exchange(b"test");
        assert!(result.is_ok());

        // First transport should have been tried once
        assert_eq!(t1_calls.load(Ordering::SeqCst), 1);
        // Second transport should have succeeded
        assert_eq!(t2_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_all_transports_fail() {
        let t1 = MockTransport::new("http");
        t1.set_fail(true);

        let t2 = MockTransport::new("https");
        t2.set_fail(true);

        let mut chain = TransportChain::with_threshold(vec![Box::new(t1), Box::new(t2)], 1);

        let result = chain.exchange(b"test");
        assert!(matches!(result, Err(KrakenError::AllTransportsFailed)));
    }

    #[test]
    fn test_skip_unavailable_transport() {
        let t1 = MockTransport::new("http");
        t1.set_available(false);
        let t1_calls = t1.call_count.clone();

        let t2 = MockTransport::new("https");
        let t2_calls = t2.call_count.clone();

        let mut chain = TransportChain::new(vec![Box::new(t1), Box::new(t2)]);

        let result = chain.exchange(b"test");
        assert!(result.is_ok());

        // First transport should not have been called
        assert_eq!(t1_calls.load(Ordering::SeqCst), 0);
        // Second transport should have been called
        assert_eq!(t2_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_threshold_before_fallback() {
        let t1 = MockTransport::new("http");
        t1.set_fail(true);
        let t1_calls = t1.call_count.clone();

        let t2 = MockTransport::new("https");

        // Threshold of 3 means we try t1 three times before falling back
        let mut chain = TransportChain::with_threshold(vec![Box::new(t1), Box::new(t2)], 3);

        // This will try t1 three times, then t2 once
        let result = chain.exchange(b"test");
        assert!(result.is_ok());
        assert_eq!(t1_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    #[should_panic(expected = "requires at least one transport")]
    fn test_empty_chain_panics() {
        let _chain = TransportChain::new(vec![]);
    }
}
