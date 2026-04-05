//! Malleable C2 Profile Schema
//!
//! Defines the structure for malleable profiles that customize HTTP traffic patterns
//! to evade network-based detection. Inspired by Cobalt Strike's malleable C2 profiles.

use serde::{Deserialize, Serialize};

/// Complete malleable profile definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalleableProfile {
    /// Profile name (e.g., "amazon", "outlook")
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: String,

    /// Global settings applied to all transactions
    #[serde(default)]
    pub global: GlobalSettings,

    /// HTTP GET transaction settings (beacon check-in)
    #[serde(default)]
    pub http_get: HttpSettings,

    /// HTTP POST transaction settings (task results)
    #[serde(default)]
    pub http_post: HttpSettings,

    /// HTTPS-specific overrides
    #[serde(default)]
    pub https: Option<HttpsSettings>,

    /// Staging configuration (initial payload delivery)
    #[serde(default)]
    pub stage: Option<StageSettings>,
}

impl Default for MalleableProfile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: "Default malleable profile".to_string(),
            global: GlobalSettings::default(),
            http_get: HttpSettings::default_get(),
            http_post: HttpSettings::default_post(),
            https: None,
            stage: None,
        }
    }
}

/// Global settings applied across all HTTP transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    /// Jitter percentage (0-100) for callback timing randomization
    #[serde(default = "default_jitter")]
    pub jitter: u8,

    /// Sleep time in seconds between callbacks
    #[serde(default = "default_sleeptime")]
    pub sleeptime: u32,

    /// User-Agent header value
    #[serde(default = "default_useragent")]
    pub useragent: String,

    /// DNS idle IP address (returned when no tasks pending)
    #[serde(default = "default_dns_idle")]
    pub dns_idle: String,

    /// Named pipe name for SMB beacon
    #[serde(default = "default_pipename")]
    pub pipename: String,

    /// Maximum DNS TXT record data size
    #[serde(default = "default_maxdns")]
    pub maxdns: usize,

    /// Data jitter - random bytes to append (0-100)
    #[serde(default)]
    pub data_jitter: u8,
}

fn default_jitter() -> u8 {
    20
}

fn default_sleeptime() -> u32 {
    60
}

fn default_useragent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
}

fn default_dns_idle() -> String {
    "0.0.0.0".to_string()
}

fn default_pipename() -> String {
    "\\\\.\\pipe\\msagent_##".to_string()
}

fn default_maxdns() -> usize {
    255
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            jitter: default_jitter(),
            sleeptime: default_sleeptime(),
            useragent: default_useragent(),
            dns_idle: default_dns_idle(),
            pipename: default_pipename(),
            maxdns: default_maxdns(),
            data_jitter: 0,
        }
    }
}

/// HTTP transaction settings (GET or POST)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSettings {
    /// URI paths to use (randomly selected)
    #[serde(default = "default_uris")]
    pub uris: Vec<String>,

    /// HTTP verb (GET, POST, PUT, etc.)
    #[serde(default = "default_verb")]
    pub verb: String,

    /// HTTP headers to include
    #[serde(default)]
    pub headers: Vec<HttpHeader>,

    /// Client-side data transformation (beacon -> server)
    #[serde(default)]
    pub client: DataTransform,

    /// Server-side data transformation (server -> beacon)
    #[serde(default)]
    pub server: DataTransform,
}

fn default_uris() -> Vec<String> {
    vec!["/api/v1/status".to_string()]
}

fn default_verb() -> String {
    "GET".to_string()
}

impl HttpSettings {
    pub fn default_get() -> Self {
        Self {
            uris: vec!["/api/v1/beacon".to_string()],
            verb: "GET".to_string(),
            headers: vec![
                HttpHeader {
                    name: "Accept".to_string(),
                    value: "application/json".to_string(),
                },
                HttpHeader {
                    name: "Accept-Language".to_string(),
                    value: "en-US,en;q=0.9".to_string(),
                },
            ],
            client: DataTransform::default(),
            server: DataTransform::default(),
        }
    }

    pub fn default_post() -> Self {
        Self {
            uris: vec!["/api/v1/submit".to_string()],
            verb: "POST".to_string(),
            headers: vec![
                HttpHeader {
                    name: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                },
                HttpHeader {
                    name: "Accept".to_string(),
                    value: "application/json".to_string(),
                },
            ],
            client: DataTransform::default(),
            server: DataTransform::default(),
        }
    }
}

impl Default for HttpSettings {
    fn default() -> Self {
        Self::default_get()
    }
}

/// HTTP header definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    /// Header name
    pub name: String,

    /// Header value
    pub value: String,
}

/// Data transformation pipeline
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataTransform {
    /// Ordered list of transforms to apply
    #[serde(default)]
    pub transforms: Vec<TransformStep>,

    /// Where to place the transformed data
    #[serde(default)]
    pub output: OutputLocation,
}

/// Individual transform operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum TransformStep {
    /// Base64 encode (standard alphabet)
    Base64,

    /// Base64 URL-safe encode
    Base64Url,

    /// Hex encode
    Hex,

    /// XOR with key
    Xor {
        /// XOR key (hex-encoded)
        key: String,
    },

    /// Prepend string
    Prepend {
        /// String to prepend
        data: String,
    },

    /// Append string
    Append {
        /// String to append
        data: String,
    },

    /// NetBIOS encode (uppercase 'a' variant)
    NetBios,

    /// NetBIOS encode (lowercase 'a' variant)
    NetBiosLower,

    /// Mask with random key (XOR + prepend key)
    Mask,

    /// Reverse byte order
    Reverse,
}

/// Where to output transformed data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum OutputLocation {
    /// Place in HTTP body
    Body,

    /// Place in URI parameter
    #[serde(rename = "UriParam")]
    UriParam {
        /// Parameter name
        name: String,
    },

    /// Place in HTTP header
    Header {
        /// Header name
        name: String,
    },

    /// Place in Cookie
    Cookie {
        /// Cookie name
        name: String,
    },

    /// Print data (for debugging, discards output)
    Print,
}

impl Default for OutputLocation {
    fn default() -> Self {
        OutputLocation::Body
    }
}

/// HTTPS-specific settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpsSettings {
    /// Override URIs for HTTPS
    #[serde(default)]
    pub uris: Option<Vec<String>>,

    /// Additional headers for HTTPS
    #[serde(default)]
    pub headers: Vec<HttpHeader>,

    /// TLS certificate to use (PEM)
    #[serde(default)]
    pub certificate: Option<String>,

    /// TLS private key (PEM)
    #[serde(default)]
    pub private_key: Option<String>,
}

/// Staging configuration for initial payload delivery
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StageSettings {
    /// Obfuscate the payload
    #[serde(default)]
    pub obfuscate: bool,

    /// Use self-signed certificate for staging
    #[serde(default)]
    pub userwx: bool,

    /// Transform for stage data
    #[serde(default)]
    pub transform: Vec<TransformStep>,
}

impl MalleableProfile {
    /// Load profile from TOML string
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Load profile from TOML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::from_toml(&content)?)
    }

    /// Serialize profile to TOML
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Get a random URI for the specified transaction type
    pub fn random_uri(&self, is_post: bool) -> &str {
        let settings = if is_post {
            &self.http_post
        } else {
            &self.http_get
        };

        if settings.uris.is_empty() {
            "/api/v1/beacon"
        } else {
            // In practice, use a random selection
            &settings.uris[0]
        }
    }

    /// Validate profile configuration
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.name.is_empty() {
            errors.push("Profile name cannot be empty".to_string());
        }

        if self.global.jitter > 100 {
            errors.push("Jitter must be between 0 and 100".to_string());
        }

        if self.http_get.uris.is_empty() {
            errors.push("HTTP GET must have at least one URI".to_string());
        }

        if self.http_post.uris.is_empty() {
            errors.push("HTTP POST must have at least one URI".to_string());
        }

        // Validate transforms
        for (i, transform) in self.http_get.client.transforms.iter().enumerate() {
            if let TransformStep::Xor { key } = transform {
                if hex::decode(key).is_err() {
                    errors.push(format!(
                        "HTTP GET client transform {}: XOR key must be valid hex",
                        i
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_profile() {
        let profile = MalleableProfile::default();
        assert_eq!(profile.name, "default");
        assert!(!profile.http_get.uris.is_empty());
        assert!(!profile.http_post.uris.is_empty());
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml = r#"
            name = "test"
            description = "Test profile"
        "#;

        let profile = MalleableProfile::from_toml(toml).unwrap();
        assert_eq!(profile.name, "test");
        assert_eq!(profile.global.jitter, 20);
    }

    #[test]
    fn test_parse_full_toml() {
        let toml = r#"
            name = "amazon"
            description = "Mimics Amazon traffic"

            [global]
            jitter = 25
            sleeptime = 120
            useragent = "Mozilla/5.0 Test"

            [http_get]
            uris = ["/s/ref=nb_sb_noss", "/gp/product"]
            verb = "GET"

            [[http_get.headers]]
            name = "Accept"
            value = "text/html"

            [http_get.client]
            transforms = [
                { type = "Base64Url" },
                { type = "Prepend", data = "session=" }
            ]

            [http_get.client.output]
            type = "Cookie"
            name = "session-id"
        "#;

        let profile = MalleableProfile::from_toml(toml).unwrap();
        assert_eq!(profile.name, "amazon");
        assert_eq!(profile.global.jitter, 25);
        assert_eq!(profile.http_get.uris.len(), 2);
        assert_eq!(profile.http_get.client.transforms.len(), 2);

        if let OutputLocation::Cookie { name } = &profile.http_get.client.output {
            assert_eq!(name, "session-id");
        } else {
            panic!("Expected Cookie output");
        }
    }

    #[test]
    fn test_validation() {
        let mut profile = MalleableProfile::default();
        assert!(profile.validate().is_ok());

        profile.name = String::new();
        assert!(profile.validate().is_err());

        profile.name = "test".to_string();
        profile.global.jitter = 150;
        let errors = profile.validate().unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Jitter")));
    }

    #[test]
    fn test_transform_serialization() {
        let transform = TransformStep::Xor {
            key: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&transform).unwrap();
        assert!(json.contains("Xor"));
        assert!(json.contains("deadbeef"));
    }

    #[test]
    fn test_parse_amazon_profile() {
        let toml = include_str!("../../../profiles/amazon.toml");
        let profile = MalleableProfile::from_toml(toml).expect("Failed to parse amazon.toml");
        assert_eq!(profile.name, "amazon");
        assert_eq!(profile.global.jitter, 20);
        assert_eq!(profile.global.sleeptime, 60);
        assert!(!profile.http_get.uris.is_empty());
        assert!(!profile.http_post.uris.is_empty());
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_parse_outlook_profile() {
        let toml = include_str!("../../../profiles/outlook.toml");
        let profile = MalleableProfile::from_toml(toml).expect("Failed to parse outlook.toml");
        assert_eq!(profile.name, "outlook");
        assert_eq!(profile.global.jitter, 15);
        assert!(!profile.http_get.uris.is_empty());
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_parse_slack_profile() {
        let toml = include_str!("../../../profiles/slack.toml");
        let profile = MalleableProfile::from_toml(toml).expect("Failed to parse slack.toml");
        assert_eq!(profile.name, "slack");
        assert_eq!(profile.global.jitter, 10);
        assert!(!profile.http_get.uris.is_empty());
        assert!(profile.validate().is_ok());
    }
}
