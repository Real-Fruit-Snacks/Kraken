//! Kraken Config - Build-time configuration baking

pub mod bake;
pub mod profile;
pub mod profile_compile;
pub mod types;

pub use bake::*;
pub use profile::*;
pub use profile_compile::*;
pub use types::*;

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use insta::{assert_json_snapshot, assert_snapshot};

    #[test]
    fn test_default_implant_config_toml() {
        let config = ImplantConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert_snapshot!("default_implant_config_toml", toml_str);
    }

    #[test]
    fn test_default_implant_config_json() {
        let config = ImplantConfig::default();
        assert_json_snapshot!("default_implant_config_json", config);
    }

    #[test]
    fn test_full_implant_config_toml() {
        let config = ImplantConfig {
            server_public_key: "abc123def456".to_string(),
            transports: vec![
                TransportConfig {
                    transport_type: TransportType::Https,
                    address: "https://primary.c2.example.com:443".to_string(),
                    cert_pin: Some("deadbeef".to_string()),
                    proxy: None,
                    dns: None,
                    domain_front_host: None,
                },
                TransportConfig {
                    transport_type: TransportType::Dns,
                    address: "8.8.8.8:53".to_string(),
                    cert_pin: None,
                    proxy: Some(ProxyConfig {
                        proxy_type: ProxyType::Socks5,
                        address: "127.0.0.1:9050".to_string(),
                        username: Some("user".to_string()),
                        password: Some("pass".to_string()),
                    }),
                    dns: Some(DnsTransportConfig {
                        domain: "c2.example.com".to_string(),
                        ..Default::default()
                    }),
                    domain_front_host: None,
                },
            ],
            profile: ProfileConfig::default(),
            checkin_interval: 300,
            jitter_percent: 30,
            max_retries: 5,
            kill_date: 1735689600, // 2025-01-01
            working_hours: Some(WorkingHours {
                start_hour: 9,
                end_hour: 17,
                days: vec![1, 2, 3, 4, 5], // Mon-Fri
                timezone_offset: -5,
            }),
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert_snapshot!("full_implant_config_toml", toml_str);
    }

    #[test]
    fn test_transport_types_json() {
        let types = vec![
            TransportType::Http,
            TransportType::Https,
            TransportType::Tcp,
            TransportType::Dns,
        ];
        assert_json_snapshot!("transport_types", types);
    }

    #[test]
    fn test_transform_types_json() {
        let transforms = vec![
            Transform::None,
            Transform::Base64,
            Transform::Base64Url,
            Transform::Hex,
        ];
        assert_json_snapshot!("transform_types", transforms);
    }
}
