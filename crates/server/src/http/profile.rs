//! Profile-based HTTP transforms for server-side request/response handling
//!
//! Validates incoming requests against profile expectations and applies
//! encoding transforms to request bodies and response bodies.

use axum::http::HeaderMap;
use config::{ProfileConfig, Transform};

/// Validate that incoming request headers match the profile
///
/// Returns `false` if:
/// - User-Agent doesn't match
/// - Required headers are missing or have wrong values
pub fn validate_request(profile: &ProfileConfig, headers: &HeaderMap) -> bool {
    // Check User-Agent
    match headers.get("User-Agent") {
        Some(ua) => {
            if ua.to_str().unwrap_or("") != profile.user_agent {
                tracing::debug!(
                    expected = %profile.user_agent,
                    received = ?ua,
                    "user-agent mismatch"
                );
                return false;
            }
        }
        None => {
            tracing::debug!("missing user-agent header");
            return false;
        }
    }

    // Check required request headers
    for (name, expected_value) in &profile.request_headers {
        match headers.get(name.as_str()) {
            Some(actual) => {
                if actual.to_str().unwrap_or("") != expected_value {
                    tracing::debug!(
                        header = %name,
                        expected = %expected_value,
                        received = ?actual,
                        "header value mismatch"
                    );
                    return false;
                }
            }
            None => {
                tracing::debug!(header = %name, "missing required header");
                return false;
            }
        }
    }

    true
}

/// Decode request body according to profile transform
pub fn decode_request(profile: &ProfileConfig, body: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_transform(&profile.request_transform, body)
}

/// Encode response body according to profile transform
pub fn encode_response(profile: &ProfileConfig, data: &[u8]) -> Vec<u8> {
    encode_transform(&profile.response_transform, data)
}

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
pub fn decode_transform(transform: &Transform, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    match transform {
        Transform::None => Ok(data.to_vec()),
        Transform::Base64 => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            STANDARD
                .decode(data)
                .map_err(|e| DecodeError::Base64(e.to_string()))
        }
        Transform::Base64Url => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            URL_SAFE_NO_PAD
                .decode(data)
                .map_err(|e| DecodeError::Base64Url(e.to_string()))
        }
        Transform::Hex => hex::decode(data).map_err(|e| DecodeError::Hex(e.to_string())),
    }
}

/// Errors that can occur during decode operations
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("base64 decode failed: {0}")]
    Base64(String),

    #[error("base64url decode failed: {0}")]
    Base64Url(String),

    #[error("hex decode failed: {0}")]
    Hex(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn default_profile() -> ProfileConfig {
        ProfileConfig::default()
    }

    #[test]
    fn test_validate_request_success() {
        let profile = default_profile();
        let mut headers = HeaderMap::new();
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(&profile.user_agent).unwrap(),
        );
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );

        assert!(validate_request(&profile, &headers));
    }

    #[test]
    fn test_validate_request_wrong_user_agent() {
        let profile = default_profile();
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", HeaderValue::from_static("curl/7.68.0"));
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );

        assert!(!validate_request(&profile, &headers));
    }

    #[test]
    fn test_validate_request_missing_header() {
        let profile = default_profile();
        let mut headers = HeaderMap::new();
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(&profile.user_agent).unwrap(),
        );
        // Missing Accept and Accept-Language

        assert!(!validate_request(&profile, &headers));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"test payload with \x00 binary \xff data";

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
    fn test_base64_encoding() {
        let data = b"hello";
        let encoded = encode_transform(&Transform::Base64, data);
        assert_eq!(encoded, b"aGVsbG8=");
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"\xca\xfe\xba\xbe";
        let encoded = encode_transform(&Transform::Hex, data);
        assert_eq!(encoded, b"cafebabe");
    }
}
