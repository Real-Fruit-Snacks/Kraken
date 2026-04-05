//! Module signing — Ed25519 key pair management and blob signing/building.

use common::{KrakenError, ModuleBlobHeader, ARCH_X64_WINDOWS, ARCH_X64_LINUX, ARCH_ARM64_WINDOWS, ARCH_ARM64_LINUX};
use ring::signature::{Ed25519KeyPair, KeyPair};

// ---------------------------------------------------------------------------
// ModuleSigner
// ---------------------------------------------------------------------------

/// Server-side Ed25519 signer for module blobs.
pub struct ModuleSigner {
    keypair: Ed25519KeyPair,
}

impl ModuleSigner {
    /// Generate a fresh PKCS#8-encoded Ed25519 key pair.
    ///
    /// The returned bytes can be persisted and later passed to [`ModuleSigner::new`].
    pub fn generate_pkcs8() -> Result<Vec<u8>, KrakenError> {
        use ring::rand::SystemRandom;
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| KrakenError::Crypto("failed to generate Ed25519 key pair".into()))?;
        Ok(pkcs8.as_ref().to_vec())
    }

    /// Create a new signer from a PKCS#8-encoded private key.
    pub fn new(private_key: &[u8]) -> Result<Self, KrakenError> {
        let keypair = Ed25519KeyPair::from_pkcs8(private_key)
            .map_err(|_| KrakenError::Crypto("invalid signing key".into()))?;
        Ok(Self { keypair })
    }

    /// Return the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key is always 32 bytes")
    }

    /// Sign an unsigned blob buffer.
    ///
    /// The blob must have a valid `ModuleBlobHeader` at byte 0. The signature
    /// is computed over the entire `blob_without_sig` slice and appended via
    /// the wire layout used by `ModuleBlob`:
    ///
    /// ```text
    /// [ header ][ module_id ][ module_name ][ sig_len (4 B LE) ][ signature ][ code ]
    /// ```
    ///
    /// `blob_without_sig` is expected to contain everything **except** the
    /// `sig_len` prefix and the signature bytes — i.e.:
    ///
    /// ```text
    /// [ header ][ module_id ][ module_name ][ code ]
    /// ```
    ///
    /// The function inserts `sig_len || signature` between the strings and
    /// the code section.
    pub fn sign(&self, blob_without_sig: &[u8]) -> Result<Vec<u8>, KrakenError> {
        if blob_without_sig.len() < ModuleBlobHeader::SIZE {
            return Err(KrakenError::InvalidModuleBlob);
        }

        // Read header fields via pointer cast (packed struct — read by copy).
        let header = unsafe { &*(blob_without_sig.as_ptr() as *const ModuleBlobHeader) };
        header.validate()?;

        let id_len = header.module_id_len as usize;
        let name_len = header.module_name_len as usize;

        // Insertion point: just after header + id + name.
        let insert_at = ModuleBlobHeader::SIZE + id_len + name_len;
        if blob_without_sig.len() < insert_at {
            return Err(KrakenError::InvalidModuleBlob);
        }

        // Sign the entire unsigned blob.
        let signature = self.keypair.sign(blob_without_sig);
        let sig_bytes = signature.as_ref();
        let sig_len = sig_bytes.len() as u32;

        // Build signed blob: prefix + sig_len (4 B LE) + signature + remainder.
        let mut signed = Vec::with_capacity(blob_without_sig.len() + 4 + sig_bytes.len());
        signed.extend_from_slice(&blob_without_sig[..insert_at]);
        signed.extend_from_slice(&sig_len.to_le_bytes());
        signed.extend_from_slice(sig_bytes);
        signed.extend_from_slice(&blob_without_sig[insert_at..]);

        Ok(signed)
    }
}

// ---------------------------------------------------------------------------
// build_unsigned_blob
// ---------------------------------------------------------------------------

/// Construct an unsigned module blob from raw compiled code.
///
/// Layout produced:
/// ```text
/// [ header (80 B) ][ module_id bytes ][ module_name bytes ][ code ]
/// ```
///
/// `version` is `(major, minor, patch)`.
pub fn build_unsigned_blob(
    module_id: &str,
    module_name: &str,
    version: (u8, u8, u8),
    arch: u8,
    flags: u8,
    code: &[u8],
    entry_offset: u32,
) -> Vec<u8> {
    let compiled_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let header = ModuleBlobHeader {
        magic: ModuleBlobHeader::MAGIC,
        format_version: ModuleBlobHeader::CURRENT_VERSION,
        arch,
        flags,
        module_id_len: module_id.len() as u16,
        module_name_len: module_name.len() as u16,
        version: pack_version(version),
        code_size: code.len() as u32,
        entry_offset,
        min_implant_version: pack_version((0, 1, 0)),
        compiled_at,
        reserved: [0u8; 44],
    };

    let mut blob = Vec::with_capacity(ModuleBlobHeader::SIZE + module_id.len() + module_name.len() + code.len());

    // Header bytes.
    blob.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&header as *const _ as *const u8, ModuleBlobHeader::SIZE)
    });

    // Strings (no null terminator — lengths are stored in header).
    blob.extend_from_slice(module_id.as_bytes());
    blob.extend_from_slice(module_name.as_bytes());

    // Code section.
    blob.extend_from_slice(code);

    blob
}

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------

/// Map a Rust target triple to the corresponding `ARCH_*` constant.
pub fn arch_for_platform(platform: &str) -> Result<u8, KrakenError> {
    match platform {
        "x86_64-pc-windows-gnu" | "x86_64-pc-windows-msvc" => Ok(ARCH_X64_WINDOWS),
        "x86_64-unknown-linux-gnu" => Ok(ARCH_X64_LINUX),
        "aarch64-pc-windows-msvc" => Ok(ARCH_ARM64_WINDOWS),
        "aarch64-unknown-linux-gnu" => Ok(ARCH_ARM64_LINUX),
        other => Err(KrakenError::Module(format!("unsupported platform: {}", other))),
    }
}

// ---------------------------------------------------------------------------
// pack_version helper
// ---------------------------------------------------------------------------

/// Pack `(major, minor, patch)` into a single `u32`.
///
/// Layout: `(major as u32) << 16 | (minor as u32) << 8 | patch as u32`
pub fn pack_version((major, minor, patch): (u8, u8, u8)) -> u32 {
    ((major as u32) << 16) | ((minor as u32) << 8) | (patch as u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_version_roundtrip() {
        let packed = pack_version((1, 2, 3));
        assert_eq!((packed >> 16) & 0xFF, 1);
        assert_eq!((packed >> 8) & 0xFF, 2);
        assert_eq!(packed & 0xFF, 3);
    }

    #[test]
    fn arch_for_platform_known() {
        assert_eq!(arch_for_platform("x86_64-unknown-linux-gnu").unwrap(), ARCH_X64_LINUX);
        assert_eq!(arch_for_platform("x86_64-pc-windows-msvc").unwrap(), ARCH_X64_WINDOWS);
        assert_eq!(arch_for_platform("aarch64-unknown-linux-gnu").unwrap(), ARCH_ARM64_LINUX);
    }

    #[test]
    fn arch_for_platform_unknown() {
        assert!(arch_for_platform("wasm32-unknown-unknown").is_err());
    }

    #[test]
    fn build_unsigned_blob_structure() {
        let code = vec![0xCC; 16];
        let blob = build_unsigned_blob("test.mod", "Test Module", (1, 0, 0), ARCH_X64_LINUX, 0, &code, 0);
        assert!(blob.len() >= ModuleBlobHeader::SIZE);
        assert_eq!(&blob[0..4], b"KMOD");
    }
}
