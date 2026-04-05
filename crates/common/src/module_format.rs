//! Module blob format types for Kraken Phase 3
//!
//! Defines the binary format used to package, identify, and verify loadable
//! modules distributed through the C2 infrastructure.

use crate::error::KrakenError;

// ---------------------------------------------------------------------------
// Architecture constants
// ---------------------------------------------------------------------------

pub const ARCH_X64_WINDOWS: u8 = 1;
pub const ARCH_X64_LINUX: u8 = 2;
pub const ARCH_ARM64_WINDOWS: u8 = 3;
pub const ARCH_ARM64_LINUX: u8 = 4;

// ---------------------------------------------------------------------------
// Flag bit positions
// ---------------------------------------------------------------------------

/// Module requires elevated privileges to load.
pub const FLAG_REQUIRES_ELEVATION: u8 = 0b0000_0001;
/// Module is only valid on Windows targets.
pub const FLAG_WINDOWS_ONLY: u8 = 0b0000_0010;
/// Module is only valid on Linux targets.
pub const FLAG_LINUX_ONLY: u8 = 0b0000_0100;

// ---------------------------------------------------------------------------
// ModuleBlobHeader
// ---------------------------------------------------------------------------

/// Fixed 80-byte header that precedes every serialised module blob.
///
/// The header is laid out in C-compatible packed form so that it can be
/// read directly from raw bytes with a single pointer cast after the magic
/// and length fields have been validated.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct ModuleBlobHeader {
    /// Must equal `ModuleBlobHeader::MAGIC` (`b"KMOD"`).
    pub magic: [u8; 4],
    /// Wire-format version; currently `ModuleBlobHeader::CURRENT_VERSION` (1).
    pub format_version: u16,
    /// Target architecture (one of the `ARCH_*` constants).
    pub arch: u8,
    /// Capability/compatibility flags (see `FLAG_*` constants).
    pub flags: u8,
    /// Byte length of the UTF-8 module identifier that follows the header.
    pub module_id_len: u16,
    /// Byte length of the human-readable module name that follows the id.
    pub module_name_len: u16,
    /// Packed semantic version: `(major << 24) | (minor << 16) | patch`.
    pub version: u32,
    /// Byte length of the executable code section.
    pub code_size: u32,
    /// Byte offset of the entry-point within the code section.
    pub entry_offset: u32,
    /// Minimum implant version required to load this module (packed semver).
    pub min_implant_version: u32,
    /// Unix timestamp (seconds) at which the blob was compiled.
    pub compiled_at: u64,
    /// Reserved for future use; must be zeroed by producers.
    pub reserved: [u8; 44],
}

impl ModuleBlobHeader {
    /// Four-byte magic number: ASCII `KMOD`.
    pub const MAGIC: [u8; 4] = *b"KMOD";

    /// The only format version this implementation understands.
    pub const CURRENT_VERSION: u16 = 1;

    /// On-wire size of the header in bytes (must equal `size_of::<Self>()`).
    pub const SIZE: usize = 80;

    /// Validate that the header is internally consistent.
    ///
    /// Checks:
    /// - magic bytes match `MAGIC`
    /// - `format_version` is `CURRENT_VERSION`
    /// - `arch` is one of the recognised architecture constants
    /// - `entry_offset` is within the declared code section
    /// - mutually-exclusive platform flags are not both set
    pub fn validate(&self) -> Result<(), KrakenError> {
        // Read packed fields into locals to avoid UB from misaligned references.
        let magic = self.magic;
        let format_version = self.format_version;
        let arch = self.arch;
        let flags = self.flags;
        let code_size = self.code_size;
        let entry_offset = self.entry_offset;

        if magic != Self::MAGIC {
            return Err(KrakenError::InvalidModuleBlob);
        }

        if format_version != Self::CURRENT_VERSION {
            return Err(KrakenError::InvalidModuleBlob);
        }

        if !matches!(
            arch,
            ARCH_X64_WINDOWS | ARCH_X64_LINUX | ARCH_ARM64_WINDOWS | ARCH_ARM64_LINUX
        ) {
            return Err(KrakenError::InvalidModuleBlob);
        }

        // entry_offset must lie within the code section.
        if entry_offset >= code_size {
            return Err(KrakenError::InvalidModuleBlob);
        }

        // windows_only and linux_only are mutually exclusive.
        if (flags & FLAG_WINDOWS_ONLY != 0) && (flags & FLAG_LINUX_ONLY != 0) {
            return Err(KrakenError::InvalidModuleBlob);
        }

        Ok(())
    }

    /// Returns `true` when the header's `arch` field matches the architecture
    /// this binary was compiled for.
    #[allow(unreachable_code)]
    pub fn arch_matches_current(&self) -> bool {
        let arch = self.arch;

        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        return arch == ARCH_X64_WINDOWS;

        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        return arch == ARCH_X64_LINUX;

        #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
        return arch == ARCH_ARM64_WINDOWS;

        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        return arch == ARCH_ARM64_LINUX;

        // Unknown host – conservatively return false.
        false
    }
}

// Compile-time assertion: the header must be exactly 80 bytes.
const _: () = assert!(
    core::mem::size_of::<ModuleBlobHeader>() == ModuleBlobHeader::SIZE,
    "ModuleBlobHeader must be exactly 80 bytes"
);

// ---------------------------------------------------------------------------
// ModuleBlob
// ---------------------------------------------------------------------------

/// A parsed, zero-copy view into a raw module blob buffer.
///
/// All fields are slices or references into the original `data` buffer passed
/// to [`ModuleBlob::parse`]; no heap allocation is required beyond the struct
/// itself.
#[derive(Debug)]
pub struct ModuleBlob<'a> {
    /// Validated, borrowed reference to the fixed-size header.
    pub header: &'a ModuleBlobHeader,
    /// UTF-8 module identifier (e.g. `"kraken.recon.portscan"`).
    pub module_id: &'a str,
    /// Human-readable module name (e.g. `"Port Scanner"`).
    pub module_name: &'a str,
    /// Raw signature bytes that cover the blob up to (but not including) this
    /// field. The signature algorithm is determined out-of-band by the loader.
    pub signature: &'a [u8],
    /// Executable code bytes; length equals `header.code_size`.
    pub code: &'a [u8],
}

impl<'a> ModuleBlob<'a> {
    /// Wire layout after the fixed header:
    ///
    /// ```text
    /// [ header (80 B) ][ module_id (module_id_len B) ][ module_name (module_name_len B) ]
    /// [ signature_len (4 B, LE u32) ][ signature (signature_len B) ][ code (code_size B) ]
    /// ```
    pub fn parse(data: &'a [u8]) -> Result<Self, KrakenError> {
        if data.len() < ModuleBlobHeader::SIZE {
            return Err(KrakenError::InvalidModuleBlob);
        }

        // SAFETY: We verified `data` is at least `SIZE` bytes.  The header is
        // `repr(C, packed)` so every byte offset is defined.  We only create a
        // shared reference, so no aliasing rules are violated.
        let header = unsafe {
            &*(data.as_ptr() as *const ModuleBlobHeader)
        };

        header.validate()?;

        let mut cursor = ModuleBlobHeader::SIZE;

        // --- module_id ---
        let id_len = header.module_id_len as usize;
        let id_end = cursor + id_len;
        if data.len() < id_end {
            return Err(KrakenError::InvalidModuleBlob);
        }
        let module_id = core::str::from_utf8(&data[cursor..id_end])
            .map_err(|_| KrakenError::InvalidModuleBlob)?;
        cursor = id_end;

        // --- module_name ---
        let name_len = header.module_name_len as usize;
        let name_end = cursor + name_len;
        if data.len() < name_end {
            return Err(KrakenError::InvalidModuleBlob);
        }
        let module_name = core::str::from_utf8(&data[cursor..name_end])
            .map_err(|_| KrakenError::InvalidModuleBlob)?;
        cursor = name_end;

        // --- signature length prefix (4-byte little-endian u32) ---
        if data.len() < cursor + 4 {
            return Err(KrakenError::InvalidModuleBlob);
        }
        let sig_len = u32::from_le_bytes(
            data[cursor..cursor + 4]
                .try_into()
                .map_err(|_| KrakenError::InvalidModuleBlob)?,
        ) as usize;
        cursor += 4;

        // --- signature ---
        let sig_end = cursor + sig_len;
        if data.len() < sig_end {
            return Err(KrakenError::InvalidModuleBlob);
        }
        let signature = &data[cursor..sig_end];
        cursor = sig_end;

        // --- code ---
        let code_size = header.code_size as usize;
        let code_end = cursor + code_size;
        if data.len() < code_end {
            return Err(KrakenError::InvalidModuleBlob);
        }
        let code = &data[cursor..code_end];

        Ok(Self {
            header,
            module_id,
            module_name,
            signature,
            code,
        })
    }

    /// Returns the bytes that were signed, suitable for passing to a
    /// signature-verification routine.
    ///
    /// This reconstructs the original unsigned blob from a signed blob:
    /// `header || module_id || module_name || code`
    ///
    /// This matches exactly what [`crate::module_store::signing::ModuleSigner::sign`]
    /// computes its signature over (the entire `blob_without_sig` slice).
    ///
    /// The caller is responsible for ensuring `data` is a valid signed blob
    /// (i.e. one produced by `ModuleSigner::sign`).
    pub fn signed_data(data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        if data.len() < ModuleBlobHeader::SIZE {
            return Err(KrakenError::InvalidModuleBlob);
        }

        // Re-read lengths from the raw header bytes without constructing a
        // full ModuleBlob (avoids a second validate() call).
        let header = unsafe {
            &*(data.as_ptr() as *const ModuleBlobHeader)
        };

        // Read packed fields by copy to avoid misaligned ref UB.
        let id_len = header.module_id_len as usize;
        let name_len = header.module_name_len as usize;
        let code_size = header.code_size as usize;

        // In the signed blob the layout after header+id+name is:
        //   sig_len (4 B LE) || signature (sig_len B) || code (code_size B)
        // We need to skip over sig_len and signature to find the code bytes.
        let strings_end = ModuleBlobHeader::SIZE + id_len + name_len;

        if data.len() < strings_end + 4 {
            return Err(KrakenError::InvalidModuleBlob);
        }

        let sig_len = u32::from_le_bytes(
            data[strings_end..strings_end + 4]
                .try_into()
                .map_err(|_| KrakenError::InvalidModuleBlob)?,
        ) as usize;

        let code_start = strings_end + 4 + sig_len;
        let code_end = code_start + code_size;

        if data.len() < code_end {
            return Err(KrakenError::InvalidModuleBlob);
        }

        // Reconstruct [header][id][name][code] — the original unsigned blob.
        let mut unsigned = Vec::with_capacity(strings_end + code_size);
        unsigned.extend_from_slice(&data[..strings_end]);
        unsigned.extend_from_slice(&data[code_start..code_end]);

        Ok(unsigned)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_header() -> [u8; 80] {
        let mut buf = [0u8; 80];
        buf[0..4].copy_from_slice(b"KMOD");
        // format_version = 1 (LE)
        buf[4] = 1;
        buf[5] = 0;
        // arch = x64-linux
        buf[6] = ARCH_X64_LINUX;
        // flags = 0
        buf[7] = 0;
        // module_id_len = 4
        buf[8] = 4;
        buf[9] = 0;
        // module_name_len = 4
        buf[10] = 4;
        buf[11] = 0;
        // version = 1 (LE u32) @ offset 12
        buf[12] = 1;
        // code_size = 8 (LE u32) @ offset 16
        buf[16] = 8;
        // entry_offset = 0 (LE u32) @ offset 20 – valid: 0 < 8
        buf[20] = 0;
        buf
    }

    fn make_valid_blob() -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&make_valid_header());
        // module_id: "test"
        blob.extend_from_slice(b"test");
        // module_name: "Test"
        blob.extend_from_slice(b"Test");
        // signature_len = 3 (LE u32)
        blob.extend_from_slice(&3u32.to_le_bytes());
        // signature bytes
        blob.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        // code (8 bytes)
        blob.extend_from_slice(&[0u8; 8]);
        blob
    }

    #[test]
    fn parse_roundtrip() {
        let blob_data = make_valid_blob();
        let blob = ModuleBlob::parse(&blob_data).expect("parse failed");
        assert_eq!(blob.module_id, "test");
        assert_eq!(blob.module_name, "Test");
        assert_eq!(blob.signature, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(blob.code.len(), 8);
    }

    #[test]
    fn signed_data_excludes_signature() {
        let blob_data = make_valid_blob();
        let sd = ModuleBlob::signed_data(&blob_data).expect("signed_data failed");
        // header(80) + id(4) + name(4) + code(8) = 96
        // Matches what the signer covers: [header][id][name][code]
        assert_eq!(sd.len(), 96);
        assert_eq!(&sd[..4], b"KMOD");
        // Last 8 bytes should be the code section (all zeros in make_valid_blob).
        assert_eq!(&sd[88..], &[0u8; 8]);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut blob_data = make_valid_blob();
        blob_data[0] = b'X';
        assert!(ModuleBlob::parse(&blob_data).is_err());
    }

    #[test]
    fn conflicting_platform_flags_rejected() {
        let mut hdr = make_valid_header();
        hdr[7] = FLAG_WINDOWS_ONLY | FLAG_LINUX_ONLY;
        let header = unsafe { &*(hdr.as_ptr() as *const ModuleBlobHeader) };
        assert!(header.validate().is_err());
    }

    #[test]
    fn entry_offset_out_of_bounds_rejected() {
        let mut hdr = make_valid_header();
        // Set entry_offset = 8 which equals code_size = 8, must be strictly less.
        // entry_offset is at byte offset 20 in the packed struct.
        hdr[20] = 8;
        let header = unsafe { &*(hdr.as_ptr() as *const ModuleBlobHeader) };
        assert!(header.validate().is_err());
    }

    #[test]
    fn header_size_is_80() {
        assert_eq!(core::mem::size_of::<ModuleBlobHeader>(), 80);
    }
}
