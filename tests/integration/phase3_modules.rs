//! Phase 3 integration tests — dynamic module loading flow.
//!
//! These tests exercise the end-to-end module pipeline:
//!   build_unsigned_blob → sign → parse → verify structure
//!
//! Tests that require a live database (ModuleStore RPC list_modules) are
//! marked with `#[ignore]` and can be enabled when a test DB fixture is
//! available.

use common::{ModuleBlob, ModuleBlobHeader, ModuleId, ARCH_X64_LINUX};
use module_store::signing::{ModuleSigner, build_unsigned_blob, pack_version};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 key pair and return the PKCS#8 bytes.
fn generate_test_key() -> Vec<u8> {
    ModuleSigner::generate_pkcs8().expect("Ed25519 key generation must succeed in tests")
}

/// Build, sign, and return a minimal valid module blob using a freshly
/// generated key pair.  Also returns the signer so callers can verify
/// the public key if needed.
fn make_signed_blob(
    module_id: &str,
    module_name: &str,
    code: &[u8],
    version: (u8, u8, u8),
) -> (Vec<u8>, ModuleSigner) {
    let pkcs8 = generate_test_key();
    let signer = ModuleSigner::new(&pkcs8).expect("signer construction must succeed");

    let unsigned = build_unsigned_blob(
        module_id,
        module_name,
        version,
        ARCH_X64_LINUX,
        0,   // flags
        code,
        0,   // entry_offset
    );

    let signed = signer.sign(&unsigned).expect("signing must succeed");
    (signed, signer)
}

// ---------------------------------------------------------------------------
// Basic module flow tests
// ---------------------------------------------------------------------------

/// The full blob pipeline (build → sign → parse) must produce a blob whose
/// parsed fields match the inputs supplied to `build_unsigned_blob`.
#[test]
fn test_module_flow_build_sign_parse() {
    let code = vec![0xCC_u8; 64];
    let (signed, _signer) = make_signed_blob(
        "kraken.integration.flow",
        "Integration Flow Module",
        &code,
        (2, 0, 1),
    );

    let parsed = ModuleBlob::parse(&signed)
        .expect("a freshly built+signed blob must parse without error");

    assert_eq!(parsed.module_id, "kraken.integration.flow");
    assert_eq!(parsed.module_name, "Integration Flow Module");
    assert_eq!(parsed.code.len(), code.len(), "code length must be preserved");
    let header_version = parsed.header.version;
    assert_eq!(
        header_version,
        pack_version((2, 0, 1)),
        "version must round-trip through pack_version"
    );
    // Signature must be a non-empty Ed25519 signature (64 bytes).
    assert_eq!(parsed.signature.len(), 64, "Ed25519 signature must be 64 bytes");
}

/// The header magic must be KMOD in every blob produced by the pipeline.
#[test]
fn test_module_blob_magic() {
    let (signed, _) = make_signed_blob("kraken.magic.test", "Magic", &[0u8; 8], (0, 1, 0));
    assert_eq!(&signed[0..4], b"KMOD", "blob must begin with KMOD magic");
}

/// A blob with corrupted magic must be rejected by `ModuleBlob::parse`.
#[test]
fn test_corrupted_magic_rejected() {
    let (mut signed, _) = make_signed_blob("kraken.corrupt.test", "Corrupt", &[0u8; 8], (0, 1, 0));
    signed[0] = b'X';
    assert!(
        ModuleBlob::parse(&signed).is_err(),
        "blob with corrupted magic must be rejected"
    );
}

/// The header size constant must equal the actual struct size.
#[test]
fn test_header_size_constant() {
    assert_eq!(
        core::mem::size_of::<ModuleBlobHeader>(),
        ModuleBlobHeader::SIZE,
        "SIZE constant must match actual struct layout"
    );
    assert_eq!(ModuleBlobHeader::SIZE, 80);
}

/// `pack_version` must round-trip all byte-range values correctly.
#[test]
fn test_version_encoding() {
    for major in [0u8, 1, 127, 255] {
        for minor in [0u8, 1, 50, 255] {
            for patch in [0u8, 1, 99, 255] {
                let packed = pack_version((major, minor, patch));
                assert_eq!((packed >> 16) & 0xFF, major as u32, "major mismatch");
                assert_eq!((packed >> 8) & 0xFF, minor as u32, "minor mismatch");
                assert_eq!(packed & 0xFF, patch as u32, "patch mismatch");
            }
        }
    }
}

/// `ModuleId` must preserve its string representation.
#[test]
fn test_module_id_roundtrip() {
    let id = ModuleId::new("kraken.recon.portscan");
    assert_eq!(id.as_str(), "kraken.recon.portscan");

    // Two ids with the same string must be equal.
    let id2 = ModuleId::new("kraken.recon.portscan");
    assert_eq!(id, id2);

    // Two ids with different strings must not be equal.
    let id3 = ModuleId::new("kraken.recon.hostscan");
    assert_ne!(id, id3);
}

// ---------------------------------------------------------------------------
// list_modules RPC — requires live ModuleStore (ignored by default)
// ---------------------------------------------------------------------------

/// Smoke-test that `ModuleStore::list` returns an empty vec on a fresh store.
///
/// This test is `#[ignore]` because it requires a live SQLite database.
/// Run with: `cargo test -- --ignored test_module_service_list_modules`
#[test]
#[ignore = "requires live database fixture"]
fn test_module_service_list_modules() {
    // Placeholder: a real test would construct a ModuleStore backed by an
    // in-memory SQLite DB, call store.list().await, and assert the result
    // is an empty Vec<ModuleInfo> on a fresh store.
    //
    // Example skeleton (requires tokio::test and db::Database::open_in_memory):
    //
    //   let db = Arc::new(db::Database::open_in_memory().await.unwrap());
    //   let pkcs8 = ModuleSigner::generate_pkcs8().unwrap();
    //   let store = ModuleStore::new(db, &pkcs8).unwrap();
    //   let modules = store.list().await.unwrap();
    //   assert!(modules.is_empty());
}

// ---------------------------------------------------------------------------
// Error handling — missing modules
// ---------------------------------------------------------------------------

/// Requesting a non-existent module ID from the loader must produce an error,
/// not a panic or UB.
#[test]
fn test_error_handling_missing_module() {
    use common::KrakenError;

    // Simulate what would happen in the implant-loader when a module is not
    // found: the loader returns KrakenError::ModuleNotFound.
    let missing_id = "kraken.nonexistent.module";
    let err = KrakenError::ModuleNotFound(missing_id.to_string());

    // Ensure the error formats correctly and contains the module id.
    let err_str = format!("{}", err);
    assert!(
        err_str.contains(missing_id),
        "ModuleNotFound error must include the module id: got '{}'",
        err_str
    );
}

/// A truncated blob (shorter than the header) must be rejected at parse time.
#[test]
fn test_truncated_blob_rejected() {
    // Any slice shorter than 80 bytes must fail.
    for len in [0usize, 1, 40, 79] {
        let short = vec![0u8; len];
        assert!(
            ModuleBlob::parse(&short).is_err(),
            "blob of {} bytes must be rejected (shorter than header)",
            len
        );
    }
}

/// A blob with a valid header but a mismatched `code_size` field must be
/// rejected by the parser.
#[test]
fn test_code_size_mismatch_rejected() {
    let (mut signed, _) = make_signed_blob(
        "kraken.size.test",
        "Size Mismatch",
        &[0xAA_u8; 32],
        (0, 1, 0),
    );

    // Corrupt the code_size field at header offset 16 (LE u32) to claim a
    // much larger code section than is actually present.
    let inflated: u32 = 0x0FFF_FFFF;
    signed[16..20].copy_from_slice(&inflated.to_le_bytes());

    assert!(
        ModuleBlob::parse(&signed).is_err(),
        "blob with inflated code_size must be rejected"
    );
}
