use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let key_path = out_dir.join("signing_pubkey.bin");

    // Write a 32-byte placeholder public key.
    // In production this will be replaced by the real Ed25519 public key
    // baked in at build time via the module-store signing workflow.
    if !key_path.exists() {
        let placeholder = [0u8; 32];
        fs::write(&key_path, placeholder).expect("failed to write placeholder signing_pubkey.bin");
    }

    // Generate IMPLANT_VERSION_PACKED from Cargo.toml version for module
    // compatibility checking. Packed format: (major << 16) | (minor << 8) | patch
    let version = env!("CARGO_PKG_VERSION");
    let parts: Vec<&str> = version.split('.').collect();
    let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let packed = (major << 16) | (minor << 8) | patch;
    println!("cargo:rustc-env=IMPLANT_VERSION_PACKED={}", packed);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=KRAKEN_SIGNING_PUBKEY");

    // Allow the operator to override the placeholder at build time by setting
    // KRAKEN_SIGNING_PUBKEY to a path pointing at a 32-byte raw Ed25519 public key.
    if let Ok(pubkey_path) = env::var("KRAKEN_SIGNING_PUBKEY") {
        let src = PathBuf::from(&pubkey_path);
        let bytes = fs::read(src)
            .unwrap_or_else(|e| panic!("failed to read KRAKEN_SIGNING_PUBKEY={pubkey_path}: {e}"));
        assert_eq!(
            bytes.len(),
            32,
            "KRAKEN_SIGNING_PUBKEY must be exactly 32 bytes (raw Ed25519 public key)"
        );
        fs::write(&key_path, &bytes).expect("failed to write signing_pubkey.bin from env");
        println!("cargo:rerun-if-changed={pubkey_path}");
    }
}
