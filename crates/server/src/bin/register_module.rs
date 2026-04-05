//! Register a compiled module in the module store
//!
//! Usage: kraken-register-module --key module_signing.key --module target/.../libmod_shell.so --id mod-shell --platform x86_64-unknown-linux-gnu

use clap::Parser;
use module_store::signing::{ModuleSigner, build_unsigned_blob, arch_for_platform};
use std::fs;

#[derive(Parser)]
struct Args {
    /// Path to PKCS#8 signing key
    #[arg(long)]
    key: String,

    /// Path to compiled module (.so or .dll)
    #[arg(long)]
    module: String,

    /// Module ID (e.g., "mod-shell")
    #[arg(long)]
    id: String,

    /// Target platform (e.g., "x86_64-unknown-linux-gnu")
    #[arg(long)]
    platform: String,

    /// Output path for signed blob
    #[arg(long, default_value = "module.blob")]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load signing key
    let key_bytes = fs::read(&args.key)?;
    let signer = ModuleSigner::new(&key_bytes)?;
    println!("Loaded signing key, pubkey: {}", hex::encode(signer.public_key()));

    // Load module code
    let code = fs::read(&args.module)?;
    println!("Loaded module: {} bytes", code.len());

    // Determine architecture from platform triple
    let arch = arch_for_platform(&args.platform)?;

    // Build unsigned blob
    let unsigned = build_unsigned_blob(
        &args.id,
        &args.id,  // name same as id for simplicity
        (0, 1, 0), // version 0.1.0
        arch,
        0,         // flags
        &code,
        0,         // entry_offset (will be resolved at load time)
    );

    // Sign
    let signed = signer.sign(&unsigned)?;
    println!("Signed blob: {} bytes", signed.len());

    // Write output
    fs::write(&args.output, &signed)?;
    println!("Written to: {}", args.output);

    Ok(())
}
