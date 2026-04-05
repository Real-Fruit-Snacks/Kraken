//! Generate Ed25519 keypair for module signing
use module_store::signing::ModuleSigner;
use std::fs;

fn main() {
    let pkcs8 = ModuleSigner::generate_pkcs8().expect("key generation failed");
    let signer = ModuleSigner::new(&pkcs8).expect("invalid key");
    let pubkey = signer.public_key();

    fs::write("module_signing.key", &pkcs8).expect("failed to write private key");
    fs::write("module_signing.pub", pubkey).expect("failed to write public key");

    println!("Generated keypair:");
    println!("  Private: module_signing.key ({} bytes PKCS#8)", pkcs8.len());
    println!("  Public:  module_signing.pub (32 bytes)");
    println!("\nTo use:");
    println!("  export KRAKEN_MODULE_KEY_FILE=module_signing.key");
    println!("  export KRAKEN_SIGNING_PUBKEY=$(xxd -p module_signing.pub | tr -d '\\n')");
}
