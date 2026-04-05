//! Kraken performance benchmarks
//!
//! Run with: `cargo bench`
//!
//! ## Benchmark targets
//!
//! | Benchmark | Target | Spec Requirement |
//! |-----------|--------|------------------|
//! | crypto/x25519_keygen | Key generation | - |
//! | crypto/x25519_dh | Diffie-Hellman | - |
//! | crypto/aes_gcm_encrypt | AES-GCM encrypt | - |
//! | crypto/aes_gcm_decrypt | AES-GCM decrypt | - |
//! | crypto/handshake | Full mTLS handshake | <100ms |
//! | crypto/signature_verify | Ed25519 verify | <10ms |
//! | mesh/add_link | Link establishment | <1s |
//! | mesh/compute_route | Route computation | <100ms relay |
//! | mesh/topology_update | Topology change | <5s |
//! | module/sign | Module signing | <100ms |
//! | module/load | Module loading | <100ms |

pub mod helpers;
