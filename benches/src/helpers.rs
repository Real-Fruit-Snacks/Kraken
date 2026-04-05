//! Benchmark helpers and test data generators

use common::ImplantId;

/// Generate a random ImplantId for benchmarks
pub fn random_implant_id() -> ImplantId {
    ImplantId::new()
}

/// Generate random bytes of specified length
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Common payload sizes for benchmarking
pub const PAYLOAD_SMALL: usize = 64;
pub const PAYLOAD_MEDIUM: usize = 4096;
pub const PAYLOAD_LARGE: usize = 65536;
