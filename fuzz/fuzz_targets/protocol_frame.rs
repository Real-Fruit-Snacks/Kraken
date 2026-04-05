#![no_main]
//! Fuzz target for protocol frame decoding
//!
//! Tests that malformed frame data never causes panics or unbounded allocations.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode frame - should never panic
    let _ = protocol::decode_with_length::<protocol::CheckIn>(data);
    let _ = protocol::decode_with_length::<protocol::CheckInResponse>(data);
    let _ = protocol::decode_with_length::<protocol::TaskResultEvent>(data);
});
