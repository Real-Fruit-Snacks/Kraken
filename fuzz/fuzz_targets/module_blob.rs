#![no_main]
//! Fuzz target for module blob parsing
//!
//! Tests that malformed module blobs never cause panics or unbounded allocations.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse module blob - should never panic
    // The parser should gracefully reject malformed data
    let _ = common::ModuleBlob::parse(data);
});
