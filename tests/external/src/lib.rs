//! External validation test suite
//!
//! These tests validate evasion capabilities in a controlled lab environment.
//! They are marked #[ignore] by default as they require:
//!
//! 1. Windows target with appropriate security software installed
//! 2. Administrator privileges for some tests
//! 3. Isolated network environment
//!
//! To run: `cargo test -p external-validation -- --ignored --test-threads=1`
//!
//! **WARNING**: These tests may trigger security alerts. Only run in a lab.

pub mod detection_rate;
pub mod memory_scan;

#[cfg(windows)]
pub mod etw_validation;

#[cfg(windows)]
pub mod amsi_validation;
