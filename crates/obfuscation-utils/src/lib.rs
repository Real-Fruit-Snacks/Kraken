//! Kraken obfuscation utilities — post-build PE manipulation
//!
//! Provides tools applied as post-build steps on compiled implant binaries:
//!
//! - [`pe_sections`]: Rename well-known PE section names to random identifiers
//!   to evade static YARA rules and signature-based detection.
//! - [`timestamps`]: Zero or randomize PE timestamps to prevent forensic
//!   analysis from determining compilation time.

pub mod pe_sections;
pub mod timestamps;
