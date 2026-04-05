//! Phase 4 OPSEC evasion techniques
//!
//! All techniques are feature-flagged for authorized red team operations.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar
//!
//! Modules are always compiled (with stubs on non-Windows) to enable testing.
//! Actual evasion features require Windows + feature flags.

pub mod anti_debug;
pub mod anti_vm;
pub mod heap_encrypt;
pub mod imports;
pub mod indirect_syscall;
pub mod sleep_mask;
pub mod stack_spoof;
pub mod syscall;
