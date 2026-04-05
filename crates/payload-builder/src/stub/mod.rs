//! Bootstrap stub selection.
//!
//! Provides architecture-dispatched generation of the PIC bootstrap stub
//! that performs PEB walking, API resolution, payload decryption, and
//! reflective PE loading.

pub mod x64_stub;
pub mod x86_stub;

use crate::{Arch, BuilderError};
use crate::shellcode::ShellcodeConfig;

/// Generate the bootstrap stub for the target architecture.
pub fn generate_stub(config: &ShellcodeConfig) -> Result<Vec<u8>, BuilderError> {
    match config.arch {
        Arch::X64 => Ok(x64_stub::generate_x64_stub(config)),
        Arch::X86 => Ok(x86_stub::generate_x86_stub(config)),
    }
}
