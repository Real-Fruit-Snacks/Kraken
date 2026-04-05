//! Kraken C2 payload generation toolkit.
//!
//! Provides builders for multiple payload output formats:
//!
//! - **Shellcode** (`shellcode`): Position-independent code blob with PEB-walking bootstrap
//! - **DLL** (`dll`): DLL with configurable exports for sideloading / hijacking
//! - **PowerShell** (`powershell`): Download cradles with AMSI bypass and obfuscation
//! - **Service EXE** (`service`): Windows service template for SCM-based persistence
//!
//! ## Architecture
//!
//! Each module exposes a `Config` struct and a `generate_*()` entry-point that
//! returns either raw bytes (`Vec<u8>`) or source-code strings ready for
//! cross-compilation.
//!
//! ## Detection (Blue Team)
//!
//! Every generated artifact is accompanied by YARA / Sigma detection guidance
//! in the crate-level documentation and in `docs/detection/`.

pub mod dll;
pub mod encrypt;
pub mod encode;
pub mod powershell;
pub mod service;
pub mod shellcode;
pub mod sideload_targets;
pub mod stub;

use thiserror::Error;

/// Errors produced by the payload-builder pipeline.
#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("invalid PE format: {0}")]
    InvalidPe(String),

    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("template generation error: {0}")]
    Template(String),
}

/// Target CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Arch {
    X64,
    X86,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X64 => write!(f, "x64"),
            Arch::X86 => write!(f, "x86"),
        }
    }
}

/// Encryption algorithm applied to embedded payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EncryptionType {
    /// Rolling XOR with a multi-byte key.
    Xor,
    /// No encryption — useful for debugging.
    None,
}

/// Top-level output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Shellcode,
    Dll,
    PowerShell,
    ServiceExe,
}

/// Unified payload options passed through the CLI.
#[derive(Debug, Clone)]
pub struct PayloadOptions {
    pub shellcode: shellcode::ShellcodeConfig,
    pub dll: dll::DllConfig,
    pub powershell: powershell::PowerShellConfig,
    pub service: service::ServiceConfig,
}

/// High-level entry-point: build a payload in the chosen format.
pub fn build_payload(
    implant_pe: &[u8],
    format: OutputFormat,
    options: &PayloadOptions,
) -> Result<Vec<u8>, BuilderError> {
    match format {
        OutputFormat::Shellcode => shellcode::generate_shellcode(implant_pe, &options.shellcode),
        OutputFormat::Dll => {
            let output = dll::generate_dll(&options.dll)?;
            Ok(output.source.into_bytes())
        }
        OutputFormat::PowerShell => {
            let script = powershell::generate_powershell(&options.powershell)?;
            Ok(script.into_bytes())
        }
        OutputFormat::ServiceExe => {
            let output = service::generate_service_template(&options.service)?;
            Ok(output.source.into_bytes())
        }
    }
}
