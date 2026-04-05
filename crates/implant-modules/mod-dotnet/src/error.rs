//! mod-dotnet error types

use std::fmt;

/// Errors that can occur during .NET assembly execution
#[derive(Debug)]
pub enum DotNetError {
    /// Platform not supported (non-Windows)
    UnsupportedPlatform(String),
    /// CLR initialization failed
    ClrInitFailed(String),
    /// Runtime not found
    RuntimeNotFound(String),
    /// AppDomain creation failed
    AppDomainFailed(String),
    /// Assembly load failed
    AssemblyLoadFailed(String),
    /// Entry point not found
    EntryPointNotFound(String),
    /// Method invocation failed
    InvocationFailed(String),
    /// Output capture failed
    OutputCaptureFailed(String),
    /// Timeout during execution
    Timeout(u32),
    /// COM error
    ComError(i32),
    /// OPSEC mitigation failed
    OpsecFailed(String),
}

impl fmt::Display for DotNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DotNetError::UnsupportedPlatform(msg) => {
                write!(f, "platform not supported: {}", msg)
            }
            DotNetError::ClrInitFailed(msg) => {
                write!(f, "CLR initialization failed: {}", msg)
            }
            DotNetError::RuntimeNotFound(msg) => {
                write!(f, "CLR runtime not found: {}", msg)
            }
            DotNetError::AppDomainFailed(msg) => {
                write!(f, "AppDomain creation failed: {}", msg)
            }
            DotNetError::AssemblyLoadFailed(msg) => {
                write!(f, "assembly load failed: {}", msg)
            }
            DotNetError::EntryPointNotFound(msg) => {
                write!(f, "entry point not found: {}", msg)
            }
            DotNetError::InvocationFailed(msg) => {
                write!(f, "method invocation failed: {}", msg)
            }
            DotNetError::OutputCaptureFailed(msg) => {
                write!(f, "output capture failed: {}", msg)
            }
            DotNetError::Timeout(secs) => {
                write!(f, "execution timeout after {} seconds", secs)
            }
            DotNetError::ComError(hr) => {
                write!(f, "COM error: 0x{:08x}", hr)
            }
            DotNetError::OpsecFailed(msg) => {
                write!(f, "OPSEC mitigation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for DotNetError {}

impl From<DotNetError> for common::KrakenError {
    fn from(e: DotNetError) -> Self {
        common::KrakenError::Module(e.to_string())
    }
}
