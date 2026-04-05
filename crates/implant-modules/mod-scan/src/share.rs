//! Network share enumeration
//!
//! Windows: uses NetShareEnum API
//! Non-Windows: returns empty (not applicable)

use common::{KrakenError, ShareEnumOutput};
#[cfg(windows)]
use common::ShareInfoEntry;
use protocol::ShareEnum;

pub fn enumerate(req: &ShareEnum) -> Result<ShareEnumOutput, KrakenError> {
    enumerate_impl(&req.target)
}

#[cfg(windows)]
fn enumerate_impl(target: &str) -> Result<ShareEnumOutput, KrakenError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::Foundation::*;

    // NetShareEnum is in netapi32, use raw FFI
    use std::ptr;

    #[allow(non_snake_case)]
    extern "system" {
        fn NetShareEnum(
            servername: *const u16,
            level: u32,
            bufptr: *mut *mut u8,
            prefmaxlen: u32,
            entriesread: *mut u32,
            totalentries: *mut u32,
            resume_handle: *mut u32,
        ) -> u32;

        fn NetApiBufferFree(buffer: *mut u8) -> u32;
    }

    // SHARE_INFO_1 layout
    #[repr(C)]
    struct ShareInfo1 {
        shi1_netname: *mut u16,
        shi1_type: u32,
        shi1_remark: *mut u16,
    }

    const MAX_PREFERRED_LENGTH: u32 = 0xFFFF_FFFF;
    const NERR_SUCCESS: u32 = 0;

    // Convert target to wide string
    let wide_target: Vec<u16> = target
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut buf_ptr: *mut u8 = ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume_handle: u32 = 0;

    let result = unsafe {
        NetShareEnum(
            wide_target.as_ptr(),
            1,
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        )
    };

    if result != NERR_SUCCESS {
        return Err(KrakenError::Internal(format!(
            "NetShareEnum failed with code {}",
            result
        )));
    }

    let mut shares: Vec<ShareInfoEntry> = Vec::new();

    if !buf_ptr.is_null() {
        let info_slice = unsafe {
            std::slice::from_raw_parts(buf_ptr as *const ShareInfo1, entries_read as usize)
        };

        for entry in info_slice {
            let name = if entry.shi1_netname.is_null() {
                String::new()
            } else {
                let len = unsafe {
                    let mut l = 0;
                    let mut p = entry.shi1_netname;
                    while *p != 0 { l += 1; p = p.add(1); }
                    l
                };
                let slice = unsafe { std::slice::from_raw_parts(entry.shi1_netname, len) };
                OsString::from_wide(slice).to_string_lossy().into_owned()
            };

            let share_type = match entry.shi1_type & 0xFFFF {
                0 => "Disk",
                1 => "Printer",
                2 => "Device",
                3 => "IPC",
                _ => "Unknown",
            }.to_string();

            let remark = if entry.shi1_remark.is_null() {
                String::new()
            } else {
                let len = unsafe {
                    let mut l = 0;
                    let mut p = entry.shi1_remark;
                    while *p != 0 { l += 1; p = p.add(1); }
                    l
                };
                let slice = unsafe { std::slice::from_raw_parts(entry.shi1_remark, len) };
                OsString::from_wide(slice).to_string_lossy().into_owned()
            };

            shares.push(ShareInfoEntry {
                name,
                share_type,
                path: String::new(), // SHARE_INFO_1 doesn't include path; need level 2
                remark,
            });
        }

        unsafe { NetApiBufferFree(buf_ptr) };
    }

    Ok(ShareEnumOutput {
        target: target.to_string(),
        shares,
    })
}

#[cfg(not(windows))]
fn enumerate_impl(target: &str) -> Result<ShareEnumOutput, KrakenError> {
    // Share enumeration is Windows-only via NetShareEnum
    Ok(ShareEnumOutput {
        target: target.to_string(),
        shares: vec![],
    })
}
