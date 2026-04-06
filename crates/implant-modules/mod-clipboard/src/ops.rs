//! Clipboard operation implementations

use common::KrakenError;

/// Get the current clipboard text content
#[cfg(target_os = "windows")]
pub fn get_clipboard_text() -> Result<String, KrakenError> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    unsafe {
        if OpenClipboard(0) == 0 {
            return Err(KrakenError::Module("OpenClipboard failed".into()));
        }

        let h_data: HANDLE = GetClipboardData(CF_UNICODETEXT as u32);
        if h_data == 0 {
            CloseClipboard();
            return Ok(String::new());
        }

        let ptr = GlobalLock(h_data as _) as *const u16;
        if ptr.is_null() {
            CloseClipboard();
            return Err(KrakenError::Module("GlobalLock failed".into()));
        }

        // Find null terminator
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        let text = String::from_utf16_lossy(slice);

        GlobalUnlock(h_data as _);
        CloseClipboard();

        Ok(text)
    }
}

/// Set the clipboard text content
#[cfg(target_os = "windows")]
pub fn set_clipboard_text(text: &str) -> Result<(), KrakenError> {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide.len() * std::mem::size_of::<u16>();

    unsafe {
        let h_mem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if h_mem.is_null() {
            return Err(KrakenError::Module("GlobalAlloc failed".into()));
        }

        let ptr = GlobalLock(h_mem) as *mut u16;
        if ptr.is_null() {
            return Err(KrakenError::Module("GlobalLock failed".into()));
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        GlobalUnlock(h_mem);

        if OpenClipboard(0) == 0 {
            return Err(KrakenError::Module("OpenClipboard failed".into()));
        }

        EmptyClipboard();
        SetClipboardData(CF_UNICODETEXT as u32, h_mem as _);
        CloseClipboard();
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn get_clipboard_text() -> Result<String, KrakenError> {
    Err(KrakenError::Module(
        "clipboard operations not supported on this platform".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn set_clipboard_text(_text: &str) -> Result<(), KrakenError> {
    Err(KrakenError::Module(
        "clipboard operations not supported on this platform".into(),
    ))
}
