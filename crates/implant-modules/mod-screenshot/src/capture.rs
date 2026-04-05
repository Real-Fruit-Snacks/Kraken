//! Platform-specific screen capture implementations

use common::KrakenError;

/// Raw captured frame
pub struct CapturedFrame {
    /// Raw BGRA pixel data (top-down row order)
    pub pixels: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub monitor_index: u32,
}

/// Capture a screenshot of the specified monitor (0 = primary).
///
/// Multi-monitor support is not yet implemented; monitor_index is recorded
/// in the result but only the primary virtual screen is captured.
#[cfg(windows)]
pub fn capture(monitor_index: u32) -> Result<CapturedFrame, KrakenError> {
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    unsafe {
        // GetDC(NULL) returns a DC for the entire virtual screen
        // In windows-sys 0.52, HWND/HDC/HBITMAP are isize (not raw pointers)
        let screen_dc = GetDC(0);
        if screen_dc == 0 {
            return Err(KrakenError::Module("GetDC failed".into()));
        }

        let width = GetSystemMetrics(SM_CXSCREEN) as u32;
        let height = GetSystemMetrics(SM_CYSCREEN) as u32;

        if width == 0 || height == 0 {
            ReleaseDC(0, screen_dc);
            return Err(KrakenError::Module("invalid screen dimensions".into()));
        }

        let mem_dc = CreateCompatibleDC(screen_dc);
        if mem_dc == 0 {
            ReleaseDC(0, screen_dc);
            return Err(KrakenError::Module("CreateCompatibleDC failed".into()));
        }

        let bitmap = CreateCompatibleBitmap(screen_dc, width as i32, height as i32);
        if bitmap == 0 {
            DeleteDC(mem_dc);
            ReleaseDC(0, screen_dc);
            return Err(KrakenError::Module("CreateCompatibleBitmap failed".into()));
        }

        let old_obj = SelectObject(mem_dc, bitmap);

        let blt_result = BitBlt(
            mem_dc,
            0,
            0,
            width as i32,
            height as i32,
            screen_dc,
            0,
            0,
            SRCCOPY,
        );

        if blt_result == 0 {
            SelectObject(mem_dc, old_obj);
            DeleteObject(bitmap);
            DeleteDC(mem_dc);
            ReleaseDC(0, screen_dc);
            return Err(KrakenError::Module("BitBlt failed".into()));
        }

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width as i32,
                // Negative height = top-down DIB (row 0 is at the top)
                biHeight: -(height as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB as u32,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [std::mem::zeroed()],
        };

        let pixel_count = (width * height * 4) as usize;
        let mut pixels: Vec<u8> = vec![0u8; pixel_count];

        let lines = GetDIBits(
            mem_dc,
            bitmap,
            0,
            height,
            pixels.as_mut_ptr() as *mut _,
            &mut bmi,
            DIB_RGB_COLORS,
        );

        SelectObject(mem_dc, old_obj);
        DeleteObject(bitmap);
        DeleteDC(mem_dc);
        ReleaseDC(0, screen_dc);

        if lines == 0 {
            return Err(KrakenError::Module("GetDIBits failed".into()));
        }

        Ok(CapturedFrame {
            pixels,
            width,
            height,
            monitor_index,
        })
    }
}

/// Stub implementation for non-Windows platforms.
#[cfg(not(windows))]
pub fn capture(_monitor_index: u32) -> Result<CapturedFrame, KrakenError> {
    Err(KrakenError::Module(
        "screenshot capture is not implemented on this platform".into(),
    ))
}
