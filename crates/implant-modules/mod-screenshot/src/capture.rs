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
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenInputDesktop, SetThreadDesktop,
    };

    // Desktop access rights — not re-exported by all windows-sys feature
    // combinations, so define them inline.
    const DESKTOP_READOBJECTS: u32 = 0x0001;
    const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;

    unsafe {
        // Verify that the calling thread has access to an interactive desktop
        // before issuing GDI calls. GetDC(0) / BitBlt succeed but capture a
        // black frame (or silently produce garbage) when the process has no
        // associated desktop — e.g. when running as a service in Session 0 or
        // on a locked workstation where the current desktop is not the input
        // desktop.
        //
        // The previous code passed GENERIC_READ (0x0200) which is NOT a valid
        // desktop-specific access right and causes OpenInputDesktop to fail
        // even from a normal interactive session. The correct flags are
        // DESKTOP_READOBJECTS (required for EnumDesktopWindows / GDI access)
        // and DESKTOP_SWITCHDESKTOP (required to verify it is the active
        // input desktop).
        let input_desktop =
            OpenInputDesktop(0, 0, DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP);
        if input_desktop == 0 {
            return Err(KrakenError::Module(
                "no accessible interactive desktop (non-interactive session or locked workstation)".into(),
            ));
        }

        // Associate this thread with the input desktop so that subsequent
        // GetDC(0) / BitBlt calls target the visible desktop rather than
        // whatever desktop the thread inherited (which may be a
        // non-interactive or disconnected desktop, producing a black frame).
        let set_ok = SetThreadDesktop(input_desktop);
        if set_ok == 0 {
            CloseDesktop(input_desktop);
            return Err(KrakenError::Module(
                "SetThreadDesktop failed — cannot attach to input desktop".into(),
            ));
        }
        // NOTE: We intentionally do NOT call CloseDesktop here. The desktop
        // handle must remain open while GDI calls reference it. It is closed
        // after the capture is complete (see below).

        // GetDC(NULL) returns a DC for the entire virtual screen
        // In windows-sys 0.52, HWND/HDC/HBITMAP are isize (not raw pointers)
        let screen_dc = GetDC(0);
        if screen_dc == 0 {
            CloseDesktop(input_desktop);
            return Err(KrakenError::Module("GetDC failed".into()));
        }

        let width = GetSystemMetrics(SM_CXSCREEN) as u32;
        let height = GetSystemMetrics(SM_CYSCREEN) as u32;

        if width == 0 || height == 0 {
            ReleaseDC(0, screen_dc);
            CloseDesktop(input_desktop);
            return Err(KrakenError::Module("invalid screen dimensions".into()));
        }

        let mem_dc = CreateCompatibleDC(screen_dc);
        if mem_dc == 0 {
            ReleaseDC(0, screen_dc);
            CloseDesktop(input_desktop);
            return Err(KrakenError::Module("CreateCompatibleDC failed".into()));
        }

        let bitmap = CreateCompatibleBitmap(screen_dc, width as i32, height as i32);
        if bitmap == 0 {
            DeleteDC(mem_dc);
            ReleaseDC(0, screen_dc);
            CloseDesktop(input_desktop);
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
            CloseDesktop(input_desktop);
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

        // Clean up GDI resources and the desktop handle
        SelectObject(mem_dc, old_obj);
        DeleteObject(bitmap);
        DeleteDC(mem_dc);
        ReleaseDC(0, screen_dc);
        CloseDesktop(input_desktop);

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
