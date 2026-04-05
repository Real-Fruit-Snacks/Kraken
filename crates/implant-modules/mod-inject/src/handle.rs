//! RAII handle wrapper for Windows handles
//!
//! Provides automatic cleanup for Windows HANDLE values to prevent resource leaks.

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// RAII wrapper for Windows HANDLE
///
/// Automatically closes the handle when dropped.
#[cfg(windows)]
pub struct OwnedHandle(HANDLE);

#[cfg(windows)]
impl OwnedHandle {
    /// Create a new owned handle, returning None if invalid
    ///
    /// # Arguments
    /// * `h` - Raw Windows HANDLE value
    ///
    /// # Returns
    /// * `Some(OwnedHandle)` if the handle is valid
    /// * `None` if the handle is NULL or INVALID_HANDLE_VALUE
    pub fn new(h: HANDLE) -> Option<Self> {
        if h == 0 || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(h))
        }
    }

    /// Get the raw handle value
    ///
    /// Use this when passing to Windows APIs that need the raw handle.
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: We own the handle and it was valid when created
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// SAFETY: Windows HANDLEs can be safely sent between threads
#[cfg(windows)]
unsafe impl Send for OwnedHandle {}

// SAFETY: Windows HANDLEs can be safely shared between threads (read-only access)
#[cfg(windows)]
unsafe impl Sync for OwnedHandle {}

// Non-Windows stub for compilation
#[cfg(not(windows))]
pub struct OwnedHandle(());

#[cfg(not(windows))]
impl OwnedHandle {
    pub fn new(_h: isize) -> Option<Self> {
        None
    }

    pub fn as_raw(&self) -> isize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn test_owned_handle_stub() {
        // On non-Windows, creating a handle always returns None
        assert!(OwnedHandle::new(0).is_none());
        assert!(OwnedHandle::new(1234).is_none());
    }
}
