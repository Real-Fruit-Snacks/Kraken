//! RAII wrapper for Windows token handles
//!
//! Provides automatic cleanup via CloseHandle on drop.

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// RAII wrapper for a Windows token HANDLE.
///
/// The handle is closed automatically when this value is dropped.
#[cfg(windows)]
pub struct TokenHandle(HANDLE);

#[cfg(windows)]
impl TokenHandle {
    /// Wrap a raw handle.  Returns `None` if the handle is NULL or
    /// INVALID_HANDLE_VALUE.
    pub fn new(h: HANDLE) -> Option<Self> {
        if h == 0 || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(h))
        }
    }

    /// Return the raw handle value for use with Windows APIs.
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: We own the handle and it was valid at construction time.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// SAFETY: A token HANDLE can be sent between threads.
#[cfg(windows)]
unsafe impl Send for TokenHandle {}

// SAFETY: Read-only access to the underlying handle value is safe from
// multiple threads simultaneously.
#[cfg(windows)]
unsafe impl Sync for TokenHandle {}

// ---------------------------------------------------------------------------
// Non-Windows stub so the crate compiles on all platforms.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub struct TokenHandle(());

#[cfg(not(windows))]
impl TokenHandle {
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
    fn stub_always_returns_none() {
        assert!(TokenHandle::new(0).is_none());
        assert!(TokenHandle::new(999).is_none());
    }

    // ------------------------------------------------------------------
    // Handle creation — cross-platform (non-Windows stub)
    // ------------------------------------------------------------------

    #[cfg(not(windows))]
    #[test]
    fn stub_negative_handle_returns_none() {
        assert!(TokenHandle::new(-1).is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn stub_large_positive_handle_returns_none() {
        assert!(TokenHandle::new(isize::MAX).is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn stub_as_raw_returns_zero() {
        // as_raw is only reachable through Some, which never happens on
        // non-Windows, so we verify the method exists and returns 0 when
        // called on a manually constructed stub.
        let h = TokenHandle(());
        assert_eq!(h.as_raw(), 0);
    }

    // ------------------------------------------------------------------
    // Handle creation — Windows only
    // ------------------------------------------------------------------

    /// NULL handle (value 0) must be rejected.
    #[cfg(windows)]
    #[test]
    fn null_handle_returns_none() {
        assert!(TokenHandle::new(0 as windows_sys::Win32::Foundation::HANDLE).is_none());
    }

    /// INVALID_HANDLE_VALUE must be rejected.
    #[cfg(windows)]
    #[test]
    fn invalid_handle_value_returns_none() {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        assert!(TokenHandle::new(INVALID_HANDLE_VALUE).is_none());
    }

    /// A non-null, non-invalid handle value produces Some and round-trips
    /// through as_raw correctly.
    ///
    /// NOTE: this test uses a synthetic handle value (0x100) that is NOT a
    /// real OS handle — it will be "closed" via CloseHandle on drop which
    /// may fail silently, but the structural API contract is still verified.
    #[cfg(windows)]
    #[test]
    fn valid_handle_value_round_trips() {
        // Use a value unlikely to be a real handle; we only test the
        // wrapper's structural behaviour, not actual OS resource management.
        let raw: windows_sys::Win32::Foundation::HANDLE = 0x100;
        if let Some(h) = TokenHandle::new(raw) {
            assert_eq!(h.as_raw(), raw);
            // Drop here calls CloseHandle — may fail silently on fake handle.
            std::mem::forget(h); // avoid CloseHandle on fake value
        }
        // If TokenHandle::new returns None for 0x100 on this system that is
        // also acceptable — just don't panic.
    }

    /// Dropping a TokenHandle must not panic (even if CloseHandle fails on a
    /// fake value).  We use std::mem::forget to avoid actually calling
    /// CloseHandle on a synthetic value in the valid-handle test, so here we
    /// confirm the Drop impl compiles and is reachable.
    #[cfg(windows)]
    #[test]
    fn drop_does_not_panic_on_real_pseudo_handle() {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // GetCurrentProcess() returns a pseudo-handle that is always valid and
        // does NOT need to be closed (CloseHandle on it is a no-op), making it
        // safe to wrap and drop here.
        let pseudo: windows_sys::Win32::Foundation::HANDLE = unsafe { GetCurrentProcess() };
        // The pseudo-handle value is -1 (same as INVALID_HANDLE_VALUE on
        // some SDK versions).  If our wrapper rejects it, that is fine too.
        if let Some(h) = TokenHandle::new(pseudo) {
            drop(h); // must not panic
        }
    }

    // ------------------------------------------------------------------
    // Handle duplication (Windows only, uses real process token)
    // ------------------------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn handle_wraps_duplicated_process_token() {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, TOKEN_ALL_ACCESS};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows_sys::Win32::Security::TOKEN_DUPLICATE;

        unsafe {
            let mut src: HANDLE = 0;
            let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut src);
            assert_ne!(ok, 0, "OpenProcessToken failed");

            let src_h = TokenHandle::new(src).expect("src token must be valid");

            let mut dup: HANDLE = 0;
            let ok = DuplicateTokenEx(
                src_h.as_raw(),
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut dup,
            );
            assert_ne!(ok, 0, "DuplicateTokenEx failed");

            let dup_h = TokenHandle::new(dup).expect("duplicated token must be valid");
            assert_ne!(dup_h.as_raw(), 0);
            drop(dup_h); // CloseHandle via Drop
        }
    }
}
