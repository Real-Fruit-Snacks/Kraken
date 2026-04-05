//! Platform-specific executable memory management.
//!
//! All three public functions present the same interface on every platform:
//!
//! - [`allocate_executable`] — allocate RW memory ready to receive code.
//! - [`protect_executable`] — transition the region to RX (no-write).
//! - [`free_executable`] — release the region back to the OS.
//!
//! The two-step alloc→protect pattern lets us copy bytes into the region while
//! it is still writable, then harden it before the first call.

use common::KrakenError;

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod platform {
    use super::KrakenError;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
        PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };

    pub fn allocate_executable(size: usize) -> Result<*mut u8, KrakenError> {
        // SAFETY: Windows API call with valid parameters.
        let ptr = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if ptr.is_null() {
            return Err(KrakenError::Module("VirtualAlloc failed".into()));
        }

        Ok(ptr as *mut u8)
    }

    pub fn protect_executable(base: *mut u8, size: usize) -> Result<(), KrakenError> {
        let mut old_protect: PAGE_PROTECTION_FLAGS = 0;

        // SAFETY: `base` and `size` describe the allocation returned by
        // `allocate_executable`; the old-protect output pointer is valid.
        let rc = unsafe {
            VirtualProtect(base as *const core::ffi::c_void, size, PAGE_EXECUTE_READ, &mut old_protect)
        };

        if rc == 0 {
            return Err(KrakenError::Module("VirtualProtect failed".into()));
        }

        Ok(())
    }

    pub fn free_executable(base: *mut u8, _size: usize) -> Result<(), KrakenError> {
        // SAFETY: `base` was obtained from `VirtualAlloc`; size argument is 0
        // when using MEM_RELEASE as required by the API contract.
        let rc = unsafe { VirtualFree(base as *mut core::ffi::c_void, 0, MEM_RELEASE) };

        if rc == 0 {
            return Err(KrakenError::Module("VirtualFree failed".into()));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Linux / macOS / other POSIX
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::KrakenError;

    pub fn allocate_executable(size: usize) -> Result<*mut u8, KrakenError> {
        // SAFETY: Standard mmap call requesting anonymous private mapping.
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(KrakenError::Module("mmap failed".into()));
        }

        Ok(ptr as *mut u8)
    }

    pub fn protect_executable(base: *mut u8, size: usize) -> Result<(), KrakenError> {
        // SAFETY: `base` and `size` describe the mapping created by
        // `allocate_executable`; PROT_READ|PROT_EXEC is a valid combination.
        let rc = unsafe {
            libc::mprotect(
                base as *mut libc::c_void,
                size,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };

        if rc != 0 {
            return Err(KrakenError::Module("mprotect failed".into()));
        }

        Ok(())
    }

    pub fn free_executable(base: *mut u8, size: usize) -> Result<(), KrakenError> {
        // SAFETY: `base` and `size` match the original mmap call.
        let rc = unsafe { libc::munmap(base as *mut libc::c_void, size) };

        if rc != 0 {
            return Err(KrakenError::Module("munmap failed".into()));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

/// Allocate a region of `size` bytes with read-write permissions, suitable
/// for copying code into.  The region must be transitioned to executable via
/// [`protect_executable`] before any code in it is called.
pub fn allocate_executable(size: usize) -> Result<*mut u8, KrakenError> {
    platform::allocate_executable(size)
}

/// Transition the region at `base..base+size` from read-write to
/// read-execute.  Must be called after all code bytes have been written.
pub fn protect_executable(base: *mut u8, size: usize) -> Result<(), KrakenError> {
    platform::protect_executable(base, size)
}

/// Zero and release the executable region.  The caller is responsible for
/// zeroing memory **before** calling this function (see
/// [`DynamicModuleLoader::unload`]).
pub fn free_executable(base: *mut u8, size: usize) -> Result<(), KrakenError> {
    platform::free_executable(base, size)
}
