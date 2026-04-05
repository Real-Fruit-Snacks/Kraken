//! Secure memory operations for module lifecycle management.
//!
//! This module provides security-critical functions for safely handling
//! executable code in memory:
//!
//! - [`secure_zero`] — Volatile zeroing with memory fence to prevent optimization.
//! - [`secure_unload`] — Full secure cleanup: zero, fence, then free.
//! - [`validate_module_safety`] — Pre-load validation of module blobs.

use std::ptr;
use std::sync::atomic::{fence, Ordering};

use common::KrakenError;

use crate::memory;

/// Maximum allowed code size for a module (100 KB).
pub const MAX_MODULE_SIZE: usize = 100 * 1024;

/// Module blob magic bytes (expected at offset 0).
const MODULE_MAGIC: &[u8; 4] = b"KMOD";

/// Minimum blob size: magic (4) + header fields.
const MIN_BLOB_SIZE: usize = 32;

/// Zero memory using volatile writes to prevent compiler optimization.
///
/// This function ensures that the zeroing operation cannot be elided by the
/// compiler, which is critical for security-sensitive cleanup of executable
/// code regions.
///
/// # Safety
///
/// - `ptr` must be valid for writes of `len` bytes.
/// - `ptr` must be properly aligned for `u8` writes.
/// - The memory region must not be accessed concurrently.
#[inline(never)]
pub unsafe fn secure_zero(ptr: *mut u8, len: usize) {
    // Use volatile writes byte-by-byte to prevent optimization.
    // The #[inline(never)] attribute provides additional protection against
    // the compiler optimizing away this function entirely.
    for i in 0..len {
        ptr::write_volatile(ptr.add(i), 0u8);
    }

    // Memory fence ensures all writes are visible before any subsequent
    // operations. This prevents reordering that could allow code to execute
    // before zeroing completes.
    fence(Ordering::SeqCst);
}

/// Securely unload a module: zero its code region, then free the mapping.
///
/// This function performs a secure cleanup sequence:
/// 1. Zero the memory region using volatile writes (cannot be optimized away).
/// 2. Issue a memory fence to ensure zeroing is complete.
/// 3. Release the memory back to the OS.
///
/// # Safety
///
/// - `base` must be a pointer returned by [`memory::allocate_executable`].
/// - `size` must match the size passed to the allocation function.
/// - The memory region must not be in use (no active references or calls).
pub unsafe fn secure_unload(base: *mut u8, size: usize) -> Result<(), KrakenError> {
    // Step 1 & 2: Zero memory with volatile writes and fence.
    secure_zero(base, size);

    // Step 3: Release the memory mapping.
    memory::free_executable(base, size)
}

/// Validate a module blob before loading.
///
/// Performs basic safety checks:
/// - Code size is within the allowed limit (100 KB).
/// - Blob has valid magic bytes and minimum structure.
///
/// This function should be called early in the load process to reject
/// malformed or oversized blobs before any memory allocation occurs.
pub fn validate_module_safety(blob: &[u8]) -> Result<(), KrakenError> {
    // Check minimum blob size.
    if blob.len() < MIN_BLOB_SIZE {
        return Err(KrakenError::Module(format!(
            "blob too small: {} bytes (minimum {})",
            blob.len(),
            MIN_BLOB_SIZE
        )));
    }

    // Check magic bytes.
    if &blob[0..4] != MODULE_MAGIC {
        return Err(KrakenError::Module(
            "invalid module magic bytes".into()
        ));
    }

    // Extract code size from header (assuming it's at a fixed offset).
    // The actual code section size check happens after full parsing,
    // but we can do a preliminary check on the total blob size.
    if blob.len() > MAX_MODULE_SIZE + 1024 {
        // Allow some overhead for headers, but reject obviously oversized blobs.
        return Err(KrakenError::Module(format!(
            "module blob exceeds maximum size: {} bytes (limit ~{})",
            blob.len(),
            MAX_MODULE_SIZE
        )));
    }

    Ok(())
}

/// Validate that a parsed code section is within size limits.
///
/// Call this after parsing the blob header but before allocating memory.
pub fn validate_code_size(code_size: usize) -> Result<(), KrakenError> {
    if code_size > MAX_MODULE_SIZE {
        return Err(KrakenError::Module(format!(
            "code section exceeds maximum size: {} bytes (limit {})",
            code_size, MAX_MODULE_SIZE
        )));
    }

    if code_size == 0 {
        return Err(KrakenError::Module("code section is empty".into()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_zero_clears_memory() {
        let mut buf = [0xFFu8; 64];
        unsafe {
            secure_zero(buf.as_mut_ptr(), buf.len());
        }
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn validate_rejects_small_blob() {
        let small = [0u8; 16];
        assert!(validate_module_safety(&small).is_err());
    }

    #[test]
    fn validate_rejects_bad_magic() {
        let mut blob = [0u8; 64];
        blob[0..4].copy_from_slice(b"XXXX");
        assert!(validate_module_safety(&blob).is_err());
    }

    #[test]
    fn validate_accepts_valid_magic() {
        let mut blob = [0u8; 64];
        blob[0..4].copy_from_slice(b"KMOD");
        assert!(validate_module_safety(&blob).is_ok());
    }

    #[test]
    fn validate_code_size_rejects_oversized() {
        assert!(validate_code_size(MAX_MODULE_SIZE + 1).is_err());
    }

    #[test]
    fn validate_code_size_rejects_empty() {
        assert!(validate_code_size(0).is_err());
    }

    #[test]
    fn validate_code_size_accepts_valid() {
        assert!(validate_code_size(1024).is_ok());
        assert!(validate_code_size(MAX_MODULE_SIZE).is_ok());
    }
}
