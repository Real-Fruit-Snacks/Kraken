//! Module code encryption for defense against memory forensics.
//!
//! Uses XOR encryption with a random key. While XOR is not cryptographically
//! strong, it's sufficient to defeat simple memory scanners and string searches.
//! The key is stored separately from the code to require attackers to correlate
//! multiple memory locations.
//!
//! # Security Model
//!
//! This is **not** intended to be cryptographically secure. The goal is to:
//! 1. Prevent casual discovery via `strings` or simple memory dumps
//! 2. Increase the effort required for memory forensics
//! 3. Reduce the exposure window of plaintext code
//!
//! A determined attacker with debugging access can still recover the code.

use std::sync::atomic::{fence, Ordering};

/// XOR encrypt/decrypt a memory region in-place.
///
/// Uses volatile writes to prevent compiler optimization from removing
/// the operations. A memory fence ensures all writes complete before
/// the function returns.
///
/// # Safety
///
/// - `base` must be a valid pointer to a writable memory region
/// - `size` must not exceed the allocated region
/// - The memory region must not be accessed concurrently
pub(crate) unsafe fn xor_memory_inplace(base: *mut u8, size: usize, key: &[u8; 32]) {
    for i in 0..size {
        let key_byte = key[i % 32];
        let ptr = base.add(i);
        let val = std::ptr::read_volatile(ptr);
        std::ptr::write_volatile(ptr, val ^ key_byte);
    }
    // Ensure all writes are visible before returning
    fence(Ordering::SeqCst);
}

/// Generate a cryptographically random 32-byte encryption key.
///
/// Uses the system's secure random number generator via ring.
pub fn generate_key() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key).expect("system RNG failure");
    key
}

/// Securely zero an encryption key using volatile writes.
///
/// This prevents the compiler from optimizing away the zeroing,
/// ensuring the key is actually cleared from memory.
pub fn zero_key(key: &mut [u8; 32]) {
    for byte in key.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    fence(Ordering::SeqCst);
}

/// Encryption state for a loaded module.
#[derive(Debug)]
pub struct ModuleEncryption {
    /// Random XOR key (32 bytes)
    key: [u8; 32],
    /// Whether the module is currently encrypted
    is_encrypted: bool,
    /// Reference count for nested decrypt calls
    decrypt_depth: u32,
}

impl ModuleEncryption {
    /// Create a new encryption state with a random key.
    /// The module starts in the encrypted state.
    pub fn new() -> Self {
        Self {
            key: generate_key(),
            is_encrypted: true,
            decrypt_depth: 0,
        }
    }

    /// Create encryption state for testing (with known key).
    #[cfg(test)]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key,
            is_encrypted: true,
            decrypt_depth: 0,
        }
    }

    /// Check if the module is currently encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    /// Get a reference to the encryption key (for initial encryption).
    pub fn key_ref(&self) -> &[u8; 32] {
        &self.key
    }

    /// Mark the module as encrypted (used after initial encryption).
    #[allow(dead_code)]
    pub fn set_encrypted(&mut self) {
        self.is_encrypted = true;
    }

    /// Mark the module as not encrypted (used for testing/setup).
    #[allow(dead_code)]
    pub fn set_decrypted(&mut self) {
        self.is_encrypted = false;
    }

    /// Decrypt the module code for execution.
    ///
    /// This is reference-counted to support nested calls.
    /// The first call decrypts; subsequent calls just increment the count.
    ///
    /// # Safety
    ///
    /// - `base` must point to the module's code section
    /// - `size` must be the exact size of the code section
    pub unsafe fn decrypt(&mut self, base: *mut u8, size: usize) {
        if self.decrypt_depth == 0 && self.is_encrypted {
            xor_memory_inplace(base, size, &self.key);
            self.is_encrypted = false;
        }
        self.decrypt_depth = self.decrypt_depth.saturating_add(1);
    }

    /// Re-encrypt the module code after execution.
    ///
    /// Only actually encrypts when the reference count reaches zero.
    ///
    /// # Safety
    ///
    /// - `base` must point to the module's code section
    /// - `size` must be the exact size of the code section
    pub unsafe fn encrypt(&mut self, base: *mut u8, size: usize) {
        self.decrypt_depth = self.decrypt_depth.saturating_sub(1);
        if self.decrypt_depth == 0 && !self.is_encrypted {
            xor_memory_inplace(base, size, &self.key);
            self.is_encrypted = true;
        }
    }

    /// Securely clear the encryption key.
    ///
    /// Call this before freeing the module memory.
    pub fn clear_key(&mut self) {
        zero_key(&mut self.key);
    }
}

impl Default for ModuleEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ModuleEncryption {
    fn drop(&mut self) {
        // Always zero the key on drop as a safety measure
        zero_key(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_roundtrip() {
        let mut data = [0x41u8; 64]; // "AAAA..."
        let original = data;
        let key = [0x55u8; 32];

        unsafe {
            xor_memory_inplace(data.as_mut_ptr(), data.len(), &key);
        }
        // After XOR with 0x55, 0x41 becomes 0x14
        assert_ne!(data, original, "data should be encrypted");
        assert_eq!(data[0], 0x41 ^ 0x55);

        unsafe {
            xor_memory_inplace(data.as_mut_ptr(), data.len(), &key);
        }
        // Second XOR restores original
        assert_eq!(data, original, "data should be restored");
    }

    #[test]
    fn test_generate_key_is_random() {
        let key1 = generate_key();
        let key2 = generate_key();
        assert_ne!(key1, key2, "keys should be different");
        assert_ne!(key1, [0u8; 32], "key should not be all zeros");
    }

    #[test]
    fn test_zero_key() {
        let mut key = generate_key();
        assert_ne!(key, [0u8; 32]);
        zero_key(&mut key);
        assert_eq!(key, [0u8; 32], "key should be zeroed");
    }

    #[test]
    fn test_module_encryption_lifecycle() {
        // This test simulates the full load sequence:
        // 1. Code is loaded as plaintext
        // 2. We encrypt it for storage
        // 3. Later we decrypt for execution
        // 4. Then re-encrypt after execution

        let mut enc = ModuleEncryption::with_key([0x42u8; 32]);
        let mut code = [0x90u8; 128]; // NOP sled (plaintext)
        let original = code;

        // ModuleEncryption::new() starts with is_encrypted = true,
        // but this is incorrect for the initial state. The loader
        // will encrypt after creation. Simulate that:

        // Actually, for this test we need to simulate the load sequence:
        // 1. Code is loaded plaintext
        // 2. We encrypt it (XOR)
        // 3. Later we decrypt for execution
        // 4. Then re-encrypt

        // Reset
        let mut enc = ModuleEncryption::with_key([0x42u8; 32]);
        let mut code = [0x90u8; 128];
        let original = code;

        // Simulate initial encryption after load (what the loader does)
        // Start with is_encrypted = false to match reality
        enc.is_encrypted = false;
        unsafe { enc.encrypt(code.as_mut_ptr(), code.len()) };
        assert!(enc.is_encrypted());
        assert_ne!(code, original, "code should be encrypted");

        // Now decrypt for execution
        unsafe { enc.decrypt(code.as_mut_ptr(), code.len()) };
        assert!(!enc.is_encrypted());
        assert_eq!(code, original, "code should be decrypted");

        // Re-encrypt after execution
        unsafe { enc.encrypt(code.as_mut_ptr(), code.len()) };
        assert!(enc.is_encrypted());
        assert_ne!(code, original, "code should be encrypted again");
    }

    #[test]
    fn test_nested_decrypt_calls() {
        let mut enc = ModuleEncryption::with_key([0x42u8; 32]);
        enc.is_encrypted = false; // Start decrypted
        let mut code = [0x90u8; 64];
        let original = code;

        // Encrypt first
        unsafe { enc.encrypt(code.as_mut_ptr(), code.len()) };
        assert!(enc.is_encrypted());

        // First decrypt
        unsafe { enc.decrypt(code.as_mut_ptr(), code.len()) };
        assert!(!enc.is_encrypted());
        assert_eq!(code, original);

        // Nested decrypt (shouldn't change anything)
        unsafe { enc.decrypt(code.as_mut_ptr(), code.len()) };
        assert!(!enc.is_encrypted());
        assert_eq!(code, original);

        // First encrypt (shouldn't encrypt yet, depth = 1)
        unsafe { enc.encrypt(code.as_mut_ptr(), code.len()) };
        assert!(!enc.is_encrypted()); // Still decrypted
        assert_eq!(code, original);

        // Second encrypt (now actually encrypts, depth = 0)
        unsafe { enc.encrypt(code.as_mut_ptr(), code.len()) };
        assert!(enc.is_encrypted());
        assert_ne!(code, original);
    }

    #[test]
    fn test_drop_zeros_key() {
        let key_copy;
        {
            let enc = ModuleEncryption::with_key([0xFFu8; 32]);
            key_copy = enc.key;
            assert_eq!(key_copy, [0xFFu8; 32]);
            // enc drops here
        }
        // Can't actually verify the key was zeroed since enc is dropped,
        // but we can verify the zero_key function works
        let mut test_key = [0xFFu8; 32];
        zero_key(&mut test_key);
        assert_eq!(test_key, [0u8; 32]);
    }
}
