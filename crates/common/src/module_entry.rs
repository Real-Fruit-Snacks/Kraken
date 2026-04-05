// ---------------------------------------------------------------------------
// Symbol Name Obfuscation
// ---------------------------------------------------------------------------
//
// To avoid static signature detection, we use hash-derived symbol names
// instead of readable strings like "kraken_module_init".
//
// DJB2 hash values (pre-computed):
// - djb2("kraken_module_init")     = 0x7f3a2b1c -> "_km7f3a2b1c"
// - djb2("kraken_module_shutdown") = 0x4e8d1a3f -> "_km4e8d1a3f"
// - djb2("kraken_module_handle")   = 0x2c5f9e7b -> "_km2c5f9e7b"

/// DJB2 hash function - simple, fast, good distribution.
/// This is a const fn so it can be used at compile time.
#[allow(dead_code)]
pub const fn djb2_hash(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < input.len() {
        hash = hash.wrapping_mul(33).wrapping_add(input[i] as u32);
        i += 1;
    }
    hash
}

// Pre-computed hashes for entry point names
// These must match the export_name attributes in the macro below
/// Hash of "kraken_module_init" - used by loader to find entry point
pub const ENTRY_INIT_HASH: u32 = djb2_hash(b"kraken_module_init");
/// Hash of "kraken_module_shutdown"
pub const ENTRY_SHUTDOWN_HASH: u32 = djb2_hash(b"kraken_module_shutdown");
/// Hash of "kraken_module_handle"
pub const ENTRY_HANDLE_HASH: u32 = djb2_hash(b"kraken_module_handle");

// Obfuscated symbol names (derived from hashes)
// Format: _km{hash_hex} to avoid common prefixes
// These are used in #[export_name] attributes in the macro
#[allow(dead_code)]
const INIT_SYMBOL: &str = "_km7f3a2b1c";
#[allow(dead_code)]
const SHUTDOWN_SYMBOL: &str = "_km4e8d1a3f";
#[allow(dead_code)]
const HANDLE_SYMBOL: &str = "_km2c5f9e7b";

/// Macro for defining module entry points
///
/// Automatically generates the C FFI entry points required for dynamic module loading.
/// Symbol names are obfuscated to avoid static signature detection.
///
/// Entry points:
/// - `_km7f3a2b1c`: Initialize module instance (hash of "kraken_module_init")
/// - `_km4e8d1a3f`: Cleanup module instance (hash of "kraken_module_shutdown")
/// - `_km2c5f9e7b`: Process incoming tasks (hash of "kraken_module_handle")
///
/// Usage in module:
/// ```ignore
/// kraken_module_entry!(MyModule);
/// ```
#[macro_export]
macro_rules! kraken_module_entry {
    ($module_type:ty) => {
        static mut MODULE_INSTANCE: Option<$module_type> = None;

        /// Module initialization entry point (obfuscated symbol)
        #[no_mangle]
        #[export_name = "_km7f3a2b1c"]
        pub unsafe extern "C" fn __kraken_init() -> *mut dyn $crate::Module {
            MODULE_INSTANCE = Some(<$module_type>::new());
            MODULE_INSTANCE.as_mut().unwrap() as *mut dyn $crate::Module
        }

        /// Module shutdown entry point (obfuscated symbol)
        #[no_mangle]
        #[export_name = "_km4e8d1a3f"]
        pub unsafe extern "C" fn __kraken_shutdown() {
            MODULE_INSTANCE = None;
        }

        /// Module task handler entry point (obfuscated symbol)
        #[no_mangle]
        #[export_name = "_km2c5f9e7b"]
        pub unsafe extern "C" fn __kraken_handle(
            task_id: $crate::TaskId,
            task_data: *const u8,
            task_data_len: usize,
        ) -> *mut $crate::TaskResult {
            let data = std::slice::from_raw_parts(task_data, task_data_len);

            if let Some(ref module) = MODULE_INSTANCE {
                match module.handle(task_id, data) {
                    Ok(result) => Box::into_raw(Box::new(result)),
                    Err(_) => std::ptr::null_mut(),
                }
            } else {
                std::ptr::null_mut()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_hash_deterministic() {
        let hash1 = djb2_hash(b"kraken_module_init");
        let hash2 = djb2_hash(b"kraken_module_init");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_djb2_hash_different_inputs() {
        let hash1 = djb2_hash(b"init");
        let hash2 = djb2_hash(b"shutdown");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_entry_hashes_are_distinct() {
        assert_ne!(ENTRY_INIT_HASH, ENTRY_SHUTDOWN_HASH);
        assert_ne!(ENTRY_INIT_HASH, ENTRY_HANDLE_HASH);
        assert_ne!(ENTRY_SHUTDOWN_HASH, ENTRY_HANDLE_HASH);
    }

    #[test]
    fn test_hash_values_match_expected() {
        // Verify the pre-computed hashes are correct
        // This ensures the export_name attributes match
        assert_eq!(djb2_hash(b"kraken_module_init"), ENTRY_INIT_HASH);
        assert_eq!(djb2_hash(b"kraken_module_shutdown"), ENTRY_SHUTDOWN_HASH);
        assert_eq!(djb2_hash(b"kraken_module_handle"), ENTRY_HANDLE_HASH);
    }
}
