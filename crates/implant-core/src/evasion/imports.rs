//! Import obfuscation — Phase 4 OPSEC
//!
//! Runtime API resolution to hide imports from static analysis.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar
//!
//! Instead of importing functions through the IAT (Import Address Table),
//! we resolve them at runtime using GetProcAddress with hashed names.

#[cfg(target_os = "windows")]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::sync::Mutex;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

/// DJB2 hash function for API name hashing
#[cfg(windows)]
pub const fn djb2_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < data.len() {
        hash = hash.wrapping_mul(33).wrapping_add(data[i] as u32);
        i += 1;
    }
    hash
}

/// Pre-computed hashes for common modules
#[cfg(windows)]
pub mod module_hashes {
    use super::djb2_hash;

    pub const KERNEL32: u32 = djb2_hash(b"kernel32.dll");
    pub const NTDLL: u32 = djb2_hash(b"ntdll.dll");
    pub const USER32: u32 = djb2_hash(b"user32.dll");
    pub const ADVAPI32: u32 = djb2_hash(b"advapi32.dll");
    pub const WS2_32: u32 = djb2_hash(b"ws2_32.dll");
}

/// Pre-computed hashes for common functions
#[cfg(windows)]
pub mod function_hashes {
    use super::djb2_hash;

    // kernel32.dll
    pub const VIRTUAL_ALLOC: u32 = djb2_hash(b"VirtualAlloc");
    pub const VIRTUAL_FREE: u32 = djb2_hash(b"VirtualFree");
    pub const VIRTUAL_PROTECT: u32 = djb2_hash(b"VirtualProtect");
    pub const CREATE_THREAD: u32 = djb2_hash(b"CreateThread");
    pub const WAIT_FOR_SINGLE_OBJECT: u32 = djb2_hash(b"WaitForSingleObject");
    pub const SLEEP: u32 = djb2_hash(b"Sleep");
    pub const GET_PROC_ADDRESS: u32 = djb2_hash(b"GetProcAddress");
    pub const LOAD_LIBRARY_A: u32 = djb2_hash(b"LoadLibraryA");
    pub const GET_MODULE_HANDLE_A: u32 = djb2_hash(b"GetModuleHandleA");

    // ntdll.dll
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtAllocateVirtualMemory");
    pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtProtectVirtualMemory");
    pub const NT_WRITE_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtWriteVirtualMemory");
    pub const RTL_INIT_UNICODE_STRING: u32 = djb2_hash(b"RtlInitUnicodeString");
}

/// Cache for resolved function addresses
#[cfg(target_os = "windows")]
struct ImportCache {
    /// Map from (module_hash, function_hash) to function address
    cache: HashMap<(u32, u32), usize>,
}

#[cfg(target_os = "windows")]
impl ImportCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    fn get(&self, module_hash: u32, func_hash: u32) -> Option<usize> {
        self.cache.get(&(module_hash, func_hash)).copied()
    }

    fn insert(&mut self, module_hash: u32, func_hash: u32, addr: usize) {
        self.cache.insert((module_hash, func_hash), addr);
    }
}

#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    static ref IMPORT_CACHE: Mutex<ImportCache> = Mutex::new(ImportCache::new());
}

/// Module name mapping for hash lookup
#[cfg(target_os = "windows")]
const MODULE_NAMES: &[(u32, &[u8])] = &[
    (module_hashes::KERNEL32, b"kernel32.dll\0"),
    (module_hashes::NTDLL, b"ntdll.dll\0"),
    (module_hashes::USER32, b"user32.dll\0"),
    (module_hashes::ADVAPI32, b"advapi32.dll\0"),
    (module_hashes::WS2_32, b"ws2_32.dll\0"),
];

/// Function name mapping for hash lookup
#[cfg(target_os = "windows")]
const FUNCTION_NAMES: &[(u32, &[u8])] = &[
    (function_hashes::VIRTUAL_ALLOC, b"VirtualAlloc\0"),
    (function_hashes::VIRTUAL_FREE, b"VirtualFree\0"),
    (function_hashes::VIRTUAL_PROTECT, b"VirtualProtect\0"),
    (function_hashes::CREATE_THREAD, b"CreateThread\0"),
    (
        function_hashes::WAIT_FOR_SINGLE_OBJECT,
        b"WaitForSingleObject\0",
    ),
    (function_hashes::SLEEP, b"Sleep\0"),
    (function_hashes::GET_PROC_ADDRESS, b"GetProcAddress\0"),
    (function_hashes::LOAD_LIBRARY_A, b"LoadLibraryA\0"),
    (function_hashes::GET_MODULE_HANDLE_A, b"GetModuleHandleA\0"),
    (
        function_hashes::NT_ALLOCATE_VIRTUAL_MEMORY,
        b"NtAllocateVirtualMemory\0",
    ),
    (
        function_hashes::NT_PROTECT_VIRTUAL_MEMORY,
        b"NtProtectVirtualMemory\0",
    ),
    (
        function_hashes::NT_WRITE_VIRTUAL_MEMORY,
        b"NtWriteVirtualMemory\0",
    ),
    (
        function_hashes::RTL_INIT_UNICODE_STRING,
        b"RtlInitUnicodeString\0",
    ),
];

/// Resolve a function by module and function hash
///
/// Returns the function address or None if not found.
#[cfg(target_os = "windows")]
pub fn resolve_import(module_hash: u32, func_hash: u32) -> Option<usize> {
    // Check cache first
    {
        let cache = IMPORT_CACHE.lock().unwrap();
        if let Some(addr) = cache.get(module_hash, func_hash) {
            return Some(addr);
        }
    }

    // Find module name
    let module_name = MODULE_NAMES
        .iter()
        .find(|(h, _)| *h == module_hash)
        .map(|(_, n)| *n)?;

    // Find function name
    let func_name = FUNCTION_NAMES
        .iter()
        .find(|(h, _)| *h == func_hash)
        .map(|(_, n)| *n)?;

    // Resolve the function
    unsafe {
        // Try GetModuleHandle first (module already loaded)
        let mut module = GetModuleHandleA(module_name.as_ptr());

        // If not loaded, try LoadLibrary
        if module == 0 {
            module = LoadLibraryA(module_name.as_ptr());
            if module == 0 {
                return None;
            }
        }

        // Get function address
        let func = GetProcAddress(module, func_name.as_ptr());
        let addr = func? as usize;

        // Cache the result
        let mut cache = IMPORT_CACHE.lock().unwrap();
        cache.insert(module_hash, func_hash, addr);

        Some(addr)
    }
}

/// Resolve a function and cast to the specified type
///
/// # Safety
/// The caller must ensure the function signature matches the requested type.
#[cfg(target_os = "windows")]
pub unsafe fn resolve_import_as<T>(module_hash: u32, func_hash: u32) -> Option<T>
where
    T: Copy,
{
    let addr = resolve_import(module_hash, func_hash)?;
    Some(std::mem::transmute_copy(&addr))
}

/// Clear the import cache
#[cfg(target_os = "windows")]
pub fn clear_cache() {
    let mut cache = IMPORT_CACHE.lock().unwrap();
    cache.cache.clear();
}

// =============================================================================
// Non-Windows stubs
// =============================================================================

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn resolve_import(_module_hash: u32, _func_hash: u32) -> Option<usize> {
    None
}

#[cfg(not(target_os = "windows"))]
/// # Safety
///
/// Caller must ensure `T` is a valid type to construct from the resolved import.
#[allow(dead_code)]
pub unsafe fn resolve_import_as<T>(_module_hash: u32, _func_hash: u32) -> Option<T>
where
    T: Copy,
{
    None
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn clear_cache() {}

// =============================================================================
// Macro for declaring obfuscated imports
// =============================================================================

/// Macro to call a function resolved at runtime
///
/// Usage:
/// ```ignore
/// let result = obf_call!(
///     kernel32::VirtualAlloc,
///     fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID,
///     ptr::null_mut(), size, MEM_COMMIT, PAGE_READWRITE
/// );
/// ```
#[macro_export]
macro_rules! obf_call {
    ($module:ident::$func:ident, $sig:ty, $($args:expr),* $(,)?) => {{
        use $crate::evasion::imports::{module_hashes, function_hashes, resolve_import_as};

        let func: Option<$sig> = unsafe {
            resolve_import_as(
                module_hashes::$module,
                function_hashes::$func,
            )
        };

        match func {
            Some(f) => Some(f($($args),*)),
            None => None,
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_hash_empty() {
        assert_eq!(djb2_hash(b""), 5381);
    }

    #[test]
    fn test_djb2_hash_known_values() {
        // Verify hash consistency
        assert_eq!(djb2_hash(b"kernel32.dll"), module_hashes::KERNEL32);
        assert_eq!(djb2_hash(b"ntdll.dll"), module_hashes::NTDLL);
        assert_eq!(djb2_hash(b"VirtualAlloc"), function_hashes::VIRTUAL_ALLOC);
    }

    #[test]
    fn test_module_hashes_unique() {
        let hashes = [
            module_hashes::KERNEL32,
            module_hashes::NTDLL,
            module_hashes::USER32,
            module_hashes::ADVAPI32,
            module_hashes::WS2_32,
        ];

        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "Module hash collision at {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_function_hashes_unique() {
        let hashes = [
            function_hashes::VIRTUAL_ALLOC,
            function_hashes::VIRTUAL_FREE,
            function_hashes::VIRTUAL_PROTECT,
            function_hashes::CREATE_THREAD,
            function_hashes::SLEEP,
            function_hashes::NT_ALLOCATE_VIRTUAL_MEMORY,
        ];

        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "Function hash collision at {} and {}", i, j);
            }
        }
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_resolve_import_non_windows() {
        let result = resolve_import(module_hashes::KERNEL32, function_hashes::VIRTUAL_ALLOC);
        assert!(result.is_none());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_resolve_kernel32_function() {
        // VirtualAlloc should be resolvable
        let result = resolve_import(module_hashes::KERNEL32, function_hashes::VIRTUAL_ALLOC);
        assert!(result.is_some(), "VirtualAlloc should be resolvable");
        assert!(result.unwrap() != 0, "VirtualAlloc address should be non-zero");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_resolve_ntdll_function() {
        let result = resolve_import(module_hashes::NTDLL, function_hashes::NT_ALLOCATE_VIRTUAL_MEMORY);
        assert!(result.is_some(), "NtAllocateVirtualMemory should be resolvable");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_import_cache() {
        // Clear cache first
        clear_cache();

        // First resolution
        let addr1 = resolve_import(module_hashes::KERNEL32, function_hashes::SLEEP);
        assert!(addr1.is_some());

        // Second resolution should hit cache
        let addr2 = resolve_import(module_hashes::KERNEL32, function_hashes::SLEEP);
        assert_eq!(addr1, addr2);
    }
}
