//! PE parsing helpers for ntdll unhooking
//!
//! Provides utilities for parsing PE headers and finding sections.

/// DOS header signature "MZ"
pub const DOS_SIGNATURE: u16 = 0x5A4D;

/// PE signature "PE\0\0"
pub const PE_SIGNATURE: u32 = 0x00004550;

/// Section characteristics for .text
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;

/// Information about a PE section
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
}

impl SectionInfo {
    /// Check if this is the .text section
    pub fn is_text(&self) -> bool {
        &self.name[..5] == b".text"
    }

    /// Check if section contains executable code
    pub fn is_executable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            || (self.characteristics & IMAGE_SCN_CNT_CODE) != 0
    }
}

/// Parse PE and find the .text section
/// Returns (virtual_address_offset, size) relative to module base
#[cfg(target_os = "windows")]
pub unsafe fn find_text_section(base: *const u8) -> Option<SectionInfo> {
    // Check DOS signature
    let dos_sig = *(base as *const u16);
    if dos_sig != DOS_SIGNATURE {
        return None;
    }

    // Get e_lfanew (offset to PE header) at offset 0x3C
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let pe_header = base.add(e_lfanew);

    // Check PE signature
    let pe_sig = *(pe_header as *const u32);
    if pe_sig != PE_SIGNATURE {
        return None;
    }

    // Parse FILE_HEADER (starts at PE + 4)
    let file_header = pe_header.add(4);
    let number_of_sections = *(file_header.add(2) as *const u16) as usize;
    let size_of_optional_header = *(file_header.add(16) as *const u16) as usize;

    // OPTIONAL_HEADER starts at FILE_HEADER + 20
    let optional_header = file_header.add(20);

    // SECTION_HEADER array starts after OPTIONAL_HEADER
    let first_section = optional_header.add(size_of_optional_header);

    // Each section header is 40 bytes
    for i in 0..number_of_sections {
        let section = first_section.add(i * 40);

        // Read section name (8 bytes)
        let mut name = [0u8; 8];
        for j in 0..8 {
            name[j] = *section.add(j);
        }

        // Read section info
        let virtual_size = *(section.add(8) as *const u32);
        let virtual_address = *(section.add(12) as *const u32);
        let raw_data_size = *(section.add(16) as *const u32);
        let raw_data_offset = *(section.add(20) as *const u32);
        let characteristics = *(section.add(36) as *const u32);

        let info = SectionInfo {
            name,
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
        };

        if info.is_text() {
            return Some(info);
        }
    }

    None
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn find_text_section(_base: *const u8) -> Option<SectionInfo> {
    None
}

/// Get the base address of a loaded module by name
#[cfg(target_os = "windows")]
pub fn get_module_base(name: &str) -> Option<*const u8> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

    // Convert to null-terminated C string
    let mut name_bytes: Vec<u8> = name.bytes().collect();
    name_bytes.push(0);

    unsafe {
        let handle = GetModuleHandleA(name_bytes.as_ptr());
        if handle == 0 {
            None
        } else {
            Some(handle as *const u8)
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_module_base(_name: &str) -> Option<*const u8> {
    None
}

/// Get the address of an exported function
#[cfg(target_os = "windows")]
pub fn get_proc_address(module: *const u8, name: &str) -> Option<*const u8> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

    let mut name_bytes: Vec<u8> = name.bytes().collect();
    name_bytes.push(0);

    unsafe {
        let addr = GetProcAddress(module as isize, name_bytes.as_ptr());
        if addr.is_none() {
            None
        } else {
            Some(addr.unwrap() as *const u8)
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_proc_address(_module: *const u8, _name: &str) -> Option<*const u8> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_info_is_text() {
        let mut info = SectionInfo {
            name: [0; 8],
            virtual_address: 0x1000,
            virtual_size: 0x5000,
            raw_data_offset: 0x400,
            raw_data_size: 0x5000,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        };

        // Not .text yet
        assert!(!info.is_text());

        // Set .text name
        info.name[..5].copy_from_slice(b".text");
        assert!(info.is_text());
    }

    #[test]
    fn test_section_info_is_executable() {
        let info = SectionInfo {
            name: [0; 8],
            virtual_address: 0,
            virtual_size: 0,
            raw_data_offset: 0,
            raw_data_size: 0,
            characteristics: IMAGE_SCN_MEM_EXECUTE,
        };
        assert!(info.is_executable());

        let info2 = SectionInfo {
            characteristics: 0,
            ..info
        };
        assert!(!info2.is_executable());
    }

    #[test]
    fn test_constants() {
        assert_eq!(DOS_SIGNATURE, 0x5A4D);
        assert_eq!(PE_SIGNATURE, 0x00004550);
    }
}
