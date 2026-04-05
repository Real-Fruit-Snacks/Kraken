//! BOF memory loader
//!
//! Loads COFF sections into memory, applies relocations, and executes the entry point.

use crate::beacon_api;
use crate::coff::{
    CoffFile, CoffRelocation, IMAGE_REL_AMD64_ADDR64, IMAGE_REL_AMD64_ADDR32NB,
    IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_1, IMAGE_REL_AMD64_REL32_2,
    IMAGE_REL_AMD64_REL32_3, IMAGE_REL_AMD64_REL32_4, IMAGE_REL_AMD64_REL32_5,
    IMAGE_SCN_MEM_EXECUTE,
};
use common::KrakenError;
use std::collections::HashMap;
use std::ptr;

/// Loaded section in memory
struct LoadedSection {
    base: *mut u8,
    size: usize,
    is_executable: bool,
}

/// Trampoline for far calls (when target is >2GB away)
/// Structure: mov rax, <addr>; jmp rax (12 bytes)
const TRAMPOLINE_SIZE: usize = 12;
const MAX_TRAMPOLINES: usize = 64;

/// BOF loader for in-memory COFF execution
pub struct BofLoader {
    sections: Vec<LoadedSection>,
    symbol_map: HashMap<String, usize>,
    /// Trampoline table for far function calls
    trampoline_base: *mut u8,
    trampoline_count: usize,
    /// Map from target address to trampoline address
    trampoline_map: HashMap<usize, usize>,
}

impl BofLoader {
    pub fn new() -> Self {
        // Allocate trampoline table
        let trampoline_size = TRAMPOLINE_SIZE * MAX_TRAMPOLINES;
        let trampoline_base = Self::allocate_trampoline_table(trampoline_size);

        Self {
            sections: Vec::new(),
            symbol_map: HashMap::new(),
            trampoline_base,
            trampoline_count: 0,
            trampoline_map: HashMap::new(),
        }
    }

    #[cfg(target_os = "windows")]
    fn allocate_trampoline_table(size: usize) -> *mut u8 {
        use windows_sys::Win32::System::Memory::*;
        unsafe {
            VirtualAlloc(
                ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8
        }
    }

    #[cfg(target_os = "linux")]
    fn allocate_trampoline_table(size: usize) -> *mut u8 {
        unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut u8
        }
    }

    /// Create a trampoline for a far call target
    /// Returns the trampoline address that can be called instead
    fn get_or_create_trampoline(&mut self, target_addr: usize) -> Result<usize, KrakenError> {
        // Check if we already have a trampoline for this target
        if let Some(&trampoline_addr) = self.trampoline_map.get(&target_addr) {
            return Ok(trampoline_addr);
        }

        if self.trampoline_count >= MAX_TRAMPOLINES {
            return Err(KrakenError::Internal("too many trampolines".into()));
        }

        if self.trampoline_base.is_null() {
            return Err(KrakenError::Internal("trampoline table not allocated".into()));
        }

        let trampoline_addr = unsafe {
            self.trampoline_base.add(self.trampoline_count * TRAMPOLINE_SIZE)
        };

        // Write trampoline: mov rax, <addr>; jmp rax
        // 48 B8 <8-byte addr>  = movabs rax, imm64
        // FF E0                = jmp rax
        unsafe {
            let p = trampoline_addr;
            *p = 0x48; // REX.W
            *p.add(1) = 0xB8; // MOV RAX, imm64
            // Write 64-bit address (little-endian)
            let addr_bytes = (target_addr as u64).to_le_bytes();
            ptr::copy_nonoverlapping(addr_bytes.as_ptr(), p.add(2), 8);
            *p.add(10) = 0xFF; // JMP
            *p.add(11) = 0xE0; // RAX
        }

        let result = trampoline_addr as usize;
        self.trampoline_map.insert(target_addr, result);
        self.trampoline_count += 1;

        Ok(result)
    }

    /// Load a parsed COFF file into memory
    pub fn load(&mut self, coff: &CoffFile) -> Result<(), KrakenError> {
        // Allocate memory for each section
        for section in &coff.sections {
            let size = section.data.len().max(section.virtual_size as usize).max(1);
            let is_executable = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

            let base = self.allocate_section(size)?;

            // Copy section data
            unsafe {
                ptr::copy_nonoverlapping(section.data.as_ptr(), base, section.data.len());
                // Zero-fill remainder if virtual_size > raw_data
                if size > section.data.len() {
                    ptr::write_bytes(base.add(section.data.len()), 0, size - section.data.len());
                }
            }

            self.sections.push(LoadedSection {
                base,
                size,
                is_executable,
            });
        }

        // Build symbol map for internal symbols
        for symbol in &coff.symbols {
            if symbol.section > 0 {
                let section_idx = (symbol.section - 1) as usize;
                if section_idx < self.sections.len() {
                    let addr = unsafe {
                        self.sections[section_idx]
                            .base
                            .add(symbol.value as usize) as usize
                    };
                    self.symbol_map.insert(symbol.name.clone(), addr);
                }
            }
        }

        // Apply relocations
        for (section_idx, relocs) in &coff.relocations {
            self.apply_relocations(*section_idx, relocs, coff)?;
        }

        // Make executable sections executable
        for section in &self.sections {
            if section.is_executable {
                self.protect_executable(section.base, section.size)?;
            }
        }

        Ok(())
    }

    /// Allocate memory for a section
    #[cfg(target_os = "windows")]
    fn allocate_section(&self, size: usize) -> Result<*mut u8, KrakenError> {
        use windows_sys::Win32::System::Memory::*;

        let base = unsafe {
            VirtualAlloc(
                ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8
        };

        if base.is_null() {
            return Err(KrakenError::Internal("VirtualAlloc failed".into()));
        }

        Ok(base)
    }

    #[cfg(target_os = "linux")]
    fn allocate_section(&self, size: usize) -> Result<*mut u8, KrakenError> {
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut u8
        };

        if base == libc::MAP_FAILED as *mut u8 {
            return Err(KrakenError::Internal("mmap failed".into()));
        }

        Ok(base)
    }

    /// Make a memory region executable
    #[cfg(target_os = "windows")]
    fn protect_executable(&self, base: *mut u8, size: usize) -> Result<(), KrakenError> {
        use windows_sys::Win32::System::Memory::*;

        let mut old_protect: u32 = 0;
        let result =
            unsafe { VirtualProtect(base as *const _, size, PAGE_EXECUTE_READ, &mut old_protect) };

        if result == 0 {
            return Err(KrakenError::Internal("VirtualProtect failed".into()));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn protect_executable(&self, base: *mut u8, size: usize) -> Result<(), KrakenError> {
        let result =
            unsafe { libc::mprotect(base as *mut _, size, libc::PROT_READ | libc::PROT_EXEC) };

        if result != 0 {
            return Err(KrakenError::Internal("mprotect failed".into()));
        }

        Ok(())
    }

    /// Apply relocations for a section
    fn apply_relocations(
        &mut self,
        section_idx: usize,
        relocs: &[CoffRelocation],
        coff: &CoffFile,
    ) -> Result<(), KrakenError> {
        let section_base = self.sections[section_idx].base;

        for reloc in relocs {
            if reloc.symbol_index as usize >= coff.symbols.len() {
                return Err(KrakenError::Internal(format!(
                    "relocation symbol index out of bounds: {}",
                    reloc.symbol_index
                )));
            }

            let symbol = &coff.symbols[reloc.symbol_index as usize];

            // Resolve symbol address
            let target_addr = self.resolve_symbol_for_reloc(symbol)?;

            let reloc_addr = unsafe { section_base.add(reloc.offset as usize) };

            // Apply relocation based on type
            // Apply relocation based on type
            match reloc.reloc_type {
                IMAGE_REL_AMD64_ADDR64 => {
                    // Absolute 64-bit address - no range issues
                    unsafe {
                        *(reloc_addr as *mut u64) = target_addr as u64;
                    }
                }
                IMAGE_REL_AMD64_ADDR32NB => {
                    // 32-bit address without base (RVA-style)
                    // For in-memory loaded BOFs, use lower 32 bits of absolute address
                    // This works when all sections are allocated in low 4GB or same region
                    let addr32 = target_addr as u32;
                    unsafe {
                        *(reloc_addr as *mut u32) = addr32;
                    }
                }
                IMAGE_REL_AMD64_REL32
                | IMAGE_REL_AMD64_REL32_1
                | IMAGE_REL_AMD64_REL32_2
                | IMAGE_REL_AMD64_REL32_3
                | IMAGE_REL_AMD64_REL32_4
                | IMAGE_REL_AMD64_REL32_5 => {
                    // 32-bit relative address - check if target is within range
                    let addend: i64 = match reloc.reloc_type {
                        IMAGE_REL_AMD64_REL32 => 4,
                        IMAGE_REL_AMD64_REL32_1 => 5,
                        IMAGE_REL_AMD64_REL32_2 => 6,
                        IMAGE_REL_AMD64_REL32_3 => 7,
                        IMAGE_REL_AMD64_REL32_4 => 8,
                        IMAGE_REL_AMD64_REL32_5 => 9,
                        _ => unreachable!(),
                    };

                    let relative = (target_addr as i64) - (reloc_addr as i64 + addend);

                    // Check if relative offset fits in 32 bits
                    let final_addr = if relative > i32::MAX as i64 || relative < i32::MIN as i64 {
                        // Target too far - use trampoline
                        let trampoline = self.get_or_create_trampoline(target_addr)?;
                        let tramp_relative = (trampoline as i64) - (reloc_addr as i64 + addend);
                        if tramp_relative > i32::MAX as i64 || tramp_relative < i32::MIN as i64 {
                            return Err(KrakenError::Internal(
                                "trampoline also out of range".into(),
                            ));
                        }
                        tramp_relative as i32
                    } else {
                        relative as i32
                    };

                    unsafe {
                        *(reloc_addr as *mut i32) = final_addr;
                    }
                }
                _ => {
                    return Err(KrakenError::Internal(format!(
                        "unsupported relocation type: 0x{:04x}",
                        reloc.reloc_type
                    )));
                }
            }
        }

        Ok(())
    }

    /// Resolve a symbol for relocation purposes
    fn resolve_symbol_for_reloc(
        &self,
        symbol: &crate::coff::CoffSymbol,
    ) -> Result<usize, KrakenError> {
        // Check for import symbols (__imp_DLL$Function)
        if symbol.name.starts_with("__imp_") {
            let import_name = &symbol.name[6..];
            return self.resolve_import(import_name);
        }

        // Check for Beacon API symbols
        if symbol.name.starts_with("Beacon") {
            return beacon_api::resolve(&symbol.name);
        }

        // Check our symbol map
        if let Some(&addr) = self.symbol_map.get(&symbol.name) {
            return Ok(addr);
        }

        // External symbol in a section
        if symbol.section > 0 {
            let section_idx = (symbol.section - 1) as usize;
            if section_idx < self.sections.len() {
                let addr = unsafe {
                    self.sections[section_idx]
                        .base
                        .add(symbol.value as usize) as usize
                };
                return Ok(addr);
            }
        }

        Err(KrakenError::Internal(format!(
            "unresolved symbol: {}",
            symbol.name
        )))
    }

    /// Resolve a dynamic import (DLL$Function format)
    #[cfg(target_os = "windows")]
    fn resolve_import(&self, name: &str) -> Result<usize, KrakenError> {
        use windows_sys::Win32::System::LibraryLoader::*;

        // Parse DLL$Function format
        let parts: Vec<&str> = name.split('$').collect();
        if parts.len() != 2 {
            return Err(KrakenError::Internal(format!(
                "invalid import format: {}",
                name
            )));
        }

        let dll_name = format!("{}.dll\0", parts[0]);
        let func_name = format!("{}\0", parts[1]);

        unsafe {
            // Try to get existing module handle
            let mut module = GetModuleHandleA(dll_name.as_ptr());

            // If not loaded, load it
            if module == 0 {
                module = LoadLibraryA(dll_name.as_ptr());
                if module == 0 {
                    return Err(KrakenError::Internal(format!(
                        "cannot load library: {}",
                        parts[0]
                    )));
                }
            }

            // Get function address
            let proc = GetProcAddress(module, func_name.as_ptr());
            if proc.is_none() {
                return Err(KrakenError::Internal(format!(
                    "cannot find function: {}",
                    parts[1]
                )));
            }

            Ok(proc.unwrap() as usize)
        }
    }

    #[cfg(target_os = "linux")]
    fn resolve_import(&self, name: &str) -> Result<usize, KrakenError> {
        // On Linux, BOFs typically aren't used, but we can support it via dlopen/dlsym
        // For now, return an error
        Err(KrakenError::Internal(format!(
            "dynamic imports not supported on Linux: {}",
            name
        )))
    }

    /// Resolve an exported symbol by name
    pub fn resolve_symbol(&self, name: &str) -> Result<*const (), KrakenError> {
        // Try with underscore prefix (common in COFF)
        let prefixed_name = format!("_{}", name);

        if let Some(&addr) = self.symbol_map.get(&prefixed_name) {
            return Ok(addr as *const ());
        }

        if let Some(&addr) = self.symbol_map.get(name) {
            return Ok(addr as *const ());
        }

        Err(KrakenError::Internal(format!("symbol not found: {}", name)))
    }

    /// Execute the BOF entry point
    ///
    /// # Safety
    /// The entry point must be a valid function pointer with the BOF signature:
    /// `void go(char* args, int len)`
    pub unsafe fn execute(&self, entry: *const (), args: &[u8]) -> i32 {
        // BOF entry point signature: void go(char* args, int len)
        let func: extern "C" fn(*const u8, i32) = std::mem::transmute(entry);

        func(args.as_ptr(), args.len() as i32);

        0 // BOFs don't return exit codes
    }

    /// Unload the BOF and free all memory
    pub fn unload(&mut self) {
        for section in &self.sections {
            // Restore write permission before zeroing (executable sections are read-only)
            #[cfg(target_os = "windows")]
            unsafe {
                use windows_sys::Win32::System::Memory::*;
                let mut old_protect: u32 = 0;
                VirtualProtect(
                    section.base as *const _,
                    section.size,
                    PAGE_READWRITE,
                    &mut old_protect,
                );
            }

            #[cfg(target_os = "linux")]
            unsafe {
                libc::mprotect(
                    section.base as *mut _,
                    section.size,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }

            // Zero memory before freeing (security)
            unsafe {
                ptr::write_bytes(section.base, 0, section.size);
            }

            #[cfg(target_os = "windows")]
            unsafe {
                use windows_sys::Win32::System::Memory::*;
                VirtualFree(section.base as *mut _, 0, MEM_RELEASE);
            }

            #[cfg(target_os = "linux")]
            unsafe {
                libc::munmap(section.base as *mut _, section.size);
            }
        }

        self.sections.clear();
        self.symbol_map.clear();

        // Free trampoline table
        if !self.trampoline_base.is_null() {
            let trampoline_size = TRAMPOLINE_SIZE * MAX_TRAMPOLINES;

            #[cfg(target_os = "windows")]
            unsafe {
                use windows_sys::Win32::System::Memory::*;
                VirtualFree(self.trampoline_base as *mut _, 0, MEM_RELEASE);
            }

            #[cfg(target_os = "linux")]
            unsafe {
                libc::munmap(self.trampoline_base as *mut _, trampoline_size);
            }

            self.trampoline_base = ptr::null_mut();
        }
        self.trampoline_count = 0;
        self.trampoline_map.clear();
    }
}

impl Default for BofLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BofLoader {
    fn drop(&mut self) {
        if !self.sections.is_empty() {
            self.unload();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_new() {
        let loader = BofLoader::new();
        assert!(loader.sections.is_empty());
        assert!(loader.symbol_map.is_empty());
    }
}
