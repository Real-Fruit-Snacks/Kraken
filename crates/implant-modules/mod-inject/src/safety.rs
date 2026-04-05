//! Safety checks for process injection
//!
//! Implements safeguards to prevent injection into critical system processes
//! and to verify architecture compatibility.

use common::KrakenError;

/// Processes that should never be injection targets
///
/// These are critical system processes where injection would likely cause
/// system instability or is heavily monitored by security tools.
#[cfg(windows)]
const DENYLIST: &[&str] = &[
    "csrss.exe",    // Client/Server Runtime - critical, causes BSOD if crashed
    "smss.exe",     // Session Manager - critical bootstrap process
    "lsass.exe",    // Local Security Authority - heavily monitored, credential theft indicator
    "services.exe", // Service Control Manager - critical
    "wininit.exe",  // Windows Initialization - critical
    "winlogon.exe", // Windows Logon - critical, handles secure attention sequence
    "svchost.exe",  // Service Host - often monitored, many instances
];

/// Check if target process is on the denylist
///
/// # Arguments
/// * `pid` - Process ID to check
///
/// # Returns
/// * `Ok(())` if the process is not on the denylist
/// * `Err(KrakenError::Module)` if the process is denied
#[cfg(windows)]
pub fn check_denylist(pid: u32) -> Result<(), KrakenError> {
    use crate::handle::OwnedHandle;
    use windows_sys::Win32::System::ProcessStatus::K32GetModuleBaseNameW;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let handle = OwnedHandle::new(handle)
        .ok_or_else(|| KrakenError::Module("failed to open process for denylist check".into()))?;

    let mut name_buf = [0u16; 260];
    let len = unsafe {
        K32GetModuleBaseNameW(
            handle.as_raw(),
            0,  // NULL module handle means main executable
            name_buf.as_mut_ptr(),
            260,
        )
    };

    if len == 0 {
        // Can't get process name - allow the attempt but log warning
        tracing::warn!(pid, "could not retrieve process name for denylist check");
        return Ok(());
    }

    let name = String::from_utf16_lossy(&name_buf[..len as usize]).to_lowercase();

    for denied in DENYLIST {
        if name == *denied {
            tracing::warn!(pid, name = %denied, "injection blocked: target is on denylist");
            return Err(KrakenError::Module(format!(
                "injection into {} is blocked for safety",
                denied
            )));
        }
    }

    Ok(())
}

/// Check architecture compatibility between injector and target
///
/// Cross-architecture injection (x86 -> x64 or x64 -> x86) is not supported
/// and will fail at runtime. This check prevents wasted effort.
///
/// # Arguments
/// * `pid` - Process ID to check
///
/// # Returns
/// * `Ok(())` if architectures match
/// * `Err(KrakenError::Module)` if there is an architecture mismatch
#[cfg(windows)]
pub fn check_architecture(pid: u32) -> Result<(), KrakenError> {
    use crate::handle::OwnedHandle;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let handle = OwnedHandle::new(handle)
        .ok_or_else(|| KrakenError::Module("failed to open process for arch check".into()))?;

    let mut target_is_wow64: i32 = 0;
    let result = unsafe { IsWow64Process(handle.as_raw(), &mut target_is_wow64) };

    if result == 0 {
        // Can't determine architecture - allow attempt
        tracing::warn!(pid, "could not determine target process architecture");
        return Ok(());
    }

    // Get current process WoW64 status
    let current = unsafe { GetCurrentProcess() };
    let mut current_is_wow64: i32 = 0;
    let result = unsafe { IsWow64Process(current, &mut current_is_wow64) };

    if result == 0 {
        // Can't determine our own architecture - allow attempt
        return Ok(());
    }

    // On x64 Windows:
    // - WoW64 = 1 means 32-bit process running under WoW64 emulation
    // - WoW64 = 0 means native 64-bit process
    // We can only inject same-arch: x64->x64 or x86->x86
    if target_is_wow64 != current_is_wow64 {
        let our_arch = if current_is_wow64 != 0 { "x86" } else { "x64" };
        let target_arch = if target_is_wow64 != 0 { "x86" } else { "x64" };
        tracing::warn!(
            pid,
            our_arch,
            target_arch,
            "architecture mismatch detected"
        );
        return Err(KrakenError::Module(format!(
            "architecture mismatch: {} implant cannot inject into {} process",
            our_arch, target_arch
        )));
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn check_denylist(_pid: u32) -> Result<(), KrakenError> {
    Ok(())
}

#[cfg(not(windows))]
pub fn check_architecture(_pid: u32) -> Result<(), KrakenError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn test_denylist_contents() {
        // Verify critical processes are in denylist
        assert!(DENYLIST.contains(&"lsass.exe"));
        assert!(DENYLIST.contains(&"csrss.exe"));
        assert!(DENYLIST.contains(&"smss.exe"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_check_denylist_stub() {
        // Non-Windows always passes
        assert!(check_denylist(1234).is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_check_architecture_stub() {
        // Non-Windows always passes
        assert!(check_architecture(1234).is_ok());
    }
}
