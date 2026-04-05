//! Anti-debug detection — Phase 4 OPSEC
//! Detection rules: wiki/detection/sigma/kraken_opsec.yml

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;

/// Check if a debugger is attached
#[cfg(target_os = "windows")]
pub fn is_debugger_present() -> bool {
    check_api_debugger() || check_peb_debugger()
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn is_debugger_present() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn check_api_debugger() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(target_os = "windows")]
fn check_peb_debugger() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let peb: *const u8;
            core::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
            );
            // BeingDebugged is at offset 2 in PEB
            *peb.add(2) != 0
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_debugger_present_returns_bool() {
        // Verify the function runs without panicking
        let result = is_debugger_present();
        assert!(result == true || result == false);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_is_debugger_present_non_windows() {
        // Non-Windows stub always returns false
        assert!(!is_debugger_present());
    }
}
