//! Service operation implementations (Windows-only)

use common::{KrakenError, ServiceInfoOutput, ServiceListOutput, ServiceOpResult};
use protocol::{SvcCreate, SvcDelete, SvcList, SvcModify, SvcQuery, SvcStart, SvcStop};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[cfg(windows)]
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, StartServiceW,
    SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START,
    SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STOP, SERVICE_WIN32_OWN_PROCESS,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    ENUM_SERVICE_STATUS_PROCESSW,
};

// ============================================================
// Helpers (Windows)
// ============================================================

/// Convert a Rust &str to a null-terminated UTF-16 Vec<u16>
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect()
}

/// Convert a null-terminated UTF-16 pointer to a String
#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    OsString::from_wide(slice).to_string_lossy().into_owned()
}

/// Map a service start type constant to a human-readable string
#[cfg(windows)]
fn start_type_name(t: u32) -> &'static str {
    match t {
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

/// Map a service state constant to a human-readable string
#[cfg(windows)]
fn state_name(state: u32) -> &'static str {
    match state {
        1 => "Stopped",
        2 => "StartPending",
        3 => "StopPending",
        4 => "Running",
        5 => "ContinuePending",
        6 => "PausePending",
        7 => "Paused",
        _ => "Unknown",
    }
}

// ============================================================
// Public API (Windows)
// ============================================================

/// List services
#[cfg(windows)]
pub fn svc_list(task: &SvcList) -> Result<ServiceListOutput, KrakenError> {
    use std::mem;

    let sc_manager = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if sc_manager == 0 {
        return Err(KrakenError::Module("OpenSCManagerW failed".into()));
    }

    let mut bytes_needed: u32 = 0;
    let mut services_returned: u32 = 0;
    let mut resume_handle: u32 = 0;

    // First call to determine buffer size
    let _ = unsafe {
        EnumServicesStatusExW(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_STATE_ALL,
            std::ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        )
    };

    if bytes_needed == 0 {
        unsafe { CloseServiceHandle(sc_manager) };
        return Ok(ServiceListOutput { services: vec![] });
    }

    let mut buffer: Vec<u8> = vec![0u8; bytes_needed as usize];
    resume_handle = 0;
    services_returned = 0;

    let result = unsafe {
        EnumServicesStatusExW(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_STATE_ALL,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        )
    };

    if result == 0 {
        unsafe { CloseServiceHandle(sc_manager) };
        return Err(KrakenError::Module("EnumServicesStatusExW failed".into()));
    }

    let entry_size = mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
    let mut services = Vec::new();

    let name_filter = task.name_filter.as_deref().unwrap_or("");
    let running_only = task.running_only.unwrap_or(false);

    for i in 0..services_returned as usize {
        let entry_ptr = unsafe { buffer.as_ptr().add(i * entry_size) } as *const ENUM_SERVICE_STATUS_PROCESSW;
        let entry = unsafe { &*entry_ptr };

        let name = unsafe { wide_ptr_to_string(entry.lpServiceName) };
        let display_name = unsafe { wide_ptr_to_string(entry.lpDisplayName) };
        let state = entry.ServiceStatusProcess.dwCurrentState;

        if running_only && state != 4 {
            continue;
        }
        if !name_filter.is_empty()
            && !name.to_lowercase().contains(&name_filter.to_lowercase())
            && !display_name.to_lowercase().contains(&name_filter.to_lowercase())
        {
            continue;
        }

        services.push(common::ServiceInfo {
            name,
            display_name,
            status: state_name(state).to_string(),
            pid: entry.ServiceStatusProcess.dwProcessId,
        });
    }

    unsafe { CloseServiceHandle(sc_manager) };
    Ok(ServiceListOutput { services })
}

/// Query a single service's detailed configuration
#[cfg(windows)]
pub fn svc_query(task: &SvcQuery) -> Result<ServiceInfoOutput, KrakenError> {
    let sc_manager = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT,
        )
    };
    if sc_manager == 0 {
        return Err(KrakenError::Module("OpenSCManagerW failed".into()));
    }

    let name_wide = to_wide(&task.name);
    let svc_handle = unsafe {
        OpenServiceW(
            sc_manager,
            name_wide.as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if svc_handle == 0 {
        unsafe { CloseServiceHandle(sc_manager) };
        return Err(KrakenError::Module(format!(
            "OpenServiceW failed for service '{}'",
            task.name
        )));
    }

    // Determine buffer size for QueryServiceConfigW
    let mut bytes_needed: u32 = 0;
    let _ = unsafe {
        QueryServiceConfigW(svc_handle, std::ptr::null_mut(), 0, &mut bytes_needed)
    };

    let mut config_buf: Vec<u8> = vec![0u8; bytes_needed as usize];
    let result = unsafe {
        QueryServiceConfigW(
            svc_handle,
            config_buf.as_mut_ptr() as *mut _,
            config_buf.len() as u32,
            &mut bytes_needed,
        )
    };

    if result == 0 {
        unsafe {
            CloseServiceHandle(svc_handle);
            CloseServiceHandle(sc_manager);
        }
        return Err(KrakenError::Module("QueryServiceConfigW failed".into()));
    }

    // QUERY_SERVICE_CONFIGW layout: dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName,
    // lpLoadOrderGroup, dwTagId, lpDependencies, lpServiceStartName, lpDisplayName
    // We read the fields by offset using the known struct layout
    let config_ptr = config_buf.as_ptr();
    let (binary_path, start_type_val, account, display_name) = unsafe {
        // QUERY_SERVICE_CONFIGW offsets (x64):
        //   0: dwServiceType (u32)
        //   4: dwStartType (u32)
        //   8: dwErrorControl (u32)
        //  16: lpBinaryPathName (*const u16)
        //  24: lpLoadOrderGroup (*const u16)
        //  32: dwTagId (u32)
        //  40: lpDependencies (*const u16)
        //  48: lpServiceStartName (*const u16)
        //  56: lpDisplayName (*const u16)
        let start_type_val = *(config_ptr.add(4) as *const u32);
        let binary_path_ptr = *(config_ptr.add(16) as *const *const u16);
        let account_ptr = *(config_ptr.add(48) as *const *const u16);
        let display_name_ptr = *(config_ptr.add(56) as *const *const u16);

        (
            wide_ptr_to_string(binary_path_ptr),
            start_type_val,
            wide_ptr_to_string(account_ptr),
            wide_ptr_to_string(display_name_ptr),
        )
    };

    unsafe {
        CloseServiceHandle(svc_handle);
        CloseServiceHandle(sc_manager);
    }

    Ok(ServiceInfoOutput {
        name: task.name.clone(),
        display_name,
        binary_path,
        status: String::new(), // status requires separate query
        start_type: start_type_name(start_type_val).to_string(),
        account,
        pid: 0,
        description: String::new(),
    })
}

/// Create a new service
#[cfg(windows)]
pub fn svc_create(task: &SvcCreate) -> Result<ServiceOpResult, KrakenError> {
    let sc_manager = unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS)
    };
    if sc_manager == 0 {
        return Err(KrakenError::Module("OpenSCManagerW failed".into()));
    }

    let name_wide = to_wide(&task.name);
    let display_wide = to_wide(&task.display_name);
    let binary_wide = to_wide(&task.binary_path);

    let start_type = task.start_type.unwrap_or(SERVICE_DEMAND_START);
    let account = task.account.as_deref();
    let account_wide: Option<Vec<u16>> = account.map(to_wide);
    let account_ptr = account_wide
        .as_ref()
        .map(|v| v.as_ptr())
        .unwrap_or(std::ptr::null());

    let svc_handle = unsafe {
        CreateServiceW(
            sc_manager,
            name_wide.as_ptr(),
            display_wide.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            start_type,
            SERVICE_ERROR_NORMAL,
            binary_wide.as_ptr(),
            std::ptr::null(), // load order group
            std::ptr::null_mut(), // tag id
            std::ptr::null(), // dependencies
            account_ptr,
            std::ptr::null(), // password
        )
    };

    unsafe { CloseServiceHandle(sc_manager) };

    if svc_handle == 0 {
        return Err(KrakenError::Module(format!(
            "CreateServiceW failed for service '{}'",
            task.name
        )));
    }

    unsafe { CloseServiceHandle(svc_handle) };

    Ok(ServiceOpResult {
        operation: "create".to_string(),
        service_name: task.name.clone(),
        success: true,
        message: Some(format!("service '{}' created", task.name)),
    })
}

/// Delete a service
#[cfg(windows)]
pub fn svc_delete(task: &SvcDelete) -> Result<ServiceOpResult, KrakenError> {
    let sc_manager = unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS)
    };
    if sc_manager == 0 {
        return Err(KrakenError::Module("OpenSCManagerW failed".into()));
    }

    let name_wide = to_wide(&task.name);
    let svc_handle = unsafe {
        OpenServiceW(sc_manager, name_wide.as_ptr(), SERVICE_ALL_ACCESS)
    };
    unsafe { CloseServiceHandle(sc_manager) };

    if svc_handle == 0 {
        return Err(KrakenError::Module(format!(
            "OpenServiceW failed for service '{}'",
            task.name
        )));
    }

    let result = unsafe { DeleteService(svc_handle) };
    unsafe { CloseServiceHandle(svc_handle) };

    if result == 0 {
        return Err(KrakenError::Module(format!(
            "DeleteService failed for service '{}'",
            task.name
        )));
    }

    Ok(ServiceOpResult {
        operation: "delete".to_string(),
        service_name: task.name.clone(),
        success: true,
        message: Some(format!("service '{}' deleted", task.name)),
    })
}

/// Start a service
#[cfg(windows)]
pub fn svc_start(task: &SvcStart) -> Result<ServiceOpResult, KrakenError> {
    let sc_manager = unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT)
    };
    if sc_manager == 0 {
        return Err(KrakenError::Module("OpenSCManagerW failed".into()));
    }

    let name_wide = to_wide(&task.name);
    let svc_handle = unsafe {
        OpenServiceW(sc_manager, name_wide.as_ptr(), SERVICE_START)
    };
    unsafe { CloseServiceHandle(sc_manager) };

    if svc_handle == 0 {
        return Err(KrakenError::Module(format!(
            "OpenServiceW failed for service '{}'",
            task.name
        )));
    }

    let result = unsafe { StartServiceW(svc_handle, 0, std::ptr::null()) };
    unsafe { CloseServiceHandle(svc_handle) };

    if result == 0 {
        return Err(KrakenError::Module(format!(
            "StartServiceW failed for service '{}'",
            task.name
        )));
    }

    Ok(ServiceOpResult {
        operation: "start".to_string(),
        service_name: task.name.clone(),
        success: true,
        message: Some(format!("service '{}' started", task.name)),
    })
}

/// Stop a service
#[cfg(windows)]
pub fn svc_stop(task: &SvcStop) -> Result<ServiceOpResult, KrakenError> {
    let sc_manager = unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT)
    };
    if sc_manager == 0 {
        return Err(KrakenError::Module("OpenSCManagerW failed".into()));
    }

    let name_wide = to_wide(&task.name);
    let svc_handle = unsafe {
        OpenServiceW(sc_manager, name_wide.as_ptr(), SERVICE_STOP)
    };
    unsafe { CloseServiceHandle(sc_manager) };

    if svc_handle == 0 {
        return Err(KrakenError::Module(format!(
            "OpenServiceW failed for service '{}'",
            task.name
        )));
    }

    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    let result = unsafe { ControlService(svc_handle, SERVICE_CONTROL_STOP, &mut status) };
    unsafe { CloseServiceHandle(svc_handle) };

    if result == 0 {
        return Err(KrakenError::Module(format!(
            "ControlService(STOP) failed for service '{}'",
            task.name
        )));
    }

    Ok(ServiceOpResult {
        operation: "stop".to_string(),
        service_name: task.name.clone(),
        success: true,
        message: Some(format!("service '{}' stop requested", task.name)),
    })
}

/// Modify a service's configuration
#[cfg(windows)]
pub fn svc_modify(task: &SvcModify) -> Result<ServiceOpResult, KrakenError> {
    let sc_manager = unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT)
    };
    if sc_manager == 0 {
        return Err(KrakenError::Module("OpenSCManagerW failed".into()));
    }

    let name_wide = to_wide(&task.name);
    let svc_handle = unsafe {
        OpenServiceW(sc_manager, name_wide.as_ptr(), SERVICE_CHANGE_CONFIG)
    };
    unsafe { CloseServiceHandle(sc_manager) };

    if svc_handle == 0 {
        return Err(KrakenError::Module(format!(
            "OpenServiceW failed for service '{}'",
            task.name
        )));
    }

    let binary_wide: Option<Vec<u16>> = task.binary_path.as_deref().map(to_wide);
    let binary_ptr = binary_wide
        .as_ref()
        .map(|v| v.as_ptr())
        .unwrap_or(std::ptr::null());

    // SERVICE_NO_CHANGE = 0xFFFFFFFF — pass when field should not be modified
    let start_type = task.start_type.unwrap_or(0xFFFF_FFFF);

    let result = unsafe {
        ChangeServiceConfigW(
            svc_handle,
            0xFFFF_FFFF,  // dwServiceType: SERVICE_NO_CHANGE
            start_type,   // dwStartType
            0xFFFF_FFFF,  // dwErrorControl: SERVICE_NO_CHANGE
            binary_ptr,   // lpBinaryPathName: null = no change
            std::ptr::null(), // lpLoadOrderGroup
            std::ptr::null_mut(), // lpdwTagId
            std::ptr::null(), // lpDependencies
            std::ptr::null(), // lpServiceStartName
            std::ptr::null(), // lpPassword
            std::ptr::null(), // lpDisplayName
        )
    };

    unsafe { CloseServiceHandle(svc_handle) };

    if result == 0 {
        return Err(KrakenError::Module(format!(
            "ChangeServiceConfigW failed for service '{}'",
            task.name
        )));
    }

    Ok(ServiceOpResult {
        operation: "modify".to_string(),
        service_name: task.name.clone(),
        success: true,
        message: Some(format!("service '{}' modified", task.name)),
    })
}

// ============================================================
// Non-Windows stubs
// ============================================================

#[cfg(not(windows))]
pub fn svc_list(_task: &SvcList) -> Result<ServiceListOutput, KrakenError> {
    Err(KrakenError::Module(
        "service operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn svc_query(_task: &SvcQuery) -> Result<ServiceInfoOutput, KrakenError> {
    Err(KrakenError::Module(
        "service operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn svc_create(_task: &SvcCreate) -> Result<ServiceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "service operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn svc_delete(_task: &SvcDelete) -> Result<ServiceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "service operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn svc_start(_task: &SvcStart) -> Result<ServiceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "service operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn svc_stop(_task: &SvcStop) -> Result<ServiceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "service operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn svc_modify(_task: &SvcModify) -> Result<ServiceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "service operations are only supported on Windows".into(),
    ))
}
