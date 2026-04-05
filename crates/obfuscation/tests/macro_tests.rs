//! Integration tests for obfuscation macros
//!
//! Tests the encrypted_string! and djb2_hash! proc macros.

use obfuscation::{djb2_hash, encrypted_string, junk_code, obf_if, obf_loop};

// =============================================================================
// encrypted_string! tests
// =============================================================================

#[test]
fn test_encrypted_string_basic() {
    let decrypted = encrypted_string!("hello world");
    assert_eq!(decrypted, "hello world");
}

#[test]
fn test_encrypted_string_empty() {
    let decrypted = encrypted_string!("");
    assert_eq!(decrypted, "");
}

#[test]
fn test_encrypted_string_single_char() {
    let decrypted = encrypted_string!("x");
    assert_eq!(decrypted, "x");
}

#[test]
fn test_encrypted_string_special_chars() {
    let decrypted = encrypted_string!("!@#$%^&*()_+-=[]{}|;':\",./<>?");
    assert_eq!(decrypted, "!@#$%^&*()_+-=[]{}|;':\",./<>?");
}

#[test]
fn test_encrypted_string_newlines() {
    let decrypted = encrypted_string!("line1\nline2\nline3");
    assert_eq!(decrypted, "line1\nline2\nline3");
}

#[test]
fn test_encrypted_string_tabs() {
    let decrypted = encrypted_string!("col1\tcol2\tcol3");
    assert_eq!(decrypted, "col1\tcol2\tcol3");
}

#[test]
fn test_encrypted_string_unicode() {
    let decrypted = encrypted_string!("Hello, 世界! 🦀");
    assert_eq!(decrypted, "Hello, 世界! 🦀");
}

#[test]
fn test_encrypted_string_long() {
    let decrypted = encrypted_string!(
        "This is a much longer string that exceeds the 16-byte key length to verify proper cycling."
    );
    assert_eq!(
        decrypted,
        "This is a much longer string that exceeds the 16-byte key length to verify proper cycling."
    );
}

#[test]
fn test_encrypted_string_exactly_16_bytes() {
    // Exactly 16 bytes to test key boundary
    let decrypted = encrypted_string!("0123456789ABCDEF");
    assert_eq!(decrypted, "0123456789ABCDEF");
}

#[test]
fn test_encrypted_string_api_names() {
    // Test with realistic API names that would be obfuscated
    let name1 = encrypted_string!("kernel32.dll");
    let name2 = encrypted_string!("VirtualAlloc");
    let name3 = encrypted_string!("NtProtectVirtualMemory");

    assert_eq!(name1, "kernel32.dll");
    assert_eq!(name2, "VirtualAlloc");
    assert_eq!(name3, "NtProtectVirtualMemory");
}

// =============================================================================
// djb2_hash! tests
// =============================================================================

#[test]
fn test_djb2_hash_empty() {
    let hash: u32 = djb2_hash!("");
    assert_eq!(hash, 5381);
}

#[test]
fn test_djb2_hash_single_char() {
    let hash: u32 = djb2_hash!("a");
    // 5381 * 33 + 97 = 177670
    assert_eq!(hash, 5381u32.wrapping_mul(33).wrapping_add(b'a' as u32));
}

#[test]
fn test_djb2_hash_known_dll_names() {
    // These are commonly used in API hashing
    let kernel32: u32 = djb2_hash!("kernel32.dll");
    let ntdll: u32 = djb2_hash!("ntdll.dll");
    let user32: u32 = djb2_hash!("user32.dll");

    // All should be unique
    assert_ne!(kernel32, ntdll);
    assert_ne!(kernel32, user32);
    assert_ne!(ntdll, user32);

    // Should be non-zero
    assert_ne!(kernel32, 0);
    assert_ne!(ntdll, 0);
    assert_ne!(user32, 0);
}

#[test]
fn test_djb2_hash_known_api_names() {
    let virtual_alloc: u32 = djb2_hash!("VirtualAlloc");
    let virtual_protect: u32 = djb2_hash!("VirtualProtect");
    let get_proc_address: u32 = djb2_hash!("GetProcAddress");
    let load_library: u32 = djb2_hash!("LoadLibraryA");

    // All should be unique
    let hashes = [virtual_alloc, virtual_protect, get_proc_address, load_library];
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hash collision detected");
        }
    }
}

#[test]
fn test_djb2_hash_nt_functions() {
    let nt_allocate: u32 = djb2_hash!("NtAllocateVirtualMemory");
    let nt_protect: u32 = djb2_hash!("NtProtectVirtualMemory");
    let nt_write: u32 = djb2_hash!("NtWriteVirtualMemory");
    let nt_read: u32 = djb2_hash!("NtReadVirtualMemory");
    let nt_close: u32 = djb2_hash!("NtClose");

    // All should be unique
    let hashes = [nt_allocate, nt_protect, nt_write, nt_read, nt_close];
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hash collision at {} and {}", i, j);
        }
    }
}

#[test]
fn test_djb2_hash_deterministic() {
    // Same string should always produce same hash
    let hash1: u32 = djb2_hash!("test");
    let hash2: u32 = djb2_hash!("test");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_djb2_hash_case_sensitive() {
    let lower: u32 = djb2_hash!("virtualalloc");
    let upper: u32 = djb2_hash!("VIRTUALALLOC");
    let mixed: u32 = djb2_hash!("VirtualAlloc");

    assert_ne!(lower, upper);
    assert_ne!(lower, mixed);
    assert_ne!(upper, mixed);
}

#[test]
fn test_djb2_hash_similar_strings() {
    // Strings that differ by one char should have different hashes
    let s1: u32 = djb2_hash!("test1");
    let s2: u32 = djb2_hash!("test2");
    let s3: u32 = djb2_hash!("test3");

    assert_ne!(s1, s2);
    assert_ne!(s2, s3);
    assert_ne!(s1, s3);
}

// =============================================================================
// Cross-verification tests
// =============================================================================

/// Helper function to compute DJB2 hash at runtime for verification
fn djb2_runtime(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash
}

#[test]
fn test_djb2_macro_matches_runtime() {
    // Verify the macro produces same results as runtime computation
    assert_eq!(djb2_hash!("kernel32.dll"), djb2_runtime(b"kernel32.dll"));
    assert_eq!(djb2_hash!("ntdll.dll"), djb2_runtime(b"ntdll.dll"));
    assert_eq!(djb2_hash!("VirtualAlloc"), djb2_runtime(b"VirtualAlloc"));
    assert_eq!(
        djb2_hash!("NtAllocateVirtualMemory"),
        djb2_runtime(b"NtAllocateVirtualMemory")
    );
}

// =============================================================================
// obf_if! tests
// =============================================================================

#[test]
fn test_obf_if_true_branch() {
    let result = obf_if!(true, { 42 }, { 0 });
    assert_eq!(result, 42);
}

#[test]
fn test_obf_if_false_branch() {
    let result = obf_if!(false, { 42 }, { 0 });
    assert_eq!(result, 0);
}

#[test]
fn test_obf_if_with_expression() {
    let x = 10;
    let result = obf_if!(x > 5, { "greater" }, { "lesser" });
    assert_eq!(result, "greater");

    let y = 3;
    let result2 = obf_if!(y > 5, { "greater" }, { "lesser" });
    assert_eq!(result2, "lesser");
}

#[test]
fn test_obf_if_with_side_effects() {
    let mut counter = 0;
    let _ = obf_if!(
        true,
        {
            counter += 1;
            counter
        },
        {
            counter += 10;
            counter
        }
    );
    assert_eq!(counter, 1);
}

#[test]
fn test_obf_if_returns_value() {
    let result: i32 = obf_if!(1 + 1 == 2, { 100 }, { 200 });
    assert_eq!(result, 100);
}

// =============================================================================
// junk_code! tests
// =============================================================================

#[test]
fn test_junk_code_compiles() {
    // Just verify it compiles and runs without panic
    junk_code!();
}

#[test]
fn test_junk_code_multiple() {
    // Multiple junk_code! calls should work
    junk_code!();
    let x = 5;
    junk_code!();
    let y = 10;
    junk_code!();
    assert_eq!(x + y, 15);
}

#[test]
fn test_junk_code_in_loop() {
    for i in 0..3 {
        junk_code!();
        let _ = i * 2;
    }
}

// =============================================================================
// obf_loop! tests
// =============================================================================

#[test]
fn test_obf_loop_basic() {
    let mut sum = 0;
    obf_loop!(5, |i: usize| {
        sum += i;
    });
    // 0 + 1 + 2 + 3 + 4 = 10
    assert_eq!(sum, 10);
}

#[test]
fn test_obf_loop_zero_iterations() {
    let mut counter = 0;
    obf_loop!(0, |_i: usize| {
        counter += 1;
    });
    assert_eq!(counter, 0);
}

#[test]
fn test_obf_loop_captures_variables() {
    let multiplier = 3;
    let mut results = Vec::new();
    obf_loop!(4, |i: usize| {
        results.push(i * multiplier);
    });
    assert_eq!(results, vec![0, 3, 6, 9]);
}
