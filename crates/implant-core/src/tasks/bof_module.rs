//! BOF task execution using mod-bof module

use crate::error::ImplantResult;
use common::{Module, TaskId, TaskResult};

/// Execute a BOF task using the mod-bof module
pub fn execute_bof_module(task_data: &[u8]) -> ImplantResult<Vec<u8>> {
    let module = mod_bof::BofModule::new();

    let task_result = module
        .handle(TaskId::new(), task_data)
        .map_err(|e| crate::error::ImplantError::Task(e.to_string()))?;

    // Serialize the result
    match task_result {
        TaskResult::BofOutput(output) => {
            let result = protocol::BofResult {
                output: output.output,
                exit_code: output.exit_code,
                error: output.error,
            };
            Ok(protocol::encode(&result))
        }
        _ => Err(crate::error::ImplantError::Task(
            "unexpected task result type".to_string(),
        )),
    }
}

#[cfg(test)]
#[cfg(feature = "mod-bof")]
mod tests {
    use super::*;

    #[test]
    fn test_execute_bof_module_invalid_task_data() {
        // Malformed protobuf bytes that cannot be decoded as BofTask.
        // Wire type 7 is reserved/invalid in protobuf, so this triggers a decode error.
        let invalid_data = &[0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0x02, 0x03];
        let result = execute_bof_module(invalid_data);
        assert!(
            result.is_err(),
            "expected error for malformed task data, got Ok"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("task error"),
            "expected 'task error' in message, got: {msg}"
        );
    }

    #[test]
    fn test_execute_bof_module_empty_task_data() {
        // Empty bytes decode to a default BofTask (bof_data = empty vec).
        // COFF parsing of empty data must fail, returning a task error.
        let result = execute_bof_module(&[]);
        assert!(
            result.is_err(),
            "expected error for empty task data, got Ok"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("task error"),
            "expected 'task error' in message, got: {msg}"
        );
    }
}
