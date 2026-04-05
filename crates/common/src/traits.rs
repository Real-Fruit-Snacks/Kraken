//! Core traits for Kraken components

use crate::{KrakenError, ModuleId, TaskId, TaskResult};

/// Transport for implant-server communication
pub trait Transport: Send + Sync {
    /// Unique identifier for this transport type
    fn id(&self) -> &'static str;

    /// Exchange data with the server
    fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError>;

    /// Check if transport is currently available
    fn is_available(&self) -> bool;

    /// Reset transport state (e.g., after failure)
    fn reset(&mut self);
}

/// Implant capability module
pub trait Module: Send + Sync {
    /// Module identifier
    fn id(&self) -> &ModuleId;

    /// Human-readable name
    fn name(&self) -> &'static str;

    /// Module version
    fn version(&self) -> &'static str;

    /// Handle a task for this module
    fn handle(&self, task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError>;

    /// Clean shutdown
    fn shutdown(&self) -> Result<(), KrakenError> {
        Ok(())
    }
}

/// Dynamic module entry point signature
#[allow(improper_ctypes_definitions)]
pub type DynamicModuleEntry = unsafe extern "C" fn(context: *mut ()) -> *mut dyn Module;

