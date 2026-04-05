//! Task execution
//!
//! All module task execution now goes through the module registry.
//! The individual task handler modules are kept for backwards compatibility
//! but the primary path is via registry::registry().get(task_type).

pub mod module_loader;

// Re-export for external use (dynamic module blob loading)
#[allow(unused_imports)]
pub use module_loader::execute_module_task;
