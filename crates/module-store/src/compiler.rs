//! Module compilation orchestration.
//!
//! This module handles building Kraken modules from source and extracting
//! the necessary metadata (entry point offset, etc.) from the compiled binary.

use common::KrakenError;
use goblin::Object;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// CompiledModule
// ---------------------------------------------------------------------------

/// Represents a successfully compiled module with extracted metadata.
#[derive(Debug, Clone)]
pub struct CompiledModule {
    /// Module identifier (e.g., "shell", "file", "bof").
    pub id: String,
    /// Human-readable module name.
    pub name: String,
    /// Semantic version string (e.g., "0.1.0").
    pub version: String,
    /// Optional description from Cargo.toml.
    pub description: Option<String>,
    /// Target platform triple (e.g., "x86_64-unknown-linux-gnu").
    pub platform: String,
    /// Raw compiled binary code.
    pub code: Vec<u8>,
    /// Offset to the `kraken_module_init` entry point within the binary.
    pub entry_offset: u32,
}

// ---------------------------------------------------------------------------
// ModuleCompiler
// ---------------------------------------------------------------------------

/// Orchestrates module compilation and artifact processing.
pub struct ModuleCompiler {
    /// Path to the Kraken workspace root.
    workspace_path: PathBuf,
}

impl ModuleCompiler {
    /// Create a new compiler rooted at the given workspace path.
    pub fn new(workspace_path: impl Into<PathBuf>) -> Self {
        Self {
            workspace_path: workspace_path.into(),
        }
    }

    /// Compile a module for the specified target platform.
    ///
    /// # Arguments
    ///
    /// * `module_name` - Cargo package name (e.g., "mod-shell").
    /// * `target` - Rust target triple (e.g., "x86_64-unknown-linux-gnu").
    ///
    /// # Returns
    ///
    /// A [`CompiledModule`] containing the binary and metadata, or an error
    /// if compilation or artifact processing fails.
    pub fn compile(&self, module_name: &str, target: &str) -> Result<CompiledModule, KrakenError> {
        info!(module_name, target, "compiling module");

        // Build the module using cargo.
        self.run_cargo_build(module_name, target)?;

        // Locate the output artifact.
        let artifact_path = self.find_artifact(module_name, target)?;
        debug!(?artifact_path, "found artifact");

        // Read the binary.
        let code = std::fs::read(&artifact_path).map_err(|e| {
            KrakenError::Module(format!("failed to read artifact: {}", e))
        })?;

        // Parse and find entry offset.
        let entry_offset = find_entry_offset(&code)?;
        debug!(entry_offset, "found entry point offset");

        // Read module metadata from Cargo.toml.
        let (id, name, version, description) = self.read_module_metadata(module_name)?;

        Ok(CompiledModule {
            id,
            name,
            version,
            description,
            platform: target.to_string(),
            code,
            entry_offset,
        })
    }

    /// Run `cargo build` for the specified module and target.
    fn run_cargo_build(&self, module_name: &str, target: &str) -> Result<(), KrakenError> {
        let output = Command::new("cargo")
            .current_dir(&self.workspace_path)
            .args([
                "build",
                "--release",
                "--package",
                module_name,
                "--target",
                target,
                "--lib",
            ])
            .output()
            .map_err(|e| KrakenError::Module(format!("failed to run cargo: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KrakenError::Module(format!(
                "cargo build failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Find the compiled artifact (shared library) path.
    fn find_artifact(&self, module_name: &str, target: &str) -> Result<PathBuf, KrakenError> {
        // Convert module name to library name (replace hyphens with underscores).
        let lib_name = module_name.replace('-', "_");

        // Determine library extension based on target.
        let ext = if target.contains("windows") {
            "dll"
        } else if target.contains("darwin") || target.contains("macos") {
            "dylib"
        } else {
            "so"
        };

        // Construct expected path: target/{target}/release/lib{name}.{ext}
        let artifact_path = self
            .workspace_path
            .join("target")
            .join(target)
            .join("release")
            .join(format!("lib{}.{}", lib_name, ext));

        // On Windows, the library might not have "lib" prefix.
        let alt_path = self
            .workspace_path
            .join("target")
            .join(target)
            .join("release")
            .join(format!("{}.{}", lib_name, ext));

        if artifact_path.exists() {
            Ok(artifact_path)
        } else if alt_path.exists() {
            Ok(alt_path)
        } else {
            Err(KrakenError::Module(format!(
                "artifact not found at {:?} or {:?}",
                artifact_path, alt_path
            )))
        }
    }

    /// Read module metadata from Cargo.toml.
    fn read_module_metadata(
        &self,
        module_name: &str,
    ) -> Result<(String, String, String, Option<String>), KrakenError> {
        // Find the module's Cargo.toml.
        let cargo_toml_path = self.find_cargo_toml(module_name)?;

        let content = std::fs::read_to_string(cargo_toml_path).map_err(|e| {
            KrakenError::Module(format!("failed to read Cargo.toml: {}", e))
        })?;

        let manifest: toml::Value = content.parse().map_err(|e| {
            KrakenError::Module(format!("failed to parse Cargo.toml: {}", e))
        })?;

        let package = manifest
            .get("package")
            .ok_or_else(|| KrakenError::Module("missing [package] in Cargo.toml".into()))?;

        let name = package
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KrakenError::Module("missing package.name".into()))?;

        let version = package
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KrakenError::Module("missing package.version".into()))?;

        let description = package
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Derive module ID from package name (strip "mod-" prefix if present).
        let id = name.strip_prefix("mod-").unwrap_or(name).to_string();

        Ok((id, name.to_string(), version.to_string(), description))
    }

    /// Find the Cargo.toml path for a module.
    fn find_cargo_toml(&self, module_name: &str) -> Result<PathBuf, KrakenError> {
        // Check common locations for module crates.
        let candidates = [
            self.workspace_path
                .join("crates")
                .join("implant-modules")
                .join(module_name)
                .join("Cargo.toml"),
            self.workspace_path
                .join("crates")
                .join(module_name)
                .join("Cargo.toml"),
            self.workspace_path
                .join("modules")
                .join(module_name)
                .join("Cargo.toml"),
        ];

        for path in &candidates {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        Err(KrakenError::Module(format!(
            "Cargo.toml not found for module '{}'",
            module_name
        )))
    }
}

// ---------------------------------------------------------------------------
// Entry point offset extraction
// ---------------------------------------------------------------------------

/// Find the offset of the `kraken_module_init` symbol in the binary.
fn find_entry_offset(binary: &[u8]) -> Result<u32, KrakenError> {
    match Object::parse(binary) {
        Ok(Object::PE(pe)) => find_entry_offset_pe(&pe),
        Ok(Object::Elf(elf)) => find_entry_offset_elf(&elf, binary),
        Ok(Object::Mach(_)) => Err(KrakenError::Module(
            "Mach-O binaries not yet supported".into(),
        )),
        Ok(_) => Err(KrakenError::Module("unsupported binary format".into())),
        Err(e) => Err(KrakenError::Module(format!(
            "failed to parse binary: {}",
            e
        ))),
    }
}

/// Find entry offset in a PE (Windows) binary.
fn find_entry_offset_pe(pe: &goblin::pe::PE) -> Result<u32, KrakenError> {
    const ENTRY_SYMBOL: &str = "kraken_module_init";

    // Search exported symbols.
    for export in &pe.exports {
        if let Some(name) = export.name {
            if name == ENTRY_SYMBOL {
                // export.rva is the relative virtual address.
                return Ok(export.rva as u32);
            }
        }
    }

    Err(KrakenError::Module(format!(
        "entry symbol '{}' not found in PE exports",
        ENTRY_SYMBOL
    )))
}

/// Find entry offset in an ELF (Linux) binary.
fn find_entry_offset_elf(elf: &goblin::elf::Elf, binary: &[u8]) -> Result<u32, KrakenError> {
    const ENTRY_SYMBOL: &str = "kraken_module_init";

    // Search dynamic symbols first (for shared libraries).
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == ENTRY_SYMBOL && sym.st_value != 0 {
                return convert_vaddr_to_offset(elf, binary, sym.st_value);
            }
        }
    }

    // Fall back to regular symbol table.
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name == ENTRY_SYMBOL && sym.st_value != 0 {
                return convert_vaddr_to_offset(elf, binary, sym.st_value);
            }
        }
    }

    Err(KrakenError::Module(format!(
        "entry symbol '{}' not found in ELF symbol tables",
        ENTRY_SYMBOL
    )))
}

/// Convert a virtual address to a file offset.
fn convert_vaddr_to_offset(
    elf: &goblin::elf::Elf,
    _binary: &[u8],
    vaddr: u64,
) -> Result<u32, KrakenError> {
    // Find the program header that contains this virtual address.
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_LOAD {
            let start = phdr.p_vaddr;
            let end = start + phdr.p_memsz;
            if vaddr >= start && vaddr < end {
                // Calculate file offset: vaddr - segment_vaddr + segment_file_offset
                let offset = vaddr - start + phdr.p_offset;
                return Ok(offset as u32);
            }
        }
    }

    // If no LOAD segment found, the vaddr might already be a file offset
    // in position-independent executables.
    Ok(vaddr as u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_creation() {
        let compiler = ModuleCompiler::new("/tmp/workspace");
        assert_eq!(compiler.workspace_path, PathBuf::from("/tmp/workspace"));
    }

    #[test]
    fn test_lib_name_conversion() {
        // Test that module names with hyphens are converted to underscores.
        let module_name = "mod-shell";
        let lib_name = module_name.replace('-', "_");
        assert_eq!(lib_name, "mod_shell");
    }

    #[test]
    fn test_id_from_name() {
        // Test stripping "mod-" prefix.
        let name = "mod-shell";
        let id = name.strip_prefix("mod-").unwrap_or(name).to_string();
        assert_eq!(id, "shell");

        let name2 = "custom-module";
        let id2 = name2.strip_prefix("mod-").unwrap_or(name2).to_string();
        assert_eq!(id2, "custom-module");
    }
}
