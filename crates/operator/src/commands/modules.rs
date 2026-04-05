//! Module management commands

use anyhow::Result;
use common::ImplantId;

use crate::cli::CliState;
use crate::display::{print_modules_table, print_success, ModuleDisplayInfo};

/// List available modules
pub async fn list(cli: &CliState) -> Result<()> {
    let modules = cli.client.list_modules().await?;

    // Convert to display format
    let display_modules: Vec<ModuleDisplayInfo> = modules
        .iter()
        .map(|module| {
            // Format platforms as comma-separated list
            let platforms = if module.platforms.is_empty() {
                "all".to_string()
            } else {
                module.platforms
                    .iter()
                    .map(|p| p.platform.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            // Format sizes (simplified - use platform versions if available)
            let sizes = if !module.platforms.is_empty() {
                module.platforms
                    .iter()
                    .map(|p| format_bytes(p.size))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                "N/A".to_string()
            };

            ModuleDisplayInfo {
                id: module.id.clone(),
                name: module.name.clone(),
                description: module.description.clone().unwrap_or_else(|| "No description".to_string()),
                platforms,
                sizes,
            }
        })
        .collect();

    print_modules_table(&display_modules);

    Ok(())
}

/// Load a module onto the current session
pub async fn load(cli: &CliState, name: &str, version: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    cli.client
        .load_module(implant_id, name, version.map(|s| s.to_string()))
        .await?;

    print_success(&format!("Module '{}' loaded", name));

    Ok(())
}

/// Unload a module from the current session
pub async fn unload(cli: &CliState, name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    cli.client.unload_module(implant_id, name).await?;

    print_success(&format!("Module '{}' unloaded", name));

    Ok(())
}

/// Format bytes as human-readable size
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_idx])
}
