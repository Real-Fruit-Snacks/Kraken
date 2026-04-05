//! Table formatting and display utilities for CLI output

use comfy_table::{presets::NOTHING, Cell, CellAlignment, Color as ComfyColor, ContentArrangement, Table};


use crate::theme::Theme;

/// Implant display info
#[derive(Debug, Clone)]
pub struct ImplantInfo {
    pub id: String,       // short 4-byte hex for display
    pub full_id: Vec<u8>, // full 16-byte UUID for dispatch
    pub name: String,
    pub state: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub last_seen: String,
    pub tags: Vec<String>, // session tags for organization
}

/// Job display info
#[derive(Debug, Clone)]
pub struct JobDisplayInfo {
    pub job_id: u32,
    pub task_id: String,      // Short hex for display
    pub description: String,
    pub status: String,       // "running", "completed", "failed", "cancelled"
    pub progress: u32,        // 0-100
    pub created_at: String,   // HH:MM:SS
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
    pub output_preview: String, // First 100 chars of output
}

/// Loot item display info
#[derive(Debug, Clone)]
pub struct LootItem {
    pub loot_type: String,
    pub source: String,
    pub value: String,
    pub captured_at: String,
    pub detail_fields: Vec<(String, String)>,
}

/// Module display info
#[derive(Debug, Clone)]
pub struct ModuleDisplayInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub platforms: String,
    pub sizes: String,
}

/// Output line for command output
#[derive(Debug, Clone)]
pub struct OutputLine {
    pub timestamp: String,
    pub line_type: String, // "command", "stdout", "stderr", "info", "error"
    pub content: String,
}

/// Event info
#[derive(Debug, Clone)]
pub struct EventInfo {
    pub timestamp: String,
    pub event_type: String,
    pub details: String,
}

/// Print Kraken ASCII art banner
pub fn print_banner() {
    let banner = r#"
    ██╗  ██╗██████╗  █████╗ ██╗  ██╗███████╗███╗   ██╗
    ██║ ██╔╝██╔══██╗██╔══██╗██║ ██╔╝██╔════╝████╗  ██║
    █████╔╝ ██████╔╝███████║█████╔╝ █████╗  ██╔██╗ ██║
    ██╔═██╗ ██╔══██╗██╔══██║██╔═██╗ ██╔══╝  ██║╚██╗██║
    ██║  ██╗██║  ██║██║  ██║██║  ██╗███████╗██║ ╚████║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
                                    Command & Control Framework
"#;

    if Theme::is_interactive() {
        println!("{}", Theme::banner().apply_to(banner));
    } else {
        println!("{}", banner);
    }
}

/// Print a generic table with Catppuccin styling
pub fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    if rows.is_empty() {
        print_info("No results");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Add header row
    let header_cells: Vec<Cell> = headers
        .iter()
        .map(|h| {
            if Theme::is_interactive() {
                Cell::new(h)
                    .fg(ComfyColor::Rgb { r: 180, g: 190, b: 254 }) // Lavender
                    .set_alignment(CellAlignment::Left)
            } else {
                Cell::new(h).set_alignment(CellAlignment::Left)
            }
        })
        .collect();
    table.set_header(header_cells);

    // Add data rows
    for row in rows {
        table.add_row(row);
    }

    println!("{}", table);
}

/// Print implants table
pub fn print_implants_table(implants: &[ImplantInfo]) {
    if implants.is_empty() {
        print_info("No sessions");
        return;
    }

    let headers = vec!["ID", "Name", "State", "Hostname", "User", "OS", "Last Seen"];
    let rows: Vec<Vec<String>> = implants
        .iter()
        .map(|imp| {
            let state_str = if Theme::is_interactive() {
                Theme::implant_state(&imp.state)
                    .apply_to(&imp.state)
                    .to_string()
            } else {
                imp.state.clone()
            };

            vec![
                imp.id.clone(),
                imp.name.clone(),
                state_str,
                imp.hostname.clone(),
                imp.username.clone(),
                imp.os.clone(),
                imp.last_seen.clone(),
            ]
        })
        .collect();

    print_table(&headers, rows);

    // Print summary
    let active = implants.iter().filter(|i| i.state == "active").count();
    let lost = implants.iter().filter(|i| i.state == "lost").count();
    print_info(&format!(
        "{} sessions ({} active, {} lost)",
        implants.len(),
        active,
        lost
    ));
}

/// Print jobs table
pub fn print_jobs_table(jobs: &[JobDisplayInfo]) {
    if jobs.is_empty() {
        print_info("No jobs");
        return;
    }

    let headers = vec!["Job ID", "Task ID", "Description", "Status", "Progress", "Created"];
    let rows: Vec<Vec<String>> = jobs
        .iter()
        .map(|job| {
            let status_str = if Theme::is_interactive() {
                Theme::status_color(&job.status)
                    .apply_to(&job.status)
                    .to_string()
            } else {
                job.status.clone()
            };

            vec![
                job.job_id.to_string(),
                job.task_id.clone(),
                job.description.clone(),
                status_str,
                format!("{}%", job.progress),
                job.created_at.clone(),
            ]
        })
        .collect();

    print_table(&headers, rows);
}

/// Print loot table
pub fn print_loot_table(loot: &[LootItem]) {
    if loot.is_empty() {
        print_info("No loot");
        return;
    }

    let headers = vec!["Type", "Source", "Value", "Captured"];
    let rows: Vec<Vec<String>> = loot
        .iter()
        .map(|item| {
            vec![
                item.loot_type.clone(),
                item.source.clone(),
                item.value.clone(),
                item.captured_at.clone(),
            ]
        })
        .collect();

    print_table(&headers, rows);
    print_info(&format!("{} items", loot.len()));
}

/// Print modules table
pub fn print_modules_table(modules: &[ModuleDisplayInfo]) {
    if modules.is_empty() {
        print_info("No modules");
        return;
    }

    let headers = vec!["ID", "Name", "Description", "Platforms", "Sizes"];
    let rows: Vec<Vec<String>> = modules
        .iter()
        .map(|module| {
            vec![
                module.id.clone(),
                module.name.clone(),
                module.description.clone(),
                module.platforms.clone(),
                module.sizes.clone(),
            ]
        })
        .collect();

    print_table(&headers, rows);
    print_info(&format!("{} modules", modules.len()));
}

/// Re-export theme print functions for convenience
pub use crate::theme::{print_error, print_info, print_success};
