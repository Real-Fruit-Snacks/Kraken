//! Operator commands

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::cli::CliState;
use crate::display::{print_error, print_info};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// Show current operator information
pub async fn whoami(cli: &CliState) -> Result<()> {
    print_info("Fetching operator information...");

    match cli.client.get_self().await {
        Ok(operator) => {
            // Display operator info table
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            // Extract operator ID (first 4 bytes for display)
            let id_short = if let Some(uuid) = &operator.id {
                if uuid.value.len() >= 4 {
                    hex::encode(&uuid.value[..4])
                } else {
                    hex::encode(&uuid.value)
                }
            } else {
                "unknown".to_string()
            };

            // Format timestamps
            let created_at = if let Some(ts) = &operator.created_at {
                DateTime::<Utc>::from_timestamp_millis(ts.millis)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            let last_seen = if let Some(ts) = &operator.last_seen {
                DateTime::<Utc>::from_timestamp_millis(ts.millis)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            let status = if operator.is_active { "active" } else { "inactive" };

            // Add rows with Catppuccin styling
            if Theme::is_interactive() {
                table.add_row(vec![
                    Cell::new("ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }), // LAVENDER
                    Cell::new(id_short),
                ]);
                table.add_row(vec![
                    Cell::new("Username").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(&operator.username),
                ]);
                table.add_row(vec![
                    Cell::new("Role").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(&operator.role),
                ]);
                table.add_row(vec![
                    Cell::new("Status").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(status)
                        .fg(if operator.is_active {
                            Color::Rgb { r: 166, g: 227, b: 161 } // GREEN
                        } else {
                            Color::Rgb { r: 250, g: 179, b: 135 } // PEACH
                        }),
                ]);
                table.add_row(vec![
                    Cell::new("Created").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(created_at),
                ]);
                table.add_row(vec![
                    Cell::new("Last Seen").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(last_seen),
                ]);
            } else {
                table.add_row(vec!["ID", &id_short]);
                table.add_row(vec!["Username", &operator.username]);
                table.add_row(vec!["Role", &operator.role]);
                table.add_row(vec!["Status", status]);
                table.add_row(vec!["Created", &created_at]);
                table.add_row(vec!["Last Seen", &last_seen]);
            }

            println!("\n{}", table);
        }
        Err(e) => {
            print_error(&format!("Failed to fetch operator information: {}", e));
        }
    }

    Ok(())
}
