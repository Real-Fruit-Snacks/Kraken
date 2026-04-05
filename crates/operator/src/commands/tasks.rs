//! Task queue management commands

use anyhow::Result;
use chrono::{Local, TimeZone};

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// List tasks
pub async fn list(cli: &CliState, all: bool) -> Result<()> {
    let implant_id = if all {
        None
    } else {
        cli.active_session().map(|s| s.full_id.clone())
    };

    let tasks = cli.client.list_tasks(implant_id, None, Some(50)).await?;

    if tasks.is_empty() {
        print_info("No tasks");
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Headers
    if Theme::is_interactive() {
        table.set_header(vec![
            Cell::new("Task ID").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }), // Mauve
            Cell::new("Implant").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Type").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Status").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Issued").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
        ]);
    } else {
        table.set_header(vec!["Task ID", "Implant", "Type", "Status", "Issued"]);
    }

    // Rows
    for task in &tasks {
        let task_id_short = if task.task_id.is_some() {
            let id_bytes = task.task_id.as_ref().unwrap().value.as_slice();
            if id_bytes.len() >= 4 {
                hex::encode(&id_bytes[..4])
            } else {
                hex::encode(id_bytes)
            }
        } else {
            "unknown".to_string()
        };

        let implant_id_short = if task.implant_id.is_some() {
            let id_bytes = task.implant_id.as_ref().unwrap().value.as_slice();
            if id_bytes.len() >= 4 {
                hex::encode(&id_bytes[..4])
            } else {
                hex::encode(id_bytes)
            }
        } else {
            "unknown".to_string()
        };

        let status = match task.status {
            0 => "queued",
            1 => "dispatched",
            2 => "running",
            3 => "completed",
            4 => "failed",
            5 => "cancelled",
            _ => "unknown",
        };

        let issued = if task.issued_at.is_some() {
            let ts = task.issued_at.as_ref().unwrap();
            let millis = ts.millis;
            if millis > 0 {
                let secs = millis / 1000;
                let dt = Local.timestamp_opt(secs, 0).unwrap();
                dt.format("%H:%M:%S").to_string()
            } else {
                "N/A".to_string()
            }
        } else {
            "N/A".to_string()
        };

        if Theme::is_interactive() {
            let status_color = match task.status {
                0 => Color::Rgb {
                    r: 137,
                    g: 180,
                    b: 250,
                }, // Blue (queued)
                1 => Color::Rgb {
                    r: 250,
                    g: 179,
                    b: 135,
                }, // Peach (dispatched)
                2 => Color::Rgb {
                    r: 249,
                    g: 226,
                    b: 175,
                }, // Yellow (running)
                3 => Color::Rgb {
                    r: 166,
                    g: 228,
                    b: 161,
                }, // Green (completed)
                4 => Color::Rgb {
                    r: 248,
                    g: 139,
                    b: 168,
                }, // Red (failed)
                5 => Color::Rgb {
                    r: 186,
                    g: 187,
                    b: 241,
                }, // Lavender (cancelled)
                _ => Color::Rgb {
                    r: 205,
                    g: 214,
                    b: 244,
                }, // Text
            };

            table.add_row(vec![
                Cell::new(task_id_short),
                Cell::new(implant_id_short),
                Cell::new(&task.task_type),
                Cell::new(status).fg(status_color),
                Cell::new(issued),
            ]);
        } else {
            table.add_row(vec![
                task_id_short,
                implant_id_short,
                task.task_type.clone(),
                status.to_string(),
                issued,
            ]);
        }
    }

    println!("{table}");

    let queued = tasks.iter().filter(|t| t.status == 0).count();
    let running = tasks.iter().filter(|t| t.status == 1 || t.status == 2).count();
    let completed = tasks.iter().filter(|t| t.status == 3).count();

    print_info(&format!(
        "{} tasks ({} queued, {} running, {} completed)",
        tasks.len(),
        queued,
        running,
        completed
    ));

    Ok(())
}

/// Show task details
pub async fn show(cli: &CliState, task_id: String) -> Result<()> {
    let id_bytes = hex::decode(&task_id)
        .map_err(|e| anyhow::anyhow!("Invalid task ID format (expected hex string): {}", e))?;

    match cli.client.get_task(id_bytes).await {
        Ok(task) => {
            println!("\nTask Details:");

            if task.task_id.is_some() {
                println!(
                    "  Task ID:     {}",
                    hex::encode(&task.task_id.unwrap().value)
                );
            }
            if task.implant_id.is_some() {
                println!(
                    "  Implant ID:  {}",
                    hex::encode(&task.implant_id.unwrap().value)
                );
            }

            println!("  Type:        {}", task.task_type);

            let status = match task.status {
                0 => "queued",
                1 => "dispatched",
                2 => "running",
                3 => "completed",
                4 => "failed",
                5 => "cancelled",
                _ => "unknown",
            };
            println!("  Status:      {}", status);

            if task.issued_at.is_some() {
                let ts = task.issued_at.as_ref().unwrap();
                let millis = ts.millis;
                if millis > 0 {
                    let secs = millis / 1000;
                    let dt = Local.timestamp_opt(secs, 0).unwrap();
                    println!("  Issued:      {}", dt.format("%Y-%m-%d %H:%M:%S"));
                }
            }

            if task.dispatched_at.is_some() {
                let ts = task.dispatched_at.as_ref().unwrap();
                let millis = ts.millis;
                if millis > 0 {
                    let secs = millis / 1000;
                    let dt = Local.timestamp_opt(secs, 0).unwrap();
                    println!("  Dispatched:  {}", dt.format("%Y-%m-%d %H:%M:%S"));
                }
            }

            if task.completed_at.is_some() {
                let ts = task.completed_at.as_ref().unwrap();
                let millis = ts.millis;
                if millis > 0 {
                    let secs = millis / 1000;
                    let dt = Local.timestamp_opt(secs, 0).unwrap();
                    println!("  Completed:   {}", dt.format("%Y-%m-%d %H:%M:%S"));
                }
            }

            if task.error.is_some() {
                let error = task.error.unwrap();
                println!("  Error:       {}", error.message);
            }

            if !task.result_data.is_empty() {
                println!("  Result size: {} bytes", task.result_data.len());
            }
        }
        Err(e) => {
            print_error(&format!("Failed to get task: {}", e));
        }
    }

    Ok(())
}

/// Cancel a task
pub async fn cancel(cli: &CliState, task_id: String) -> Result<()> {
    let id_bytes = hex::decode(&task_id)
        .map_err(|e| anyhow::anyhow!("Invalid task ID format (expected hex string): {}", e))?;

    print_info(&format!("Cancelling task {}...", task_id));

    match cli.client.cancel_task(id_bytes).await {
        Ok(_) => {
            print_success(&format!("Task {} cancelled", task_id));
        }
        Err(e) => {
            print_error(&format!("Failed to cancel task: {}", e));
        }
    }

    Ok(())
}
