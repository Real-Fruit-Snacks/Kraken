//! Report generation and management commands

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// Format bytes to human-readable string
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", size as u64, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Generate a new report
pub async fn generate(
    cli: &CliState,
    title: String,
    report_type: String,
    format: String,
) -> Result<()> {
    print_info(&format!("Generating {} report '{}'...", report_type, title));

    match cli.client.generate_report(title.clone(), report_type, format).await {
        Ok((report, content)) => {
            let id_short = if report.id.len() >= 4 {
                hex::encode(&report.id[..4])
            } else {
                hex::encode(&report.id)
            };

            print_success(&format!("Report '{}' generated (ID: {})", title, id_short));
            print_info(&format!("Size: {}", format_bytes(report.size)));
            print_info(&format!("Sessions: {}, Tasks: {}", report.session_count, report.task_count));

            // Optionally save to file
            if !content.is_empty() {
                let filename = format!("{}.{}", title.replace(" ", "_"), report.output_format);
                if let Err(e) = std::fs::write(&filename, &content) {
                    print_error(&format!("Failed to save report to {}: {}", filename, e));
                } else {
                    print_success(&format!("Report saved to {}", filename));
                }
            }
        }
        Err(e) => {
            print_error(&format!("Failed to generate report: {}", e));
        }
    }

    Ok(())
}

/// List all reports
pub async fn list(cli: &CliState) -> Result<()> {
    print_info("Fetching reports...");

    match cli.client.list_reports().await {
        Ok(reports) => {
            if reports.is_empty() {
                print_info("No reports");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            // Headers
            if Theme::is_interactive() {
                table.set_header(vec![
                    Cell::new("ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Title").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Type").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Format").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Generated").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Size").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                ]);
            } else {
                table.set_header(vec!["ID", "Title", "Type", "Format", "Generated", "Size"]);
            }

            // Rows
            for report in &reports {
                let id_short = if report.id.len() >= 4 {
                    hex::encode(&report.id[..4])
                } else {
                    hex::encode(&report.id)
                };

                let generated = if let Some(ref ts) = report.generated_at {
                    DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                table.add_row(vec![
                    id_short,
                    report.title.clone(),
                    report.report_type.clone(),
                    report.output_format.clone(),
                    generated,
                    format_bytes(report.size),
                ]);
            }

            println!("{}", table);
            print_info(&format!("{} report(s)", reports.len()));
        }
        Err(e) => {
            print_error(&format!("Failed to list reports: {}", e));
        }
    }

    Ok(())
}

/// Show report details
pub async fn show(cli: &CliState, report_id: String) -> Result<()> {
    // Decode report ID
    let report_bytes = hex::decode(&report_id).unwrap_or_else(|_| report_id.as_bytes().to_vec());

    print_info(&format!("Fetching report {}...", report_id));

    match cli.client.get_report(report_bytes).await {
        Ok(report) => {
            let id_full = hex::encode(&report.id);

            if Theme::is_interactive() {
                use console::style;

                println!("\n{}", style("REPORT DETAILS").fg(crate::theme::colors::LAVENDER).bold());
                println!("  {}: {}", style("ID").fg(crate::theme::colors::TEAL), id_full);
                println!("  {}: {}", style("Title").fg(crate::theme::colors::TEAL), report.title);
                println!("  {}: {}", style("Type").fg(crate::theme::colors::TEAL), report.report_type);
                println!("  {}: {}", style("Format").fg(crate::theme::colors::TEAL), report.output_format);
                println!("  {}: {}", style("Generated By").fg(crate::theme::colors::TEAL), report.generated_by);

                if let Some(ref ts) = report.generated_at {
                    let dt = DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("  {}: {}", style("Generated At").fg(crate::theme::colors::TEAL), dt);
                }

                if let Some(ref start) = report.start_date {
                    let dt = DateTime::<Utc>::from_timestamp_millis(start.millis)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("  {}: {}", style("Start Date").fg(crate::theme::colors::TEAL), dt);
                }

                if let Some(ref end) = report.end_date {
                    let dt = DateTime::<Utc>::from_timestamp_millis(end.millis)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("  {}: {}", style("End Date").fg(crate::theme::colors::TEAL), dt);
                }

                println!("  {}: {}", style("Sessions").fg(crate::theme::colors::TEAL), report.session_count);
                println!("  {}: {}", style("Tasks").fg(crate::theme::colors::TEAL), report.task_count);
                println!("  {}: {}\n", style("Size").fg(crate::theme::colors::TEAL), format_bytes(report.size));
            } else {
                println!("\nREPORT DETAILS");
                println!("  ID: {}", id_full);
                println!("  Title: {}", report.title);
                println!("  Type: {}", report.report_type);
                println!("  Format: {}", report.output_format);
                println!("  Generated By: {}", report.generated_by);

                if let Some(ref ts) = report.generated_at {
                    let dt = DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("  Generated At: {}", dt);
                }

                if let Some(ref start) = report.start_date {
                    let dt = DateTime::<Utc>::from_timestamp_millis(start.millis)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("  Start Date: {}", dt);
                }

                if let Some(ref end) = report.end_date {
                    let dt = DateTime::<Utc>::from_timestamp_millis(end.millis)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("  End Date: {}", dt);
                }

                println!("  Sessions: {}", report.session_count);
                println!("  Tasks: {}", report.task_count);
                println!("  Size: {}\n", format_bytes(report.size));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to get report: {}", e));
        }
    }

    Ok(())
}

/// Delete a report
pub async fn delete(cli: &CliState, report_id: String) -> Result<()> {
    // Decode report ID
    let report_bytes = hex::decode(&report_id).unwrap_or_else(|_| report_id.as_bytes().to_vec());

    print_info(&format!("Deleting report {}...", report_id));

    match cli.client.delete_report(report_bytes).await {
        Ok(success) => {
            if success {
                print_success(&format!("Report {} deleted", report_id));
            } else {
                print_error("Failed to delete report");
            }
        }
        Err(e) => {
            print_error(&format!("Failed to delete report: {}", e));
        }
    }

    Ok(())
}
