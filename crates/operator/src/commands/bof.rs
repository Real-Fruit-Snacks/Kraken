//! BOF (Beacon Object File) management commands

use anyhow::Result;


use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// List BOFs in catalog
pub async fn list(cli: &CliState) -> Result<()> {
    let bofs = cli.client.list_bofs().await?;

    if bofs.is_empty() {
        print_info("No BOFs in catalog");
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Headers
    if Theme::is_interactive() {
        table.set_header(vec![
            Cell::new("ID").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }), // Mauve
            Cell::new("Name").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Description").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Arch").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Author").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
        ]);
    } else {
        table.set_header(vec!["ID", "Name", "Description", "Arch", "Author"]);
    }

    // Rows
    for bof in &bofs {
        if let Some(manifest) = &bof.manifest {
            let arch = if bof.x64_available && bof.x86_available {
                "x64/x86"
            } else if bof.x64_available {
                "x64"
            } else if bof.x86_available {
                "x86"
            } else {
                "none"
            };

            table.add_row(vec![
                manifest.id.clone(),
                manifest.name.clone(),
                manifest.description.clone(),
                arch.to_string(),
                manifest.author.clone(),
            ]);
        }
    }

    println!("{table}");
    print_info(&format!("{} BOFs in catalog", bofs.len()));

    Ok(())
}

/// Show detailed BOF information
pub async fn show(cli: &CliState, bof_id: String) -> Result<()> {
    print_info(&format!("Fetching BOF details for '{}'...", bof_id));

    match cli.client.get_bof(bof_id.clone()).await {
        Ok(bof_entry) => {
            if let Some(manifest) = &bof_entry.manifest {
                // Create details table
                let mut table = Table::new();
                table
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic);

                // Architecture availability
                let arch = if bof_entry.x64_available && bof_entry.x86_available {
                    format!(
                        "x64 ({} bytes) / x86 ({} bytes)",
                        bof_entry.x64_size, bof_entry.x86_size
                    )
                } else if bof_entry.x64_available {
                    format!("x64 ({} bytes)", bof_entry.x64_size)
                } else if bof_entry.x86_available {
                    format!("x86 ({} bytes)", bof_entry.x86_size)
                } else {
                    "none".to_string()
                };

                // Format timestamp
                use chrono::{DateTime, Utc};
                let added_at = if let Some(ts) = &bof_entry.added_at {
                    DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                // Add rows
                if Theme::is_interactive() {
                    table.add_row(vec![
                        Cell::new("ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }), // LAVENDER
                        Cell::new(&manifest.id),
                    ]);
                    table.add_row(vec![
                        Cell::new("Name").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new(&manifest.name),
                    ]);
                    table.add_row(vec![
                        Cell::new("Description").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new(&manifest.description),
                    ]);
                    table.add_row(vec![
                        Cell::new("Author").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new(&manifest.author),
                    ]);
                    table.add_row(vec![
                        Cell::new("Version").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new(&manifest.version),
                    ]);
                    table.add_row(vec![
                        Cell::new("Architecture").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new(arch),
                    ]);
                    table.add_row(vec![
                        Cell::new("Entry Point").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new(&manifest.entry_point),
                    ]);
                    table.add_row(vec![
                        Cell::new("Added").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new(added_at),
                    ]);
                    if !manifest.tags.is_empty() {
                        table.add_row(vec![
                            Cell::new("Tags").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                            Cell::new(manifest.tags.join(", ")),
                        ]);
                    }
                    if !manifest.opsec_notes.is_empty() {
                        table.add_row(vec![
                            Cell::new("OPSEC Notes").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                            Cell::new(&manifest.opsec_notes),
                        ]);
                    }
                    if !manifest.source_url.is_empty() {
                        table.add_row(vec![
                            Cell::new("Source").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                            Cell::new(&manifest.source_url),
                        ]);
                    }
                } else {
                    table.add_row(vec!["ID", &manifest.id]);
                    table.add_row(vec!["Name", &manifest.name]);
                    table.add_row(vec!["Description", &manifest.description]);
                    table.add_row(vec!["Author", &manifest.author]);
                    table.add_row(vec!["Version", &manifest.version]);
                    table.add_row(vec!["Architecture", &arch]);
                    table.add_row(vec!["Entry Point", &manifest.entry_point]);
                    table.add_row(vec!["Added", &added_at]);
                    if !manifest.tags.is_empty() {
                        let tags = manifest.tags.join(", ");
                        table.add_row(vec!["Tags", &tags]);
                    }
                    if !manifest.opsec_notes.is_empty() {
                        table.add_row(vec!["OPSEC Notes", &manifest.opsec_notes]);
                    }
                    if !manifest.source_url.is_empty() {
                        table.add_row(vec!["Source", &manifest.source_url]);
                    }
                }

                println!("\n{}", table);

                // Arguments table if any
                if !manifest.arguments.is_empty() {
                    let mut args_table = Table::new();
                    args_table
                        .load_preset(UTF8_FULL)
                        .set_content_arrangement(ContentArrangement::Dynamic);

                    if Theme::is_interactive() {
                        args_table.set_header(vec![
                            Cell::new("Argument").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                            Cell::new("Type").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                            Cell::new("Required").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                            Cell::new("Description").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        ]);
                    } else {
                        args_table.set_header(vec!["Argument", "Type", "Required", "Description"]);
                    }

                    for arg in &manifest.arguments {
                        let required = if arg.required { "yes" } else { "no" };
                        args_table.add_row(vec![
                            arg.name.clone(),
                            format!("{:?}", arg.arg_type),
                            required.to_string(),
                            arg.description.clone(),
                        ]);
                    }

                    println!("\n{}", if Theme::is_interactive() {
                        console::style("ARGUMENTS").fg(crate::theme::colors::LAVENDER).bold().to_string()
                    } else {
                        "ARGUMENTS".to_string()
                    });
                    println!("{}", args_table);
                }
            } else {
                print_error("BOF manifest not found");
            }
        }
        Err(e) => {
            print_error(&format!("Failed to fetch BOF details: {}", e));
        }
    }

    Ok(())
}

/// Execute BOF on current session
pub async fn execute(cli: &CliState, bof_id: String, args: Vec<String>) -> Result<()> {
    let session = cli.active_session().unwrap();

    print_info(&format!("Executing BOF '{}'...", bof_id));

    match cli
        .client
        .execute_bof(session.full_id.clone(), bof_id.clone(), args)
        .await
    {
        Ok(response) => {
            if response.task_id.is_some() {
                let task_id_bytes = response.task_id.unwrap().value;
                let task_id_short = if task_id_bytes.len() >= 4 {
                    hex::encode(&task_id_bytes[..4])
                } else {
                    hex::encode(&task_id_bytes)
                };
                print_success(&format!(
                    "BOF '{}' dispatched (task ID: {})",
                    bof_id, task_id_short
                ));
                print_info("Use 'tasks' to monitor execution");
            } else {
                print_success(&format!("BOF '{}' executed", bof_id));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to execute BOF: {}", e));
        }
    }

    Ok(())
}

/// Delete BOF from catalog
pub async fn delete(cli: &CliState, bof_id: String) -> Result<()> {
    print_info(&format!("Deleting BOF '{}'...", bof_id));

    match cli.client.delete_bof(bof_id.clone()).await {
        Ok(success) => {
            if success {
                print_success(&format!("BOF '{}' deleted", bof_id));
            } else {
                print_error(&format!("Failed to delete BOF '{}'", bof_id));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to delete BOF: {}", e));
        }
    }

    Ok(())
}

/// Validate BOF compatibility with current session
pub async fn validate(cli: &CliState, bof_id: String) -> Result<()> {
    let session = cli.active_session().unwrap();

    print_info(&format!("Validating BOF '{}' for current session...", bof_id));

    match cli
        .client
        .validate_bof(session.full_id.clone(), bof_id.clone())
        .await
    {
        Ok(response) => {
            if response.compatible {
                print_success(&format!("BOF '{}' is compatible", bof_id));
                if !response.recommended_arch.is_empty() {
                    print_info(&format!("Recommended architecture: {}", response.recommended_arch));
                }
            } else {
                print_error(&format!("BOF '{}' is NOT compatible with this implant", bof_id));
            }

            if !response.warnings.is_empty() {
                println!();
                if Theme::is_interactive() {
                    println!("{}", console::style("OPSEC WARNINGS").fg(crate::theme::colors::PEACH).bold());
                } else {
                    println!("OPSEC WARNINGS");
                }
                for warning in &response.warnings {
                    if Theme::is_interactive() {
                        println!("  {} {}", console::style("⚠").fg(crate::theme::colors::PEACH), warning);
                    } else {
                        println!("  * {}", warning);
                    }
                }
            }
        }
        Err(e) => {
            print_error(&format!("Failed to validate BOF: {}", e));
        }
    }

    Ok(())
}

/// List recent BOF execution history
pub async fn history(cli: &CliState, bof_id: Option<String>, limit: u32) -> Result<()> {
    let session = cli.active_session();
    let implant_id = session.map(|s| s.full_id.clone());

    print_info("Fetching BOF execution history...");

    match cli
        .client
        .list_bof_executions(implant_id, bof_id.clone(), limit)
        .await
    {
        Ok(response) => {
            if response.executions.is_empty() {
                print_info("No BOF executions found");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            // Headers
            if Theme::is_interactive() {
                table.set_header(vec![
                    Cell::new("Execution ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("BOF ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Implant").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Status").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Exit Code").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Executed").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                ]);
            } else {
                table.set_header(vec!["Execution ID", "BOF ID", "Implant", "Status", "Exit Code", "Executed"]);
            }

            // Rows
            for exec in &response.executions {
                let exec_id_short = if let Some(ref id) = exec.id {
                    if id.value.len() >= 4 {
                        hex::encode(&id.value[..4])
                    } else {
                        hex::encode(&id.value)
                    }
                } else {
                    "unknown".to_string()
                };

                let implant_short = if let Some(ref id) = exec.implant_id {
                    if id.value.len() >= 4 {
                        hex::encode(&id.value[..4])
                    } else {
                        hex::encode(&id.value)
                    }
                } else {
                    "unknown".to_string()
                };

                let status = if exec.completed {
                    if exec.error.is_some() {
                        "failed"
                    } else {
                        "completed"
                    }
                } else {
                    "running"
                };

                let exit_code = exec
                    .exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let executed_at = if let Some(ref ts) = exec.executed_at {
                    use chrono::{DateTime, Utc};
                    DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                table.add_row(vec![
                    exec_id_short,
                    exec.bof_id.clone(),
                    implant_short,
                    status.to_string(),
                    exit_code,
                    executed_at,
                ]);
            }

            println!("{}", table);
            print_info(&format!("{} execution(s)", response.executions.len()));
        }
        Err(e) => {
            print_error(&format!("Failed to fetch execution history: {}", e));
        }
    }

    Ok(())
}

/// Upload BOF to server catalog
pub async fn upload(_cli: &CliState, file: String) -> Result<()> {

    print_info(&format!("BOF file: {}", file));
    print_error("BOF upload requires manual manifest creation");
    print_info("A BOF manifest specifies:");
    print_info("  - name, description, author");
    print_info("  - function entrypoint and arguments");
    print_info("  - x64 and x86 object file paths");
    print_info("");
    print_info("Use the server's gRPC BOFService.UploadBOF endpoint directly");
    print_info("Example: gRPC client with BofManifest + x64_data + x86_data");
    Ok(())
}
