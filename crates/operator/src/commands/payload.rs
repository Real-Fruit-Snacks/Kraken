//! Payload generation commands

use anyhow::Result;
use chrono::{Local, TimeZone};
use std::fs;

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// Generate a new payload
pub async fn generate(
    cli: &CliState,
    format: String,
    listener_id: String,
    output: String,
    os: Option<String>,
    arch: Option<String>,
) -> Result<()> {
    let os = os.unwrap_or_else(|| "windows".to_string());
    let arch = arch.unwrap_or_else(|| "x64".to_string());

    // Parse listener ID (hex string)
    let listener_id_bytes = hex::decode(&listener_id)
        .map_err(|e| anyhow::anyhow!("Invalid listener ID format (expected hex string): {}", e))?;

    print_info(&format!(
        "Generating {} payload for {} {}...",
        format, os, arch
    ));

    let name = format!("implant-{}-{}", os, arch);
    let c2_endpoints = vec!["http://localhost:8080".to_string()]; // Default, should come from listener

    match cli
        .client
        .generate_payload(
            name.clone(),
            os.clone(),
            arch.clone(),
            format.clone(),
            listener_id_bytes,
            c2_endpoints,
        )
        .await
    {
        Ok(response) => {
            if response.payload.is_some() && !response.content.is_empty() {
                // Write payload to file
                match fs::write(&output, &response.content) {
                    Ok(_) => {
                        let payload = response.payload.unwrap();
                        print_success(&format!(
                            "Payload generated: {} ({} bytes)",
                            output,
                            response.content.len()
                        ));
                        print_info(&format!("  Format: {} {}/{}", format, os, arch));
                        if !payload.hash.is_empty() {
                            print_info(&format!("  SHA256: {}", payload.hash));
                        }
                    }
                    Err(e) => {
                        print_error(&format!("Failed to write payload file: {}", e));
                    }
                }
            } else {
                print_error("Payload generation returned empty content");
            }
        }
        Err(e) => {
            print_error(&format!("Failed to generate payload: {}", e));
        }
    }

    Ok(())
}

/// List generated payloads
pub async fn list(cli: &CliState) -> Result<()> {
    let payloads = cli.client.list_payloads().await?;

    if payloads.is_empty() {
        print_info("No payloads generated");
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
            Cell::new("OS/Arch").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Format").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Size").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Generated").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
        ]);
    } else {
        table.set_header(vec!["ID", "Name", "OS/Arch", "Format", "Size", "Generated"]);
    }

    // Rows
    for payload in &payloads {
        let id_short = if payload.id.len() >= 4 {
            hex::encode(&payload.id[..4])
        } else if !payload.id.is_empty() {
            hex::encode(&payload.id)
        } else {
            "unknown".to_string()
        };

        let os_arch = format!("{}/{}", payload.os, payload.arch);

        let size_kb = payload.size / 1024;

        let generated = if payload.generated_at.is_some() {
            let ts = payload.generated_at.as_ref().unwrap();
            let millis = ts.millis;
            if millis > 0 {
                let secs = millis / 1000;
                let dt = Local.timestamp_opt(secs, 0).unwrap();
                dt.format("%Y-%m-%d %H:%M").to_string()
            } else {
                "N/A".to_string()
            }
        } else {
            "N/A".to_string()
        };

        table.add_row(vec![
            id_short,
            payload.name.clone(),
            os_arch,
            payload.format.clone(),
            format!("{} KB", size_kb),
            generated,
        ]);
    }

    println!("{table}");
    print_info(&format!("{} payloads", payloads.len()));

    Ok(())
}

/// Show payload details
pub async fn show(cli: &CliState, payload_id: String) -> Result<()> {
    use console::style;

    let id_bytes = hex::decode(&payload_id)
        .map_err(|e| anyhow::anyhow!("Invalid payload ID format (expected hex string): {}", e))?;

    let payload = cli.client.get_payload(id_bytes).await?;

    if Theme::is_interactive() {
        println!("\n{}", style("PAYLOAD DETAILS").fg(crate::theme::colors::LAVENDER).bold());
        println!("{} {}", style("ID:").fg(crate::theme::colors::TEAL), payload_id);
        println!("{} {}", style("Name:").fg(crate::theme::colors::TEAL), payload.name);
        println!("{} {}/{}", style("Target:").fg(crate::theme::colors::TEAL), payload.os, payload.arch);
        println!("{} {}", style("Format:").fg(crate::theme::colors::TEAL), payload.format);
        println!("{} {} KB", style("Size:").fg(crate::theme::colors::TEAL), payload.size / 1024);

        if !payload.hash.is_empty() {
            println!("{} {}", style("SHA256:").fg(crate::theme::colors::TEAL), payload.hash);
        }

        if let Some(ref ts) = payload.generated_at {
            let millis = ts.millis;
            if millis > 0 {
                let secs = millis / 1000;
                let dt = Local.timestamp_opt(secs, 0).unwrap();
                println!("{} {}", style("Generated:").fg(crate::theme::colors::TEAL), dt.format("%Y-%m-%d %H:%M:%S"));
            }
        }

        println!("\n{}", style("TRANSPORT").fg(crate::theme::colors::LAVENDER).bold());
        println!("{} {}", style("Type:").fg(crate::theme::colors::TEAL), payload.transport);
        println!();
    } else {
        println!("\nPAYLOAD DETAILS");
        println!("ID: {}", payload_id);
        println!("Name: {}", payload.name);
        println!("Target: {}/{}", payload.os, payload.arch);
        println!("Format: {}", payload.format);
        println!("Size: {} KB", payload.size / 1024);

        if !payload.hash.is_empty() {
            println!("SHA256: {}", payload.hash);
        }

        println!("\nTRANSPORT");
        println!("Type: {}", payload.transport);
        println!();
    }

    Ok(())
}

/// Delete a payload
pub async fn delete(cli: &CliState, payload_id: String) -> Result<()> {
    let id_bytes = hex::decode(&payload_id)
        .map_err(|e| anyhow::anyhow!("Invalid payload ID format (expected hex string): {}", e))?;

    print_info(&format!("Deleting payload {}...", payload_id));

    match cli.client.delete_payload(id_bytes).await {
        Ok(success) => {
            if success {
                print_success(&format!("Payload {} deleted", payload_id));
            } else {
                print_error(&format!("Failed to delete payload {}", payload_id));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to delete payload: {}", e));
        }
    }

    Ok(())
}
