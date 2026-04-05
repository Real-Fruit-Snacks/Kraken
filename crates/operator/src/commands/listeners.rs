//! Listener management commands

use anyhow::Result;
use chrono::{Local, TimeZone};

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// List all listeners
pub async fn list(cli: &CliState) -> Result<()> {
    let listeners = cli.client.list_listeners().await?;

    if listeners.is_empty() {
        print_info("No listeners running");
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
            Cell::new("Type").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Address").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Profile").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Status").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Connections").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Started").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
        ]);
    } else {
        table.set_header(vec![
            "ID",
            "Type",
            "Address",
            "Profile",
            "Status",
            "Connections",
            "Started",
        ]);
    }

    // Rows
    for listener in &listeners {
        let id_short = if listener.id.is_some() {
            let id_bytes = listener.id.as_ref().unwrap().value.as_slice();
            if id_bytes.len() >= 4 {
                hex::encode(&id_bytes[..4])
            } else {
                hex::encode(id_bytes)
            }
        } else {
            "unknown".to_string()
        };

        let address = format!("{}:{}", listener.bind_host, listener.bind_port);

        let status = if listener.is_running {
            "running"
        } else {
            "stopped"
        };

        let started = if listener.started_at.is_some() {
            let ts = listener.started_at.as_ref().unwrap();
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
            let status_color = if listener.is_running {
                Color::Rgb {
                    r: 166,
                    g: 228,
                    b: 161,
                } // Green
            } else {
                Color::Rgb {
                    r: 248,
                    g: 139,
                    b: 168,
                } // Red
            };

            table.add_row(vec![
                Cell::new(id_short),
                Cell::new(&listener.listener_type),
                Cell::new(address),
                Cell::new(&listener.profile_id),
                Cell::new(status).fg(status_color),
                Cell::new(listener.connections_total.to_string()),
                Cell::new(started),
            ]);
        } else {
            table.add_row(vec![
                id_short,
                listener.listener_type.clone(),
                address,
                listener.profile_id.clone(),
                status.to_string(),
                listener.connections_total.to_string(),
                started,
            ]);
        }
    }

    println!("{table}");

    let active = listeners.iter().filter(|l| l.is_running).count();
    print_info(&format!(
        "{} listeners ({} active)",
        listeners.len(),
        active
    ));

    Ok(())
}

/// Start a new listener
pub async fn start(
    cli: &CliState,
    listener_type: String,
    bind_host: String,
    bind_port: u32,
    profile: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    dns_domain: Option<String>,
) -> Result<()> {
    // Validate listener type
    match listener_type.as_str() {
        "http" | "https" | "dns" => {}
        _ => {
            print_error("Invalid listener type. Use: http, https, or dns");
            return Ok(());
        }
    }

    // Validate HTTPS requirements
    if listener_type == "https" && (tls_cert.is_none() || tls_key.is_none()) {
        print_error("HTTPS listener requires --cert and --key parameters");
        return Ok(());
    }

    // Validate DNS requirements
    if listener_type == "dns" && dns_domain.is_none() {
        print_error("DNS listener requires --domain parameter");
        return Ok(());
    }

    print_info(&format!(
        "Starting {} listener on {}:{}...",
        listener_type, bind_host, bind_port
    ));

    match cli
        .client
        .start_listener(
            listener_type.clone(),
            bind_host.clone(),
            bind_port,
            profile,
            tls_cert,
            tls_key,
            dns_domain,
        )
        .await
    {
        Ok(listener) => {
            let id_short = if listener.id.is_some() {
                let id_bytes = listener.id.as_ref().unwrap().value.as_slice();
                if id_bytes.len() >= 4 {
                    hex::encode(&id_bytes[..4])
                } else {
                    hex::encode(id_bytes)
                }
            } else {
                "unknown".to_string()
            };
            print_success(&format!(
                "Listener started: {} (ID: {})",
                listener_type, id_short
            ));
        }
        Err(e) => {
            print_error(&format!("Failed to start listener: {}", e));
        }
    }

    Ok(())
}

/// Stop a listener
pub async fn stop(cli: &CliState, listener_id: String) -> Result<()> {
    // Parse listener ID (hex string)
    let id_bytes = hex::decode(&listener_id).map_err(|e| {
        anyhow::anyhow!("Invalid listener ID format (expected hex string): {}", e)
    })?;

    print_info(&format!("Stopping listener {}...", listener_id));

    match cli.client.stop_listener(id_bytes).await {
        Ok(_) => {
            print_success(&format!("Listener {} stopped", listener_id));
        }
        Err(e) => {
            print_error(&format!("Failed to stop listener: {}", e));
        }
    }

    Ok(())
}
