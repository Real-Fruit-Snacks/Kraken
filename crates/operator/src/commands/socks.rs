//! SOCKS proxy management commands

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// Start SOCKS proxy on current session
pub async fn start(
    cli: &CliState,
    bind_host: String,
    bind_port: u32,
    version: String,
    reverse: bool,
) -> Result<()> {
    let session = cli.active_session().unwrap();

    // Parse SOCKS version
    let socks_version = match version.to_lowercase().as_str() {
        "4" | "socks4" => 1,
        "4a" | "socks4a" => 2,
        "5" | "socks5" => 3,
        _ => {
            print_error(&format!(
                "Unknown SOCKS version '{}'. Use: 4, 4a, 5",
                version
            ));
            return Ok(());
        }
    };

    let proxy_type = if reverse { "reverse" } else { "forward" };
    print_info(&format!(
        "Starting SOCKS{} {} proxy on {}:{}...",
        version, proxy_type, bind_host, bind_port
    ));

    match cli
        .client
        .start_proxy(
            session.full_id.clone(),
            bind_host.clone(),
            bind_port,
            socks_version,
            reverse,
        )
        .await
    {
        Ok(response) => {
            let proxy_id_short = if let Some(proxy_id) = &response.proxy_id {
                if proxy_id.value.len() >= 4 {
                    hex::encode(&proxy_id.value[..4])
                } else {
                    hex::encode(&proxy_id.value)
                }
            } else {
                "unknown".to_string()
            };

            let task_id_short = if let Some(task_id) = &response.task_id {
                if task_id.value.len() >= 4 {
                    hex::encode(&task_id.value[..4])
                } else {
                    hex::encode(&task_id.value)
                }
            } else {
                "unknown".to_string()
            };

            print_success(&format!(
                "SOCKS proxy started (proxy ID: {}, task ID: {})",
                proxy_id_short, task_id_short
            ));
            print_info("Use 'socks list' to monitor proxy status");
        }
        Err(e) => {
            print_error(&format!("Failed to start SOCKS proxy: {}", e));
        }
    }

    Ok(())
}

/// Stop SOCKS proxy
pub async fn stop(cli: &CliState, proxy_id: String) -> Result<()> {
    // Decode proxy ID
    let proxy_bytes = hex::decode(&proxy_id).unwrap_or_else(|_| proxy_id.as_bytes().to_vec());

    print_info(&format!("Stopping SOCKS proxy {}...", proxy_id));

    match cli.client.stop_proxy(proxy_bytes).await {
        Ok(success) => {
            if success {
                print_success(&format!("SOCKS proxy {} stopped", proxy_id));
            } else {
                print_error(&format!("Failed to stop SOCKS proxy {}", proxy_id));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to stop SOCKS proxy: {}", e));
        }
    }

    Ok(())
}

/// List SOCKS proxies
pub async fn list(cli: &CliState) -> Result<()> {
    let session = cli.active_session();

    let implant_id = session.map(|s| s.full_id.clone());

    let response = cli.client.list_proxies(implant_id).await?;

    if response.proxies.is_empty() {
        print_info("No active SOCKS proxies");
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Helper function to format bytes
    fn format_bytes(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    // Headers
    if Theme::is_interactive() {
        table.set_header(vec![
            Cell::new("ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
            Cell::new("Bind").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
            Cell::new("Version").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
            Cell::new("State").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
            Cell::new("Bytes In").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
            Cell::new("Bytes Out").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
            Cell::new("Conns").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
        ]);
    } else {
        table.set_header(vec!["ID", "Bind", "Version", "State", "Bytes In", "Bytes Out", "Conns"]);
    }

    // Rows
    for proxy in &response.proxies {
        let id_short = if let Some(ref id) = proxy.id {
            if id.value.len() >= 4 {
                hex::encode(&id.value[..4])
            } else {
                hex::encode(&id.value)
            }
        } else {
            "unknown".to_string()
        };

        let bind = format!("{}:{}", proxy.bind_host, proxy.bind_port);

        let version = match proxy.version {
            1 => "SOCKS4",
            2 => "SOCKS4A",
            3 => "SOCKS5",
            _ => "unknown",
        };

        let state = match proxy.state {
            0 => "unknown",
            1 => "starting",
            2 => "active",
            3 => "stopping",
            4 => "stopped",
            5 => "error",
            _ => "unknown",
        };

        let bytes_in_str = format_bytes(proxy.bytes_in);
        let bytes_out_str = format_bytes(proxy.bytes_out);
        let conns = format!("{}/{}", proxy.active_connections, proxy.total_connections);

        table.add_row(vec![
            id_short,
            bind,
            version.to_string(),
            state.to_string(),
            bytes_in_str,
            bytes_out_str,
            conns,
        ]);
    }

    println!("{}", table);
    print_info(&format!("{} SOCKS proxies", response.proxies.len()));

    Ok(())
}

/// Show detailed SOCKS proxy statistics
pub async fn stats(cli: &CliState, proxy_id: String) -> Result<()> {
    // Decode proxy ID
    let proxy_bytes = hex::decode(&proxy_id).unwrap_or_else(|_| proxy_id.as_bytes().to_vec());

    print_info(&format!("Fetching statistics for proxy {}...", proxy_id));

    match cli.client.get_proxy_stats(proxy_bytes).await {
        Ok(stats) => {
            // Helper function to format bytes
            fn format_bytes(bytes: u64) -> String {
                if bytes < 1024 {
                    format!("{} B", bytes)
                } else if bytes < 1024 * 1024 {
                    format!("{:.2} KB", bytes as f64 / 1024.0)
                } else if bytes < 1024 * 1024 * 1024 {
                    format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
                } else {
                    format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
                }
            }

            // Statistics table
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            if Theme::is_interactive() {
                table.add_row(vec![
                    Cell::new("Bytes In").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(format_bytes(stats.bytes_in)),
                ]);
                table.add_row(vec![
                    Cell::new("Bytes Out").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(format_bytes(stats.bytes_out)),
                ]);
                table.add_row(vec![
                    Cell::new("Active Connections").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(stats.active_connections.to_string()),
                ]);
                table.add_row(vec![
                    Cell::new("Total Connections").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(stats.total_connections.to_string()),
                ]);
            } else {
                table.add_row(vec!["Bytes In", &format_bytes(stats.bytes_in)]);
                table.add_row(vec!["Bytes Out", &format_bytes(stats.bytes_out)]);
                table.add_row(vec!["Active Connections", &stats.active_connections.to_string()]);
                table.add_row(vec!["Total Connections", &stats.total_connections.to_string()]);
            }

            println!("\n{}", table);

            // Active connections table
            if !stats.connections.is_empty() {
                let mut conn_table = Table::new();
                conn_table
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic);

                if Theme::is_interactive() {
                    conn_table.set_header(vec![
                        Cell::new("Conn ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("Remote").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("Target").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("Bytes In").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("Bytes Out").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("Connected").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    ]);
                } else {
                    conn_table.set_header(vec!["Conn ID", "Remote", "Target", "Bytes In", "Bytes Out", "Connected"]);
                }

                for conn in &stats.connections {
                    let connected_at = if let Some(ts) = &conn.connected_at {
                        DateTime::<Utc>::from_timestamp_millis(ts.millis)
                            .map(|dt| dt.format("%H:%M:%S").to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    } else {
                        "unknown".to_string()
                    };

                    conn_table.add_row(vec![
                        conn.connection_id.to_string(),
                        conn.remote_addr.clone(),
                        conn.target_addr.clone(),
                        format_bytes(conn.bytes_in),
                        format_bytes(conn.bytes_out),
                        connected_at,
                    ]);
                }

                println!("\n{}", if Theme::is_interactive() {
                    console::style("ACTIVE CONNECTIONS").fg(crate::theme::colors::LAVENDER).bold().to_string()
                } else {
                    "ACTIVE CONNECTIONS".to_string()
                });
                println!("{}", conn_table);
            }
        }
        Err(e) => {
            print_error(&format!("Failed to fetch proxy statistics: {}", e));
        }
    }

    Ok(())
}
