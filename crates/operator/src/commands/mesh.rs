//! Mesh topology commands

use anyhow::Result;

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// Show mesh topology
pub async fn topology(cli: &CliState) -> Result<()> {
    print_info("Fetching mesh topology...");

    match cli.client.get_mesh_topology().await {
        Ok(topology) => {
            if topology.nodes.is_empty() {
                print_info("No mesh nodes configured");
                return Ok(());
            }

            // Display nodes table
            let mut nodes_table = Table::new();
            nodes_table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            if Theme::is_interactive() {
                nodes_table.set_header(vec![
                    Cell::new("Implant ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Role").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Egress").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                ]);
            } else {
                nodes_table.set_header(vec!["Implant ID", "Role", "Egress"]);
            }

            for node in &topology.nodes {
                let id_short = if node.implant_id.len() >= 4 {
                    hex::encode(&node.implant_id[..4])
                } else {
                    hex::encode(&node.implant_id)
                };

                let role = match node.role {
                    0 => "unknown",
                    1 => "listener",
                    2 => "relay",
                    3 => "client",
                    _ => "unknown",
                };

                let egress = if node.has_egress { "yes" } else { "no" };

                nodes_table.add_row(vec![id_short, role.to_string(), egress.to_string()]);
            }

            println!("\n{}", if Theme::is_interactive() {
                console::style("MESH NODES").fg(crate::theme::colors::LAVENDER).bold().to_string()
            } else {
                "MESH NODES".to_string()
            });
            println!("{}", nodes_table);

            // Display links table if any
            if !topology.links.is_empty() {
                let mut links_table = Table::new();
                links_table
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic);

                if Theme::is_interactive() {
                    links_table.set_header(vec![
                        Cell::new("From").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("To").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("Transport").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("State").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                        Cell::new("Latency").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    ]);
                } else {
                    links_table.set_header(vec!["From", "To", "Transport", "State", "Latency"]);
                }

                for link in &topology.links {
                    let from_short = if link.from_id.len() >= 4 {
                        hex::encode(&link.from_id[..4])
                    } else {
                        hex::encode(&link.from_id)
                    };

                    let to_short = if link.to_id.len() >= 4 {
                        hex::encode(&link.to_id[..4])
                    } else {
                        hex::encode(&link.to_id)
                    };

                    let transport = match link.transport {
                        0 => "unknown",
                        1 => "SMB",
                        2 => "TCP",
                        3 => "UDP",
                        _ => "unknown",
                    };

                    let state = match link.state {
                        0 => "unknown",
                        1 => "establishing",
                        2 => "active",
                        3 => "dormant",
                        4 => "broken",
                        _ => "unknown",
                    };

                    let latency = if link.latency_ms > 0 {
                        format!("{}ms", link.latency_ms)
                    } else {
                        "N/A".to_string()
                    };

                    links_table.add_row(vec![from_short, to_short, transport.to_string(), state.to_string(), latency]);
                }

                println!("\n{}", if Theme::is_interactive() {
                    console::style("MESH LINKS").fg(crate::theme::colors::LAVENDER).bold().to_string()
                } else {
                    "MESH LINKS".to_string()
                });
                println!("{}", links_table);
            }

            print_success(&format!("{} nodes, {} links", topology.nodes.len(), topology.links.len()));
        }
        Err(e) => {
            print_error(&format!("Failed to fetch mesh topology: {}", e));
        }
    }

    Ok(())
}

/// Connect to a mesh peer
pub async fn connect(
    cli: &CliState,
    peer_id: String,
    transport: String,
    address: String,
    port: u32,
) -> Result<()> {
    let session = cli.active_session().unwrap();

    // Decode peer ID
    let peer_bytes = hex::decode(&peer_id).unwrap_or_else(|_| peer_id.as_bytes().to_vec());

    // Parse transport type
    let transport_type = match transport.to_lowercase().as_str() {
        "smb" => 1,
        "tcp" => 2,
        _ => {
            print_error(&format!("Unknown transport type '{}'. Use: smb, tcp", transport));
            return Ok(());
        }
    };

    print_info(&format!(
        "Connecting to peer {} via {} at {}:{}...",
        peer_id, transport, address, port
    ));

    match cli
        .client
        .connect_peer(
            session.full_id.clone(),
            peer_bytes,
            transport_type,
            address.clone(),
            port,
            String::new(), // pipe_name (for SMB)
        )
        .await
    {
        Ok(task_id) => {
            let task_id_short = if task_id.len() >= 4 {
                hex::encode(&task_id[..4])
            } else {
                hex::encode(&task_id)
            };
            print_success(&format!(
                "Mesh connect task dispatched (task ID: {})",
                task_id_short
            ));
            print_info("Use 'tasks' to monitor connection establishment");
        }
        Err(e) => {
            print_error(&format!("Failed to connect to peer: {}", e));
        }
    }

    Ok(())
}

/// Disconnect from a mesh peer
pub async fn disconnect(cli: &CliState, peer_id: String) -> Result<()> {
    let session = cli.active_session().unwrap();

    // Decode peer ID
    let peer_bytes = hex::decode(&peer_id).unwrap_or_else(|_| peer_id.as_bytes().to_vec());

    print_info(&format!("Disconnecting from peer {}...", peer_id));

    match cli
        .client
        .disconnect_peer(session.full_id.clone(), peer_bytes)
        .await
    {
        Ok(task_id) => {
            let task_id_short = if task_id.len() >= 4 {
                hex::encode(&task_id[..4])
            } else {
                hex::encode(&task_id)
            };
            print_success(&format!(
                "Mesh disconnect task dispatched (task ID: {})",
                task_id_short
            ));
        }
        Err(e) => {
            print_error(&format!("Failed to disconnect from peer: {}", e));
        }
    }

    Ok(())
}

/// Set mesh role for current session
pub async fn role(cli: &CliState, role: String) -> Result<()> {
    let session = cli.active_session().unwrap();

    // Parse role type
    let role_type = match role.to_lowercase().as_str() {
        "leaf" => 0,
        "relay" => 1,
        "hub" => 2,
        _ => {
            print_error(&format!("Unknown role '{}'. Use: leaf, relay, hub", role));
            return Ok(());
        }
    };

    print_info(&format!("Setting mesh role to '{}'...", role));

    match cli
        .client
        .set_mesh_role(session.full_id.clone(), role_type)
        .await
    {
        Ok(task_id) => {
            let task_id_short = if task_id.len() >= 4 {
                hex::encode(&task_id[..4])
            } else {
                hex::encode(&task_id)
            };
            print_success(&format!(
                "Mesh role task dispatched (task ID: {})",
                task_id_short
            ));
        }
        Err(e) => {
            print_error(&format!("Failed to set mesh role: {}", e));
        }
    }

    Ok(())
}

/// Start mesh listener on current session
pub async fn listen(
    cli: &CliState,
    port: u32,
    transport: String,
    bind_address: String,
) -> Result<()> {
    let session = cli.active_session().unwrap();

    // Parse transport type
    let transport_type = match transport.to_lowercase().as_str() {
        "smb" => 1,
        "tcp" => 2,
        _ => {
            print_error(&format!("Unknown transport type '{}'. Use: smb, tcp", transport));
            return Ok(());
        }
    };

    print_info(&format!(
        "Starting mesh listener on {}:{} ({})...",
        bind_address, port, transport
    ));

    match cli
        .client
        .mesh_listen(
            session.full_id.clone(),
            port,
            transport_type,
            bind_address.clone(),
        )
        .await
    {
        Ok(task_id) => {
            let task_id_short = if task_id.len() >= 4 {
                hex::encode(&task_id[..4])
            } else {
                hex::encode(&task_id)
            };
            print_success(&format!(
                "Mesh listener task dispatched (task ID: {})",
                task_id_short
            ));
        }
        Err(e) => {
            print_error(&format!("Failed to start mesh listener: {}", e));
        }
    }

    Ok(())
}

/// Compute route between two mesh nodes
pub async fn route(cli: &CliState, from_id: String, to_id: String, max_paths: u32) -> Result<()> {
    // Decode IDs
    let from_bytes = hex::decode(&from_id).unwrap_or_else(|_| from_id.as_bytes().to_vec());
    let to_bytes = hex::decode(&to_id).unwrap_or_else(|_| to_id.as_bytes().to_vec());

    print_info(&format!(
        "Computing route from {} to {}...",
        from_id, to_id
    ));

    match cli
        .client
        .compute_route(from_bytes, to_bytes, max_paths)
        .await
    {
        Ok(response) => {
            if response.routes.is_empty() {
                print_info("No routes found");
                return Ok(());
            }

            for (idx, route) in response.routes.iter().enumerate() {
                let hops: Vec<String> = route
                    .hops
                    .iter()
                    .map(|hop| {
                        if hop.len() >= 4 {
                            hex::encode(&hop[..4])
                        } else {
                            hex::encode(hop)
                        }
                    })
                    .collect();

                if Theme::is_interactive() {
                    println!(
                        "  {} {} → {}",
                        console::style(format!("Route {}:", idx + 1))
                            .fg(crate::theme::colors::LAVENDER)
                            .bold(),
                        console::style(&from_id).fg(crate::theme::colors::TEAL),
                        console::style(hops.join(" → ")).fg(crate::theme::colors::TEAL)
                    );
                } else {
                    println!("  Route {}: {} → {}", idx + 1, from_id, hops.join(" → "));
                }
            }

            print_success(&format!("{} route(s) found", response.routes.len()));
        }
        Err(e) => {
            print_error(&format!("Failed to compute route: {}", e));
        }
    }

    Ok(())
}
