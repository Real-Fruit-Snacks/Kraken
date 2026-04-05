//! Session management commands

use anyhow::Result;

use crate::cli::CliState;
use crate::display::{print_error, print_implants_table, print_info, ImplantInfo};

/// List all sessions
pub async fn list(cli: &mut CliState) -> Result<()> {
    // Refresh implants cache
    cli.refresh_implants().await?;

    let implants = cli.get_implants();
    print_implants_table(implants);

    Ok(())
}

/// Select a session by ID prefix
pub async fn use_session(cli: &mut CliState, id_prefix: &str) -> Result<()> {
    // Refresh to get latest implants
    cli.refresh_implants().await?;

    let implants = cli.get_implants();

    // Find matching implants
    let matches: Vec<&ImplantInfo> = implants
        .iter()
        .filter(|imp| imp.id.starts_with(id_prefix))
        .collect();

    match matches.len() {
        0 => {
            print_error(&format!("No session found with ID prefix '{}'", id_prefix));
        }
        1 => {
            let implant = matches[0].clone();
            print_info(&format!(
                "Selected session {} ({}@{})",
                implant.id, implant.username, implant.hostname
            ));
            cli.set_active_session(implant);
        }
        _ => {
            print_error(&format!(
                "Ambiguous session ID '{}'. Matches:",
                id_prefix
            ));
            for imp in matches {
                println!("  {} - {}@{}", imp.id, imp.username, imp.hostname);
            }
        }
    }

    Ok(())
}

/// Background the current session
pub fn back(cli: &mut CliState) {
    if cli.active_session().is_some() {
        print_info("Backgrounded session");
        cli.clear_active_session();
    } else {
        print_info("No active session");
    }
}

/// Show detailed session information
pub async fn info(cli: &CliState, session_id: &str) -> Result<()> {
    use crate::theme::Theme;
    use console::style;
    use chrono::{DateTime, Utc};

    let id_bytes = hex::decode(session_id)
        .map_err(|e| anyhow::anyhow!("Invalid session ID format (expected hex string): {}", e))?;

    let implant = cli.client.get_implant(id_bytes).await?;

    if Theme::is_interactive() {
        println!("\n{}", style("SESSION DETAILS").fg(crate::theme::colors::LAVENDER).bold());

        if let Some(ref id) = implant.id {
            let id_str = hex::encode(&id.value);
            println!("{} {}", style("ID:").fg(crate::theme::colors::TEAL), id_str);
        }

        if let Some(ref sysinfo) = implant.system_info {
            println!("{} {}", style("Hostname:").fg(crate::theme::colors::TEAL), sysinfo.hostname);
            println!("{} {}", style("Username:").fg(crate::theme::colors::TEAL), sysinfo.username);
            println!("{} {}", style("OS:").fg(crate::theme::colors::TEAL), sysinfo.os_name);
            println!("{} {}", style("Arch:").fg(crate::theme::colors::TEAL), sysinfo.os_arch);
            println!("{} {}", style("PID:").fg(crate::theme::colors::TEAL), sysinfo.process_id);

            if !sysinfo.process_name.is_empty() {
                println!("{} {}", style("Process:").fg(crate::theme::colors::TEAL), sysinfo.process_name);
            }
        }

        let state = match implant.state {
            0 => "unknown",
            1 => "active",
            2 => "dormant",
            3 => "dead",
            4 => "retired",
            _ => "unknown",
        };
        println!("{} {}", style("State:").fg(crate::theme::colors::TEAL), state);

        if let Some(ref ts) = implant.registered_at {
            let secs = ts.millis / 1000;
            if let Some(dt) = DateTime::<Utc>::from_timestamp(secs, 0) {
                println!("{} {}", style("Registered:").fg(crate::theme::colors::TEAL), dt.format("%Y-%m-%d %H:%M:%S UTC"));
            }
        }

        if let Some(ref ts) = implant.last_seen {
            let secs = ts.millis / 1000;
            if let Some(dt) = DateTime::<Utc>::from_timestamp(secs, 0) {
                println!("{} {}", style("Last Seen:").fg(crate::theme::colors::TEAL), dt.format("%Y-%m-%d %H:%M:%S UTC"));
            }
        }

        if !implant.tags.is_empty() {
            println!("{} {}", style("Tags:").fg(crate::theme::colors::TEAL), implant.tags.join(", "));
        }

        println!();
    } else {
        println!("\nSESSION DETAILS");

        if let Some(ref id) = implant.id {
            println!("ID: {}", hex::encode(&id.value));
        }

        if let Some(ref sysinfo) = implant.system_info {
            println!("Hostname: {}", sysinfo.hostname);
            println!("Username: {}", sysinfo.username);
            println!("OS: {}", sysinfo.os_name);
            println!("Arch: {}", sysinfo.os_arch);
            println!("PID: {}", sysinfo.process_id);

            if !sysinfo.process_name.is_empty() {
                println!("Process: {}", sysinfo.process_name);
            }
        }

        let state = match implant.state {
            0 => "unknown",
            1 => "active",
            2 => "dormant",
            3 => "dead",
            4 => "retired",
            _ => "unknown",
        };
        println!("State: {}", state);

        if !implant.tags.is_empty() {
            println!("Tags: {}", implant.tags.join(", "));
        }

        println!();
    }

    Ok(())
}

/// Retire a session (mark as inactive)
pub async fn retire(cli: &CliState, session_id: &str) -> Result<()> {
    use crate::display::print_success;

    let id_bytes = hex::decode(session_id)
        .map_err(|e| anyhow::anyhow!("Invalid session ID format (expected hex string): {}", e))?;

    print_info(&format!("Retiring session {}...", session_id));

    match cli.client.retire_implant(id_bytes).await {
        Ok(implant) => {
            print_success(&format!("Session {} retired", session_id));
            if let Some(ref sysinfo) = implant.system_info {
                print_info(&format!("State: {}@{}", sysinfo.username, sysinfo.hostname));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to retire session: {}", e));
        }
    }

    Ok(())
}

/// Delete a session from database
pub async fn delete(cli: &CliState, session_id: &str) -> Result<()> {
    use crate::display::print_success;

    let id_bytes = hex::decode(session_id)
        .map_err(|e| anyhow::anyhow!("Invalid session ID format (expected hex string): {}", e))?;

    print_info(&format!("Deleting session {} from database...", session_id));

    match cli.client.delete_implant(id_bytes).await {
        Ok(success) => {
            if success {
                print_success(&format!("Session {} deleted", session_id));
            } else {
                print_error(&format!("Failed to delete session {}", session_id));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to delete session: {}", e));
        }
    }

    Ok(())
}

/// Burn a session (permanently destroy implant)
pub async fn burn(cli: &CliState, session_id: &str) -> Result<()> {
    use crate::display::print_success;

    let id_bytes = hex::decode(session_id)
        .map_err(|e| anyhow::anyhow!("Invalid session ID format (expected hex string): {}", e))?;

    // Confirm with user
    println!("\nWARNING: This will permanently destroy the implant on the target system.");
    println!("This action CANNOT be undone.");
    println!("\nAre you sure you want to burn session {}? Type 'yes' to confirm:", session_id);

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() != "yes" {
        print_info("Burn cancelled");
        return Ok(());
    }

    print_info(&format!("Burning session {}...", session_id));

    match cli.client.burn_implant(id_bytes, "Operator requested burn".to_string()).await {
        Ok(implant) => {
            print_success(&format!("Session {} burned", session_id));
            if let Some(ref sysinfo) = implant.system_info {
                print_info(&format!("Target: {}@{}", sysinfo.username, sysinfo.hostname));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to burn session: {}", e));
        }
    }

    Ok(())
}

/// Validate tag format (alphanumeric + hyphens only, no spaces)
fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    if tag.contains(' ') {
        anyhow::bail!("Tag cannot contain spaces");
    }

    if !tag.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!("Tag can only contain alphanumeric characters, hyphens, and underscores");
    }

    Ok(())
}

/// Add a tag to a session
pub async fn tag(cli: &CliState, session_id: &str, tag: &str) -> Result<()> {
    use crate::display::print_success;

    // Validate tag format
    validate_tag(tag)?;

    let id_bytes = hex::decode(session_id)
        .map_err(|e| anyhow::anyhow!("Invalid session ID format (expected hex string): {}", e))?;

    // Get current implant to read existing tags
    let implant = cli.client.get_implant(id_bytes.clone()).await?;

    // Check if tag already exists
    if implant.tags.contains(&tag.to_string()) {
        print_info(&format!("Session {} already has tag '{}'", session_id, tag));
        return Ok(());
    }

    // Add new tag to existing tags
    let mut new_tags = implant.tags.clone();
    new_tags.push(tag.to_string());

    // Update implant with new tags
    match cli.client.update_implant(
        id_bytes,
        None,  // name
        new_tags,
        None,  // notes
        None,  // checkin_interval
        None,  // jitter_percent
    ).await {
        Ok(_) => {
            print_success(&format!("Added tag '{}' to session {}", tag, session_id));
        }
        Err(e) => {
            print_error(&format!("Failed to add tag: {}", e));
        }
    }

    Ok(())
}

/// Remove a tag from a session
pub async fn untag(cli: &CliState, session_id: &str, tag: &str) -> Result<()> {
    use crate::display::print_success;

    let id_bytes = hex::decode(session_id)
        .map_err(|e| anyhow::anyhow!("Invalid session ID format (expected hex string): {}", e))?;

    // Get current implant to read existing tags
    let implant = cli.client.get_implant(id_bytes.clone()).await?;

    // Check if tag exists
    if !implant.tags.contains(&tag.to_string()) {
        print_info(&format!("Session {} does not have tag '{}'", session_id, tag));
        return Ok(());
    }

    // Remove tag from existing tags
    let new_tags: Vec<String> = implant.tags
        .into_iter()
        .filter(|t| t != tag)
        .collect();

    // Update implant with new tags
    match cli.client.update_implant(
        id_bytes,
        None,  // name
        new_tags,
        None,  // notes
        None,  // checkin_interval
        None,  // jitter_percent
    ).await {
        Ok(_) => {
            print_success(&format!("Removed tag '{}' from session {}", tag, session_id));
        }
        Err(e) => {
            print_error(&format!("Failed to remove tag: {}", e));
        }
    }

    Ok(())
}

/// List all sessions with a specific tag
pub async fn list_by_tag(cli: &mut CliState, tag: &str) -> Result<()> {
    // Refresh implants cache
    cli.refresh_implants().await?;

    let implants = cli.get_implants();

    // Filter implants by tag
    let tagged_implants: Vec<ImplantInfo> = implants
        .iter()
        .filter(|imp| imp.tags.contains(&tag.to_string()))
        .cloned()
        .collect();

    if tagged_implants.is_empty() {
        print_info(&format!("No sessions found with tag '{}'", tag));
    } else {
        print_info(&format!("Sessions with tag '{}':", tag));
        print_implants_table(&tagged_implants);
    }

    Ok(())
}
