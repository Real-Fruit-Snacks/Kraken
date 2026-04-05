//! Loot management commands

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

use crate::cli::CliState;
use crate::cred_export;
use crate::display::{print_error, print_info, print_loot_table, print_success, LootItem};

/// Validate export path to prevent directory traversal attacks
fn validate_export_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);

    // Reject absolute paths outside current directory
    if path.is_absolute() {
        return Err(anyhow::anyhow!("Absolute paths not allowed for export"));
    }

    // Reject paths with .. components
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(anyhow::anyhow!("Path traversal (..) not allowed in export path"));
    }

    // Canonicalize relative to current directory
    let current_dir = std::env::current_dir()?;
    let full_path = current_dir.join(path);

    // Ensure the canonicalized path is still within current directory
    let canonical = full_path.canonicalize().unwrap_or(full_path.clone());
    if !canonical.starts_with(&current_dir) {
        return Err(anyhow::anyhow!("Export path must be within current directory"));
    }

    Ok(full_path)
}

/// List loot items (optionally filtered by type)
pub async fn list(cli: &CliState, type_filter: Option<&str>) -> Result<()> {
    // Map type string to proto enum value
    let filter_value = type_filter.and_then(|t| match t {
        "credential" => Some(1),
        "hash" => Some(2),
        "token" => Some(3),
        "file" => Some(4),
        _ => None,
    });

    let entries = cli.client.list_loot(filter_value).await?;

    // Convert to display format
    let loot_items: Vec<LootItem> = entries
        .iter()
        .map(|entry| {
            let loot_type = match entry.loot_type {
                1 => "credential",
                2 => "hash",
                3 => "token",
                4 => "file",
                _ => "unknown",
            };

            let captured_at = if let Some(ref ts) = entry.collected_at {
                format_timestamp(ts.millis / 1000)
            } else {
                "N/A".to_string()
            };

            // Extract value from the data oneof
            let value = match &entry.data {
                Some(protocol::loot_entry::Data::Credential(cred)) => {
                    format!("{}:{}", cred.username, cred.password)
                }
                Some(protocol::loot_entry::Data::Hash(hash)) => {
                    hash.hash.clone()
                }
                Some(protocol::loot_entry::Data::Token(token)) => {
                    token.token_value.chars().take(32).collect::<String>() + "..."
                }
                Some(protocol::loot_entry::Data::File(file)) => {
                    file.filename.clone()
                }
                None => "unknown".to_string(),
            };

            // Build detail fields from data
            let detail_fields: Vec<(String, String)> = Vec::new();

            LootItem {
                loot_type: loot_type.to_string(),
                source: entry.source.clone(),
                value,
                captured_at,
                detail_fields,
            }
        })
        .collect();

    print_loot_table(&loot_items);

    Ok(())
}

/// Search loot by value or source using server-side FTS5 full-text search
pub async fn search(cli: &CliState, query: &str) -> Result<()> {
    let response = cli.client.search_loot(query.to_string(), None).await?;

    if response.entries.is_empty() {
        print_info(&format!("No loot found matching '{}' ({} total in database)", query, response.total_count));
        return Ok(());
    }

    // Convert to display format
    let loot_items: Vec<LootItem> = response.entries
        .iter()
        .map(|entry| {
            let loot_type = match entry.loot_type {
                1 => "credential",
                2 => "hash",
                3 => "token",
                4 => "file",
                _ => "unknown",
            };

            let captured_at = if let Some(ref ts) = entry.collected_at {
                format_timestamp(ts.millis / 1000)
            } else {
                "N/A".to_string()
            };

            // Extract value from the data oneof
            let value = match &entry.data {
                Some(protocol::loot_entry::Data::Credential(cred)) => {
                    format!("{}:{}", cred.username, cred.password)
                }
                Some(protocol::loot_entry::Data::Hash(hash)) => {
                    hash.hash.clone()
                }
                Some(protocol::loot_entry::Data::Token(token)) => {
                    token.token_value.chars().take(32).collect::<String>() + "..."
                }
                Some(protocol::loot_entry::Data::File(file)) => {
                    file.filename.clone()
                }
                None => "unknown".to_string(),
            };

            let detail_fields: Vec<(String, String)> = Vec::new();

            LootItem {
                loot_type: loot_type.to_string(),
                source: entry.source.clone(),
                value,
                captured_at,
                detail_fields,
            }
        })
        .collect();

    print_loot_table(&loot_items);
    print_info(&format!("Showing {} of {} total matches", response.entries.len(), response.total_count));

    Ok(())
}

/// Export loot to file (JSON, CSV, or Markdown)
pub async fn export(cli: &CliState, path: &str) -> Result<()> {
    // Validate export path to prevent directory traversal
    let validated_path = validate_export_path(path)?;

    // Determine format from file extension
    let format = if path.ends_with(".csv") {
        "csv"
    } else if path.ends_with(".md") || path.ends_with(".markdown") {
        "markdown"
    } else {
        "json"
    };

    let response = cli.client.export_loot(format.to_string(), None).await?;

    // Write to file
    match std::fs::write(&validated_path, &response.data) {
        Ok(_) => {
            print_success(&format!("Exported loot to {} ({} bytes, {} format)", path, response.data.len(), format));
        }
        Err(e) => {
            print_error(&format!("Failed to write to {}: {}", path, e));
        }
    }

    Ok(())
}

/// Show detailed loot entry
pub async fn show(cli: &CliState, loot_id: &str) -> Result<()> {
    use crate::theme::Theme;
    use console::style;

    let id_bytes = hex::decode(loot_id)
        .map_err(|e| anyhow::anyhow!("Invalid loot ID format (expected hex string): {}", e))?;

    let entry = cli.client.get_loot(id_bytes).await?;

    if Theme::is_interactive() {
        println!("\n{}", style("LOOT ENTRY").fg(crate::theme::colors::LAVENDER).bold());
        println!("{} {}", style("ID:").fg(crate::theme::colors::TEAL), loot_id);

        let loot_type = match entry.loot_type {
            1 => "credential",
            2 => "hash",
            3 => "token",
            4 => "file",
            _ => "unknown",
        };
        println!("{} {}", style("Type:").fg(crate::theme::colors::TEAL), loot_type);
        println!("{} {}", style("Source:").fg(crate::theme::colors::TEAL), entry.source);

        if let Some(ref ts) = entry.collected_at {
            let captured_at = format_timestamp(ts.millis / 1000);
            println!("{} {}", style("Collected:").fg(crate::theme::colors::TEAL), captured_at);
        }

        // Type-specific details
        match &entry.data {
            Some(protocol::loot_entry::Data::Credential(cred)) => {
                println!("\n{}", style("CREDENTIAL DETAILS").fg(crate::theme::colors::LAVENDER).bold());
                println!("{} {}", style("Username:").fg(crate::theme::colors::TEAL), cred.username);
                println!("{} {}", style("Password:").fg(crate::theme::colors::TEAL), cred.password);
                if let Some(ref domain) = cred.domain {
                    println!("{} {}", style("Domain:").fg(crate::theme::colors::TEAL), domain);
                }
            }
            Some(protocol::loot_entry::Data::Hash(hash)) => {
                println!("\n{}", style("HASH DETAILS").fg(crate::theme::colors::LAVENDER).bold());
                println!("{} {}", style("Username:").fg(crate::theme::colors::TEAL), hash.username);
                println!("{} {}", style("Hash Type:").fg(crate::theme::colors::TEAL), hash.hash_type);
                println!("{} {}", style("Hash:").fg(crate::theme::colors::TEAL), hash.hash);
            }
            Some(protocol::loot_entry::Data::Token(token)) => {
                println!("\n{}", style("TOKEN DETAILS").fg(crate::theme::colors::LAVENDER).bold());
                println!("{} {}", style("Token Type:").fg(crate::theme::colors::TEAL), token.token_type);
                println!("{} {}", style("Value:").fg(crate::theme::colors::TEAL), token.token_value);
            }
            Some(protocol::loot_entry::Data::File(file)) => {
                println!("\n{}", style("FILE DETAILS").fg(crate::theme::colors::LAVENDER).bold());
                println!("{} {}", style("Filename:").fg(crate::theme::colors::TEAL), file.filename);
                println!("{} {}", style("Original Path:").fg(crate::theme::colors::TEAL), file.original_path);
                println!("{} {} bytes", style("Size:").fg(crate::theme::colors::TEAL), file.size);
            }
            None => {}
        }
        println!();
    } else {
        println!("\nLOOT ENTRY");
        println!("ID: {}", loot_id);

        let loot_type = match entry.loot_type {
            1 => "credential",
            2 => "hash",
            3 => "token",
            4 => "file",
            _ => "unknown",
        };
        println!("Type: {}", loot_type);
        println!("Source: {}", entry.source);

        // Print type-specific details
        match &entry.data {
            Some(protocol::loot_entry::Data::Credential(cred)) => {
                println!("\nCREDENTIAL DETAILS");
                println!("Username: {}", cred.username);
                println!("Password: {}", cred.password);
                if let Some(ref domain) = cred.domain {
                    println!("Domain: {}", domain);
                }
            }
            Some(protocol::loot_entry::Data::Hash(hash)) => {
                println!("\nHASH DETAILS");
                println!("Username: {}", hash.username);
                println!("Hash Type: {}", hash.hash_type);
                println!("Hash: {}", hash.hash);
            }
            Some(protocol::loot_entry::Data::Token(token)) => {
                println!("\nTOKEN DETAILS");
                println!("Token Type: {}", token.token_type);
                println!("Value: {}", token.token_value);
            }
            Some(protocol::loot_entry::Data::File(file)) => {
                println!("\nFILE DETAILS");
                println!("Filename: {}", file.filename);
                println!("Original Path: {}", file.original_path);
                println!("Size: {} bytes", file.size);
            }
            None => {}
        }
        println!();
    }

    Ok(())
}

/// Delete a loot entry
pub async fn delete(cli: &CliState, loot_id: &str) -> Result<()> {
    let id_bytes = hex::decode(loot_id)
        .map_err(|e| anyhow::anyhow!("Invalid loot ID format (expected hex string): {}", e))?;

    print_info(&format!("Deleting loot entry {}...", loot_id));

    match cli.client.delete_loot(id_bytes).await {
        Ok(success) => {
            if success {
                print_success(&format!("Loot entry {} deleted", loot_id));
            } else {
                print_error(&format!("Failed to delete loot entry {}", loot_id));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to delete loot: {}", e));
        }
    }

    Ok(())
}

/// Export hashes in hashcat format
pub async fn export_hashcat(cli: &CliState, path: &str) -> Result<()> {
    // Validate export path to prevent directory traversal
    let validated_path = validate_export_path(path)?;

    // Fetch all loot entries (filter for hash type = 2)
    let entries = cli.client.list_loot(Some(2)).await?;

    if entries.is_empty() {
        print_info("No hash entries found to export");
        return Ok(());
    }

    // Format for hashcat
    let output = cred_export::format_hashcat(&entries)?;

    // Write to file
    match std::fs::write(&validated_path, &output) {
        Ok(_) => {
            print_success(&format!(
                "Exported {} hashes to {} (hashcat format)",
                entries.len(),
                path
            ));
        }
        Err(e) => {
            print_error(&format!("Failed to write to {}: {}", path, e));
        }
    }

    Ok(())
}

/// Export hashes in John the Ripper format
pub async fn export_jtr(cli: &CliState, path: &str) -> Result<()> {
    // Validate export path to prevent directory traversal
    let validated_path = validate_export_path(path)?;

    // Fetch all loot entries (filter for hash type = 2)
    let entries = cli.client.list_loot(Some(2)).await?;

    if entries.is_empty() {
        print_info("No hash entries found to export");
        return Ok(());
    }

    // Format for JtR
    let output = cred_export::format_jtr(&entries)?;

    // Write to file
    match std::fs::write(&validated_path, &output) {
        Ok(_) => {
            print_success(&format!(
                "Exported {} hashes to {} (JtR format)",
                entries.len(),
                path
            ));
        }
        Err(e) => {
            print_error(&format!("Failed to write to {}: {}", path, e));
        }
    }

    Ok(())
}

/// Display loot statistics
pub async fn stats(cli: &CliState) -> Result<()> {
    use crate::theme::Theme;
    use console::style;

    // Fetch all loot entries
    let entries = cli.client.list_loot(None).await?;

    if entries.is_empty() {
        print_info("No loot entries in database");
        return Ok(());
    }

    // Compute statistics
    let stats = cred_export::compute_stats(&entries);

    if Theme::is_interactive() {
        println!("\n{}", style("LOOT STATISTICS").fg(crate::theme::colors::LAVENDER).bold());
        println!("{} {}", style("Total entries:").fg(crate::theme::colors::TEAL), stats.total);

        println!("\n{}", style("BY TYPE").fg(crate::theme::colors::LAVENDER).bold());
        let mut types: Vec<_> = stats.by_type.iter().collect();
        types.sort_by_key(|(k, _)| *k);
        for (type_name, count) in types {
            println!("  {}: {}", style(type_name).fg(crate::theme::colors::TEXT), count);
        }

        if !stats.by_hash_type.is_empty() {
            println!("\n{}", style("BY HASH TYPE").fg(crate::theme::colors::LAVENDER).bold());
            let mut hash_types: Vec<_> = stats.by_hash_type.iter().collect();
            hash_types.sort_by_key(|(k, _)| *k);
            for (hash_type, count) in hash_types {
                println!("  {}: {}", style(hash_type).fg(crate::theme::colors::TEXT), count);
            }
        }
        println!();
    } else {
        println!("\nLOOT STATISTICS");
        println!("Total entries: {}", stats.total);

        println!("\nBY TYPE");
        let mut types: Vec<_> = stats.by_type.iter().collect();
        types.sort_by_key(|(k, _)| *k);
        for (type_name, count) in types {
            println!("  {}: {}", type_name, count);
        }

        if !stats.by_hash_type.is_empty() {
            println!("\nBY HASH TYPE");
            let mut hash_types: Vec<_> = stats.by_hash_type.iter().collect();
            hash_types.sort_by_key(|(k, _)| *k);
            for (hash_type, count) in hash_types {
                println!("  {}: {}", hash_type, count);
            }
        }
        println!();
    }

    Ok(())
}

/// Format a Unix timestamp to HH:MM:SS
fn format_timestamp(ts: i64) -> String {
    if ts == 0 {
        return "N/A".to_string();
    }

    if let Some(dt) = DateTime::<Utc>::from_timestamp(ts, 0) {
        dt.format("%H:%M:%S").to_string()
    } else {
        "invalid".to_string()
    }
}
