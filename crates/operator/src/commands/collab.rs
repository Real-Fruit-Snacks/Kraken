//! Collaboration commands for multi-operator coordination

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// List online operators
pub async fn online(cli: &CliState) -> Result<()> {
    print_info("Fetching online operators...");

    match cli.client.get_online_operators().await {
        Ok(operators) => {
            if operators.is_empty() {
                print_info("No operators online");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            // Headers
            if Theme::is_interactive() {
                table.set_header(vec![
                    Cell::new("Username").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Active Session").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Last Activity").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                ]);
            } else {
                table.set_header(vec!["Username", "Active Session", "Last Activity"]);
            }

            // Rows
            for op in &operators {
                let active_session = if let Some(ref session_id) = op.active_session {
                    if session_id.value.len() >= 4 {
                        hex::encode(&session_id.value[..4])
                    } else {
                        hex::encode(&session_id.value)
                    }
                } else {
                    "-".to_string()
                };

                let last_activity = if let Some(ref ts) = op.last_activity {
                    DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                table.add_row(vec![
                    op.username.clone(),
                    active_session,
                    last_activity,
                ]);
            }

            println!("{}", table);
            print_info(&format!("{} operator(s) online", operators.len()));
        }
        Err(e) => {
            print_error(&format!("Failed to fetch online operators: {}", e));
        }
    }

    Ok(())
}

/// Lock a session
pub async fn lock(cli: &CliState, session_id: String, reason: Option<String>) -> Result<()> {
    // Decode session ID
    let session_bytes = hex::decode(&session_id).unwrap_or_else(|_| session_id.as_bytes().to_vec());

    print_info(&format!("Locking session {}...", session_id));

    match cli.client.lock_session(session_bytes, reason).await {
        Ok(lock) => {
            print_success(&format!("Session {} locked", session_id));
            if let Some(ref reason_str) = lock.reason {
                print_info(&format!("Reason: {}", reason_str));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to lock session: {}", e));
        }
    }

    Ok(())
}

/// Unlock a session
pub async fn unlock(cli: &CliState, session_id: String) -> Result<()> {
    // Decode session ID
    let session_bytes = hex::decode(&session_id).unwrap_or_else(|_| session_id.as_bytes().to_vec());

    print_info(&format!("Unlocking session {}...", session_id));

    match cli.client.unlock_session(session_bytes).await {
        Ok(_) => {
            print_success(&format!("Session {} unlocked", session_id));
        }
        Err(e) => {
            print_error(&format!("Failed to unlock session: {}", e));
        }
    }

    Ok(())
}

/// List session locks
pub async fn locks(cli: &CliState) -> Result<()> {
    print_info("Fetching session locks...");

    match cli.client.get_session_locks().await {
        Ok(locks) => {
            if locks.is_empty() {
                print_info("No locked sessions");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            // Headers
            if Theme::is_interactive() {
                table.set_header(vec![
                    Cell::new("Session ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Locked By").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Locked At").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Reason").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                ]);
            } else {
                table.set_header(vec!["Session ID", "Locked By", "Locked At", "Reason"]);
            }

            // Rows
            for lock in &locks {
                let session_short = if let Some(ref id) = lock.session_id {
                    if id.value.len() >= 4 {
                        hex::encode(&id.value[..4])
                    } else {
                        hex::encode(&id.value)
                    }
                } else {
                    "unknown".to_string()
                };

                let locked_at = if let Some(ref ts) = lock.locked_at {
                    DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                let reason = lock.reason.clone().unwrap_or_else(|| "-".to_string());

                table.add_row(vec![
                    session_short,
                    lock.username.clone(),
                    locked_at,
                    reason,
                ]);
            }

            println!("{}", table);
            print_info(&format!("{} locked session(s)", locks.len()));
        }
        Err(e) => {
            print_error(&format!("Failed to fetch session locks: {}", e));
        }
    }

    Ok(())
}

/// Send chat message
pub async fn chat(cli: &CliState, message: String, session_id: Option<String>) -> Result<()> {
    let session_bytes = session_id.as_ref().map(|id| {
        hex::decode(id).unwrap_or_else(|_| id.as_bytes().to_vec())
    });

    match cli.client.send_chat(message.clone(), session_bytes).await {
        Ok(_) => {
            print_success("Message sent");
        }
        Err(e) => {
            print_error(&format!("Failed to send message: {}", e));
        }
    }

    Ok(())
}

/// Get chat history
pub async fn history(cli: &CliState, session_id: Option<String>, limit: u32) -> Result<()> {
    let session_bytes = session_id.as_ref().map(|id| {
        hex::decode(id).unwrap_or_else(|_| id.as_bytes().to_vec())
    });

    print_info("Fetching chat history...");

    match cli.client.get_chat_history(session_bytes, limit).await {
        Ok(response) => {
            if response.messages.is_empty() {
                print_info("No messages");
                return Ok(());
            }

            for msg in &response.messages {
                let timestamp = if let Some(ref ts) = msg.created_at {
                    DateTime::<Utc>::from_timestamp_millis(ts.millis)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_else(|| "??:??:??".to_string())
                } else {
                    "??:??:??".to_string()
                };

                if Theme::is_interactive() {
                    println!(
                        "[{}] {}: {}",
                        console::style(timestamp).fg(crate::theme::colors::SUBTEXT0),
                        console::style(&msg.from_username).fg(crate::theme::colors::LAVENDER).bold(),
                        msg.message
                    );
                } else {
                    println!("[{}] {}: {}", timestamp, msg.from_username, msg.message);
                }
            }

            print_info(&format!("{} message(s)", response.messages.len()));
            if response.has_more {
                print_info("More messages available (use higher limit or pagination)");
            }
        }
        Err(e) => {
            print_error(&format!("Failed to fetch chat history: {}", e));
        }
    }

    Ok(())
}

/// Get collaboration statistics
pub async fn stats(cli: &CliState) -> Result<()> {
    print_info("Fetching collaboration statistics...");

    match cli.client.get_collab_stats().await {
        Ok(stats) => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            if Theme::is_interactive() {
                table.add_row(vec![
                    Cell::new("Online Operators").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(stats.online_operators.to_string()),
                ]);
                table.add_row(vec![
                    Cell::new("Active Sessions").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(stats.active_sessions.to_string()),
                ]);
                table.add_row(vec![
                    Cell::new("Locked Sessions").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new(stats.locked_sessions.to_string()),
                ]);
            } else {
                table.add_row(vec!["Online Operators", &stats.online_operators.to_string()]);
                table.add_row(vec!["Active Sessions", &stats.active_sessions.to_string()]);
                table.add_row(vec!["Locked Sessions", &stats.locked_sessions.to_string()]);
            }

            println!("\n{}", table);
        }
        Err(e) => {
            print_error(&format!("Failed to fetch statistics: {}", e));
        }
    }

    Ok(())
}
