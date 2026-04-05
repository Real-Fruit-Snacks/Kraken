//! Kraken operator CLI

use anyhow::Result;
use clap::Parser;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::{Config, Editor};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

mod cli;
mod client;
mod commands;
mod cred_export;
mod display;
mod file_browser;
mod history;
mod process_tree;
mod theme;

use cli::{CliState, KrakenHelper};
use display::{print_banner, print_error, print_info, print_success};

#[derive(Parser)]
#[command(name = "kraken-operator")]
#[command(about = "Kraken C2 Operator Console", long_about = None)]
struct Args {
    /// Teamserver address
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    server: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Use Vi editing mode instead of Emacs
    #[arg(long)]
    vi: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging to file
    setup_logging(&args.log_level)?;

    // Print banner
    print_banner();

    // Connect to teamserver
    print_info(&format!("Connecting to teamserver at {}", args.server));

    let cli = match CliState::new(&args.server).await {
        Ok(c) => {
            print_success("Connected to teamserver");
            c
        }
        Err(e) => {
            print_error(&format!("Failed to connect: {}", e));
            print_info("The operator will still start, but commands will fail until server is available");

            // For now, we'll exit on connection failure
            // In production, we could allow offline mode
            return Err(e);
        }
    };

    // Run REPL
    run_repl(cli, args.vi).await?;

    Ok(())
}

/// Setup file-based logging
fn setup_logging(log_level: &str) -> Result<()> {
    // Create logs directory
    let log_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kraken")
        .join("logs");

    std::fs::create_dir_all(&log_dir)?;

    let file_appender = tracing_appender::rolling::daily(log_dir, "operator.log");

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(file_appender)
        .with_ansi(false)
        .init();

    Ok(())
}

/// Run the interactive REPL
async fn run_repl(mut cli: CliState, vi_mode: bool) -> Result<()> {
    // Setup rustyline configuration
    let config = Config::builder()
        .auto_add_history(true)
        .history_ignore_space(true)
        .build();

    let helper = KrakenHelper::new();
    let mut editor = Editor::with_config(config)?;
    editor.set_helper(Some(helper));

    // Set editing mode
    if vi_mode {
        editor.set_edit_mode(rustyline::EditMode::Vi);
    }

    // REPL loop
    loop {
        let prompt = cli.prompt();

        match editor.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Parse and dispatch command
                let cmd = commands::parse(line);
                match commands::dispatch(cmd, &mut cli).await {
                    Ok(true) => {
                        // Exit requested
                        print_info("Goodbye");
                        break;
                    }
                    Ok(false) => {
                        // Command executed successfully - add to history
                        if let Err(e) = cli.history.add(line) {
                            tracing::warn!("Failed to save command to history: {}", e);
                        }

                        // Update tab completion data after commands that might change session list
                        if line.starts_with("sessions") || line.starts_with("use") {
                            if let Some(helper) = editor.helper() {
                                helper.update_from_cli(&cli);
                            }
                        }
                    }
                    Err(e) => {
                        print_error(&format!("Error: {}", e));
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C pressed
                print_info("Use 'exit' to quit");
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D pressed
                print_info("Goodbye");
                break;
            }
            Err(e) => {
                print_error(&format!("Input error: {}", e));
                break;
            }
        }
    }

    Ok(())
}
