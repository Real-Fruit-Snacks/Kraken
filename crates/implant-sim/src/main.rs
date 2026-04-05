//! Simulated implant binary for testing C2 infrastructure
//!
//! Usage:
//!   implant-sim --server http://localhost:8080 [--server-pub-key <hex>]

use anyhow::{anyhow, Result};
use clap::Parser;
use crypto::X25519PublicKey;
use implant_sim::SimulatedImplant;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Simulated implant for testing Kraken C2 infrastructure
#[derive(Parser, Debug)]
#[command(name = "implant-sim")]
#[command(about = "Simulated implant for local C2 testing")]
struct Args {
    /// C2 server URL
    #[arg(long, default_value = "http://localhost:8080")]
    server: String,

    /// Server's static X25519 public key (hex-encoded, 64 chars)
    /// If not provided, uses a test key (NOT FOR PRODUCTION)
    #[arg(long)]
    server_pub_key: Option<String>,

    /// Check-in interval in seconds (overrides default)
    #[arg(long)]
    interval: Option<u32>,

    /// Jitter percentage (0-100)
    #[arg(long)]
    jitter: Option<u32>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Run once (register + single check-in) then exit
    #[arg(long)]
    once: bool,
}

fn parse_log_level(s: &str) -> Level {
    match s.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

fn parse_server_pub_key(hex_key: Option<String>) -> Result<X25519PublicKey> {
    match hex_key {
        Some(hex) => {
            let bytes = hex::decode(hex)
                .map_err(|e| anyhow!("invalid hex for server public key: {}", e))?;
            X25519PublicKey::from_bytes(&bytes)
                .map_err(|e| anyhow!("invalid server public key: {}", e))
        }
        None => {
            // Generate a test key for development
            // WARNING: This is insecure and only for testing!
            info!("WARNING: Using generated test key - NOT FOR PRODUCTION");
            let (pub_key, _priv_key) = crypto::x25519::generate_keypair()
                .map_err(|e| anyhow!("failed to generate test keypair: {}", e))?;
            Ok(pub_key)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = parse_log_level(&args.log_level);
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    info!("implant-sim starting");
    info!("server: {}", args.server);

    // Parse server public key
    let server_pub_key = parse_server_pub_key(args.server_pub_key)?;

    // Create simulated implant
    let mut config = config::ImplantConfig::default();
    if let Some(interval) = args.interval {
        config.checkin_interval = interval;
    }
    if let Some(jitter) = args.jitter {
        config.jitter_percent = jitter;
    }

    let mut implant = SimulatedImplant::with_config(args.server.clone(), server_pub_key, config);

    if args.once {
        // Single registration + check-in for testing
        info!("running in single-shot mode");

        match implant.register().await {
            Ok(()) => {
                info!(
                    "registration successful, implant_id: {:?}",
                    implant.implant_id()
                );
            }
            Err(e) => {
                error!("registration failed: {}", e);
                return Err(e);
            }
        }

        match implant.checkin().await {
            Ok(tasks) => {
                info!("check-in successful, received {} tasks", tasks.len());
                for task in &tasks {
                    let task_id = task
                        .task_id
                        .as_ref()
                        .map(|u| hex::encode(&u.value))
                        .unwrap_or_else(|| "unknown".to_string());
                    info!("  task: {} (type: {})", task_id, task.task_type);
                }
            }
            Err(e) => {
                error!("check-in failed: {}", e);
                return Err(e);
            }
        }

        info!("single-shot mode complete");
    } else {
        // Run the main loop
        info!(
            "entering main loop (interval={}s, jitter={}%)",
            implant.checkin_interval(),
            config::ImplantConfig::default().jitter_percent
        );

        if let Err(e) = implant.run().await {
            error!("implant error: {}", e);
            return Err(e);
        }
    }

    info!("implant-sim shutting down");
    Ok(())
}
