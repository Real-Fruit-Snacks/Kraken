//! Background service that detects lost implants and emits lifecycle events.
//!
//! Every `CHECK_INTERVAL` seconds the checker queries for implants whose
//! `last_seen` timestamp is older than 3 × their configured `checkin_interval`.
//! Implants that cross that threshold transition to `Lost`; implants that were
//! `Lost` and have since checked in are transitioned back to `Active` (recovery
//! is handled in the HTTP check-in handler — see `http/handler.rs`).

use std::sync::Arc;
use std::time::Duration;

use common::ImplantState;
use protocol::{implant_event::Event as EventVariant, ImplantEvent, ImplantLostEvent, Timestamp};

use crate::state::ServerState;

/// How often the health-checker wakes up and scans the database.
const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Spawn the health-checker as a background Tokio task.
///
/// The task runs until the `ServerState` is dropped (i.e. the server shuts
/// down).  The returned `JoinHandle` can be ignored — the task is
/// self-contained.
pub fn spawn(state: Arc<ServerState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(state).await;
    })
}

async fn run(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    // The first tick fires immediately; skip it so we don't run a check before
    // the server has finished starting up.
    interval.tick().await;

    loop {
        interval.tick().await;
        if let Err(e) = check_once(&state).await {
            tracing::warn!(error = %e, "health-checker: error during stale-implant scan");
        }
    }
}

/// Single scan pass — marks stale Active/Staging implants as Lost.
async fn check_once(state: &ServerState) -> Result<(), String> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    let stale = state
        .db
        .implants()
        .find_stale_implants(now_ms)
        .await
        .map_err(|e| format!("db query failed: {e}"))?;

    for record in stale {
        // Only transition implants that are currently Active or Staging.
        // Lost implants are already in the right state; terminal implants
        // cannot transition (the query excludes them, but be defensive).
        if !matches!(record.state, ImplantState::Active | ImplantState::Staging) {
            continue;
        }

        tracing::info!(
            implant_id = %record.id,
            name = %record.name,
            state = %record.state,
            last_seen_ms = ?record.last_seen,
            "implant missed 3 consecutive check-ins — marking Lost"
        );

        state
            .db
            .implants()
            .update_state(record.id, ImplantState::Lost)
            .await
            .map_err(|e| format!("failed to mark implant {} as Lost: {e}", record.id))?;

        // Expire all queued/dispatched tasks for the lost implant
        match state.db.tasks().expire_tasks_for_implant(record.id).await {
            Ok(count) if count > 0 => {
                tracing::info!(
                    implant_id = %record.id,
                    expired_tasks = count,
                    "expired tasks for lost implant"
                );
            }
            Err(e) => {
                tracing::warn!(
                    implant_id = %record.id,
                    error = %e,
                    "failed to expire tasks for lost implant"
                );
            }
            _ => {}
        }

        state.publish_event(ImplantEvent {
            timestamp: Some(Timestamp::now()),
            event: Some(EventVariant::Lost(ImplantLostEvent {
                implant_id: Some(record.id.into()),
            })),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::{ImplantId, ImplantState};
    use db::ImplantRecord;

    /// Helper: create an in-memory database and run migrations.
    async fn make_db() -> db::Database {
        let db = db::Database::connect(":memory:").await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    /// Insert a minimal implant record with the given state, checkin_interval,
    /// and last_seen timestamp.
    async fn insert_implant(
        db: &db::Database,
        state: ImplantState,
        checkin_interval_secs: i32,
        last_seen_ms: Option<i64>,
    ) -> ImplantId {
        let id = ImplantId::new();
        let now = chrono::Utc::now().timestamp_millis();
        db.implants()
            .create(&ImplantRecord {
                id,
                name: format!("test-{}", id),
                state,
                hostname: None,
                username: None,
                domain: None,
                os_name: None,
                os_version: None,
                os_arch: None,
                process_id: None,
                process_name: None,
                process_path: None,
                is_elevated: false,
                integrity_level: None,
                local_ips: vec![],
                checkin_interval: checkin_interval_secs,
                jitter_percent: 0,
                symmetric_key: None,
                nonce_counter: -1,
                registered_at: now,
                last_seen: last_seen_ms,
            })
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn stale_active_implant_is_marked_lost_and_event_emitted() {
        let db = make_db().await;
        let crypto = crypto::ServerCrypto::new(
            crypto::ServerCrypto::generate_master_key().unwrap(),
        );
        let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
        let ms = std::sync::Arc::new(
            module_store::ModuleStore::new(std::sync::Arc::new(db.clone()), &signing_key).unwrap(),
        );
        let audit_key = b"test-audit-key-health-checker!";
        let jwt = crate::auth::jwt::JwtManager::from_env_or_master_key(&[0u8; 32]).unwrap();
        let state = ServerState::new(db, crypto, ms, audit_key.to_vec(), jwt);
        let mut event_rx = state.subscribe_events();

        // checkin_interval = 60 s  →  stale threshold = 180 000 ms
        // Set last_seen 200 s ago so the implant is definitely stale.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let last_seen = now_ms - 200_000; // 200 s ago
        let id = insert_implant(&state.db, ImplantState::Active, 60, Some(last_seen)).await;

        check_once(&state).await.expect("check_once failed");

        // State in DB should now be Lost
        let record = state.db.implants().get(id).await.unwrap().unwrap();
        assert_eq!(record.state, ImplantState::Lost, "implant should be Lost");

        // An ImplantLostEvent should have been published
        let event = event_rx.try_recv().expect("expected an event on the channel");
        match event.event {
            Some(EventVariant::Lost(lost_event)) => {
                let event_id = common::ImplantId::from_bytes(
                    &lost_event.implant_id.unwrap().value,
                )
                .unwrap();
                assert_eq!(event_id, id);
            }
            other => panic!("expected Lost event, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fresh_active_implant_is_not_marked_lost() {
        let db = make_db().await;
        let crypto = crypto::ServerCrypto::new(
            crypto::ServerCrypto::generate_master_key().unwrap(),
        );
        let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
        let ms = std::sync::Arc::new(
            module_store::ModuleStore::new(std::sync::Arc::new(db.clone()), &signing_key).unwrap(),
        );
        let audit_key = b"test-audit-key-health-checker!";
        let jwt = crate::auth::jwt::JwtManager::from_env_or_master_key(&[0u8; 32]).unwrap();
        let state = ServerState::new(db, crypto, ms, audit_key.to_vec(), jwt);

        // last_seen = 30 s ago, threshold = 180 s  →  not stale
        let now_ms = chrono::Utc::now().timestamp_millis();
        let last_seen = now_ms - 30_000;
        let id = insert_implant(&state.db, ImplantState::Active, 60, Some(last_seen)).await;

        check_once(&state).await.expect("check_once failed");

        let record = state.db.implants().get(id).await.unwrap().unwrap();
        assert_eq!(record.state, ImplantState::Active, "implant should remain Active");
    }

    #[tokio::test]
    async fn already_lost_implant_is_not_double_processed() {
        let db = make_db().await;
        let crypto = crypto::ServerCrypto::new(
            crypto::ServerCrypto::generate_master_key().unwrap(),
        );
        let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
        let ms = std::sync::Arc::new(
            module_store::ModuleStore::new(std::sync::Arc::new(db.clone()), &signing_key).unwrap(),
        );
        let audit_key = b"test-audit-key-health-checker!";
        let jwt = crate::auth::jwt::JwtManager::from_env_or_master_key(&[0u8; 32]).unwrap();
        let state = ServerState::new(db, crypto, ms, audit_key.to_vec(), jwt);
        let mut event_rx = state.subscribe_events();

        // Insert an implant that is already Lost and stale
        let now_ms = chrono::Utc::now().timestamp_millis();
        let last_seen = now_ms - 500_000;
        let id = insert_implant(&state.db, ImplantState::Lost, 60, Some(last_seen)).await;

        check_once(&state).await.expect("check_once failed");

        // State should still be Lost, no new event
        let record = state.db.implants().get(id).await.unwrap().unwrap();
        assert_eq!(record.state, ImplantState::Lost, "implant should stay Lost");
        assert!(
            event_rx.try_recv().is_err(),
            "no event should be emitted for already-Lost implant"
        );
    }
}
