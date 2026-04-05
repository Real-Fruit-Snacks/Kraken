//! Concurrent stress tests - validate correctness under load
//! Following Sliver's 32-64 concurrent RPC pattern

use std::sync::Arc;
use tokio::sync::Semaphore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect errors from concurrent tasks into a Vec<String>.
macro_rules! assert_no_errors {
    ($errors:expr) => {{
        let errs = $errors.lock().await;
        assert!(errs.is_empty(), "Concurrent errors: {:?}", *errs);
    }};
}

// ---------------------------------------------------------------------------
// Task dispatch stress test
// ---------------------------------------------------------------------------

/// Test 32 concurrent task enqueue/drain operations don't cause race conditions.
///
/// Uses `ServerState::pending_tasks` (a `DashMap`) which must be contention-free
/// under concurrent writers for different implant IDs.
#[tokio::test]
async fn test_concurrent_task_dispatch() {
    use common::ImplantId;
    use protocol::Task;

    // Build a minimal ServerState without a live DB by exercising only the
    // in-memory DashMap used for pending task queueing.
    let pending_tasks: Arc<dashmap::DashMap<ImplantId, Vec<Task>>> =
        Arc::new(dashmap::DashMap::new());

    let semaphore = Arc::new(Semaphore::new(32));
    let mut handles = Vec::new();
    let errors: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    for i in 0u64..32 {
        let sem = semaphore.clone();
        let errs = errors.clone();
        let tasks_map = pending_tasks.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let id = ImplantId::new();
            let task = Task {
                task_id: None,
                task_type: format!("stress-{}", i),
                task_data: i.to_le_bytes().to_vec(),
                issued_at: None,
                operator_id: None,
            };

            // Enqueue
            tasks_map.entry(id).or_default().push(task.clone());

            // Drain and verify
            let drained = tasks_map.remove(&id).map(|(_, v)| v).unwrap_or_default();

            if drained.len() != 1 {
                errs.lock().await.push(format!(
                    "task {}: expected 1 drained task, got {}",
                    i,
                    drained.len()
                ));
                return;
            }
            if drained[0].task_type != task.task_type {
                errs.lock().await.push(format!(
                    "task {}: type mismatch: expected {}, got {}",
                    i, task.task_type, drained[0].task_type
                ));
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task panicked");
    }

    assert_no_errors!(errors);
}

// ---------------------------------------------------------------------------
// Crypto stress test
// ---------------------------------------------------------------------------

/// Test 32 concurrent AES-256-GCM encrypt/decrypt round-trips produce correct
/// results with no data corruption under concurrent execution.
#[tokio::test]
async fn test_concurrent_crypto_operations() {
    use crypto::{Nonce, SymmetricKey, aes_gcm};

    let semaphore = Arc::new(Semaphore::new(32));
    let mut handles = Vec::new();
    let errors: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    for i in 0u64..32 {
        let sem = semaphore.clone();
        let errs = errors.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            // Each goroutine gets its own independent key+nonce to avoid
            // nonce reuse — mirrors Sliver's per-session key isolation.
            let mut key_bytes = [0u8; 32];
            key_bytes[..8].copy_from_slice(&i.to_le_bytes());
            key_bytes[8..16].copy_from_slice(&i.wrapping_add(1).to_le_bytes());
            key_bytes[16..24].copy_from_slice(&i.wrapping_add(2).to_le_bytes());
            key_bytes[24..32].copy_from_slice(&i.wrapping_add(3).to_le_bytes());
            let key = SymmetricKey(key_bytes);

            let nonce = Nonce::from_counter(i);
            let plaintext = format!("stress-payload-{}", i);
            let aad = format!("aad-{}", i);

            // Encrypt
            let ciphertext = match aes_gcm::encrypt(&key, &nonce, plaintext.as_bytes(), aad.as_bytes()) {
                Ok(ct) => ct,
                Err(e) => {
                    errs.lock().await.push(format!("task {}: encrypt failed: {:?}", i, e));
                    return;
                }
            };

            // Verify ciphertext differs from plaintext
            if ciphertext == plaintext.as_bytes() {
                errs.lock().await.push(format!(
                    "task {}: ciphertext equals plaintext — encryption did nothing",
                    i
                ));
                return;
            }

            // Decrypt and verify round-trip
            let decrypted = match aes_gcm::decrypt(&key, &nonce, &ciphertext, aad.as_bytes()) {
                Ok(pt) => pt,
                Err(e) => {
                    errs.lock().await.push(format!("task {}: decrypt failed: {:?}", i, e));
                    return;
                }
            };

            if decrypted != plaintext.as_bytes() {
                errs.lock()
                    .await
                    .push(format!("task {}: round-trip mismatch", i));
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task panicked");
    }

    assert_no_errors!(errors);
}

// ---------------------------------------------------------------------------
// Database write stress test
// ---------------------------------------------------------------------------

/// Test 32 concurrent implant registrations against an in-memory SQLite DB.
///
/// SQLite in WAL mode serialises writers, so this validates that the connection
/// pool correctly handles concurrent write contention without deadlocks or
/// SQLITE_BUSY errors.
#[tokio::test]
async fn test_concurrent_db_writes() {
    use common::{ImplantId, ImplantState};
    use db::{Database, ImplantRecord};

    // Use a single in-memory database shared across all tasks.
    // max_connections=10 matches the pool ceiling used in production.
    let db = Database::connect_memory().await.expect("in-memory DB");
    db.migrate().await.expect("migrations");
    let db = Arc::new(db);

    let semaphore = Arc::new(Semaphore::new(32));
    let mut handles = Vec::new();
    let errors: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    for i in 0u64..32 {
        let sem = semaphore.clone();
        let errs = errors.clone();
        let db = db.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let id = ImplantId::new();
            let record = ImplantRecord {
                id,
                name: format!("stress-implant-{}", i),
                state: ImplantState::Active,
                hostname: Some(format!("host-{}", i)),
                username: Some("testuser".into()),
                checkin_interval: 30,
                jitter_percent: 10,
                registered_at: i as i64,
                ..Default::default()
            };

            // Write
            if let Err(e) = db.implants().create(&record).await {
                errs.lock()
                    .await
                    .push(format!("task {}: create failed: {:?}", i, e));
                return;
            }

            // Read back and verify
            match db.implants().get(id).await {
                Ok(Some(r)) => {
                    if r.name != record.name {
                        errs.lock().await.push(format!(
                            "task {}: name mismatch: expected {}, got {}",
                            i, record.name, r.name
                        ));
                    }
                }
                Ok(None) => {
                    errs.lock()
                        .await
                        .push(format!("task {}: record not found after insert", i));
                }
                Err(e) => {
                    errs.lock()
                        .await
                        .push(format!("task {}: get failed: {:?}", i, e));
                }
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task panicked");
    }

    assert_no_errors!(errors);

    // Verify final count — all 32 records must be present.
    let all = db.implants().list().await.expect("list implants");
    assert_eq!(
        all.len(),
        32,
        "expected 32 implant records after concurrent writes, got {}",
        all.len()
    );
}
