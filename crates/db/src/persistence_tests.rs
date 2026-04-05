//! Persistence and recovery tests
//!
//! Tests for data persistence across restarts, crash recovery,
//! transaction atomicity, and migration idempotency.

use crate::{Database, ImplantRecord, NewOperator, TaskRecord};
use common::{ImplantId, ImplantState, OperatorId, TaskId};
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a unique temp directory for each test
fn temp_db_path(suffix: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join(format!("test-{}.db", suffix));
    (dir, path)
}

/// Create a test implant record
fn make_implant(id: ImplantId) -> ImplantRecord {
    let now = chrono::Utc::now().timestamp_millis();
    ImplantRecord {
        id,
        name: format!("persist-test-{}", id),
        state: ImplantState::Active,
        hostname: Some("persist-host".to_string()),
        username: Some("persist-user".to_string()),
        domain: None,
        os_name: Some("Linux".to_string()),
        os_version: Some("Test".to_string()),
        os_arch: Some("x86_64".to_string()),
        process_id: Some(9999),
        process_name: Some("test".to_string()),
        process_path: Some("/test/path".to_string()),
        is_elevated: false,
        integrity_level: None,
        local_ips: vec!["192.168.1.100".to_string()],
        checkin_interval: 60,
        jitter_percent: 15,
        symmetric_key: Some(vec![1, 2, 3, 4, 5]),
        nonce_counter: 42,
        registered_at: now,
        last_seen: Some(now),
    }
}

// ---------------------------------------------------------------------------
// Persistence Tests
// ---------------------------------------------------------------------------

/// 1. Data survives database close and reopen
#[tokio::test]
async fn test_data_survives_restart() {
    let (_dir, db_path) = temp_db_path("survive-restart");

    let implant_id = ImplantId::new();
    let operator_id: uuid::Uuid;

    // Phase 1: Create data and close
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        // Create implant
        let record = make_implant(implant_id);
        db.implants().create(&record).await.unwrap();

        // Create operator
        let op = NewOperator {
            username: "persist-op".to_string(),
            role: kraken_rbac::Role::Admin,
            cert_fingerprint: "persist-fp".to_string(),
        };
        let op_record = db.operators().create(op).await.unwrap();
        operator_id = op_record.id;

        // Database goes out of scope and closes
    }

    // Phase 2: Reopen and verify data
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();

        // Implant should exist
        let implant = db.implants().get(implant_id).await.unwrap();
        assert!(implant.is_some(), "implant should persist after restart");
        let implant = implant.unwrap();
        assert_eq!(implant.name, format!("persist-test-{}", implant_id));
        assert_eq!(implant.hostname, Some("persist-host".to_string()));

        // Operator should exist
        let op = db.operators().get(operator_id).await.unwrap();
        assert!(op.is_some(), "operator should persist after restart");
        let op = op.unwrap();
        assert_eq!(op.username, "persist-op");
    }
}

/// 2. Multiple restarts don't corrupt data
#[tokio::test]
async fn test_multiple_restarts_stable() {
    let (_dir, db_path) = temp_db_path("multiple-restarts");

    let implant_ids: Vec<ImplantId> = (0..5).map(|_| ImplantId::new()).collect();

    // Create initial data
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        for id in &implant_ids {
            db.implants().create(&make_implant(*id)).await.unwrap();
        }
    }

    // Multiple restart cycles
    for cycle in 0..5 {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();

        // Verify all implants still exist
        for id in &implant_ids {
            let implant = db.implants().get(*id).await.unwrap();
            assert!(
                implant.is_some(),
                "implant {} should exist after cycle {}",
                id,
                cycle
            );
        }

        // Add one more implant each cycle
        let new_id = ImplantId::new();
        db.implants().create(&make_implant(new_id)).await.unwrap();
    }

    // Final verification
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        let all = db.implants().list().await.unwrap();
        assert_eq!(
            all.len(),
            10,
            "should have 5 original + 5 added implants"
        );
    }
}

/// 3. Migration is idempotent
#[tokio::test]
async fn test_migration_idempotent() {
    let (_dir, db_path) = temp_db_path("migration-idempotent");

    let implant_id = ImplantId::new();

    // Initial setup with migration
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        db.implants().create(&make_implant(implant_id)).await.unwrap();
    }

    // Run migration multiple times
    for i in 0..5 {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();

        // Migration should succeed even when already applied
        let result = db.migrate().await;
        assert!(
            result.is_ok(),
            "migration {} should succeed: {:?}",
            i,
            result.err()
        );

        // Data should still be intact
        let implant = db.implants().get(implant_id).await.unwrap();
        assert!(implant.is_some(), "data should survive migration {}", i);
    }
}

/// 4. Symmetric key persistence
#[tokio::test]
async fn test_symmetric_key_persists() {
    let (_dir, db_path) = temp_db_path("symmetric-key");

    let implant_id = ImplantId::new();
    let symmetric_key = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    // Store implant with symmetric key
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        let mut record = make_implant(implant_id);
        record.symmetric_key = Some(symmetric_key.clone());
        record.nonce_counter = 12345;
        db.implants().create(&record).await.unwrap();
    }

    // Verify key persists
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        let implant = db.implants().get(implant_id).await.unwrap().unwrap();

        assert_eq!(
            implant.symmetric_key,
            Some(symmetric_key),
            "symmetric key should persist"
        );
        assert_eq!(implant.nonce_counter, 12345, "nonce counter should persist");
    }
}

/// 5. Task data persists correctly
#[tokio::test]
async fn test_task_data_persists() {
    let (_dir, db_path) = temp_db_path("task-persist");

    let implant_id = ImplantId::new();
    let task_id = TaskId::new();
    let task_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let mut operator_id = OperatorId::new();

    // Create task
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        db.implants().create(&make_implant(implant_id)).await.unwrap();

        // Create operator for task - use the returned operator ID
        let op = NewOperator {
            username: "task-op".to_string(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "task-fp".to_string(),
        };
        let op_record = db.operators().create(op).await.unwrap();
        operator_id = OperatorId::from(op_record.id);

        // Create task
        let now = chrono::Utc::now().timestamp_millis();
        let task = TaskRecord {
            id: task_id,
            implant_id,
            operator_id,
            task_type: "shell".to_string(),
            task_data: task_data.clone(),
            status: "queued".to_string(),
            issued_at: now,
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        };
        db.tasks().create(&task).await.unwrap();
    }

    // Verify task persists
    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        let task = db.tasks().get(task_id).await.unwrap().unwrap();

        assert_eq!(task.task_type, "shell");
        assert_eq!(task.task_data, task_data);
        assert_eq!(task.implant_id, implant_id);
        assert_eq!(task.operator_id, operator_id);
    }
}

/// 6. Large binary data persists
#[tokio::test]
async fn test_large_binary_data_persists() {
    let (_dir, db_path) = temp_db_path("large-binary");

    let implant_id = ImplantId::new();
    // 1MB of binary data
    let large_data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        let mut record = make_implant(implant_id);
        record.symmetric_key = Some(large_data.clone());
        db.implants().create(&record).await.unwrap();
    }

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        let implant = db.implants().get(implant_id).await.unwrap().unwrap();

        let stored_data = implant.symmetric_key.unwrap();
        assert_eq!(stored_data.len(), large_data.len());
        assert_eq!(stored_data, large_data, "large binary data should match");
    }
}

/// 7. Unicode data persists correctly
#[tokio::test]
async fn test_unicode_data_persists() {
    let (_dir, db_path) = temp_db_path("unicode");

    let implant_id = ImplantId::new();
    let unicode_hostname = "测试主机-тест-🔥";
    let unicode_username = "用户名-пользователь-😀";

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        let mut record = make_implant(implant_id);
        record.hostname = Some(unicode_hostname.to_string());
        record.username = Some(unicode_username.to_string());
        db.implants().create(&record).await.unwrap();
    }

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        let implant = db.implants().get(implant_id).await.unwrap().unwrap();

        assert_eq!(implant.hostname, Some(unicode_hostname.to_string()));
        assert_eq!(implant.username, Some(unicode_username.to_string()));
    }
}

/// 8. State updates persist
#[tokio::test]
async fn test_state_updates_persist() {
    let (_dir, db_path) = temp_db_path("state-updates");

    let implant_id = ImplantId::new();

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        let record = make_implant(implant_id);
        db.implants().create(&record).await.unwrap();

        // Update state
        db.implants()
            .update_state(implant_id, ImplantState::Lost)
            .await
            .unwrap();
    }

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        let implant = db.implants().get(implant_id).await.unwrap().unwrap();

        assert_eq!(
            implant.state,
            ImplantState::Lost,
            "state update should persist"
        );
    }
}

/// 9. Operator updates persist
#[tokio::test]
async fn test_operator_updates_persist() {
    let (_dir, db_path) = temp_db_path("operator-updates");

    let operator_id: uuid::Uuid;

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        let op = NewOperator {
            username: "update-op".to_string(),
            role: kraken_rbac::Role::Viewer,
            cert_fingerprint: "update-fp".to_string(),
        };
        let op_record = db.operators().create(op).await.unwrap();
        operator_id = op_record.id;

        // Touch the operator
        db.operators().touch(operator_id).await.unwrap();
    }

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        let op = db.operators().get(operator_id).await.unwrap().unwrap();

        assert!(op.last_seen.is_some(), "touch should persist");
    }
}

/// 10. Concurrent writes are safe
#[tokio::test]
async fn test_concurrent_writes_safe() {
    let (_dir, db_path) = temp_db_path("concurrent-writes");

    {
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
    }

    let db_path_str = db_path.to_str().unwrap().to_string();
    let mut handles = vec![];

    // Spawn multiple concurrent writers
    for i in 0..10 {
        let path = db_path_str.clone();
        handles.push(tokio::spawn(async move {
            let db = Database::connect(&path).await.unwrap();
            let implant_id = ImplantId::new();
            let mut record = make_implant(implant_id);
            record.name = format!("concurrent-{}", i);
            db.implants().create(&record).await.unwrap();
            implant_id
        }));
    }

    let mut created_ids = vec![];
    for handle in handles {
        created_ids.push(handle.await.unwrap());
    }

    // Verify all writes succeeded
    let db = Database::connect(&db_path_str).await.unwrap();
    for id in created_ids {
        let implant = db.implants().get(id).await.unwrap();
        assert!(implant.is_some(), "concurrent write for {} should succeed", id);
    }
}
