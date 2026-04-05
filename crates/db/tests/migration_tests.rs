//! Migration, concurrency, connection pool, data integrity, and WAL mode tests.
//!
//! These tests live in `tests/` so they compile as an integration test crate
//! with access to the public API of the `db` crate only.

use db::{
    AuditEntry, Database, ImplantRecord, NewOperator, TaskRecord,
};
use db::loot::LootRow;
use common::{ImplantId, ImplantState, OperatorId, TaskId};
use std::path::PathBuf;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn temp_db(suffix: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(format!("{}.db", suffix));
    (dir, path)
}

async fn open_migrated(path: &PathBuf) -> Database {
    let db = Database::connect(path.to_str().unwrap())
        .await
        .expect("connect");
    db.migrate().await.expect("migrate");
    db
}

async fn mem_db() -> Database {
    let db = Database::connect_memory().await.expect("connect_memory");
    db.migrate().await.expect("migrate");
    db
}

fn make_implant(id: ImplantId) -> ImplantRecord {
    ImplantRecord {
        id,
        name: format!("test-{}", id),
        state: ImplantState::Active,
        registered_at: chrono::Utc::now().timestamp_millis(),
        ..Default::default()
    }
}

async fn create_operator(db: &Database) -> uuid::Uuid {
    let op = NewOperator {
        username: format!("op-{}", uuid::Uuid::new_v4()),
        role: kraken_rbac::Role::Operator,
        cert_fingerprint: format!("fp-{}", uuid::Uuid::new_v4()),
    };
    db.operators().create(op).await.expect("create operator").id
}

fn loot_id(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

fn make_loot(id: Vec<u8>, implant_id_bytes: &[u8], loot_type: &str) -> LootRow {
    LootRow {
        id,
        implant_id: implant_id_bytes.to_vec(),
        task_id: None,
        loot_type: loot_type.to_string(),
        captured_at: chrono::Utc::now().timestamp_millis(),
        source: Some("migration-test".to_string()),
        username: None,
        password: None,
        domain: None,
        host: None,
        port: None,
        protocol: None,
        hash_type: None,
        hash_value: None,
        token_type: None,
        token_data: None,
        expires_at: None,
        principal: None,
        service: None,
        filename: None,
        original_path: None,
        file_size: None,
        file_hash: None,
        blob_path: None,
    }
}

/// Insert a raw implant row using pool() so loot FK constraints are satisfied
/// without going through ImplantRepo (which uses typed UUIDs).
async fn insert_raw_implant(db: &Database, id_bytes: &[u8]) {
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO implants (id, name, state, checkin_interval, jitter_percent, \
         key_nonce_counter, registered_at) \
         VALUES (?, 'loot-implant', 'active', 60, 20, 0, ?)",
    )
    .bind(id_bytes)
    .bind(now)
    .execute(db.pool())
    .await
    .expect("insert raw implant");
}

// ===========================================================================
// 1. Schema Tests
// ===========================================================================

/// Verify every expected table exists after migration.
#[tokio::test]
async fn schema_all_tables_exist() {
    let db = mem_db().await;
    let pool = db.pool();

    let expected_tables = [
        "operators",
        "implants",
        "implant_state_history",
        "listeners",
        "profiles",
        "tasks",
        "task_chunks",
        "audit_log",
        "server_config",
        "loot",
        "modules",
        "module_latest",
        "operator_allowed_sessions",
        "operator_allowed_listeners",
        "chat_messages",
    ];

    for table in &expected_tables {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
        )
        .bind(*table)
        .fetch_one(pool)
        .await
        .expect("query sqlite_master");
        assert_eq!(row.0, 1, "table '{}' should exist after migration", table);
    }
}

/// Verify expected indexes exist.
#[tokio::test]
async fn schema_indexes_exist() {
    let db = mem_db().await;
    let pool = db.pool();

    let expected_indexes = [
        "idx_implants_state",
        "idx_implants_last_seen",
        "idx_implants_name",
        "idx_tasks_implant",
        "idx_tasks_status",
        "idx_tasks_issued",
        "idx_audit_log_time",
        "idx_audit_log_action",
        "idx_loot_implant",
        "idx_loot_type",
        "idx_loot_captured",
        "idx_chat_messages_created",
        "idx_oas_operator",
        "idx_oas_session",
    ];

    for idx in &expected_indexes {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?",
        )
        .bind(*idx)
        .fetch_one(pool)
        .await
        .expect("query sqlite_master for index");
        assert_eq!(row.0, 1, "index '{}' should exist after migration", idx);
    }
}

/// Verify foreign key constraints are defined in the schema.
/// We check that the FK-carrying tables list the expected parent tables
/// via PRAGMA foreign_key_list.
#[tokio::test]
async fn schema_foreign_keys_defined() {
    let db = mem_db().await;
    let pool = db.pool();

    // (child_table, expected_parent_table)
    let fk_pairs = [
        ("implant_state_history", "implants"),
        ("tasks", "implants"),
        ("tasks", "operators"),
        ("loot", "implants"),
        ("task_chunks", "tasks"),
        ("operator_allowed_sessions", "operators"),
        ("operator_allowed_sessions", "implants"),
        ("operator_allowed_listeners", "operators"),
        ("operator_allowed_listeners", "listeners"),
        ("chat_messages", "operators"),
    ];

    for (child, parent) in &fk_pairs {
        // PRAGMA foreign_key_list returns one row per FK column; `table` column is the parent.
        let rows: Vec<(i64, i64, String)> =
            sqlx::query_as(&format!("PRAGMA foreign_key_list({})", child))
                .fetch_all(pool)
                .await
                .expect("pragma fk list");

        let has_fk = rows.iter().any(|(_, _, tbl)| tbl == *parent);
        assert!(
            has_fk,
            "table '{}' should have FK referencing '{}'",
            child, parent
        );
    }
}

/// Verify views are created.
#[tokio::test]
async fn schema_views_exist() {
    let db = mem_db().await;
    let pool = db.pool();

    for view in &["active_implants", "recent_tasks"] {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name=?",
        )
        .bind(*view)
        .fetch_one(pool)
        .await
        .expect("query views");
        assert_eq!(row.0, 1, "view '{}' should exist", view);
    }
}

// ===========================================================================
// 2. Concurrency Tests
// ===========================================================================

/// Ten tasks register sessions (implants) concurrently — all should succeed,
/// no duplicates, no corruption.
#[tokio::test]
async fn concurrency_session_registration_10_parallel() {
    let (_dir, path) = temp_db("conc-sessions");
    open_migrated(&path).await; // create schema once

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let p = path.clone();
            tokio::spawn(async move {
                let db = Database::connect(p.to_str().unwrap())
                    .await
                    .expect("connect");
                let id = ImplantId::new();
                let record = ImplantRecord {
                    id,
                    name: format!("sess-{}", i),
                    state: ImplantState::Active,
                    registered_at: chrono::Utc::now().timestamp_millis(),
                    ..Default::default()
                };
                db.implants().create(&record).await.expect("create implant");
                id
            })
        })
        .collect();

    let mut ids = Vec::new();
    for h in handles {
        ids.push(h.await.expect("join"));
    }

    let db = Database::connect(path.to_str().unwrap())
        .await
        .expect("connect verify");
    let all = db.implants().list().await.expect("list");
    assert_eq!(all.len(), 10, "all 10 concurrent session registrations should persist");

    // No duplicate IDs
    let mut seen = std::collections::HashSet::new();
    for r in &all {
        assert!(seen.insert(r.id), "duplicate implant id found: {}", r.id);
    }
}

/// Ten tasks create tasks concurrently against a shared DB connection pool.
#[tokio::test]
async fn concurrency_task_creation_10_parallel() {
    let (_dir, path) = temp_db("conc-tasks");
    let db = open_migrated(&path).await;

    let op_id = create_operator(&db).await;
    let implant_id = ImplantId::new();
    db.implants()
        .create(&make_implant(implant_id))
        .await
        .expect("implant");

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let db2 = db.clone();
            tokio::spawn(async move {
                let task = TaskRecord {
                    id: TaskId::new(),
                    implant_id,
                    operator_id: OperatorId::from(op_id),
                    task_type: format!("cmd-{}", i),
                    task_data: vec![i as u8; 8],
                    status: "queued".to_string(),
                    issued_at: chrono::Utc::now().timestamp_millis(),
                    dispatched_at: None,
                    completed_at: None,
                    result_data: None,
                    error_message: None,
                };
                db2.tasks().create(&task).await.expect("create task");
            })
        })
        .collect();

    for h in handles {
        h.await.expect("join");
    }

    let pending = db.tasks().list_pending(implant_id).await.expect("list");
    assert_eq!(pending.len(), 10, "all 10 concurrent tasks should be present");
}

/// Ten tasks store loot concurrently.
#[tokio::test]
async fn concurrency_loot_storage_10_parallel() {
    let (_dir, path) = temp_db("conc-loot");
    let db = open_migrated(&path).await;

    // Use a raw implant bytes ID (LootRepo uses Vec<u8>)
    let implant_bytes: Vec<u8> = vec![0xCC; 16];
    insert_raw_implant(&db, &implant_bytes).await;

    let handles: Vec<_> = (0..10u8)
        .map(|i| {
            let db2 = db.clone();
            let iid = implant_bytes.clone();
            tokio::spawn(async move {
                let mut row = make_loot(vec![i; 16], &iid, "credential");
                row.username = Some(format!("user-{}", i));
                db2.loot().insert(&row).await.expect("insert loot");
            })
        })
        .collect();

    for h in handles {
        h.await.expect("join");
    }

    let count = db.loot().count(None).await.expect("count");
    assert_eq!(count, 10, "all 10 concurrent loot inserts should be present");
}

/// Concurrent readers and a writer — readers should always see a consistent
/// view; no panics or errors.
#[tokio::test]
async fn concurrency_read_write_contention() {
    let (_dir, path) = temp_db("conc-rw");
    let db = open_migrated(&path).await;

    // Pre-populate 5 implants
    for _ in 0..5 {
        db.implants()
            .create(&make_implant(ImplantId::new()))
            .await
            .expect("seed implant");
    }

    // Spawn 5 readers + 5 writers concurrently
    let mut handles = Vec::new();

    for _ in 0..5 {
        let db2 = db.clone();
        handles.push(tokio::spawn(async move {
            let list = db2.implants().list().await.expect("list in reader");
            assert!(list.len() >= 5, "reader should see at least the seeded implants");
        }));
    }

    for i in 0..5u32 {
        let db2 = db.clone();
        handles.push(tokio::spawn(async move {
            let record = ImplantRecord {
                id: ImplantId::new(),
                name: format!("rw-writer-{}", i),
                state: ImplantState::Active,
                registered_at: chrono::Utc::now().timestamp_millis(),
                ..Default::default()
            };
            db2.implants().create(&record).await.expect("write in writer");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    let final_count = db.implants().list().await.expect("final list").len();
    assert_eq!(final_count, 10, "5 seed + 5 written = 10 implants");
}

/// Transaction isolation: a completed task update should not affect other tasks.
#[tokio::test]
async fn concurrency_transaction_isolation() {
    let db = mem_db().await;

    let op_id = create_operator(&db).await;
    let implant_id = ImplantId::new();
    db.implants()
        .create(&make_implant(implant_id))
        .await
        .expect("implant");

    let task_ids: Vec<TaskId> = (0..5)
        .map(|_| TaskId::new())
        .collect();

    for &tid in &task_ids {
        let task = TaskRecord {
            id: tid,
            implant_id,
            operator_id: OperatorId::from(op_id),
            task_type: "shell".to_string(),
            task_data: vec![],
            status: "queued".to_string(),
            issued_at: chrono::Utc::now().timestamp_millis(),
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        };
        db.tasks().create(&task).await.expect("create task");
    }

    // Complete only the first task
    db.tasks()
        .update_result(task_ids[0], "completed", Some(b"ok"), None)
        .await
        .expect("update_result");

    // The other 4 tasks should still be queued
    let pending = db.tasks().list_pending(implant_id).await.expect("list");
    assert_eq!(
        pending.len(),
        4,
        "only the targeted task should be updated; others remain queued"
    );

    // The completed task should not appear in pending
    let completed_id = task_ids[0];
    assert!(
        !pending.iter().any(|t| t.id == completed_id),
        "completed task must not appear in pending list"
    );
}

// ===========================================================================
// 3. Connection Pool Tests
// ===========================================================================

/// Pool exhaustion: open many connections and verify operations still succeed
/// (SQLite will queue/wait, not error immediately for reads on separate file connections).
#[tokio::test]
async fn pool_exhaustion_behavior() {
    let (_dir, path) = temp_db("pool-exhaust");
    open_migrated(&path).await;

    // Open many connections concurrently - SQLite should handle this gracefully
    let handles: Vec<_> = (0..20)
        .map(|_| {
            let p = path.clone();
            tokio::spawn(async move {
                let db = Database::connect(p.to_str().unwrap())
                    .await
                    .expect("connect");
                // Just do a read operation
                let list = db.implants().list().await.expect("list");
                list.len()
            })
        })
        .collect();

    for h in handles {
        let count = h.await.expect("join");
        assert_eq!(count, 0, "empty DB should return empty list");
    }
}

/// Connection reuse: the pool reuses connections across sequential operations.
/// Verifies data is consistent across operations on the same pool.
#[tokio::test]
async fn pool_connection_reuse() {
    let db = mem_db().await;

    // Perform sequential writes and reads using the same pool
    for i in 0..5 {
        let id = ImplantId::new();
        db.implants()
            .create(&ImplantRecord {
                id,
                name: format!("reuse-{}", i),
                state: ImplantState::Active,
                registered_at: chrono::Utc::now().timestamp_millis(),
                ..Default::default()
            })
            .await
            .expect("create");

        // Immediately read back — should be visible on the same pool
        let fetched = db.implants().get(id).await.expect("get");
        assert!(fetched.is_some(), "write {} should be visible on next read", i);
    }

    let all = db.implants().list().await.expect("list");
    assert_eq!(all.len(), 5);
}

/// Connection timeout / busy: file DB with concurrent writers — verify no
/// permanent hangs (SQLite busy_timeout should allow retries).
#[tokio::test]
async fn pool_no_permanent_deadlock() {
    let (_dir, path) = temp_db("pool-timeout");
    let db = open_migrated(&path).await;

    // Saturate the pool with concurrent writes — should complete without hanging
    let handles: Vec<_> = (0..15)
        .map(|_| {
            let db2 = db.clone();
            tokio::spawn(async move {
                db2.audit()
                    .log(&AuditEntry::new("pool-test"))
                    .await
                    .expect("log audit")
            })
        })
        .collect();

    let mut total = 0i64;
    for h in handles {
        total += h.await.expect("join");
    }

    // All 15 should have gotten row IDs > 0
    assert!(total > 0);
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(db.pool())
        .await
        .expect("count");
    assert_eq!(count.0, 15, "all 15 audit entries should be committed");
}

// ===========================================================================
// 4. Data Integrity Tests
// ===========================================================================

/// Store and retrieve a 2 MB blob to verify SQLite handles large BLOBs correctly.
#[tokio::test]
async fn integrity_large_blob_storage_and_retrieval() {
    let db = mem_db().await;

    let implant_id = ImplantId::new();
    let blob: Vec<u8> = (0u32..2 * 1024 * 1024)
        .map(|i| (i % 251) as u8) // prime modulus for non-trivial pattern
        .collect();

    db.implants()
        .create(&ImplantRecord {
            id: implant_id,
            name: "blob-test".to_string(),
            state: ImplantState::Active,
            symmetric_key: Some(blob.clone()),
            registered_at: chrono::Utc::now().timestamp_millis(),
            ..Default::default()
        })
        .await
        .expect("create with large blob");

    let fetched = db
        .implants()
        .get(implant_id)
        .await
        .expect("get")
        .expect("some");

    let stored = fetched.symmetric_key.expect("blob should be present");
    assert_eq!(stored.len(), blob.len(), "blob length must match");
    assert_eq!(stored, blob, "blob contents must be bit-for-bit identical");
}

/// Verify multi-language and emoji UTF-8 strings round-trip without corruption.
#[tokio::test]
async fn integrity_utf8_text_handling() {
    let db = mem_db().await;

    let test_cases = [
        ("Arabic", "مرحبا", "مستخدم"),
        ("Chinese", "你好世界", "用户名"),
        ("Japanese", "こんにちは", "ユーザー"),
        ("Emoji", "🦑🔥💻", "🤖👾"),
        ("Mixed", "Ünïcödé-тест-测试", "αβγδ"),
        ("RTL+LTR", "שלום world مرحبا", "user"),
        ("Null-like-chars", "line1\nline2\ttab", "user\u{0}nul"),
    ];

    for (label, hostname, username) in &test_cases {
        let id = ImplantId::new();
        db.implants()
            .create(&ImplantRecord {
                id,
                name: format!("utf8-{}", label),
                state: ImplantState::Active,
                hostname: Some(hostname.to_string()),
                username: Some(username.to_string()),
                registered_at: chrono::Utc::now().timestamp_millis(),
                ..Default::default()
            })
            .await
            .unwrap_or_else(|e| panic!("create {} failed: {}", label, e));

        let fetched = db.implants().get(id).await.expect("get").expect("some");
        assert_eq!(
            fetched.hostname.as_deref(),
            Some(*hostname),
            "{}: hostname mismatch",
            label
        );
        assert_eq!(
            fetched.username.as_deref(),
            Some(*username),
            "{}: username mismatch",
            label
        );
    }
}

/// Verify that optional/nullable fields are stored and retrieved as None correctly.
#[tokio::test]
async fn integrity_null_value_handling() {
    let db = mem_db().await;

    let id = ImplantId::new();
    // Create with all optional fields as None
    db.implants()
        .create(&ImplantRecord {
            id,
            name: "null-test".to_string(),
            state: ImplantState::Active,
            registered_at: chrono::Utc::now().timestamp_millis(),
            hostname: None,
            username: None,
            domain: None,
            os_name: None,
            os_version: None,
            os_arch: None,
            process_id: None,
            process_name: None,
            process_path: None,
            integrity_level: None,
            symmetric_key: None,
            last_seen: None,
            ..Default::default()
        })
        .await
        .expect("create with nulls");

    let fetched = db.implants().get(id).await.expect("get").expect("some");
    assert!(fetched.hostname.is_none(), "hostname should be None");
    assert!(fetched.username.is_none(), "username should be None");
    assert!(fetched.domain.is_none(), "domain should be None");
    assert!(fetched.os_name.is_none(), "os_name should be None");
    assert!(fetched.symmetric_key.is_none(), "symmetric_key should be None");
    assert!(fetched.last_seen.is_none(), "last_seen should be None");
}

/// Foreign key cascade delete: deleting an implant cascades to tasks and loot.
#[tokio::test]
async fn integrity_foreign_key_cascade_on_delete() {
    let (_dir, path) = temp_db("fk-cascade");
    // Must enable FK enforcement at runtime for SQLite
    let db = open_migrated(&path).await;

    // Enable FK constraints (SQLite requires explicit PRAGMA per connection)
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(db.pool())
        .await
        .expect("enable fk");

    let op_id = create_operator(&db).await;
    let implant_id = ImplantId::new();
    db.implants()
        .create(&make_implant(implant_id))
        .await
        .expect("implant");

    // Create a task referencing the implant
    let task_id = TaskId::new();
    db.tasks()
        .create(&TaskRecord {
            id: task_id,
            implant_id,
            operator_id: OperatorId::from(op_id),
            task_type: "shell".to_string(),
            task_data: b"whoami".to_vec(),
            status: "queued".to_string(),
            issued_at: chrono::Utc::now().timestamp_millis(),
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        })
        .await
        .expect("task");

    // Create loot referencing the implant (raw bytes for LootRepo)
    let implant_bytes = implant_id.as_bytes().to_vec();
    let loot_id_bytes = loot_id(0x77);
    db.loot()
        .insert(&make_loot(loot_id_bytes.clone(), &implant_bytes, "credential"))
        .await
        .expect("loot");

    // Verify task and loot exist
    assert!(db.tasks().get(task_id).await.expect("get task").is_some());
    assert!(db.loot().get(&loot_id_bytes).await.expect("get loot").is_some());

    // Delete the implant
    sqlx::query("DELETE FROM implants WHERE id = ?")
        .bind(implant_id.as_bytes().as_slice())
        .execute(db.pool())
        .await
        .expect("delete implant");

    // Task and loot should cascade-delete
    let task_after = db.tasks().get(task_id).await.expect("get task after");
    assert!(task_after.is_none(), "task should cascade-delete with implant");

    let loot_after = db.loot().get(&loot_id_bytes).await.expect("get loot after");
    assert!(loot_after.is_none(), "loot should cascade-delete with implant");
}

/// Task chunks cascade-delete when their parent task is deleted.
#[tokio::test]
async fn integrity_task_chunk_cascade_on_delete() {
    let (_dir, path) = temp_db("chunk-cascade");
    let db = open_migrated(&path).await;

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(db.pool())
        .await
        .expect("enable fk");

    let op_id = create_operator(&db).await;
    let implant_id = ImplantId::new();
    db.implants().create(&make_implant(implant_id)).await.expect("implant");

    let task_id = TaskId::new();
    db.tasks()
        .create(&TaskRecord {
            id: task_id,
            implant_id,
            operator_id: OperatorId::from(op_id),
            task_type: "shell".to_string(),
            task_data: vec![],
            status: "queued".to_string(),
            issued_at: chrono::Utc::now().timestamp_millis(),
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        })
        .await
        .expect("task");

    // Insert task chunks directly via SQL (no high-level API)
    let now = chrono::Utc::now().timestamp_millis();
    for seq in 0..3i64 {
        sqlx::query(
            "INSERT INTO task_chunks (task_id, sequence, chunk_data, is_final, received_at) \
             VALUES (?, ?, ?, 0, ?)",
        )
        .bind(task_id.as_bytes().as_slice())
        .bind(seq)
        .bind(vec![seq as u8; 32])
        .bind(now)
        .execute(db.pool())
        .await
        .expect("insert chunk");
    }

    let chunk_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM task_chunks WHERE task_id = ?")
            .bind(task_id.as_bytes().as_slice())
            .fetch_one(db.pool())
            .await
            .expect("count chunks");
    assert_eq!(chunk_count.0, 3);

    // Delete the task
    sqlx::query("DELETE FROM tasks WHERE id = ?")
        .bind(task_id.as_bytes().as_slice())
        .execute(db.pool())
        .await
        .expect("delete task");

    let chunk_after: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM task_chunks WHERE task_id = ?")
            .bind(task_id.as_bytes().as_slice())
            .fetch_one(db.pool())
            .await
            .expect("count chunks after");
    assert_eq!(chunk_after.0, 0, "task chunks should cascade-delete");
}

// ===========================================================================
// 5. WAL Mode Tests
// ===========================================================================

/// Enable WAL mode and verify multiple concurrent readers can read while a
/// writer is active — WAL allows readers not to block.
#[tokio::test]
async fn wal_concurrent_readers_with_single_writer() {
    let (_dir, path) = temp_db("wal-readers");
    let db = open_migrated(&path).await;

    // Enable WAL
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(db.pool())
        .await
        .expect("set WAL");

    // Seed some data
    for _ in 0..5 {
        db.implants()
            .create(&make_implant(ImplantId::new()))
            .await
            .expect("seed");
    }

    // Spawn concurrent readers and one writer
    let mut handles = Vec::new();

    // 8 readers
    for _ in 0..8 {
        let db2 = db.clone();
        handles.push(tokio::spawn(async move {
            let list = db2.implants().list().await.expect("reader list");
            assert!(list.len() >= 5, "reader must see seeded data");
        }));
    }

    // 1 writer
    let db_w = db.clone();
    handles.push(tokio::spawn(async move {
        for _ in 0..3 {
            db_w.implants()
                .create(&make_implant(ImplantId::new()))
                .await
                .expect("writer create");
        }
    }));

    for h in handles {
        h.await.expect("join");
    }

    let final_list = db.implants().list().await.expect("final");
    assert_eq!(final_list.len(), 8, "5 seed + 3 written = 8 implants total");
}

/// Verify WAL checkpoint can be triggered without error.
#[tokio::test]
async fn wal_checkpoint_behavior() {
    let (_dir, path) = temp_db("wal-checkpoint");
    let db = open_migrated(&path).await;

    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(db.pool())
        .await
        .expect("set WAL");

    // Write enough data to populate the WAL
    for _ in 0..20 {
        db.audit()
            .log(&AuditEntry::new("wal-checkpoint-test"))
            .await
            .expect("audit log");
    }

    // Trigger a passive checkpoint — returns (busy, log, checkpointed) pages
    let row: (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(PASSIVE)")
        .fetch_one(db.pool())
        .await
        .expect("wal checkpoint");

    // row.0 == 0 means no error (0=ok, 1=busy, 2=no WAL)
    // We just verify the pragma executed without crashing
    let (status, _log_pages, _ckpt_pages) = row;
    assert!(
        status == 0 || status == 1,
        "wal_checkpoint should return 0 (ok) or 1 (busy), got {}",
        status
    );

    // Data should still be intact after checkpoint
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(db.pool())
        .await
        .expect("count");
    assert_eq!(count.0, 20, "all audit entries should survive checkpoint");
}

/// WAL mode: writes committed by one connection are visible to another.
#[tokio::test]
async fn wal_writer_visibility_across_connections() {
    let (_dir, path) = temp_db("wal-visibility");
    let db1 = open_migrated(&path).await;
    let db2 = Database::connect(path.to_str().unwrap())
        .await
        .expect("second connection");

    // Enable WAL on both
    for db in &[&db1, &db2] {
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(db.pool())
            .await
            .expect("wal");
    }

    let id = ImplantId::new();
    db1.implants()
        .create(&make_implant(id))
        .await
        .expect("write on db1");

    let fetched = db2.implants().get(id).await.expect("read on db2");
    assert!(
        fetched.is_some(),
        "write on db1 should be visible via db2 in WAL mode"
    );
}
