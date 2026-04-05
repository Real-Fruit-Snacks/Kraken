//! Database layer

pub mod models;
pub mod repos;

use common::KrakenError;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::path::Path;

pub use models::*;
pub use repos::*;

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, KrakenError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| KrakenError::Database(format!("create dir: {}", e)))?;
            }
        }
        let url = format!("sqlite:{}?mode=rwc", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .map_err(|e| KrakenError::Database(format!("connect: {}", e)))?;
        Ok(Self { pool })
    }

    pub async fn connect_memory() -> Result<Self, KrakenError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| KrakenError::Database(format!("memory: {}", e)))?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), KrakenError> {
        let migration_001 = include_str!("../../../migrations/001_initial.sql");
        sqlx::raw_sql(migration_001)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("migrate 001: {}", e)))?;
        let migration_003 = include_str!("../../../migrations/003_modules.sql");
        sqlx::raw_sql(migration_003)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("migrate 003: {}", e)))?;
        let migration_004 = include_str!("../../../migrations/004_operator_rbac.sql");
        sqlx::raw_sql(migration_004)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("migrate 004: {}", e)))?;
        let migration_005 = include_str!("../../../migrations/005_chat.sql");
        sqlx::raw_sql(migration_005)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("migrate 005: {}", e)))?;
        let migration_006 = include_str!("../../../migrations/006_file_transfers.sql");
        sqlx::raw_sql(migration_006)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("migrate 006: {}", e)))?;
        let migration_007 = include_str!("../../../migrations/007_session_tags.sql");
        sqlx::raw_sql(migration_007)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("migrate 007: {}", e)))?;
        tracing::info!("migrations complete");
        Ok(())
    }

    pub fn implants(&self) -> ImplantRepo {
        ImplantRepo::new(self.pool.clone())
    }
    pub fn tasks(&self) -> TaskRepo {
        TaskRepo::new(self.pool.clone())
    }
    pub fn listeners(&self) -> ListenerRepo {
        ListenerRepo::new(self.pool.clone())
    }
    pub fn audit(&self) -> AuditRepo {
        AuditRepo::new(self.pool.clone())
    }
    pub fn config(&self) -> ConfigRepo {
        ConfigRepo::new(self.pool.clone())
    }
    pub fn loot(&self) -> LootRepo {
        LootRepo::new(self.pool.clone())
    }
    pub fn modules(&self) -> ModulesRepo {
        ModulesRepo::new(self.pool.clone())
    }
    pub fn operators(&self) -> OperatorRepo {
        OperatorRepo::new(self.pool.clone())
    }
    pub fn chat(&self) -> ChatRepo {
        ChatRepo::new(self.pool.clone())
    }
    pub fn jobs(&self) -> JobRepo {
        JobRepo::new(self.pool.clone())
    }
    pub fn file_transfers(&self) -> FileTransferRepo {
        FileTransferRepo::new(self.pool.clone())
    }
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
mod persistence_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use common::{ImplantId, ImplantState, ListenerId, OperatorId, TaskId};

    /// Helper to create a test database
    async fn test_db() -> Database {
        let db = Database::connect_memory().await.expect("connect");
        db.migrate().await.expect("migrate");
        db
    }

    // ─── Database Connection Tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_connect_memory() {
        let db = Database::connect_memory().await;
        assert!(db.is_ok());
    }

    #[tokio::test]
    async fn test_connect_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let db = Database::connect(&path).await;
        assert!(db.is_ok());
        assert!(path.exists());
    }

    #[tokio::test]
    async fn test_connect_creates_parent_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("path").join("test.db");
        let db = Database::connect(&path).await;
        assert!(db.is_ok());
        assert!(path.exists());
    }

    #[tokio::test]
    async fn test_migrate_succeeds() {
        let db = Database::connect_memory().await.expect("connect");
        let result = db.migrate().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_migrate_idempotent() {
        let db = Database::connect_memory().await.expect("connect");
        db.migrate().await.expect("first migrate");
        // Second migrate should also succeed (IF NOT EXISTS)
        let result = db.migrate().await;
        assert!(result.is_ok());
    }

    // ─── ImplantRepo Tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_implant_create_and_get() {
        let db = test_db().await;
        let id = ImplantId::new();
        let record = ImplantRecord {
            id,
            name: "test-implant".to_string(),
            state: ImplantState::Active,
            hostname: Some("workstation".to_string()),
            username: Some("admin".to_string()),
            domain: Some("CORP".to_string()),
            os_name: Some("Windows".to_string()),
            os_version: Some("10.0.19041".to_string()),
            os_arch: Some("x86_64".to_string()),
            process_id: Some(1234),
            process_name: Some("explorer.exe".to_string()),
            process_path: Some("C:\\Windows\\explorer.exe".to_string()),
            is_elevated: true,
            integrity_level: Some("High".to_string()),
            local_ips: vec!["192.168.1.100".to_string()],
            checkin_interval: 60,
            jitter_percent: 10,
            symmetric_key: Some(vec![1, 2, 3, 4]),
            nonce_counter: 0,
            registered_at: chrono::Utc::now().timestamp_millis(),
            last_seen: Some(chrono::Utc::now().timestamp_millis()),
        };

        db.implants().create(&record).await.expect("create");

        let fetched = db.implants().get(id).await.expect("get");
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.name, "test-implant");
        assert_eq!(fetched.hostname, Some("workstation".to_string()));
    }

    #[tokio::test]
    async fn test_implant_list() {
        let db = test_db().await;

        // Create multiple implants
        for i in 0..5 {
            let record = ImplantRecord {
                id: ImplantId::new(),
                name: format!("implant-{}", i),
                state: ImplantState::Active,
                registered_at: chrono::Utc::now().timestamp_millis(),
                ..Default::default()
            };
            db.implants().create(&record).await.expect("create");
        }

        let list = db.implants().list().await.expect("list");
        assert_eq!(list.len(), 5);
    }

    #[tokio::test]
    async fn test_implant_update_last_seen() {
        let db = test_db().await;
        let id = ImplantId::new();
        let old_time = chrono::Utc::now().timestamp_millis() - 10000;
        let record = ImplantRecord {
            id,
            name: "test".to_string(),
            state: ImplantState::Active,
            registered_at: old_time,
            last_seen: Some(old_time),
            ..Default::default()
        };
        db.implants().create(&record).await.expect("create");

        db.implants().update_last_seen(id).await.expect("update");

        let fetched = db.implants().get(id).await.expect("get").unwrap();
        assert!(fetched.last_seen.unwrap() > old_time);
    }

    #[tokio::test]
    async fn test_implant_get_nonexistent() {
        let db = test_db().await;
        let result = db.implants().get(ImplantId::new()).await.expect("get");
        assert!(result.is_none());
    }

    // ─── TaskRepo Tests ──────────────────────────────────────────────────────

    /// Helper to create test operator
    async fn create_test_operator(db: &Database) -> uuid::Uuid {
        let new_op = NewOperator {
            username: format!("testop-{}", uuid::Uuid::new_v4()),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: format!("fp-{}", uuid::Uuid::new_v4()),
        };
        db.operators().create(new_op).await.expect("create operator").id
    }

    #[tokio::test]
    async fn test_task_create_and_get() {
        let db = test_db().await;

        // Create operator first (foreign key)
        let operator_id = create_test_operator(&db).await;

        // Create implant (foreign key)
        let implant_id = ImplantId::new();
        let implant = ImplantRecord {
            id: implant_id,
            name: "test".to_string(),
            state: ImplantState::Active,
            registered_at: chrono::Utc::now().timestamp_millis(),
            ..Default::default()
        };
        db.implants().create(&implant).await.expect("create implant");

        let task_id = TaskId::new();
        let task = TaskRecord {
            id: task_id,
            implant_id,
            operator_id: OperatorId::from(operator_id),
            task_type: "shell".to_string(),
            task_data: b"whoami".to_vec(),
            status: "pending".to_string(),
            issued_at: chrono::Utc::now().timestamp_millis(),
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        };

        db.tasks().create(&task).await.expect("create task");

        let fetched = db.tasks().get(task_id).await.expect("get");
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.task_type, "shell");
    }

    #[tokio::test]
    async fn test_task_list_pending_for_implant() {
        let db = test_db().await;

        // Create operator first
        let operator_id = create_test_operator(&db).await;

        let implant_id = ImplantId::new();
        let implant = ImplantRecord {
            id: implant_id,
            name: "test".to_string(),
            state: ImplantState::Active,
            registered_at: chrono::Utc::now().timestamp_millis(),
            ..Default::default()
        };
        db.implants().create(&implant).await.expect("create implant");

        // Create 3 queued tasks (list_pending looks for status='queued')
        for i in 0..3 {
            let task = TaskRecord {
                id: TaskId::new(),
                implant_id,
                operator_id: OperatorId::from(operator_id),
                task_type: format!("task-{}", i),
                task_data: vec![],
                status: "queued".to_string(),
                issued_at: chrono::Utc::now().timestamp_millis(),
                dispatched_at: None,
                completed_at: None,
                result_data: None,
                error_message: None,
            };
            db.tasks().create(&task).await.expect("create");
        }

        let queued = db.tasks().list_pending(implant_id).await.expect("list");
        assert_eq!(queued.len(), 3);
    }

    // ─── ListenerRepo Tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_listener_create_and_list() {
        let db = test_db().await;
        let id = ListenerId::new();
        let record = ListenerRecord {
            id,
            listener_type: "http".to_string(),
            bind_host: "0.0.0.0".to_string(),
            bind_port: 8080,
            is_running: true,
            created_at: chrono::Utc::now().timestamp_millis(),
        };

        db.listeners().create(&record).await.expect("create");

        let list = db.listeners().list().await.expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].listener_type, "http");
        assert_eq!(list[0].bind_port, 8080);
    }

    #[tokio::test]
    async fn test_listener_list_multiple() {
        let db = test_db().await;

        for port in [8080, 8443, 53] {
            let record = ListenerRecord {
                id: ListenerId::new(),
                listener_type: "http".to_string(),
                bind_host: "0.0.0.0".to_string(),
                bind_port: port,
                is_running: true,
                created_at: chrono::Utc::now().timestamp_millis(),
            };
            db.listeners().create(&record).await.expect("create");
        }

        let list = db.listeners().list().await.expect("list");
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_listener_update_running() {
        let db = test_db().await;
        let id = ListenerId::new();
        let record = ListenerRecord {
            id,
            listener_type: "http".to_string(),
            bind_host: "0.0.0.0".to_string(),
            bind_port: 8080,
            is_running: true,
            created_at: chrono::Utc::now().timestamp_millis(),
        };

        db.listeners().create(&record).await.expect("create");
        db.listeners().update_running(id, false).await.expect("update");

        let list = db.listeners().list().await.expect("list");
        assert!(!list[0].is_running);
    }

    // ─── AuditRepo Tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_audit_log() {
        let db = test_db().await;

        let entry = AuditEntry::new("test_action");
        let result = db.audit().log(&entry).await;
        assert!(result.is_ok());
        // Returns row id
        assert!(result.unwrap() > 0);
    }

    // ─── OperatorRepo Tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_operator_create_and_get() {
        let db = test_db().await;

        let new_op = NewOperator {
            username: "admin".to_string(),
            role: kraken_rbac::Role::Admin,
            cert_fingerprint: "abc123".to_string(),
        };

        let created = db.operators().create(new_op).await.expect("create");

        let fetched = db.operators().get(created.id).await.expect("get");
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.username, "admin");
        assert_eq!(fetched.role, "admin");
    }

    #[tokio::test]
    async fn test_operator_get_by_username() {
        let db = test_db().await;

        let new_op = NewOperator {
            username: "testuser".to_string(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "xyz789".to_string(),
        };

        db.operators().create(new_op).await.expect("create");

        let fetched = db.operators().get_by_username("testuser").await.expect("get");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_operator_list() {
        let db = test_db().await;

        for i in 0..3 {
            let new_op = NewOperator {
                username: format!("user{}", i),
                role: kraken_rbac::Role::Operator,
                cert_fingerprint: format!("fp{}", i),
            };
            db.operators().create(new_op).await.expect("create");
        }

        let list = db.operators().list().await.expect("list");
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_operator_touch_last_seen() {
        let db = test_db().await;

        let new_op = NewOperator {
            username: "lastseen_test".to_string(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "fp".to_string(),
        };

        let created = db.operators().create(new_op).await.expect("create");
        db.operators().touch(created.id).await.expect("touch");

        let fetched = db.operators().get(created.id).await.expect("get").unwrap();
        assert!(fetched.last_seen.is_some());
    }

    // ─── Concurrent Access Tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_concurrent_implant_creation() {
        let db = test_db().await;

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let db = db.clone();
                tokio::spawn(async move {
                    let record = ImplantRecord {
                        id: ImplantId::new(),
                        name: format!("concurrent-{}", i),
                        state: ImplantState::Active,
                        registered_at: chrono::Utc::now().timestamp_millis(),
                        ..Default::default()
                    };
                    db.implants().create(&record).await
                })
            })
            .collect();

        for handle in handles {
            handle.await.expect("join").expect("create");
        }

        let list = db.implants().list().await.expect("list");
        assert_eq!(list.len(), 10);
    }

    #[tokio::test]
    async fn test_concurrent_task_updates() {
        let db = test_db().await;

        // Create operator first
        let operator_id = create_test_operator(&db).await;

        let implant_id = ImplantId::new();
        let implant = ImplantRecord {
            id: implant_id,
            name: "concurrent-test".to_string(),
            state: ImplantState::Active,
            registered_at: chrono::Utc::now().timestamp_millis(),
            ..Default::default()
        };
        db.implants().create(&implant).await.expect("create implant");

        // Create tasks with 'queued' status
        let task_ids: Vec<_> = (0..10)
            .map(|i| {
                let id = TaskId::new();
                let task = TaskRecord {
                    id,
                    implant_id,
                    operator_id: OperatorId::from(operator_id),
                    task_type: format!("task-{}", i),
                    task_data: vec![],
                    status: "queued".to_string(),
                    issued_at: chrono::Utc::now().timestamp_millis(),
                    dispatched_at: None,
                    completed_at: None,
                    result_data: None,
                    error_message: None,
                };
                (id, task)
            })
            .collect();

        for (_, task) in &task_ids {
            db.tasks().create(task).await.expect("create");
        }

        // Mark all tasks as dispatched
        let ids: Vec<TaskId> = task_ids.iter().map(|(id, _)| *id).collect();
        db.tasks().mark_dispatched(&ids).await.expect("mark dispatched");

        // Verify tasks were dispatched
        let pending = db.tasks().list_pending(implant_id).await.expect("list pending");
        assert_eq!(pending.len(), 0); // All should be dispatched now
    }

    // ─── Error Handling Tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_duplicate_implant_id_fails() {
        let db = test_db().await;
        let id = ImplantId::new();

        let record = ImplantRecord {
            id,
            name: "first".to_string(),
            state: ImplantState::Active,
            registered_at: chrono::Utc::now().timestamp_millis(),
            ..Default::default()
        };

        db.implants().create(&record).await.expect("first create");

        let record2 = ImplantRecord {
            id, // Same ID
            name: "second".to_string(),
            state: ImplantState::Active,
            registered_at: chrono::Utc::now().timestamp_millis(),
            ..Default::default()
        };

        let result = db.implants().create(&record2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_duplicate_operator_username_fails() {
        let db = test_db().await;

        let new_op = NewOperator {
            username: "duplicate".to_string(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "fp1".to_string(),
        };
        db.operators().create(new_op).await.expect("first create");

        let new_op2 = NewOperator {
            username: "duplicate".to_string(), // Same username
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "fp2".to_string(),
        };
        let result = db.operators().create(new_op2).await;
        assert!(result.is_err());
    }
}
