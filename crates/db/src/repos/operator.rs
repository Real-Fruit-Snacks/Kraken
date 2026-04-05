//! Operator repository for RBAC

use crate::models::{NewOperator, OperatorRecord, OperatorUpdate};
use common::KrakenError;
use sqlx::SqlitePool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone)]
pub struct OperatorRepo {
    pool: SqlitePool,
}

impl OperatorRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new operator
    pub async fn create(&self, op: NewOperator) -> Result<OperatorRecord, KrakenError> {
        let id = Uuid::new_v4();
        let id_bytes = id.as_bytes().to_vec();
        let now = chrono::Utc::now().timestamp_millis();
        let role_str = op.role.as_str();

        sqlx::query(
            r#"
            INSERT INTO operators (id, username, role, cert_fingerprint, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
            "#,
        )
        .bind(&id_bytes)
        .bind(&op.username)
        .bind(role_str)
        .bind(&op.cert_fingerprint)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("create operator: {}", e)))?;

        Ok(OperatorRecord {
            id,
            username: op.username,
            role: role_str.to_string(),
            cert_fingerprint: op.cert_fingerprint,
            created_at: now,
            last_seen: None,
            is_active: true,
        })
    }

    /// Get operator by ID
    pub async fn get(&self, id: Uuid) -> Result<Option<OperatorRecord>, KrakenError> {
        let id_bytes = id.as_bytes().to_vec();
        
        let row: Option<(Vec<u8>, String, String, String, i64, Option<i64>, i64)> = sqlx::query_as(
            r#"
            SELECT id, username, role, cert_fingerprint, created_at, last_seen, is_active
            FROM operators WHERE id = ?
            "#,
        )
        .bind(&id_bytes)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("get operator: {}", e)))?;

        Ok(row.map(|r| self.row_to_record(r)))
    }

    /// Get operator by username
    pub async fn get_by_username(&self, username: &str) -> Result<Option<OperatorRecord>, KrakenError> {
        let row: Option<(Vec<u8>, String, String, String, i64, Option<i64>, i64)> = sqlx::query_as(
            r#"
            SELECT id, username, role, cert_fingerprint, created_at, last_seen, is_active
            FROM operators WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("get operator by username: {}", e)))?;

        Ok(row.map(|r| self.row_to_record(r)))
    }

    /// Get operator by certificate fingerprint
    pub async fn get_by_cert(&self, fingerprint: &str) -> Result<Option<OperatorRecord>, KrakenError> {
        let row: Option<(Vec<u8>, String, String, String, i64, Option<i64>, i64)> = sqlx::query_as(
            r#"
            SELECT id, username, role, cert_fingerprint, created_at, last_seen, is_active
            FROM operators WHERE cert_fingerprint = ?
            "#,
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("get operator by cert: {}", e)))?;

        Ok(row.map(|r| self.row_to_record(r)))
    }

    /// List all operators
    pub async fn list(&self) -> Result<Vec<OperatorRecord>, KrakenError> {
        let rows: Vec<(Vec<u8>, String, String, String, i64, Option<i64>, i64)> = sqlx::query_as(
            r#"
            SELECT id, username, role, cert_fingerprint, created_at, last_seen, is_active
            FROM operators ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("list operators: {}", e)))?;

        Ok(rows.into_iter().map(|r| self.row_to_record(r)).collect())
    }

    /// Update an operator
    pub async fn update(&self, id: Uuid, update: OperatorUpdate) -> Result<(), KrakenError> {
        let id_bytes = id.as_bytes().to_vec();

        if let Some(role) = update.role {
            sqlx::query("UPDATE operators SET role = ? WHERE id = ?")
                .bind(role.as_str())
                .bind(&id_bytes)
                .execute(&self.pool)
                .await
                .map_err(|e| KrakenError::Database(format!("update operator role: {}", e)))?;
        }

        if let Some(is_active) = update.is_active {
            sqlx::query("UPDATE operators SET is_active = ? WHERE id = ?")
                .bind(if is_active { 1i64 } else { 0i64 })
                .bind(&id_bytes)
                .execute(&self.pool)
                .await
                .map_err(|e| KrakenError::Database(format!("update operator active: {}", e)))?;
        }

        Ok(())
    }

    /// Update last seen timestamp
    pub async fn touch(&self, id: Uuid) -> Result<(), KrakenError> {
        let id_bytes = id.as_bytes().to_vec();
        let now = chrono::Utc::now().timestamp_millis();

        sqlx::query("UPDATE operators SET last_seen = ? WHERE id = ?")
            .bind(now)
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("touch operator: {}", e)))?;

        Ok(())
    }

    /// Delete an operator
    pub async fn delete(&self, id: Uuid) -> Result<(), KrakenError> {
        let id_bytes = id.as_bytes().to_vec();

        sqlx::query("DELETE FROM operators WHERE id = ?")
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("delete operator: {}", e)))?;

        Ok(())
    }

    /// Get allowed sessions for an operator (None means all sessions allowed)
    pub async fn get_allowed_sessions(&self, operator_id: Uuid) -> Result<Option<HashSet<Uuid>>, KrakenError> {
        let id_bytes = operator_id.as_bytes().to_vec();

        // Check if there are any restrictions
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM operator_allowed_sessions WHERE operator_id = ?"
        )
        .bind(&id_bytes)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("count allowed sessions: {}", e)))?;

        if count.0 == 0 {
            // No restrictions - all sessions allowed
            return Ok(None);
        }

        // Get allowed session IDs
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT session_id FROM operator_allowed_sessions WHERE operator_id = ?"
        )
        .bind(&id_bytes)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("get allowed sessions: {}", e)))?;

        let sessions: HashSet<Uuid> = rows
            .into_iter()
            .filter_map(|(bytes,)| {
                if bytes.len() == 16 {
                    let arr: [u8; 16] = bytes.try_into().ok()?;
                    Some(Uuid::from_bytes(arr))
                } else {
                    None
                }
            })
            .collect();

        Ok(Some(sessions))
    }

    /// Get allowed listeners for an operator (None means all listeners allowed)
    pub async fn get_allowed_listeners(&self, operator_id: Uuid) -> Result<Option<HashSet<Uuid>>, KrakenError> {
        let id_bytes = operator_id.as_bytes().to_vec();

        // Check if there are any restrictions
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM operator_allowed_listeners WHERE operator_id = ?"
        )
        .bind(&id_bytes)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("count allowed listeners: {}", e)))?;

        if count.0 == 0 {
            // No restrictions - all listeners allowed
            return Ok(None);
        }

        // Get allowed listener IDs
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT listener_id FROM operator_allowed_listeners WHERE operator_id = ?"
        )
        .bind(&id_bytes)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("get allowed listeners: {}", e)))?;

        let listeners: HashSet<Uuid> = rows
            .into_iter()
            .filter_map(|(bytes,)| {
                if bytes.len() == 16 {
                    let arr: [u8; 16] = bytes.try_into().ok()?;
                    Some(Uuid::from_bytes(arr))
                } else {
                    None
                }
            })
            .collect();

        Ok(Some(listeners))
    }

    /// Grant session access to an operator
    pub async fn grant_session_access(
        &self,
        operator_id: Uuid,
        session_id: Uuid,
        granted_by: Option<Uuid>,
    ) -> Result<(), KrakenError> {
        let op_bytes = operator_id.as_bytes().to_vec();
        let sess_bytes = session_id.as_bytes().to_vec();
        let granted_bytes = granted_by.map(|id| id.as_bytes().to_vec());
        let now = chrono::Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            INSERT OR IGNORE INTO operator_allowed_sessions (operator_id, session_id, granted_at, granted_by)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&op_bytes)
        .bind(&sess_bytes)
        .bind(now)
        .bind(&granted_bytes)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("grant session access: {}", e)))?;

        Ok(())
    }

    /// Revoke session access from an operator
    pub async fn revoke_session_access(
        &self,
        operator_id: Uuid,
        session_id: Uuid,
    ) -> Result<(), KrakenError> {
        let op_bytes = operator_id.as_bytes().to_vec();
        let sess_bytes = session_id.as_bytes().to_vec();

        sqlx::query(
            "DELETE FROM operator_allowed_sessions WHERE operator_id = ? AND session_id = ?"
        )
        .bind(&op_bytes)
        .bind(&sess_bytes)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("revoke session access: {}", e)))?;

        Ok(())
    }

    /// Grant listener access to an operator
    pub async fn grant_listener_access(
        &self,
        operator_id: Uuid,
        listener_id: Uuid,
        granted_by: Option<Uuid>,
    ) -> Result<(), KrakenError> {
        let op_bytes = operator_id.as_bytes().to_vec();
        let list_bytes = listener_id.as_bytes().to_vec();
        let granted_bytes = granted_by.map(|id| id.as_bytes().to_vec());
        let now = chrono::Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            INSERT OR IGNORE INTO operator_allowed_listeners (operator_id, listener_id, granted_at, granted_by)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&op_bytes)
        .bind(&list_bytes)
        .bind(now)
        .bind(&granted_bytes)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("grant listener access: {}", e)))?;

        Ok(())
    }

    /// Revoke listener access from an operator
    pub async fn revoke_listener_access(
        &self,
        operator_id: Uuid,
        listener_id: Uuid,
    ) -> Result<(), KrakenError> {
        let op_bytes = operator_id.as_bytes().to_vec();
        let list_bytes = listener_id.as_bytes().to_vec();

        sqlx::query(
            "DELETE FROM operator_allowed_listeners WHERE operator_id = ? AND listener_id = ?"
        )
        .bind(&op_bytes)
        .bind(&list_bytes)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("revoke listener access: {}", e)))?;

        Ok(())
    }

    /// Get full OperatorIdentity including access restrictions
    pub async fn get_identity(&self, id: Uuid) -> Result<Option<kraken_rbac::OperatorIdentity>, KrakenError> {
        let record = match self.get(id).await? {
            Some(r) => r,
            None => return Ok(None),
        };

        let allowed_sessions = self.get_allowed_sessions(id).await?;
        let allowed_listeners = self.get_allowed_listeners(id).await?;

        record
            .to_identity(allowed_sessions, allowed_listeners)
            .map(Some)
            .map_err(|e| KrakenError::Database(format!("convert to identity: {}", e)))
    }

    /// Get full OperatorIdentity by certificate fingerprint
    pub async fn get_identity_by_cert(&self, fingerprint: &str) -> Result<Option<kraken_rbac::OperatorIdentity>, KrakenError> {
        let record = match self.get_by_cert(fingerprint).await? {
            Some(r) => r,
            None => return Ok(None),
        };

        let allowed_sessions = self.get_allowed_sessions(record.id).await?;
        let allowed_listeners = self.get_allowed_listeners(record.id).await?;

        record
            .to_identity(allowed_sessions, allowed_listeners)
            .map(Some)
            .map_err(|e| KrakenError::Database(format!("convert to identity: {}", e)))
    }

    fn row_to_record(&self, row: (Vec<u8>, String, String, String, i64, Option<i64>, i64)) -> OperatorRecord {
        let id = if row.0.len() == 16 {
            let arr: [u8; 16] = row.0.try_into().unwrap();
            Uuid::from_bytes(arr)
        } else {
            Uuid::nil()
        };

        OperatorRecord {
            id,
            username: row.1,
            role: row.2,
            cert_fingerprint: row.3,
            created_at: row.4,
            last_seen: row.5,
            is_active: row.6 != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn test_db() -> Database {
        let db = Database::connect_memory().await.unwrap();
        db.migrate().await.unwrap();
        // Run the RBAC migration
        sqlx::raw_sql(include_str!("../../../../migrations/004_operator_rbac.sql"))
            .execute(db.pool())
            .await
            .unwrap();
        db
    }

    #[tokio::test]
    async fn test_create_operator() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "testuser".into(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "abc123".into(),
        }).await.unwrap();

        assert_eq!(op.username, "testuser");
        assert_eq!(op.role, "operator");
        assert!(op.is_active);
    }

    #[tokio::test]
    async fn test_get_operator() {
        let db = test_db().await;
        let repo = db.operators();

        let created = repo.create(NewOperator {
            username: "gettest".into(),
            role: kraken_rbac::Role::Admin,
            cert_fingerprint: "def456".into(),
        }).await.unwrap();

        let fetched = repo.get(created.id).await.unwrap().unwrap();
        assert_eq!(fetched.username, "gettest");
        assert_eq!(fetched.role, "admin");
    }

    #[tokio::test]
    async fn test_get_by_username() {
        let db = test_db().await;
        let repo = db.operators();

        repo.create(NewOperator {
            username: "findme".into(),
            role: kraken_rbac::Role::Viewer,
            cert_fingerprint: "ghi789".into(),
        }).await.unwrap();

        let found = repo.get_by_username("findme").await.unwrap().unwrap();
        assert_eq!(found.role, "viewer");
    }

    #[tokio::test]
    async fn test_get_by_cert() {
        let db = test_db().await;
        let repo = db.operators();

        repo.create(NewOperator {
            username: "certuser".into(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "unique-cert-fp".into(),
        }).await.unwrap();

        let found = repo.get_by_cert("unique-cert-fp").await.unwrap().unwrap();
        assert_eq!(found.username, "certuser");
    }

    #[tokio::test]
    async fn test_update_operator() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "updateme".into(),
            role: kraken_rbac::Role::Viewer,
            cert_fingerprint: "upd123".into(),
        }).await.unwrap();

        repo.update(op.id, OperatorUpdate {
            role: Some(kraken_rbac::Role::Admin),
            is_active: None,
        }).await.unwrap();

        let updated = repo.get(op.id).await.unwrap().unwrap();
        assert_eq!(updated.role, "admin");
    }

    #[tokio::test]
    async fn test_disable_operator() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "disableme".into(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "dis123".into(),
        }).await.unwrap();

        repo.update(op.id, OperatorUpdate {
            role: None,
            is_active: Some(false),
        }).await.unwrap();

        let updated = repo.get(op.id).await.unwrap().unwrap();
        assert!(!updated.is_active);
    }

    #[tokio::test]
    async fn test_delete_operator() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "deleteme".into(),
            role: kraken_rbac::Role::Viewer,
            cert_fingerprint: "del123".into(),
        }).await.unwrap();

        repo.delete(op.id).await.unwrap();

        let found = repo.get(op.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_list_operators() {
        let db = test_db().await;
        let repo = db.operators();

        repo.create(NewOperator {
            username: "list1".into(),
            role: kraken_rbac::Role::Admin,
            cert_fingerprint: "list1".into(),
        }).await.unwrap();

        repo.create(NewOperator {
            username: "list2".into(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "list2".into(),
        }).await.unwrap();

        let all = repo.list().await.unwrap();
        assert!(all.len() >= 2);
    }

    #[tokio::test]
    async fn test_touch_updates_last_seen() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "touchme".into(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "touch123".into(),
        }).await.unwrap();

        assert!(op.last_seen.is_none());

        repo.touch(op.id).await.unwrap();

        let updated = repo.get(op.id).await.unwrap().unwrap();
        assert!(updated.last_seen.is_some());
    }

    #[tokio::test]
    async fn test_session_access_unrestricted() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "unrestricted".into(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "unr123".into(),
        }).await.unwrap();

        // No restrictions by default
        let allowed = repo.get_allowed_sessions(op.id).await.unwrap();
        assert!(allowed.is_none());
    }

    #[tokio::test]
    async fn test_session_access_restricted() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "restricted".into(),
            role: kraken_rbac::Role::Operator,
            cert_fingerprint: "res123".into(),
        }).await.unwrap();

        // Need to create a session first (use implant)
        let session_id = Uuid::new_v4();
        // Insert a dummy implant for FK constraint
        sqlx::query("INSERT INTO implants (id, name, state, registered_at) VALUES (?, 'test', 'active', ?)")
            .bind(session_id.as_bytes().to_vec())
            .bind(chrono::Utc::now().timestamp_millis())
            .execute(db.pool())
            .await
            .unwrap();

        repo.grant_session_access(op.id, session_id, None).await.unwrap();

        let allowed = repo.get_allowed_sessions(op.id).await.unwrap().unwrap();
        assert!(allowed.contains(&session_id));
        assert_eq!(allowed.len(), 1);

        // Revoke access
        repo.revoke_session_access(op.id, session_id).await.unwrap();
        let allowed = repo.get_allowed_sessions(op.id).await.unwrap();
        assert!(allowed.is_none()); // Back to unrestricted (no entries)
    }

    #[tokio::test]
    async fn test_get_identity() {
        let db = test_db().await;
        let repo = db.operators();

        let op = repo.create(NewOperator {
            username: "identity_test".into(),
            role: kraken_rbac::Role::Admin,
            cert_fingerprint: "id123".into(),
        }).await.unwrap();

        let identity = repo.get_identity(op.id).await.unwrap().unwrap();
        assert_eq!(identity.username, "identity_test");
        assert_eq!(identity.role, kraken_rbac::Role::Admin);
        assert!(!identity.disabled);
        assert!(identity.allowed_sessions.is_none());
    }

    #[tokio::test]
    async fn test_get_identity_by_cert() {
        let db = test_db().await;
        let repo = db.operators();

        repo.create(NewOperator {
            username: "cert_identity".into(),
            role: kraken_rbac::Role::Viewer,
            cert_fingerprint: "cert-id-fp".into(),
        }).await.unwrap();

        let identity = repo.get_identity_by_cert("cert-id-fp").await.unwrap().unwrap();
        assert_eq!(identity.username, "cert_identity");
        assert_eq!(identity.role, kraken_rbac::Role::Viewer);
    }
}
