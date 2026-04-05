use crate::models::AuditEntry;
use common::KrakenError;
use sqlx::SqlitePool;

pub struct AuditRepo {
    pool: SqlitePool,
}

impl AuditRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn log(&self, e: &AuditEntry) -> Result<i64, KrakenError> {
        let details = e.details.as_ref().map(|d| d.to_string());
        let result = sqlx::query(
            "INSERT INTO audit_log (timestamp, operator_id, implant_id, action, details) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(e.timestamp)
        .bind(e.operator_id.map(|id| id.as_bytes().to_vec()))
        .bind(e.implant_id.map(|id| id.as_bytes().to_vec()))
        .bind(&e.action)
        .bind(&details)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(result.last_insert_rowid())
    }
}
