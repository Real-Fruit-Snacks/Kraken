use common::KrakenError;
use sqlx::{Row, SqlitePool};

pub struct ConfigRepo {
    pool: SqlitePool,
}

impl ConfigRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, key: &str) -> Result<Option<String>, KrakenError> {
        let row = sqlx::query("SELECT value FROM server_config WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(row.map(|r| r.get("value")))
    }

    pub async fn set(&self, key: &str, value: &str) -> Result<(), KrakenError> {
        let now = chrono::Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO server_config (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
        )
        .bind(key)
        .bind(value)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }
}
