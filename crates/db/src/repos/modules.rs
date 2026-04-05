use crate::models::ModuleRecord;
use common::KrakenError;
use sqlx::{Row, SqlitePool};

pub struct ModulesRepo {
    pool: SqlitePool,
}

impl ModulesRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Store a module blob. Inserts or replaces the (id, platform, version) entry.
    pub async fn insert(&self, r: &ModuleRecord) -> Result<(), KrakenError> {
        sqlx::query(
            "INSERT OR REPLACE INTO modules \
             (id, platform, version, name, description, hash, size, blob, compiled_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&r.id)
        .bind(&r.platform)
        .bind(&r.version)
        .bind(&r.name)
        .bind(&r.description)
        .bind(&r.hash)
        .bind(r.size)
        .bind(&r.blob)
        .bind(r.compiled_at)
        .bind(r.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    /// Retrieve blob bytes for a specific module id/platform/version.
    pub async fn get_blob(
        &self,
        id: &str,
        platform: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, KrakenError> {
        let row = sqlx::query(
            "SELECT blob FROM modules WHERE id = ? AND platform = ? AND version = ?",
        )
        .bind(id)
        .bind(platform)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(row.map(|r| r.get("blob")))
    }

    /// Get the latest version string for a module/platform pair.
    pub async fn get_latest_version(
        &self,
        module_id: &str,
        platform: &str,
    ) -> Result<Option<String>, KrakenError> {
        let row = sqlx::query(
            "SELECT version FROM module_latest WHERE module_id = ? AND platform = ?",
        )
        .bind(module_id)
        .bind(platform)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(row.map(|r| r.get("version")))
    }

    /// Set (upsert) the latest version pointer for a module/platform.
    pub async fn set_latest(
        &self,
        module_id: &str,
        platform: &str,
        version: &str,
    ) -> Result<(), KrakenError> {
        let now = chrono::Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO module_latest (module_id, platform, version, updated_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(module_id, platform) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at",
        )
        .bind(module_id)
        .bind(platform)
        .bind(version)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    /// List all modules (metadata only, no blob) ordered by id/platform/version.
    pub async fn list(&self) -> Result<Vec<ModuleRecord>, KrakenError> {
        let rows = sqlx::query(
            "SELECT id, platform, version, name, description, hash, size, blob, compiled_at, created_at \
             FROM modules ORDER BY id, platform, version",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        rows.iter().map(|r| self.row_to_record(r)).collect()
    }

    /// Delete a specific module version. Also removes the latest pointer if it pointed here.
    pub async fn delete(
        &self,
        id: &str,
        platform: &str,
        version: &str,
    ) -> Result<(), KrakenError> {
        // Remove latest pointer if it matches this version
        sqlx::query(
            "DELETE FROM module_latest WHERE module_id = ? AND platform = ? AND version = ?",
        )
        .bind(id)
        .bind(platform)
        .bind(version)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        sqlx::query("DELETE FROM modules WHERE id = ? AND platform = ? AND version = ?")
            .bind(id)
            .bind(platform)
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    fn row_to_record(&self, row: &sqlx::sqlite::SqliteRow) -> Result<ModuleRecord, KrakenError> {
        Ok(ModuleRecord {
            id: row.get("id"),
            platform: row.get("platform"),
            version: row.get("version"),
            name: row.get("name"),
            description: row.get("description"),
            hash: row.get("hash"),
            size: row.get("size"),
            blob: row.get("blob"),
            compiled_at: row.get("compiled_at"),
            created_at: row.get("created_at"),
        })
    }
}
