//! File transfer repository

use common::KrakenError;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct FileTransferRepo {
    pool: SqlitePool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FileTransfer {
    pub transfer_id: String,
    pub implant_id: Vec<u8>,
    pub file_path: String,
    pub direction: String,  // "upload" or "download"
    pub total_size: i64,
    pub bytes_transferred: i64,
    pub chunks_completed: i64,
    pub total_chunks: i64,
    pub state: String,
    pub error: Option<String>,
    pub started_at: i64,
    pub completed_at: Option<i64>,
}

impl FileTransferRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new file transfer
    pub async fn create(&self, transfer: &FileTransfer) -> Result<(), KrakenError> {
        sqlx::query(
            r#"
            INSERT INTO file_transfers (
                transfer_id, implant_id, file_path, direction,
                total_size, bytes_transferred, chunks_completed, total_chunks,
                state, error, started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&transfer.transfer_id)
        .bind(&transfer.implant_id)
        .bind(&transfer.file_path)
        .bind(&transfer.direction)
        .bind(transfer.total_size)
        .bind(transfer.bytes_transferred)
        .bind(transfer.chunks_completed)
        .bind(transfer.total_chunks)
        .bind(&transfer.state)
        .bind(&transfer.error)
        .bind(transfer.started_at)
        .bind(transfer.completed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get transfer by ID
    pub async fn get(&self, transfer_id: &str) -> Result<Option<FileTransfer>, KrakenError> {
        sqlx::query_as::<_, FileTransfer>(
            "SELECT * FROM file_transfers WHERE transfer_id = ?"
        )
        .bind(transfer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))
    }

    /// Update transfer progress
    pub async fn update_progress(
        &self,
        transfer_id: &str,
        bytes_transferred: i64,
        chunks_completed: i64,
    ) -> Result<(), KrakenError> {
        sqlx::query(
            r#"
            UPDATE file_transfers
            SET bytes_transferred = ?,
                chunks_completed = ?,
                state = CASE
                    WHEN ? >= total_chunks THEN 'completed'
                    ELSE 'in_progress'
                END
            WHERE transfer_id = ?
            "#,
        )
        .bind(bytes_transferred)
        .bind(chunks_completed)
        .bind(chunks_completed)
        .bind(transfer_id)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        Ok(())
    }

    /// Mark transfer as complete
    pub async fn mark_complete(&self, transfer_id: &str) -> Result<(), KrakenError> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "UPDATE file_transfers SET state = 'completed', completed_at = ? WHERE transfer_id = ?"
        )
        .bind(now)
        .bind(transfer_id)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        Ok(())
    }

    /// Mark transfer as failed
    pub async fn mark_failed(&self, transfer_id: &str, error: &str) -> Result<(), KrakenError> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "UPDATE file_transfers SET state = 'failed', error = ?, completed_at = ? WHERE transfer_id = ?"
        )
        .bind(error)
        .bind(now)
        .bind(transfer_id)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        Ok(())
    }

    /// List active transfers (in_progress or paused)
    pub async fn list_active(&self) -> Result<Vec<FileTransfer>, KrakenError> {
        sqlx::query_as::<_, FileTransfer>(
            r#"
            SELECT * FROM file_transfers
            WHERE state IN ('initializing', 'in_progress', 'paused')
            ORDER BY started_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))
    }

    /// List transfers by implant
    pub async fn list_by_implant(&self, implant_id: &[u8]) -> Result<Vec<FileTransfer>, KrakenError> {
        sqlx::query_as::<_, FileTransfer>(
            "SELECT * FROM file_transfers WHERE implant_id = ? ORDER BY started_at DESC LIMIT 100"
        )
        .bind(implant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))
    }

    /// Delete completed/failed transfers older than N days
    pub async fn cleanup_old(&self, days: i64) -> Result<u64, KrakenError> {
        let cutoff = chrono::Utc::now().timestamp() - (days * 86400);

        let result = sqlx::query(
            "DELETE FROM file_transfers WHERE state IN ('completed', 'failed') AND completed_at < ?"
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_db() -> Result<(crate::Database, Vec<u8>), KrakenError> {
        let db = crate::Database::connect_memory().await?;
        db.migrate().await?;

        // Create test implant
        let implant_id = vec![1u8; 16];
        let now = chrono::Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            INSERT INTO implants (id, name, state, registered_at, last_seen)
            VALUES (?, 'test-implant', 'active', ?, ?)
            "#
        )
        .bind(&implant_id)
        .bind(now)
        .bind(now)
        .execute(db.pool())
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        Ok((db, implant_id))
    }

    #[tokio::test]
    async fn test_create_transfer() -> Result<(), KrakenError> {
        let (db, implant_id) = setup_db().await?;
        let repo = db.file_transfers();

        let transfer = FileTransfer {
            transfer_id: "test-123".to_string(),
            implant_id: implant_id.clone(),
            file_path: "/tmp/test.bin".to_string(),
            direction: "download".to_string(),
            total_size: 1000000,
            bytes_transferred: 0,
            chunks_completed: 0,
            total_chunks: 10,
            state: "initializing".to_string(),
            error: None,
            started_at: chrono::Utc::now().timestamp(),
            completed_at: None,
        };

        repo.create(&transfer).await?;

        let retrieved = repo.get("test-123").await?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().file_path, "/tmp/test.bin");

        Ok(())
    }

    #[tokio::test]
    async fn test_update_progress() -> Result<(), KrakenError> {
        let (db, implant_id) = setup_db().await?;
        let repo = db.file_transfers();

        let transfer = FileTransfer {
            transfer_id: "test-456".to_string(),
            implant_id,
            file_path: "/tmp/test2.bin".to_string(),
            direction: "upload".to_string(),
            total_size: 5242880,  // 5MB
            bytes_transferred: 0,
            chunks_completed: 0,
            total_chunks: 5,
            state: "in_progress".to_string(),
            error: None,
            started_at: chrono::Utc::now().timestamp(),
            completed_at: None,
        };

        repo.create(&transfer).await?;
        repo.update_progress("test-456", 1048576, 1).await?;

        let updated = repo.get("test-456").await?.unwrap();
        assert_eq!(updated.bytes_transferred, 1048576);
        assert_eq!(updated.chunks_completed, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_mark_complete() -> Result<(), KrakenError> {
        let (db, implant_id) = setup_db().await?;
        let repo = db.file_transfers();

        let transfer = FileTransfer {
            transfer_id: "test-789".to_string(),
            implant_id,
            file_path: "/tmp/test3.bin".to_string(),
            direction: "download".to_string(),
            total_size: 1000,
            bytes_transferred: 1000,
            chunks_completed: 1,
            total_chunks: 1,
            state: "in_progress".to_string(),
            error: None,
            started_at: chrono::Utc::now().timestamp(),
            completed_at: None,
        };

        repo.create(&transfer).await?;
        repo.mark_complete("test-789").await?;

        let completed = repo.get("test-789").await?.unwrap();
        assert_eq!(completed.state, "completed");
        assert!(completed.completed_at.is_some());

        Ok(())
    }
}
