//! Job repository for background job tracking

use common::KrakenError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JobRow {
    pub job_id: i64,
    pub implant_id: Vec<u8>,
    pub task_id: Vec<u8>,
    pub description: String,
    pub status: String,
    pub progress: i64,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub error_message: Option<String>,
    pub output_size: i64,
}

#[derive(Debug, Clone)]
pub struct JobOutputRow {
    pub id: i64,
    pub job_id: i64,
    pub sequence: i64,
    pub output_data: Vec<u8>,
    pub received_at: i64,
    pub is_final: bool,
}

pub struct JobRepo {
    pool: SqlitePool,
}

impl JobRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new job
    pub async fn create(&self, row: &JobRow) -> Result<(), KrakenError> {
        sqlx::query(
            r#"
            INSERT INTO jobs (
                job_id, implant_id, task_id, description, status, progress,
                created_at, completed_at, error_message, output_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(row.job_id)
        .bind(&row.implant_id)
        .bind(&row.task_id)
        .bind(&row.description)
        .bind(&row.status)
        .bind(row.progress)
        .bind(row.created_at)
        .bind(row.completed_at)
        .bind(&row.error_message)
        .bind(row.output_size)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("insert job: {}", e)))?;
        Ok(())
    }

    /// Get a job by ID
    pub async fn get(&self, job_id: i64) -> Result<Option<JobRow>, KrakenError> {
        sqlx::query_as::<_, JobRow>("SELECT * FROM jobs WHERE job_id = ?")
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("get job: {}", e)))
    }

    /// List all jobs (optionally limit)
    pub async fn list_all(&self, limit: i32) -> Result<Vec<JobRow>, KrakenError> {
        sqlx::query_as::<_, JobRow>(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("list all jobs: {}", e)))
    }

    /// List jobs for an implant
    pub async fn list_by_implant(
        &self,
        implant_id: &[u8],
        limit: i32,
    ) -> Result<Vec<JobRow>, KrakenError> {
        sqlx::query_as::<_, JobRow>(
            "SELECT * FROM jobs WHERE implant_id = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(implant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("list jobs: {}", e)))
    }

    /// List active jobs for an implant
    pub async fn list_active(
        &self,
        implant_id: &[u8],
    ) -> Result<Vec<JobRow>, KrakenError> {
        sqlx::query_as::<_, JobRow>(
            "SELECT * FROM jobs WHERE implant_id = ? AND status = 'running' ORDER BY created_at",
        )
        .bind(implant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("list active jobs: {}", e)))
    }

    /// Update job status
    pub async fn update_status(
        &self,
        job_id: i64,
        status: &str,
        progress: i64,
        completed_at: Option<i64>,
        error_message: Option<&str>,
    ) -> Result<(), KrakenError> {
        sqlx::query(
            r#"
            UPDATE jobs
            SET status = ?, progress = ?, completed_at = ?, error_message = ?
            WHERE job_id = ?
            "#,
        )
        .bind(status)
        .bind(progress)
        .bind(completed_at)
        .bind(error_message)
        .bind(job_id)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("update job status: {}", e)))?;
        Ok(())
    }

    /// Add job output
    pub async fn add_output(
        &self,
        job_id: i64,
        sequence: i64,
        output_data: &[u8],
        is_final: bool,
    ) -> Result<(), KrakenError> {
        let received_at = chrono::Utc::now().timestamp_millis();

        sqlx::query(
            r#"
            INSERT INTO job_outputs (job_id, sequence, output_data, received_at, is_final)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(job_id)
        .bind(sequence)
        .bind(output_data)
        .bind(received_at)
        .bind(is_final as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("insert job output: {}", e)))?;

        // Update output size
        sqlx::query(
            "UPDATE jobs SET output_size = output_size + ? WHERE job_id = ?",
        )
        .bind(output_data.len() as i64)
        .bind(job_id)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("update output size: {}", e)))?;

        Ok(())
    }

    /// Get all job outputs
    pub async fn get_outputs(&self, job_id: i64) -> Result<Vec<Vec<u8>>, KrakenError> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT output_data FROM job_outputs WHERE job_id = ? ORDER BY sequence",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("get job outputs: {}", e)))?;

        Ok(rows.into_iter().map(|(data,)| data).collect())
    }

    /// Delete old completed jobs
    pub async fn cleanup_old(&self, max_age_millis: i64) -> Result<u64, KrakenError> {
        let cutoff = chrono::Utc::now().timestamp_millis() - max_age_millis;

        let result = sqlx::query(
            r#"
            DELETE FROM jobs
            WHERE status IN ('completed', 'failed', 'cancelled')
            AND completed_at < ?
            "#,
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("cleanup jobs: {}", e)))?;

        Ok(result.rows_affected())
    }

    /// Count jobs by status
    pub async fn count_by_status(
        &self,
        implant_id: &[u8],
        status: &str,
    ) -> Result<i64, KrakenError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM jobs WHERE implant_id = ? AND status = ?",
        )
        .bind(implant_id)
        .bind(status)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("count jobs: {}", e)))?;

        Ok(count.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();

        // Create tables
        sqlx::query(
            r#"
            CREATE TABLE jobs (
                job_id INTEGER PRIMARY KEY,
                implant_id BLOB NOT NULL,
                task_id BLOB NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                completed_at INTEGER,
                error_message TEXT,
                output_size INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE job_outputs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                output_data BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                is_final INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_create_job() {
        let pool = setup_test_db().await;
        let repo = JobRepo::new(pool);

        let job = JobRow {
            job_id: 1,
            implant_id: vec![1, 2, 3, 4],
            task_id: vec![5, 6, 7, 8],
            description: "test job".to_string(),
            status: "running".to_string(),
            progress: 0,
            created_at: 1000,
            completed_at: None,
            error_message: None,
            output_size: 0,
        };

        repo.create(&job).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.description, "test job");
        assert_eq!(retrieved.status, "running");
    }

    #[tokio::test]
    async fn test_update_status() {
        let pool = setup_test_db().await;
        let repo = JobRepo::new(pool);

        let job = JobRow {
            job_id: 1,
            implant_id: vec![1, 2, 3, 4],
            task_id: vec![5, 6, 7, 8],
            description: "test".to_string(),
            status: "running".to_string(),
            progress: 0,
            created_at: 1000,
            completed_at: None,
            error_message: None,
            output_size: 0,
        };

        repo.create(&job).await.unwrap();

        repo.update_status(1, "completed", 100, Some(2000), None)
            .await
            .unwrap();

        let updated = repo.get(1).await.unwrap().unwrap();
        assert_eq!(updated.status, "completed");
        assert_eq!(updated.progress, 100);
        assert_eq!(updated.completed_at, Some(2000));
    }

    #[tokio::test]
    async fn test_add_output() {
        let pool = setup_test_db().await;
        let repo = JobRepo::new(pool);

        let job = JobRow {
            job_id: 1,
            implant_id: vec![1, 2, 3, 4],
            task_id: vec![5, 6, 7, 8],
            description: "test".to_string(),
            status: "running".to_string(),
            progress: 0,
            created_at: 1000,
            completed_at: None,
            error_message: None,
            output_size: 0,
        };

        repo.create(&job).await.unwrap();

        repo.add_output(1, 0, b"output chunk 1", false)
            .await
            .unwrap();
        repo.add_output(1, 1, b"output chunk 2", true)
            .await
            .unwrap();

        let outputs = repo.get_outputs(1).await.unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0], b"output chunk 1");
        assert_eq!(outputs[1], b"output chunk 2");

        let job = repo.get(1).await.unwrap().unwrap();
        assert_eq!(job.output_size, 28); // Total bytes
    }
}
