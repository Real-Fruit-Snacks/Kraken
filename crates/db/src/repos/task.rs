use crate::models::TaskRecord;
use common::{ImplantId, KrakenError, OperatorId, TaskId};
use sqlx::{Row, SqlitePool};

pub struct TaskRepo {
    pool: SqlitePool,
}

impl TaskRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, r: &TaskRecord) -> Result<(), KrakenError> {
        sqlx::query(
            "INSERT INTO tasks (id, implant_id, operator_id, task_type, task_data, status, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(r.id.as_bytes().as_slice())
        .bind(r.implant_id.as_bytes().as_slice())
        .bind(r.operator_id.as_bytes().as_slice())
        .bind(&r.task_type)
        .bind(&r.task_data)
        .bind(&r.status)
        .bind(r.issued_at)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn get(&self, id: TaskId) -> Result<Option<TaskRecord>, KrakenError> {
        let row = sqlx::query("SELECT * FROM tasks WHERE id = ?")
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        row.map(|r| self.row_to_record(&r)).transpose()
    }

    pub async fn list_pending(
        &self,
        implant_id: ImplantId,
    ) -> Result<Vec<TaskRecord>, KrakenError> {
        let rows = sqlx::query(
            "SELECT * FROM tasks WHERE implant_id = ? AND status = 'queued' ORDER BY issued_at",
        )
        .bind(implant_id.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        rows.iter().map(|r| self.row_to_record(r)).collect()
    }

    /// Mark tasks as dispatched (sent to implant)
    pub async fn mark_dispatched(&self, task_ids: &[TaskId]) -> Result<(), KrakenError> {
        if task_ids.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp_millis();
        for id in task_ids {
            sqlx::query("UPDATE tasks SET status = 'dispatched', dispatched_at = ? WHERE id = ?")
                .bind(now)
                .bind(id.as_bytes().as_slice())
                .execute(&self.pool)
                .await
                .map_err(|e| KrakenError::Database(e.to_string()))?;
        }
        Ok(())
    }

    /// List all tasks for an implant (not just queued)
    pub async fn list_by_implant(
        &self,
        implant_id: ImplantId,
        limit: u32,
    ) -> Result<Vec<TaskRecord>, KrakenError> {
        let rows = sqlx::query(
            "SELECT * FROM tasks WHERE implant_id = ? ORDER BY issued_at DESC LIMIT ?",
        )
        .bind(implant_id.as_bytes().as_slice())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        rows.iter().map(|r| self.row_to_record(r)).collect()
    }

    /// Find dispatched tasks older than threshold (stale)
    pub async fn find_stale_dispatched(
        &self,
        now_ms: i64,
        threshold_ms: i64,
    ) -> Result<Vec<TaskRecord>, KrakenError> {
        let cutoff = now_ms - threshold_ms;
        let rows = sqlx::query(
            "SELECT * FROM tasks WHERE status = 'dispatched' AND dispatched_at < ?",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        rows.iter().map(|r| self.row_to_record(r)).collect()
    }

    /// Expire all queued/dispatched tasks for an implant (when implant is lost)
    pub async fn expire_tasks_for_implant(&self, implant_id: ImplantId) -> Result<u64, KrakenError> {
        let now = chrono::Utc::now().timestamp_millis();
        let result = sqlx::query(
            "UPDATE tasks SET status = 'expired', completed_at = ? WHERE implant_id = ? AND status IN ('queued', 'dispatched')",
        )
        .bind(now)
        .bind(implant_id.as_bytes().as_slice())
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }

    pub async fn update_result(
        &self,
        id: TaskId,
        status: &str,
        result: Option<&[u8]>,
        error: Option<&str>,
    ) -> Result<(), KrakenError> {
        let now = chrono::Utc::now().timestamp_millis();
        sqlx::query("UPDATE tasks SET status = ?, completed_at = ?, result_data = ?, error_message = ? WHERE id = ?")
            .bind(status)
            .bind(now)
            .bind(result)
            .bind(error)
            .bind(id.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    fn row_to_record(&self, row: &sqlx::sqlite::SqliteRow) -> Result<TaskRecord, KrakenError> {
        let id: Vec<u8> = row.get("id");
        let implant_id: Vec<u8> = row.get("implant_id");
        let operator_id: Vec<u8> = row.get("operator_id");
        Ok(TaskRecord {
            id: TaskId::from_bytes(&id)?,
            implant_id: ImplantId::from_bytes(&implant_id)?,
            operator_id: OperatorId::from_bytes(&operator_id)?,
            task_type: row.get("task_type"),
            task_data: row.get("task_data"),
            status: row.get("status"),
            issued_at: row.get("issued_at"),
            dispatched_at: row.get("dispatched_at"),
            completed_at: row.get("completed_at"),
            result_data: row.get("result_data"),
            error_message: row.get("error_message"),
        })
    }
}
