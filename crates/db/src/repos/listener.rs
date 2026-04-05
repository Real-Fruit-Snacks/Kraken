use crate::models::ListenerRecord;
use common::{KrakenError, ListenerId};
use sqlx::{Row, SqlitePool};

pub struct ListenerRepo {
    pool: SqlitePool,
}

impl ListenerRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, r: &ListenerRecord) -> Result<(), KrakenError> {
        sqlx::query(
            "INSERT INTO listeners (id, listener_type, bind_host, bind_port, is_running, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(r.id.as_bytes().as_slice())
        .bind(&r.listener_type)
        .bind(&r.bind_host)
        .bind(r.bind_port)
        .bind(r.is_running as i32)
        .bind(r.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<ListenerRecord>, KrakenError> {
        let rows = sqlx::query("SELECT * FROM listeners ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        rows.iter()
            .map(|r| {
                let id: Vec<u8> = r.get("id");
                Ok(ListenerRecord {
                    id: ListenerId::from_bytes(&id)?,
                    listener_type: r.get("listener_type"),
                    bind_host: r.get("bind_host"),
                    bind_port: r.get("bind_port"),
                    is_running: r.get::<i32, _>("is_running") != 0,
                    created_at: r.get("created_at"),
                })
            })
            .collect()
    }

    pub async fn update_running(&self, id: ListenerId, running: bool) -> Result<(), KrakenError> {
        sqlx::query("UPDATE listeners SET is_running = ? WHERE id = ?")
            .bind(running as i32)
            .bind(id.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }
}
