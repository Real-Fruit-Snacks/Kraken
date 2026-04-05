use crate::models::ChatMessageRecord;
use common::KrakenError;
use sqlx::SqlitePool;

pub struct ChatRepo {
    pool: SqlitePool,
}

impl ChatRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new chat message
    pub async fn insert(&self, msg: &ChatMessageRecord) -> Result<(), KrakenError> {
        sqlx::query(
            "INSERT INTO chat_messages (id, from_operator_id, from_username, message, session_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(msg.id.as_bytes().as_slice())
        .bind(msg.from_operator_id.as_bytes().as_slice())
        .bind(&msg.from_username)
        .bind(&msg.message)
        .bind(msg.session_id.map(|id| id.as_bytes().to_vec()))
        .bind(msg.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get chat history with pagination
    pub async fn get_history(
        &self,
        session_id: Option<uuid::Uuid>,
        limit: u32,
        before: Option<i64>,
    ) -> Result<Vec<ChatMessageRecord>, KrakenError> {
        let limit = limit.min(500) as i64; // Cap at 500

        let rows = if let Some(sid) = session_id {
            if let Some(before_ts) = before {
                sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, String, Option<Vec<u8>>, i64)>(
                    "SELECT id, from_operator_id, from_username, message, session_id, created_at
                     FROM chat_messages
                     WHERE session_id = ? AND created_at < ?
                     ORDER BY created_at DESC LIMIT ?"
                )
                .bind(sid.as_bytes().as_slice())
                .bind(before_ts)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            } else {
                sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, String, Option<Vec<u8>>, i64)>(
                    "SELECT id, from_operator_id, from_username, message, session_id, created_at
                     FROM chat_messages
                     WHERE session_id = ?
                     ORDER BY created_at DESC LIMIT ?"
                )
                .bind(sid.as_bytes().as_slice())
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
        } else {
            // Global chat (no session filter)
            if let Some(before_ts) = before {
                sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, String, Option<Vec<u8>>, i64)>(
                    "SELECT id, from_operator_id, from_username, message, session_id, created_at
                     FROM chat_messages
                     WHERE created_at < ?
                     ORDER BY created_at DESC LIMIT ?"
                )
                .bind(before_ts)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            } else {
                sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, String, Option<Vec<u8>>, i64)>(
                    "SELECT id, from_operator_id, from_username, message, session_id, created_at
                     FROM chat_messages
                     ORDER BY created_at DESC LIMIT ?"
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| KrakenError::Database(e.to_string()))?;

        let messages: Vec<ChatMessageRecord> = rows
            .into_iter()
            .map(|(id, from_op, from_user, msg, sess, created)| {
                ChatMessageRecord {
                    id: uuid::Uuid::from_slice(&id).unwrap_or_default(),
                    from_operator_id: uuid::Uuid::from_slice(&from_op).unwrap_or_default(),
                    from_username: from_user,
                    message: msg,
                    session_id: sess.and_then(|b| uuid::Uuid::from_slice(&b).ok()),
                    created_at: created,
                }
            })
            .collect();

        Ok(messages)
    }
}
