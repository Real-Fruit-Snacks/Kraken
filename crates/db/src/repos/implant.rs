use crate::models::{ImplantRecord, ImplantUpdate};
use common::{ImplantId, KrakenError};
use sqlx::{Row, SqlitePool};

pub struct ImplantRepo {
    pool: SqlitePool,
}

impl ImplantRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, r: &ImplantRecord) -> Result<(), KrakenError> {
        let local_ips_json = serde_json::to_string(&r.local_ips).unwrap_or_else(|_| "[]".to_string());
        sqlx::query(
            r#"INSERT INTO implants (
                id, name, state, hostname, username, domain, os_name, os_version, os_arch,
                process_id, process_name, process_path, is_elevated, integrity_level, local_ips,
                checkin_interval, jitter_percent, symmetric_key, key_nonce_counter, registered_at, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
        )
        .bind(r.id.as_bytes().as_slice())
        .bind(&r.name)
        .bind(r.state.to_string())
        .bind(&r.hostname)
        .bind(&r.username)
        .bind(&r.domain)
        .bind(&r.os_name)
        .bind(&r.os_version)
        .bind(&r.os_arch)
        .bind(r.process_id.map(|p| p as i64))
        .bind(&r.process_name)
        .bind(&r.process_path)
        .bind(r.is_elevated as i32)
        .bind(&r.integrity_level)
        .bind(&local_ips_json)
        .bind(r.checkin_interval)
        .bind(r.jitter_percent)
        .bind(&r.symmetric_key)
        .bind(r.nonce_counter)
        .bind(r.registered_at)
        .bind(r.last_seen)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn get(&self, id: ImplantId) -> Result<Option<ImplantRecord>, KrakenError> {
        let row = sqlx::query("SELECT * FROM implants WHERE id = ?")
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        row.map(|r| self.row_to_record(&r)).transpose()
    }

    pub async fn list(&self) -> Result<Vec<ImplantRecord>, KrakenError> {
        let rows = sqlx::query("SELECT * FROM implants ORDER BY last_seen DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        rows.iter().map(|r| self.row_to_record(r)).collect()
    }

    pub async fn update_last_seen(&self, id: ImplantId) -> Result<(), KrakenError> {
        let now = chrono::Utc::now().timestamp_millis();
        sqlx::query("UPDATE implants SET last_seen = ? WHERE id = ?")
            .bind(now)
            .bind(id.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    /// Update the nonce counter for an implant (should be called after each encrypted message)
    pub async fn update_nonce_counter(
        &self,
        id: ImplantId,
        counter: i64,
    ) -> Result<(), KrakenError> {
        sqlx::query("UPDATE implants SET key_nonce_counter = ? WHERE id = ?")
            .bind(counter)
            .bind(id.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    /// Atomically increment and return the new nonce counter
    pub async fn increment_nonce_counter(&self, id: ImplantId) -> Result<i64, KrakenError> {
        let row = sqlx::query(
            "UPDATE implants SET key_nonce_counter = key_nonce_counter + 1 WHERE id = ? RETURNING key_nonce_counter"
        )
        .bind(id.as_bytes().as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(row.get("key_nonce_counter"))
    }

    /// Update implant fields selectively based on which fields are Some
    pub async fn update(&self, id: ImplantId, update: ImplantUpdate) -> Result<(), KrakenError> {
        let mut set_clauses = Vec::new();

        if update.state.is_some() {
            set_clauses.push("state = ?");
        }
        if update.hostname.is_some() {
            set_clauses.push("hostname = ?");
        }
        if update.username.is_some() {
            set_clauses.push("username = ?");
        }
        if update.os_name.is_some() {
            set_clauses.push("os_name = ?");
        }
        if update.checkin_interval.is_some() {
            set_clauses.push("checkin_interval = ?");
        }
        if update.jitter_percent.is_some() {
            set_clauses.push("jitter_percent = ?");
        }

        if set_clauses.is_empty() {
            return Ok(());
        }

        let sql = format!(
            "UPDATE implants SET {} WHERE id = ?",
            set_clauses.join(", ")
        );
        let mut query = sqlx::query(&sql);

        if let Some(state) = update.state {
            query = query.bind(state.to_string());
        }
        if let Some(hostname) = update.hostname {
            query = query.bind(hostname);
        }
        if let Some(username) = update.username {
            query = query.bind(username);
        }
        if let Some(os_name) = update.os_name {
            query = query.bind(os_name);
        }
        if let Some(checkin_interval) = update.checkin_interval {
            query = query.bind(checkin_interval);
        }
        if let Some(jitter_percent) = update.jitter_percent {
            query = query.bind(jitter_percent);
        }

        query = query.bind(id.as_bytes().as_slice());

        query
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    /// Find implants that have missed 3+ consecutive check-ins (stale).
    /// Threshold: last_seen < now - (3 * checkin_interval * 1000)
    pub async fn find_stale_implants(&self, now_ms: i64) -> Result<Vec<ImplantRecord>, KrakenError> {
        // Only check Active or Staging implants (terminal states shouldn't be rechecked)
        let rows = sqlx::query(
            r#"
            SELECT * FROM implants
            WHERE state IN ('active', 'staging')
              AND last_seen IS NOT NULL
              AND last_seen < (? - (3 * checkin_interval * 1000))
            "#,
        )
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(e.to_string()))?;
        rows.iter().map(|r| self.row_to_record(r)).collect()
    }

    pub async fn delete(&self, id: ImplantId) -> Result<bool, KrakenError> {
        let result = sqlx::query("DELETE FROM implants WHERE id = ?")
            .bind(id.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    /// Update only the state field of an implant
    pub async fn update_state(
        &self,
        id: ImplantId,
        state: common::ImplantState,
    ) -> Result<(), KrakenError> {
        sqlx::query("UPDATE implants SET state = ? WHERE id = ?")
            .bind(state.to_string())
            .bind(id.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(e.to_string()))?;
        Ok(())
    }

    fn row_to_record(&self, row: &sqlx::sqlite::SqliteRow) -> Result<ImplantRecord, KrakenError> {
        let id_bytes: Vec<u8> = row.get("id");
        let state_str: String = row.get("state");
        let local_ips_json: Option<String> = row.get("local_ips");
        let local_ips: Vec<String> = local_ips_json
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let process_id: Option<i64> = row.get("process_id");
        let is_elevated: Option<i32> = row.get("is_elevated");

        Ok(ImplantRecord {
            id: ImplantId::from_bytes(&id_bytes)?,
            name: row.get("name"),
            state: state_str.parse()?,
            hostname: row.get("hostname"),
            username: row.get("username"),
            domain: row.get("domain"),
            os_name: row.get("os_name"),
            os_version: row.get("os_version"),
            os_arch: row.get("os_arch"),
            process_id: process_id.map(|p| p as u32),
            process_name: row.get("process_name"),
            process_path: row.get("process_path"),
            is_elevated: is_elevated.unwrap_or(0) != 0,
            integrity_level: row.get("integrity_level"),
            local_ips,
            checkin_interval: row.get("checkin_interval"),
            jitter_percent: row.get("jitter_percent"),
            symmetric_key: row.get("symmetric_key"),
            nonce_counter: row.get("key_nonce_counter"),
            registered_at: row.get("registered_at"),
            last_seen: row.get("last_seen"),
        })
    }
}
