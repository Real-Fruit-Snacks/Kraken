//! Loot repository

use common::KrakenError;
use sqlx::SqlitePool;

pub struct LootRepo {
    pool: SqlitePool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LootRow {
    pub id: Vec<u8>,
    pub implant_id: Vec<u8>,
    pub task_id: Option<Vec<u8>>,
    pub loot_type: String,
    pub captured_at: i64,
    pub source: Option<String>,
    // Credential
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    // Hash
    pub hash_type: Option<String>,
    pub hash_value: Option<String>,
    // Token
    pub token_type: Option<String>,
    pub token_data: Option<Vec<u8>>,
    pub expires_at: Option<i64>,
    pub principal: Option<String>,
    pub service: Option<String>,
    // File
    pub filename: Option<String>,
    pub original_path: Option<String>,
    pub file_size: Option<i64>,
    pub file_hash: Option<String>,
    pub blob_path: Option<String>,
}

impl LootRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, row: &LootRow) -> Result<(), KrakenError> {
        sqlx::query(
            r#"
            INSERT INTO loot (
                id, implant_id, task_id, loot_type, captured_at, source,
                username, password, domain, host, port, protocol,
                hash_type, hash_value,
                token_type, token_data, expires_at, principal, service,
                filename, original_path, file_size, file_hash, blob_path
            ) VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            "#,
        )
        .bind(&row.id)
        .bind(&row.implant_id)
        .bind(&row.task_id)
        .bind(&row.loot_type)
        .bind(row.captured_at)
        .bind(&row.source)
        .bind(&row.username)
        .bind(&row.password)
        .bind(&row.domain)
        .bind(&row.host)
        .bind(row.port)
        .bind(&row.protocol)
        .bind(&row.hash_type)
        .bind(&row.hash_value)
        .bind(&row.token_type)
        .bind(&row.token_data)
        .bind(row.expires_at)
        .bind(&row.principal)
        .bind(&row.service)
        .bind(&row.filename)
        .bind(&row.original_path)
        .bind(row.file_size)
        .bind(&row.file_hash)
        .bind(&row.blob_path)
        .execute(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("insert loot: {}", e)))?;
        Ok(())
    }

    pub async fn get(&self, id: &[u8]) -> Result<Option<LootRow>, KrakenError> {
        sqlx::query_as::<_, LootRow>("SELECT * FROM loot WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("get loot: {}", e)))
    }

    pub async fn query(
        &self,
        loot_type: Option<&str>,
        implant_id: Option<&[u8]>,
        username: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<LootRow>, KrakenError> {
        let mut query = String::from("SELECT * FROM loot WHERE 1=1");
        if loot_type.is_some() {
            query.push_str(" AND loot_type = ?");
        }
        if implant_id.is_some() {
            query.push_str(" AND implant_id = ?");
        }
        if username.is_some() {
            query.push_str(" AND username LIKE ?");
        }
        query.push_str(" ORDER BY captured_at DESC LIMIT ? OFFSET ?");

        let mut q = sqlx::query_as::<_, LootRow>(&query);
        if let Some(lt) = loot_type {
            q = q.bind(lt);
        }
        if let Some(iid) = implant_id {
            q = q.bind(iid);
        }
        if let Some(un) = username {
            q = q.bind(format!("%{}%", un));
        }
        q = q.bind(limit).bind(offset);

        q.fetch_all(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("query loot: {}", e)))
    }

    pub async fn delete(&self, id: &[u8]) -> Result<bool, KrakenError> {
        let result = sqlx::query("DELETE FROM loot WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| KrakenError::Database(format!("delete loot: {}", e)))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count(&self, loot_type: Option<&str>) -> Result<i64, KrakenError> {
        let query = match loot_type {
            Some(_) => "SELECT COUNT(*) as count FROM loot WHERE loot_type = ?",
            None => "SELECT COUNT(*) as count FROM loot",
        };
        let row: (i64,) = if let Some(lt) = loot_type {
            sqlx::query_as(query)
                .bind(lt)
                .fetch_one(&self.pool)
                .await
        } else {
            sqlx::query_as(query).fetch_one(&self.pool).await
        }
        .map_err(|e| KrakenError::Database(format!("count loot: {}", e)))?;
        Ok(row.0)
    }

    /// Insert a credential loot entry with deduplication.
    ///
    /// Deduplication key: `(loot_type, domain, username, source)`.
    ///
    /// - If no existing row matches the key → plain insert (new credential).
    /// - If a matching row exists AND the password/hash has changed → insert a
    ///   new row (credential rotation; preserves history).
    /// - If a matching row exists with the same password/hash → update
    ///   `captured_at` to the current timestamp (dedup; no duplicate created).
    ///
    /// Returns `true` when a new row was inserted, `false` when an existing row
    /// was updated in-place (exact duplicate suppressed).
    pub async fn upsert_credential(&self, row: &LootRow) -> Result<bool, KrakenError> {
        // Look for an existing row with the same (loot_type, domain, username, source).
        let existing: Option<(Vec<u8>, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, password, hash_value
            FROM loot
            WHERE loot_type = ?
              AND username IS ?
              AND domain   IS ?
              AND source   IS ?
            ORDER BY captured_at DESC
            LIMIT 1
            "#,
        )
        .bind(&row.loot_type)
        .bind(&row.username)
        .bind(&row.domain)
        .bind(&row.source)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("upsert_credential lookup: {}", e)))?;

        match existing {
            None => {
                // No prior entry — straight insert.
                self.insert(row).await?;
                Ok(true)
            }
            Some((existing_id, existing_password, existing_hash)) => {
                let data_unchanged = existing_password == row.password
                    && existing_hash == row.hash_value;

                if data_unchanged {
                    // Exact duplicate — just bump the timestamp.
                    sqlx::query("UPDATE loot SET captured_at = ? WHERE id = ?")
                        .bind(row.captured_at)
                        .bind(&existing_id)
                        .execute(&self.pool)
                        .await
                        .map_err(|e| {
                            KrakenError::Database(format!("upsert_credential update ts: {}", e))
                        })?;
                    Ok(false)
                } else {
                    // Credential rotated — insert new row to preserve history.
                    self.insert(row).await?;
                    Ok(true)
                }
            }
        }
    }

    /// Full-text search across username, password, domain, host, hash_value,
    /// token_data, filename, and source using SQLite FTS5.
    ///
    /// `query` accepts standard FTS5 query syntax (e.g. `"administrator"`,
    /// `domain:CORP`, `pass* OR hash`).
    pub async fn search(&self, query: &str, limit: i32) -> Result<Vec<LootRow>, KrakenError> {
        sqlx::query_as::<_, LootRow>(
            r#"
            SELECT l.*
            FROM loot l
            JOIN loot_fts ON loot_fts.rowid = l.rowid
            WHERE loot_fts MATCH ?
            ORDER BY l.captured_at DESC
            LIMIT ?
            "#,
        )
        .bind(query)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| KrakenError::Database(format!("search loot: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    /// Insert a minimal implant row so FK constraint on loot.implant_id is satisfied.
    async fn insert_dummy_implant(pool: &SqlitePool, implant_id: &[u8]) {
        let now = chrono::Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO implants (id, name, state, checkin_interval, jitter_percent, \
             symmetric_key, key_nonce_counter, registered_at) \
             VALUES (?, 'test-implant', 'active', 60, 20, NULL, 0, ?)",
        )
        .bind(implant_id)
        .bind(now)
        .execute(pool)
        .await
        .expect("insert dummy implant");
    }

    fn make_id(seed: u8) -> Vec<u8> {
        vec![seed; 16]
    }

    fn base_row(id: Vec<u8>, implant_id: Vec<u8>, loot_type: &str) -> LootRow {
        LootRow {
            id,
            implant_id,
            task_id: None,
            loot_type: loot_type.to_string(),
            captured_at: 1_700_000_000_000,
            source: Some("test-module".to_string()),
            username: None,
            password: None,
            domain: None,
            host: None,
            port: None,
            protocol: None,
            hash_type: None,
            hash_value: None,
            token_type: None,
            token_data: None,
            expires_at: None,
            principal: None,
            service: None,
            filename: None,
            original_path: None,
            file_size: None,
            file_hash: None,
            blob_path: None,
        }
    }

    async fn setup() -> (Database, Vec<u8>) {
        let db = Database::connect_memory().await.expect("memory db");
        db.migrate().await.expect("migrate");
        let implant_id = make_id(0xAA);
        insert_dummy_implant(db.pool(), &implant_id).await;
        (db, implant_id)
    }

    // -------------------------------------------------------------------------
    // test_insert_credential_loot
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_insert_credential_loot() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();
        let mut row = base_row(make_id(0x01), implant_id, "credential");
        row.username = Some("administrator".to_string());
        row.password = Some("P@ssw0rd!".to_string());
        row.domain = Some("CORP".to_string());
        row.host = Some("dc01.corp.local".to_string());
        row.port = Some(445);
        row.protocol = Some("smb".to_string());

        let result = repo.insert(&row).await;
        assert!(result.is_ok(), "insert credential loot failed: {:?}", result);
    }

    // -------------------------------------------------------------------------
    // test_insert_hash_loot
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_insert_hash_loot() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();
        let mut row = base_row(make_id(0x02), implant_id, "hash");
        row.hash_type = Some("ntlm".to_string());
        row.hash_value = Some(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".to_string(),
        );

        let result = repo.insert(&row).await;
        assert!(result.is_ok(), "insert hash loot failed: {:?}", result);
    }

    // -------------------------------------------------------------------------
    // test_insert_token_loot
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_insert_token_loot() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();
        let mut row = base_row(make_id(0x03), implant_id, "token");
        row.token_type = Some("kerberos".to_string());
        row.token_data = Some(b"fake-ticket-bytes".to_vec());
        row.expires_at = Some(1_800_000_000_000);
        row.principal = Some("user@CORP.LOCAL".to_string());
        row.service = Some("krbtgt/CORP.LOCAL".to_string());

        let result = repo.insert(&row).await;
        assert!(result.is_ok(), "insert token loot failed: {:?}", result);
    }

    // -------------------------------------------------------------------------
    // test_insert_file_loot
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_insert_file_loot() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();
        let mut row = base_row(make_id(0x04), implant_id, "file");
        row.filename = Some("sam.hive".to_string());
        row.original_path = Some(r"C:\Windows\System32\config\SAM".to_string());
        row.file_size = Some(262144);
        row.file_hash = Some("a".repeat(64));
        row.blob_path = Some("/var/kraken/loot/sam.hive".to_string());

        let result = repo.insert(&row).await;
        assert!(result.is_ok(), "insert file loot failed: {:?}", result);
    }

    // -------------------------------------------------------------------------
    // test_get_by_id
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_get_by_id() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();
        let id = make_id(0x05);
        let mut row = base_row(id.clone(), implant_id, "credential");
        row.username = Some("alice".to_string());
        row.password = Some("secret".to_string());
        repo.insert(&row).await.expect("insert");

        let fetched = repo.get(&id).await.expect("get");
        assert!(fetched.is_some(), "expected Some, got None");
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.loot_type, "credential");
        assert_eq!(fetched.username.as_deref(), Some("alice"));
        assert_eq!(fetched.password.as_deref(), Some("secret"));
    }

    // -------------------------------------------------------------------------
    // test_get_nonexistent
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_get_nonexistent() {
        let (db, _) = setup().await;
        let repo = db.loot();
        let missing_id = make_id(0xFF);

        let result = repo.get(&missing_id).await.expect("get should not error");
        assert!(result.is_none(), "expected None for missing ID, got Some");
    }

    // -------------------------------------------------------------------------
    // test_query_by_type
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_query_by_type() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        repo.insert(&base_row(make_id(0x10), implant_id.clone(), "credential"))
            .await
            .expect("insert 1");
        repo.insert(&base_row(make_id(0x11), implant_id.clone(), "hash"))
            .await
            .expect("insert 2");
        repo.insert(&base_row(make_id(0x12), implant_id.clone(), "credential"))
            .await
            .expect("insert 3");

        let creds = repo
            .query(Some("credential"), None, None, 100, 0)
            .await
            .expect("query credential");
        assert_eq!(creds.len(), 2, "expected 2 credential entries");
        assert!(creds.iter().all(|r| r.loot_type == "credential"));

        let hashes = repo
            .query(Some("hash"), None, None, 100, 0)
            .await
            .expect("query hash");
        assert_eq!(hashes.len(), 1, "expected 1 hash entry");

        let tokens = repo
            .query(Some("token"), None, None, 100, 0)
            .await
            .expect("query token");
        assert_eq!(tokens.len(), 0, "expected 0 token entries");
    }

    // -------------------------------------------------------------------------
    // test_query_by_implant
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_query_by_implant() {
        let (db, implant_id_a) = setup().await;
        let implant_id_b = make_id(0xBB);
        insert_dummy_implant(db.pool(), &implant_id_b).await;
        let repo = db.loot();

        repo.insert(&base_row(make_id(0x20), implant_id_a.clone(), "credential"))
            .await
            .expect("insert a1");
        repo.insert(&base_row(make_id(0x21), implant_id_a.clone(), "hash"))
            .await
            .expect("insert a2");
        repo.insert(&base_row(make_id(0x22), implant_id_b.clone(), "credential"))
            .await
            .expect("insert b1");

        let for_a = repo
            .query(None, Some(implant_id_a.as_slice()), None, 100, 0)
            .await
            .expect("query implant a");
        assert_eq!(for_a.len(), 2, "expected 2 entries for implant A");
        assert!(for_a.iter().all(|r| r.implant_id == implant_id_a));

        let for_b = repo
            .query(None, Some(implant_id_b.as_slice()), None, 100, 0)
            .await
            .expect("query implant b");
        assert_eq!(for_b.len(), 1, "expected 1 entry for implant B");
    }

    // -------------------------------------------------------------------------
    // test_query_by_username
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_query_by_username() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        let mut row1 = base_row(make_id(0x30), implant_id.clone(), "credential");
        row1.username = Some("administrator".to_string());
        let mut row2 = base_row(make_id(0x31), implant_id.clone(), "credential");
        row2.username = Some("admin_svc".to_string());
        let mut row3 = base_row(make_id(0x32), implant_id.clone(), "credential");
        row3.username = Some("jsmith".to_string());

        repo.insert(&row1).await.expect("insert 1");
        repo.insert(&row2).await.expect("insert 2");
        repo.insert(&row3).await.expect("insert 3");

        // LIKE search — "admin" should match "administrator" and "admin_svc"
        let admin_results = repo
            .query(None, None, Some("admin"), 100, 0)
            .await
            .expect("query by username");
        assert_eq!(admin_results.len(), 2, "expected 2 admin* matches");

        // Exact substring — only "jsmith"
        let jsmith_results = repo
            .query(None, None, Some("jsmith"), 100, 0)
            .await
            .expect("query jsmith");
        assert_eq!(jsmith_results.len(), 1);
        assert_eq!(jsmith_results[0].username.as_deref(), Some("jsmith"));

        // No match
        let none_results = repo
            .query(None, None, Some("noone"), 100, 0)
            .await
            .expect("query noone");
        assert_eq!(none_results.len(), 0);
    }

    // -------------------------------------------------------------------------
    // test_query_pagination
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_query_pagination() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        // Insert 5 credential entries with distinct captured_at so ORDER BY is stable
        for i in 0u8..5 {
            let mut row = base_row(make_id(0x40 + i), implant_id.clone(), "credential");
            row.captured_at = 1_700_000_000_000 + i as i64 * 1_000;
            repo.insert(&row).await.expect("insert");
        }

        // First page: limit 3
        let page1 = repo.query(None, None, None, 3, 0).await.expect("page 1");
        assert_eq!(page1.len(), 3);

        // Second page: limit 3, offset 3 → remaining 2
        let page2 = repo.query(None, None, None, 3, 3).await.expect("page 2");
        assert_eq!(page2.len(), 2);

        // No overlap between pages (IDs are distinct)
        let ids1: Vec<_> = page1.iter().map(|r| r.id.clone()).collect();
        let ids2: Vec<_> = page2.iter().map(|r| r.id.clone()).collect();
        for id in &ids2 {
            assert!(!ids1.contains(id), "page overlap detected");
        }

        // Beyond last page
        let page3 = repo.query(None, None, None, 3, 6).await.expect("page 3");
        assert_eq!(page3.len(), 0);
    }

    // -------------------------------------------------------------------------
    // test_delete
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_delete() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();
        let id = make_id(0x50);
        repo.insert(&base_row(id.clone(), implant_id, "hash"))
            .await
            .expect("insert");

        // Confirm it exists
        assert!(repo.get(&id).await.expect("get before delete").is_some());

        // Delete returns true for an existing row
        let deleted = repo.delete(&id).await.expect("delete");
        assert!(deleted, "delete should return true when a row was removed");

        // Confirm it is gone
        let after = repo.get(&id).await.expect("get after delete");
        assert!(after.is_none(), "row should be absent after delete");

        // Deleting again returns false (no rows affected)
        let deleted_again = repo.delete(&id).await.expect("second delete");
        assert!(!deleted_again, "second delete should return false");
    }

    // -------------------------------------------------------------------------
    // test_count
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_count() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        // Empty table
        assert_eq!(repo.count(None).await.expect("count all"), 0);
        assert_eq!(
            repo.count(Some("credential")).await.expect("count cred empty"),
            0
        );

        repo.insert(&base_row(make_id(0x60), implant_id.clone(), "credential"))
            .await
            .expect("insert 1");
        repo.insert(&base_row(make_id(0x61), implant_id.clone(), "credential"))
            .await
            .expect("insert 2");
        repo.insert(&base_row(make_id(0x62), implant_id.clone(), "hash"))
            .await
            .expect("insert 3");
        repo.insert(&base_row(make_id(0x63), implant_id.clone(), "token"))
            .await
            .expect("insert 4");
        repo.insert(&base_row(make_id(0x64), implant_id.clone(), "file"))
            .await
            .expect("insert 5");

        assert_eq!(repo.count(None).await.expect("count all"), 5);
        assert_eq!(
            repo.count(Some("credential")).await.expect("count cred"),
            2
        );
        assert_eq!(repo.count(Some("hash")).await.expect("count hash"), 1);
        assert_eq!(repo.count(Some("token")).await.expect("count token"), 1);
        assert_eq!(repo.count(Some("file")).await.expect("count file"), 1);
        assert_eq!(
            repo.count(Some("unknown")).await.expect("count unknown"),
            0
        );
    }

    // -------------------------------------------------------------------------
    // test_upsert_credential_deduplication
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_upsert_credential_same_data_deduplicates() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        let mut row = base_row(make_id(0xA0), implant_id.clone(), "credential");
        row.username = Some("jdoe".to_string());
        row.password = Some("P@ssword1".to_string());
        row.domain = Some("CORP".to_string());
        row.source = Some("mimikatz".to_string());

        // First insert — should create a new row.
        let inserted = repo.upsert_credential(&row).await.expect("upsert 1");
        assert!(inserted, "first upsert should insert a new row");
        assert_eq!(repo.count(None).await.expect("count"), 1);

        // Second upsert with identical data — should NOT create a duplicate.
        let mut row2 = base_row(make_id(0xA1), implant_id.clone(), "credential");
        row2.username = Some("jdoe".to_string());
        row2.password = Some("P@ssword1".to_string());
        row2.domain = Some("CORP".to_string());
        row2.source = Some("mimikatz".to_string());
        row2.captured_at = row.captured_at + 5_000; // newer timestamp

        let inserted2 = repo.upsert_credential(&row2).await.expect("upsert 2");
        assert!(!inserted2, "duplicate upsert should return false");
        assert_eq!(
            repo.count(None).await.expect("count after dup"),
            1,
            "table must still have exactly 1 row"
        );
    }

    #[tokio::test]
    async fn test_upsert_credential_rotation_inserts_new_row() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        let mut row = base_row(make_id(0xB0), implant_id.clone(), "credential");
        row.username = Some("alice".to_string());
        row.password = Some("OldPass1!".to_string());
        row.domain = Some("DOMAIN".to_string());
        row.source = Some("harvester".to_string());

        repo.upsert_credential(&row).await.expect("upsert original");

        // Same key but different password — credential rotation.
        let mut row2 = base_row(make_id(0xB1), implant_id.clone(), "credential");
        row2.username = Some("alice".to_string());
        row2.password = Some("NewPass2@".to_string());
        row2.domain = Some("DOMAIN".to_string());
        row2.source = Some("harvester".to_string());

        let inserted = repo.upsert_credential(&row2).await.expect("upsert rotation");
        assert!(inserted, "changed password should insert a new row");
        assert_eq!(
            repo.count(None).await.expect("count after rotation"),
            2,
            "both credential versions should exist"
        );
    }

    #[tokio::test]
    async fn test_upsert_hash_deduplication() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        let hash_val = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0";

        let mut row = base_row(make_id(0xC0), implant_id.clone(), "hash");
        row.username = Some("bob".to_string());
        row.hash_value = Some(hash_val.to_string());
        row.domain = Some("CORP".to_string());
        row.source = Some("dcsync".to_string());

        repo.upsert_credential(&row).await.expect("upsert hash 1");

        let mut row2 = base_row(make_id(0xC1), implant_id.clone(), "hash");
        row2.username = Some("bob".to_string());
        row2.hash_value = Some(hash_val.to_string());
        row2.domain = Some("CORP".to_string());
        row2.source = Some("dcsync".to_string());

        let inserted = repo.upsert_credential(&row2).await.expect("upsert hash 2");
        assert!(!inserted, "same hash should be deduped");
        assert_eq!(repo.count(None).await.expect("count"), 1);
    }

    // -------------------------------------------------------------------------
    // test_search_fts
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_search_fts() {
        let (db, implant_id) = setup().await;
        let repo = db.loot();

        // Credential row with distinctive username/domain
        let mut cred = base_row(make_id(0x70), implant_id.clone(), "credential");
        cred.username = Some("jdoe".to_string());
        cred.domain = Some("ACME".to_string());
        cred.host = Some("fileserver.acme.local".to_string());
        repo.insert(&cred).await.expect("insert cred");

        // File row
        let mut file = base_row(make_id(0x72), implant_id.clone(), "file");
        file.filename = Some("passwords.txt".to_string());
        file.source = Some("file-harvester".to_string());
        repo.insert(&file).await.expect("insert file");

        // Search by username
        let results = repo.search("jdoe", 100).await.expect("search jdoe");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username.as_deref(), Some("jdoe"));

        // Search by domain
        let results = repo.search("ACME", 100).await.expect("search ACME");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain.as_deref(), Some("ACME"));

        // Search by filename — wrap in double-quotes for FTS5 phrase/literal match
        // because '.' is a tokeniser boundary in FTS5.
        let results = repo
            .search("\"passwords.txt\"", 100)
            .await
            .expect("search filename");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filename.as_deref(), Some("passwords.txt"));

        // Search by source — wrap in double-quotes because '-' is the FTS5 NOT operator.
        let results = repo
            .search("\"file-harvester\"", 100)
            .await
            .expect("search source");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source.as_deref(), Some("file-harvester"));

        // No match
        let results = repo
            .search("nonexistent_xyz", 100)
            .await
            .expect("search none");
        assert_eq!(results.len(), 0);

        // Limit is respected: insert another cred row then limit to 1
        let mut cred2 = base_row(make_id(0x73), implant_id.clone(), "credential");
        cred2.domain = Some("ACME".to_string());
        repo.insert(&cred2).await.expect("insert cred2");
        let limited = repo.search("ACME", 1).await.expect("search limited");
        assert_eq!(limited.len(), 1);
    }
}
