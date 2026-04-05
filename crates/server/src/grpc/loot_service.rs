//! LootService gRPC implementation

use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;
use hex;

use db::repos::loot::LootRow;
use kraken_rbac::Permission;
use protocol::{
    loot_entry, CredentialLoot as ProtoCredentialLoot, DeleteLootRequest, DeleteLootResponse,
    ExportLootRequest, ExportLootResponse, FileLoot as ProtoFileLoot, GetLootRequest,
    HashLoot as ProtoHashLoot, ListLootRequest, ListLootResponse, LootEntry, LootService,
    LootType, SearchLootRequest, SearchLootResponse, StoreLootRequest, StoreLootResponse,
    Timestamp, TokenLoot as ProtoTokenLoot, Uuid as ProtoUuid,
};

use crate::auth::{get_cert_identity, resolve_operator, require_permission, OperatorIdentity};
use crate::error::ServerError;
use crate::state::ServerState;

/// Helper to get operator identity, falling back to a mock admin identity
/// in insecure mode (no client certificate present).
async fn get_operator_or_dev<T>(db: &db::Database, request: &Request<T>) -> Result<OperatorIdentity, Status> {
    match get_cert_identity(request) {
        Ok(cert_id) => resolve_operator(db, cert_id).await,
        Err(_) => {
            Ok(OperatorIdentity::new(
                "dev-operator".to_string(),
                kraken_rbac::Role::Admin,
                "dev-mode".to_string(),
            ))
        }
    }
}

pub struct LootServiceImpl {
    state: Arc<ServerState>,
}

impl LootServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

/// Convert a proto LootType i32 to the DB string representation
fn loot_type_to_str(loot_type: i32) -> &'static str {
    match LootType::try_from(loot_type).unwrap_or(LootType::Unspecified) {
        LootType::Credential => "credential",
        LootType::Hash => "hash",
        LootType::Token => "token",
        LootType::File => "file",
        LootType::Unspecified => "unknown",
    }
}

/// Convert a DB loot_type string to proto LootType i32
fn str_to_loot_type(s: &str) -> i32 {
    match s {
        "credential" => LootType::Credential as i32,
        "hash" => LootType::Hash as i32,
        "token" => LootType::Token as i32,
        "file" => LootType::File as i32,
        _ => LootType::Unspecified as i32,
    }
}

/// Convert a LootRow to a proto LootEntry
fn row_to_entry(row: &LootRow) -> Result<LootEntry, Status> {
    let id = ProtoUuid { value: row.id.clone() };
    let implant_id = ProtoUuid { value: row.implant_id.clone() };
    let loot_type = str_to_loot_type(&row.loot_type);

    let data = match row.loot_type.as_str() {
        "credential" => Some(loot_entry::Data::Credential(ProtoCredentialLoot {
            username: row.username.clone().unwrap_or_default(),
            password: row.password.clone().unwrap_or_default(),
            domain: row.domain.clone(),
            realm: None,
            host: row.host.clone(),
        })),
        "hash" => Some(loot_entry::Data::Hash(ProtoHashLoot {
            username: row.username.clone().unwrap_or_default(),
            hash: row.hash_value.clone().unwrap_or_default(),
            hash_type: row.hash_type.clone().unwrap_or_default(),
            domain: row.domain.clone(),
        })),
        "token" => Some(loot_entry::Data::Token(ProtoTokenLoot {
            token_type: row.token_type.clone().unwrap_or_default(),
            token_value: row
                .token_data
                .as_deref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
            service: row.service.clone(),
            expires_at: row.expires_at.map(Timestamp::from_millis),
        })),
        "file" => Some(loot_entry::Data::File(ProtoFileLoot {
            filename: row.filename.clone().unwrap_or_default(),
            original_path: row.original_path.clone().unwrap_or_default(),
            content: vec![],  // blob content not loaded from DB row
            size: row.file_size.unwrap_or(0) as u64,
            description: None,
        })),
        _ => None,
    };

    Ok(LootEntry {
        id: Some(id),
        implant_id: Some(implant_id),
        loot_type,
        source: row.source.clone().unwrap_or_default(),
        collected_at: Some(Timestamp::from_millis(row.captured_at)),
        data,
    })
}

/// Build a LootRow from a StoreLootRequest with a freshly-generated ID
fn store_request_to_row(req: &StoreLootRequest) -> Result<LootRow, Status> {
    let implant_id = req
        .implant_id
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("missing implant_id"))?;

    if implant_id.value.len() != 16 {
        return Err(Status::invalid_argument("implant_id must be 16 bytes"));
    }

    let loot_id = Uuid::new_v4();
    let loot_type_str = loot_type_to_str(req.loot_type).to_string();
    let now = chrono::Utc::now().timestamp_millis();

    let mut row = LootRow {
        id: loot_id.as_bytes().to_vec(),
        implant_id: implant_id.value.clone(),
        task_id: None,
        loot_type: loot_type_str,
        captured_at: now,
        source: Some(req.source.clone()),
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
    };

    match &req.data {
        Some(protocol::store_loot_request::Data::Credential(c)) => {
            row.username = Some(c.username.clone());
            row.password = Some(c.password.clone());
            row.domain = c.domain.clone();
            row.host = c.host.clone();
        }
        Some(protocol::store_loot_request::Data::Hash(h)) => {
            row.username = Some(h.username.clone());
            row.hash_value = Some(h.hash.clone());
            row.hash_type = Some(h.hash_type.clone());
            row.domain = h.domain.clone();
        }
        Some(protocol::store_loot_request::Data::Token(t)) => {
            row.token_type = Some(t.token_type.clone());
            row.token_data = Some(t.token_value.as_bytes().to_vec());
            row.service = t.service.clone();
            row.expires_at = t.expires_at.as_ref().map(|ts| ts.millis);
        }
        Some(protocol::store_loot_request::Data::File(f)) => {
            row.filename = Some(f.filename.clone());
            row.original_path = Some(f.original_path.clone());
            row.file_size = Some(f.size as i64);
        }
        None => {
            return Err(Status::invalid_argument("missing loot data"));
        }
    }

    Ok(row)
}

#[tonic::async_trait]
impl LootService for LootServiceImpl {
    async fn store_loot(
        &self,
        request: Request<StoreLootRequest>,
    ) -> Result<Response<StoreLootResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::LootView)?;

        let req = request.into_inner();
        let row = store_request_to_row(&req)?;
        let loot_id_bytes = row.id.clone();

        // Credentials and hashes use upsert to avoid duplicates.
        // All other loot types (tokens, files) are always inserted as new rows.
        if matches!(row.loot_type.as_str(), "credential" | "hash") {
            self.state
                .db
                .loot()
                .upsert_credential(&row)
                .await
                .map_err(|e| Status::from(ServerError::from(e)))?;
        } else {
            self.state
                .db
                .loot()
                .insert(&row)
                .await
                .map_err(|e| Status::from(ServerError::from(e)))?;
        }

        tracing::info!(
            loot_type = %row.loot_type,
            "loot stored"
        );

        // Publish LootCaptured event for WebSocket real-time updates
        let description = match row.loot_type.as_str() {
            "credential" => format!(
                "{}@{}",
                row.username.as_deref().unwrap_or(""),
                row.domain.as_deref().or(row.host.as_deref()).unwrap_or("")
            ),
            "hash" => format!(
                "{} ({})",
                row.username.as_deref().unwrap_or(""),
                row.hash_type.as_deref().unwrap_or("unknown")
            ),
            "token" => format!(
                "{} token",
                row.token_type.as_deref().unwrap_or("unknown")
            ),
            "file" => row.filename.clone().unwrap_or_else(|| "file".to_string()),
            _ => "loot".to_string(),
        };

        self.state.publish_loot(crate::state::LootEvent {
            loot_id: loot_id_bytes.clone(),
            implant_id: row.implant_id.clone(),
            loot_type: row.loot_type.clone(),
            description,
        });

        // Webhook: CredentialCaptured (credentials and hashes)
        if matches!(row.loot_type.as_str(), "credential" | "hash") {
            let wh_data = serde_json::json!({
                "loot_type": row.loot_type,
                "implant_id": hex::encode(&row.implant_id),
                "username": row.username,
                "domain": row.domain,
                "host": row.host,
            });
            self.state.notify_webhook(
                crate::webhook::WebhookEvent::CredentialCaptured,
                wh_data,
            ).await;
        }

        // Webhook: FileDownloaded
        if row.loot_type == "file" {
            let wh_data = serde_json::json!({
                "loot_type": row.loot_type,
                "implant_id": hex::encode(&row.implant_id),
                "filename": row.filename,
                "original_path": row.original_path,
                "file_size": row.file_size,
            });
            self.state.notify_webhook(
                crate::webhook::WebhookEvent::FileDownloaded,
                wh_data,
            ).await;
        }

        Ok(Response::new(StoreLootResponse {
            loot_id: Some(ProtoUuid { value: loot_id_bytes }),
        }))
    }

    async fn get_loot(
        &self,
        request: Request<GetLootRequest>,
    ) -> Result<Response<LootEntry>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::LootView)?;

        let req = request.into_inner();
        let loot_id = req
            .loot_id
            .ok_or_else(|| Status::invalid_argument("missing loot_id"))?;

        if loot_id.value.len() != 16 {
            return Err(Status::invalid_argument("loot_id must be 16 bytes"));
        }

        let row = self
            .state
            .db
            .loot()
            .get(&loot_id.value)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found("loot entry not found"))?;

        Ok(Response::new(row_to_entry(&row)?))
    }

    async fn list_loot(
        &self,
        request: Request<ListLootRequest>,
    ) -> Result<Response<ListLootResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::LootView)?;

        let req = request.into_inner();

        let implant_id_bytes: Option<Vec<u8>> = req
            .implant_id
            .map(|uuid| {
                if uuid.value.len() != 16 {
                    Err(Status::invalid_argument("implant_id must be 16 bytes"))
                } else {
                    Ok(uuid.value)
                }
            })
            .transpose()?;

        let type_filter: Option<String> = req
            .type_filter
            .filter(|&v| v != 0)
            .map(|v| loot_type_to_str(v).to_string());

        let limit = req.limit.unwrap_or(100) as i32;
        let offset = req.offset.unwrap_or(0) as i32;

        let rows = self
            .state
            .db
            .loot()
            .query(
                type_filter.as_deref(),
                implant_id_bytes.as_deref(),
                None,
                limit,
                offset,
            )
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let total_count = self
            .state
            .db
            .loot()
            .count(type_filter.as_deref())
            .await
            .map_err(|e| Status::from(ServerError::from(e)))? as u32;

        let entries: Vec<LootEntry> = rows
            .iter()
            .map(row_to_entry)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Response::new(ListLootResponse {
            entries,
            total_count,
        }))
    }

    async fn delete_loot(
        &self,
        request: Request<DeleteLootRequest>,
    ) -> Result<Response<DeleteLootResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::LootDelete)?;

        let req = request.into_inner();
        let loot_id = req
            .loot_id
            .ok_or_else(|| Status::invalid_argument("missing loot_id"))?;

        if loot_id.value.len() != 16 {
            return Err(Status::invalid_argument("loot_id must be 16 bytes"));
        }

        let deleted = self
            .state
            .db
            .loot()
            .delete(&loot_id.value)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        tracing::info!(deleted = deleted, "loot deleted");

        Ok(Response::new(DeleteLootResponse { success: deleted }))
    }

    async fn search_loot(
        &self,
        request: Request<SearchLootRequest>,
    ) -> Result<Response<SearchLootResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::LootView)?;

        let req = request.into_inner();

        if req.query.is_empty() {
            return Err(Status::invalid_argument("query must not be empty"));
        }

        let limit = if req.limit <= 0 { 100 } else { req.limit };

        let rows = self
            .state
            .db
            .loot()
            .search(&req.query, limit)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let total_count = rows.len() as u32;
        let entries: Vec<LootEntry> = rows
            .iter()
            .map(row_to_entry)
            .collect::<Result<Vec<_>, _>>()?;

        tracing::debug!(query = %req.query, results = total_count, "loot FTS search");

        Ok(Response::new(SearchLootResponse {
            entries,
            total_count,
        }))
    }

    async fn export_loot(
        &self,
        request: Request<ExportLootRequest>,
    ) -> Result<Response<ExportLootResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::LootExport)?;

        let req = request.into_inner();

        let implant_id_bytes: Option<Vec<u8>> = req
            .implant_id
            .map(|uuid| {
                if uuid.value.len() != 16 {
                    Err(Status::invalid_argument("implant_id must be 16 bytes"))
                } else {
                    Ok(uuid.value)
                }
            })
            .transpose()?;

        let type_filter: Option<String> = req
            .type_filter
            .filter(|&v| v != 0)
            .map(|v| loot_type_to_str(v).to_string());

        let rows = self
            .state
            .db
            .loot()
            .query(
                type_filter.as_deref(),
                implant_id_bytes.as_deref(),
                None,
                10000,
                0,
            )
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let entries: Vec<LootEntry> = rows
            .iter()
            .map(row_to_entry)
            .collect::<Result<Vec<_>, _>>()?;

        let (data, filename) = match req.format.as_str() {
            "csv" => {
                let mut out = String::from("id,implant_id,loot_type,source,collected_at\n");
                for row in &rows {
                    let id_hex = hex::encode(&row.id);
                    let implant_hex = hex::encode(&row.implant_id);
                    out.push_str(&format!(
                        "{},{},{},{},{}\n",
                        id_hex,
                        implant_hex,
                        row.loot_type,
                        row.source.as_deref().unwrap_or(""),
                        row.captured_at,
                    ));
                }
                (out.into_bytes(), "loot_export.csv".to_string())
            }
            "markdown" | "md" => {
                let mut out = String::from("# Kraken Loot Export\n\n");
                out.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")));

                // Credentials section
                let creds: Vec<_> = rows.iter().filter(|r| r.loot_type == "credential").collect();
                if !creds.is_empty() {
                    out.push_str(&format!("## Credentials ({})\n\n", creds.len()));
                    out.push_str("| Username | Domain | Host | Port | Source | Captured |\n");
                    out.push_str("|----------|--------|------|------|--------|----------|\n");
                    for row in creds {
                        let username = row.username.as_deref().unwrap_or("");
                        let domain = row.domain.as_deref().unwrap_or("");
                        let host = row.host.as_deref().unwrap_or("");
                        let port = row.port.map(|p| p.to_string()).unwrap_or_default();
                        let source = row.source.as_deref().unwrap_or("");
                        out.push_str(&format!(
                            "| {} | {} | {} | {} | {} | {} |\n",
                            username, domain, host, port, source, row.captured_at
                        ));
                    }
                    out.push('\n');
                }

                // Hashes section
                let hashes: Vec<_> = rows.iter().filter(|r| r.loot_type == "hash").collect();
                if !hashes.is_empty() {
                    out.push_str(&format!("## Hashes ({})\n\n", hashes.len()));
                    out.push_str("| Username | Hash Type | Hash | Domain | Source | Captured |\n");
                    out.push_str("|----------|-----------|------|--------|--------|----------|\n");
                    for row in hashes {
                        let username = row.username.as_deref().unwrap_or("");
                        let hash_type = row.hash_type.as_deref().unwrap_or("");
                        let hash_value = row.hash_value.as_deref().unwrap_or("");
                        let domain = row.domain.as_deref().unwrap_or("");
                        let source = row.source.as_deref().unwrap_or("");
                        out.push_str(&format!(
                            "| {} | {} | {} | {} | {} | {} |\n",
                            username, hash_type, hash_value, domain, source, row.captured_at
                        ));
                    }
                    out.push('\n');
                }

                // Tokens section
                let tokens: Vec<_> = rows.iter().filter(|r| r.loot_type == "token").collect();
                if !tokens.is_empty() {
                    out.push_str(&format!("## Tokens ({})\n\n", tokens.len()));
                    out.push_str("| Token Type | Service | Expires At | Source | Captured |\n");
                    out.push_str("|------------|---------|------------|--------|----------|\n");
                    for row in tokens {
                        let token_type = row.token_type.as_deref().unwrap_or("");
                        let service = row.service.as_deref().unwrap_or("");
                        let expires = row.expires_at.map(|ts| ts.to_string()).unwrap_or_else(|| "N/A".to_string());
                        let source = row.source.as_deref().unwrap_or("");
                        out.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            token_type, service, expires, source, row.captured_at
                        ));
                    }
                    out.push('\n');
                }

                // Files section
                let files: Vec<_> = rows.iter().filter(|r| r.loot_type == "file").collect();
                if !files.is_empty() {
                    out.push_str(&format!("## Files ({})\n\n", files.len()));
                    out.push_str("| Filename | Original Path | Size | Source | Captured |\n");
                    out.push_str("|----------|---------------|------|--------|----------|\n");
                    for row in files {
                        let filename = row.filename.as_deref().unwrap_or("");
                        let original_path = row.original_path.as_deref().unwrap_or("");
                        let size = row.file_size.unwrap_or(0);
                        let source = row.source.as_deref().unwrap_or("");
                        out.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            filename, original_path, size, source, row.captured_at
                        ));
                    }
                    out.push('\n');
                }

                (out.into_bytes(), "loot_export.md".to_string())
            }
            _ => {
                // Default: JSON
                let json = serde_json::to_vec_pretty(&entries.iter().map(|e| {
                    // Serialize to a basic JSON value since LootEntry is prost generated
                    serde_json::json!({
                        "id": e.id.as_ref().map(|u| hex::encode(&u.value)),
                        "implant_id": e.implant_id.as_ref().map(|u| hex::encode(&u.value)),
                        "loot_type": e.loot_type,
                        "source": e.source,
                        "collected_at": e.collected_at.as_ref().map(|t| t.millis),
                    })
                }).collect::<Vec<_>>())
                .map_err(|e| Status::internal(format!("json serialization error: {}", e)))?;
                (json, "loot_export.json".to_string())
            }
        };

        Ok(Response::new(ExportLootResponse { data, filename }))
    }
}
