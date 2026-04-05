//! ReportService gRPC implementation
//!
//! Provides report generation capabilities for engagements, sessions, and loot.

use std::collections::HashMap;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;

use kraken_rbac::Permission;
use protocol::{
    DeleteReportRequest, DeleteReportResponse, GenerateReportRequest, GenerateReportResponse,
    GetReportRequest, ListReportsRequest, ListReportsResponse, ReportRecord,
    report_service_server::ReportService, Timestamp,
};

use crate::auth::{get_cert_identity, resolve_operator, require_permission, OperatorIdentity};
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

/// In-memory store for generated reports (keyed by report id bytes)
#[allow(dead_code)]
struct StoredReport {
    record: ReportRecord,
    content: Vec<u8>,
}

pub struct ReportServiceImpl {
    state: Arc<ServerState>,
    /// In-memory report store protected by a tokio RwLock
    reports: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, StoredReport>>>,
}

impl ReportServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self {
            state,
            reports: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Generate a JSON report from sessions, tasks, and loot data
    async fn generate_json_report(
        &self,
        req: &GenerateReportRequest,
    ) -> Result<(Vec<u8>, u32, u32), Status> {
        let start_ms = req.start_date.as_ref().map(|t| t.millis).unwrap_or(0);
        let end_ms = req.end_date.as_ref().map(|t| t.millis).unwrap_or(i64::MAX);

        // Fetch sessions
        let sessions = if req.include_sessions {
            self.state
                .db
                .implants()
                .list()
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?
                .into_iter()
                .filter(|r| r.registered_at >= start_ms && r.registered_at <= end_ms)
                .map(|r| {
                    serde_json::json!({
                        "id": hex::encode(r.id.as_bytes()),
                        "name": r.name,
                        "hostname": r.hostname.as_deref().unwrap_or("-"),
                        "username": r.username.as_deref().unwrap_or("-"),
                        "os": format!("{} {}",
                            r.os_name.as_deref().unwrap_or("Unknown"),
                            r.os_version.as_deref().unwrap_or("")
                        ),
                        "process": r.process_name.as_deref().unwrap_or("-"),
                        "registered_at": r.registered_at,
                        "last_seen": r.last_seen,
                    })
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        // Fetch loot
        let loot = if req.include_loot {
            self.state
                .db
                .loot()
                .query(None, None, None, 1000, 0)
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": hex::encode(&r.id),
                        "type": r.loot_type,
                        "source": r.source.as_deref().unwrap_or("-"),
                        "captured_at": r.captured_at,
                    })
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        let session_count = sessions.len() as u32;
        let task_count = 0u32; // Tasks require implant_id, skip for now

        // Build report JSON
        let report = serde_json::json!({
            "title": req.title,
            "report_type": req.report_type,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "date_range": {
                "start": start_ms,
                "end": end_ms,
            },
            "summary": {
                "session_count": session_count,
                "task_count": task_count,
                "loot_count": loot.len(),
            },
            "sessions": sessions,
            "loot": loot,
        });

        let content = serde_json::to_vec_pretty(&report)
            .map_err(|e| Status::internal(format!("json error: {e}")))?;

        Ok((content, session_count, task_count))
    }

    /// Generate a Markdown report
    async fn generate_markdown_report(
        &self,
        req: &GenerateReportRequest,
    ) -> Result<(Vec<u8>, u32, u32), Status> {
        let start_ms = req.start_date.as_ref().map(|t| t.millis).unwrap_or(0);
        let end_ms = req.end_date.as_ref().map(|t| t.millis).unwrap_or(i64::MAX);

        let sessions = if req.include_sessions {
            self.state
                .db
                .implants()
                .list()
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?
                .into_iter()
                .filter(|r| r.registered_at >= start_ms && r.registered_at <= end_ms)
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        let loot = if req.include_loot {
            self.state
                .db
                .loot()
                .query(None, None, None, 1000, 0)
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?
        } else {
            vec![]
        };

        let session_count = sessions.len() as u32;
        let task_count = 0u32;

        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", req.title));
        md.push_str(&format!("**Report Type:** {}\n\n", req.report_type));
        md.push_str(&format!("**Generated:** {}\n\n", chrono::Utc::now().to_rfc3339()));
        md.push_str("---\n\n");

        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Sessions:** {}\n", session_count));
        md.push_str(&format!("- **Tasks:** {}\n", task_count));
        md.push_str(&format!("- **Loot Items:** {}\n\n", loot.len()));

        if req.include_sessions && !sessions.is_empty() {
            md.push_str("## Sessions\n\n");
            md.push_str("| Hostname | Username | OS | Process | Registered |\n");
            md.push_str("|----------|----------|----|---------|-----------|\n");
            for s in &sessions {
                md.push_str(&format!(
                    "| {} | {} | {} {} | {} | {} |\n",
                    s.hostname.as_deref().unwrap_or("-"),
                    s.username.as_deref().unwrap_or("-"),
                    s.os_name.as_deref().unwrap_or("Unknown"),
                    s.os_version.as_deref().unwrap_or(""),
                    s.process_name.as_deref().unwrap_or("-"),
                    s.registered_at
                ));
            }
            md.push_str("\n");
        }

        if req.include_loot && !loot.is_empty() {
            md.push_str("## Loot\n\n");
            md.push_str("| Type | Source | Captured |\n");
            md.push_str("|------|--------|----------|\n");
            for l in &loot {
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    l.loot_type,
                    l.source.as_deref().unwrap_or("-"),
                    l.captured_at
                ));
            }
            md.push_str("\n");
        }

        Ok((md.into_bytes(), session_count, task_count))
    }
}

#[tonic::async_trait]
impl ReportService for ReportServiceImpl {
    async fn generate_report(
        &self,
        request: Request<GenerateReportRequest>,
    ) -> Result<Response<GenerateReportResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::ReportGenerate)?;

        let req = request.into_inner();

        if req.title.is_empty() {
            return Err(Status::invalid_argument("title must not be empty"));
        }

        // Generate report based on format
        let (content, session_count, task_count) = match req.output_format.as_str() {
            "markdown" | "md" => self.generate_markdown_report(&req).await?,
            _ => self.generate_json_report(&req).await?,
        };

        let report_id = Uuid::new_v4().as_bytes().to_vec();
        let now_ms = chrono::Utc::now().timestamp_millis();

        let record = ReportRecord {
            id: report_id.clone(),
            title: req.title.clone(),
            report_type: req.report_type.clone(),
            output_format: req.output_format.clone(),
            generated_at: Some(Timestamp { millis: now_ms }),
            generated_by: operator.username.clone(),
            start_date: req.start_date.clone(),
            end_date: req.end_date.clone(),
            session_count,
            task_count,
            size: content.len() as u64,
        };

        // Store in memory
        self.reports.write().await.insert(
            report_id,
            StoredReport {
                record: record.clone(),
                content: content.clone(),
            },
        );

        tracing::info!(
            title = %req.title,
            report_type = %req.report_type,
            format = %req.output_format,
            size = content.len(),
            "report generated"
        );

        Ok(Response::new(GenerateReportResponse {
            report: Some(record),
            content,
        }))
    }

    async fn list_reports(
        &self,
        request: Request<ListReportsRequest>,
    ) -> Result<Response<ListReportsResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::ReportView)?;

        let store = self.reports.read().await;
        let reports: Vec<ReportRecord> = store.values().map(|s| s.record.clone()).collect();

        Ok(Response::new(ListReportsResponse { reports }))
    }

    async fn get_report(
        &self,
        request: Request<GetReportRequest>,
    ) -> Result<Response<ReportRecord>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::ReportView)?;

        let req = request.into_inner();

        if req.report_id.len() != 16 {
            return Err(Status::invalid_argument("report_id must be 16 bytes"));
        }

        let store = self.reports.read().await;
        let stored = store
            .get(&req.report_id)
            .ok_or_else(|| Status::not_found("report not found"))?;

        Ok(Response::new(stored.record.clone()))
    }

    async fn delete_report(
        &self,
        request: Request<DeleteReportRequest>,
    ) -> Result<Response<DeleteReportResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::ReportGenerate)?;

        let req = request.into_inner();

        if req.report_id.len() != 16 {
            return Err(Status::invalid_argument("report_id must be 16 bytes"));
        }

        let mut store = self.reports.write().await;
        let removed = store.remove(&req.report_id).is_some();

        tracing::info!(deleted = removed, "report deleted");

        Ok(Response::new(DeleteReportResponse { success: removed }))
    }
}
