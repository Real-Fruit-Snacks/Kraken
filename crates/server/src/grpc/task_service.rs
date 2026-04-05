//! TaskService gRPC implementation

use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use common::{ImplantId, OperatorId, TaskId};
use db::{TaskRecord, repos::{FileTransfer, JobRow}};
use kraken_audit::{AuditCategory, AuditEvent, AuditOutcome};
use kraken_rbac::Permission;
use protocol::{
    CancelTaskRequest, DispatchTaskRequest, DispatchTaskResponse, GetTaskRequest,
    GetTransferStatusRequest, ListActiveTransfersRequest, ListActiveTransfersResponse,
    ListTasksRequest, ListTasksResponse, StreamTaskResultsRequest, Task as ProtoTask,
    TaskInfo, TaskResultEvent, TaskService, TaskStatus as ProtoTaskStatus, Timestamp,
    FileTransferStatus, TransferState, FileUploadChunked, FileDownloadChunked,
};
use prost::Message;

use crate::auth::{get_cert_identity, resolve_operator, require_permission, OperatorIdentity};
use crate::error::ServerError;
use crate::state::ServerState;

/// Helper to get operator identity, falling back to a mock admin identity
/// in insecure mode (no client certificate present).
async fn get_operator_or_dev<T>(db: &db::Database, request: &Request<T>) -> Result<OperatorIdentity, Status> {
    match get_cert_identity(request) {
        Ok(cert_id) => resolve_operator(db, cert_id).await,
        Err(_) => {
            // No client certificate — insecure/dev mode: return a mock admin operator.
            Ok(OperatorIdentity::new(
                "dev-operator".to_string(),
                kraken_rbac::Role::Admin,
                "dev-mode".to_string(),
            ))
        }
    }
}

pub struct TaskServiceImpl {
    state: Arc<ServerState>,
    /// System operator ID used when no authenticated operator context is available
    system_operator_id: OperatorId,
}

impl TaskServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self {
            state,
            // Use a fixed system operator ID (all zeros) for determinism
            system_operator_id: OperatorId::from_bytes(&[0u8; 16]).unwrap(),
        }
    }

    /// Create TaskServiceImpl and ensure the system operator exists in DB
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
}

/// Map a status string from the DB to the proto TaskStatus enum value
fn status_str_to_proto(s: &str) -> i32 {
    match s {
        "queued" => ProtoTaskStatus::Queued as i32,
        "dispatched" => ProtoTaskStatus::Dispatched as i32,
        "completed" => ProtoTaskStatus::Completed as i32,
        "failed" => ProtoTaskStatus::Failed as i32,
        "cancelled" => ProtoTaskStatus::Cancelled as i32,
        "expired" => ProtoTaskStatus::Expired as i32,
        _ => ProtoTaskStatus::Unspecified as i32,
    }
}

fn record_to_task_info(r: &TaskRecord) -> TaskInfo {
    TaskInfo {
        task_id: Some(r.id.into()),
        implant_id: Some(r.implant_id.into()),
        operator_id: Some(r.operator_id.into()),
        task_type: r.task_type.clone(),
        status: status_str_to_proto(&r.status),
        issued_at: Some(Timestamp::from_millis(r.issued_at)),
        dispatched_at: r.dispatched_at.map(Timestamp::from_millis),
        completed_at: r.completed_at.map(Timestamp::from_millis),
        result_data: r.result_data.clone().unwrap_or_default(),
        error: r.error_message.as_deref().map(|msg| protocol::TaskError {
            code: -1,
            message: msg.to_string(),
            details: None,
        }),
    }
}

#[tonic::async_trait]
impl TaskService for TaskServiceImpl {
    async fn dispatch_task(
        &self,
        request: Request<DispatchTaskRequest>,
    ) -> Result<Response<DispatchTaskResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionInteract)?;

        let req = request.into_inner();

        let implant_id: ImplantId = req
            .implant_id
            .ok_or_else(|| Status::invalid_argument("missing implant_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        // Verify implant exists and is taskable
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

        let task_id = TaskId::new();
        let now = chrono::Utc::now().timestamp_millis();

        let task_record = TaskRecord {
            id: task_id,
            implant_id,
            operator_id: self.system_operator_id,
            task_type: req.task_type.clone(),
            task_data: req.task_data.clone(),
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

        // Track file transfers if this is a chunked upload/download
        if task_record.task_type == "file_upload_chunked" {
            if let Ok(upload) = FileUploadChunked::decode(&task_record.task_data[..]) {
                // Only create transfer record on first chunk
                if upload.chunk_index == 0 {
                    let transfer = FileTransfer {
                        transfer_id: upload.transfer_id.clone(),
                        implant_id: implant_id.as_bytes().to_vec(),
                        file_path: upload.remote_path.clone(),
                        direction: "upload".to_string(),
                        total_size: upload.total_size as i64,
                        bytes_transferred: 0,
                        chunks_completed: 0,
                        total_chunks: upload.total_chunks as i64,
                        state: "initializing".to_string(),
                        error: None,
                        started_at: chrono::Utc::now().timestamp(),
                        completed_at: None,
                    };
                    let _ = self.state.db.file_transfers().create(&transfer).await;
                }
            }
        } else if task_record.task_type == "file_download_chunked" {
            if let Ok(download) = FileDownloadChunked::decode(&task_record.task_data[..]) {
                // Only create transfer record on first chunk request
                if download.chunk_index == 0 {
                    // For downloads, we don't know total size yet, set to 0
                    let transfer = FileTransfer {
                        transfer_id: download.transfer_id.clone(),
                        implant_id: implant_id.as_bytes().to_vec(),
                        file_path: download.remote_path.clone(),
                        direction: "download".to_string(),
                        total_size: 0,  // Will be updated on first response
                        bytes_transferred: 0,
                        chunks_completed: 0,
                        total_chunks: 0,  // Will be calculated on first response
                        state: "initializing".to_string(),
                        error: None,
                        started_at: chrono::Utc::now().timestamp(),
                        completed_at: None,
                    };
                    let _ = self.state.db.file_transfers().create(&transfer).await;
                }
            }
        }

        // Create background job for long-running tasks
        let should_create_job = matches!(
            task_record.task_type.as_str(),
            "process_dump" | "screenshot" | "file_download_chunked" | "wifi"
        );

        if should_create_job {
            // Generate next job ID (simple incrementing ID)
            let job_id = chrono::Utc::now().timestamp_millis();

            let description = match task_record.task_type.as_str() {
                "process_dump" => "Process memory dump".to_string(),
                "screenshot" => "Screen capture".to_string(),
                "file_download_chunked" => "Large file download".to_string(),
                "wifi" => "WiFi credentials enumeration".to_string(),
                _ => format!("Task: {}", task_record.task_type),
            };

            let job = JobRow {
                job_id,
                implant_id: implant_id.as_bytes().to_vec(),
                task_id: task_id.as_bytes().to_vec(),
                description,
                status: "running".to_string(),
                progress: 0,
                created_at: now,
                completed_at: None,
                error_message: None,
                output_size: 0,
            };

            let _ = self.state.db.jobs().create(&job).await;
            tracing::info!(job_id = %job_id, task_id = %task_id, "background job created");
        }

        // Queue the proto task for delivery on next implant check-in
        let proto_task = ProtoTask {
            task_id: Some(task_id.into()),
            task_type: req.task_type,
            task_data: req.task_data,
            issued_at: Some(Timestamp::from_millis(now)),
            operator_id: Some(self.system_operator_id.into()),
        };
        self.state.enqueue_task(implant_id, proto_task);

        // Emit audit event for task dispatch
        let _ = self.state.audit.record(
            AuditEvent::builder(AuditCategory::Task, "dispatch")
                .outcome(AuditOutcome::Success)
                .session(implant_id.to_uuid())
                .details(serde_json::json!({
                    "task_id": task_id.to_string(),
                    "task_type": task_record.task_type,
                })),
        );

        tracing::info!(task_id = %task_id, implant_id = %implant_id, "task dispatched");

        Ok(Response::new(DispatchTaskResponse {
            task_id: Some(task_id.into()),
        }))
    }

    async fn get_task(
        &self,
        request: Request<GetTaskRequest>,
    ) -> Result<Response<TaskInfo>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();
        let task_id: TaskId = req
            .task_id
            .ok_or_else(|| Status::invalid_argument("missing task_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        let record = self
            .state
            .db
            .tasks()
            .get(task_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found(format!("task {} not found", task_id)))?;

        Ok(Response::new(record_to_task_info(&record)))
    }

    async fn list_tasks(
        &self,
        request: Request<ListTasksRequest>,
    ) -> Result<Response<ListTasksResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();

        let implant_id: Option<ImplantId> = req
            .implant_id
            .map(|uuid| {
                uuid.try_into()
                    .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))
            })
            .transpose()?;

        // Fetch pending tasks if implant_id provided, else fall through with empty
        // The db task repo only has list_pending; for a full list we use it as a base
        let records = if let Some(id) = implant_id {
            self.state
                .db
                .tasks()
                .list_pending(id)
                .await
                .map_err(|e| Status::from(ServerError::from(e)))?
        } else {
            vec![]
        };

        // Apply status filter if set
        let status_filter = req.status_filter.filter(|&v| v != 0);
        let tasks: Vec<TaskInfo> = records
            .iter()
            .filter(|r| {
                if let Some(filter) = status_filter {
                    status_str_to_proto(&r.status) == filter
                } else {
                    true
                }
            })
            .map(record_to_task_info)
            .take(req.limit.unwrap_or(100) as usize)
            .collect();

        Ok(Response::new(ListTasksResponse { tasks }))
    }

    async fn cancel_task(
        &self,
        request: Request<CancelTaskRequest>,
    ) -> Result<Response<TaskInfo>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionInteract)?;

        let req = request.into_inner();
        let task_id: TaskId = req
            .task_id
            .ok_or_else(|| Status::invalid_argument("missing task_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        let record = self
            .state
            .db
            .tasks()
            .get(task_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found(format!("task {} not found", task_id)))?;

        let already_terminal =
            matches!(record.status.as_str(), "completed" | "failed" | "cancelled");
        if already_terminal {
            return Err(Status::failed_precondition(format!(
                "task {} is already in terminal state '{}'",
                task_id, record.status
            )));
        }

        self.state
            .db
            .tasks()
            .update_result(task_id, "cancelled", None, Some("cancelled by operator"))
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Remove from in-memory queue if it hasn't been dispatched yet
        if let Some(mut tasks) = self.state.pending_tasks.get_mut(&record.implant_id) {
            tasks.retain(|t| {
                t.task_id
                    .as_ref()
                    .and_then(|uuid| TaskId::from_bytes(&uuid.value).ok())
                    .map(|id| id != task_id)
                    .unwrap_or(true)
            });
        }

        // Return updated record
        let updated = self
            .state
            .db
            .tasks()
            .get(task_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::internal("task disappeared after update"))?;

        tracing::info!(task_id = %task_id, "task cancelled");

        Ok(Response::new(record_to_task_info(&updated)))
    }

    type StreamTaskResultsStream = std::pin::Pin<
        Box<dyn futures_core::Stream<Item = Result<TaskResultEvent, Status>> + Send + 'static>,
    >;

    async fn stream_task_results(
        &self,
        request: Request<StreamTaskResultsRequest>,
    ) -> Result<Response<Self::StreamTaskResultsStream>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();
        let filter_implant: Option<ImplantId> = req
            .implant_id
            .map(|uuid| {
                uuid.try_into()
                    .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))
            })
            .transpose()?;

        let rx = self.state.subscribe_task_results();
        let stream = BroadcastStream::new(rx).filter_map(move |result| {
            match result {
                Ok(event) => {
                    // If a filter was specified, only pass events for that implant
                    if let Some(filter_id) = filter_implant {
                        let event_implant_id = event
                            .implant_id
                            .as_ref()
                            .and_then(|uuid| ImplantId::from_bytes(&uuid.value).ok());
                        if event_implant_id != Some(filter_id) {
                            return None;
                        }
                    }
                    Some(Ok(event))
                }
                Err(_lagged) => None, // skip lagged messages
            }
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_transfer_status(
        &self,
        request: Request<GetTransferStatusRequest>,
    ) -> Result<Response<FileTransferStatus>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();

        let transfer = self
            .state
            .db
            .file_transfers()
            .get(&req.transfer_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found(format!("transfer {} not found", req.transfer_id)))?;

        let state = match transfer.state.as_str() {
            "initializing" => TransferState::Initializing as i32,
            "in_progress" => TransferState::InProgress as i32,
            "paused" => TransferState::Paused as i32,
            "completed" => TransferState::Completed as i32,
            "failed" => TransferState::Failed as i32,
            _ => TransferState::Unspecified as i32,
        };

        Ok(Response::new(FileTransferStatus {
            transfer_id: transfer.transfer_id,
            file_path: transfer.file_path,
            total_size: transfer.total_size as u64,
            bytes_transferred: transfer.bytes_transferred as u64,
            chunks_completed: transfer.chunks_completed as u64,
            total_chunks: transfer.total_chunks as u64,
            state,
            error: transfer.error,
        }))
    }

    async fn list_active_transfers(
        &self,
        request: Request<ListActiveTransfersRequest>,
    ) -> Result<Response<ListActiveTransfersResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();

        let transfers = if let Some(implant_uuid) = req.implant_id {
            let implant_id = implant_uuid.value;
            self.state
                .db
                .file_transfers()
                .list_by_implant(&implant_id)
                .await
                .map_err(|e| Status::from(ServerError::from(e)))?
        } else {
            self.state
                .db
                .file_transfers()
                .list_active()
                .await
                .map_err(|e| Status::from(ServerError::from(e)))?
        };

        let transfer_statuses: Vec<FileTransferStatus> = transfers
            .into_iter()
            .map(|t| {
                let state = match t.state.as_str() {
                    "initializing" => TransferState::Initializing as i32,
                    "in_progress" => TransferState::InProgress as i32,
                    "paused" => TransferState::Paused as i32,
                    "completed" => TransferState::Completed as i32,
                    "failed" => TransferState::Failed as i32,
                    _ => TransferState::Unspecified as i32,
                };

                FileTransferStatus {
                    transfer_id: t.transfer_id,
                    file_path: t.file_path,
                    total_size: t.total_size as u64,
                    bytes_transferred: t.bytes_transferred as u64,
                    chunks_completed: t.chunks_completed as u64,
                    total_chunks: t.total_chunks as u64,
                    state,
                    error: t.error,
                }
            })
            .collect();

        Ok(Response::new(ListActiveTransfersResponse {
            transfers: transfer_statuses,
        }))
    }
}
