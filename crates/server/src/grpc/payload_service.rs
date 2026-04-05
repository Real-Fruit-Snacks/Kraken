//! PayloadService gRPC implementation

use std::sync::Arc;
use tonic::{Request, Response, Status};

use protocol::{
    DeletePayloadRequest, DeletePayloadResponse, GeneratePayloadRequest, GeneratePayloadResponse,
    GetPayloadRequest, ListPayloadsRequest, ListPayloadsResponse, Payload,
    PayloadService, Timestamp,
};

use crate::state::ServerState;

pub struct PayloadServiceImpl {
    #[allow(dead_code)]
    state: Arc<ServerState>,
}

impl PayloadServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl PayloadService for PayloadServiceImpl {
    async fn generate_payload(
        &self,
        request: Request<GeneratePayloadRequest>,
    ) -> Result<Response<GeneratePayloadResponse>, Status> {
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        if req.os.is_empty() {
            return Err(Status::invalid_argument("os is required"));
        }
        if req.arch.is_empty() {
            return Err(Status::invalid_argument("arch is required"));
        }
        if req.format.is_empty() {
            return Err(Status::invalid_argument("format is required"));
        }
        if req.transport.is_empty() {
            return Err(Status::invalid_argument("transport is required"));
        }

        let valid_os = ["windows", "linux", "darwin"];
        if !valid_os.contains(&req.os.as_str()) {
            return Err(Status::invalid_argument(
                "os must be one of: windows, linux, darwin",
            ));
        }

        let valid_arch = ["x64", "x86"];
        if !valid_arch.contains(&req.arch.as_str()) {
            return Err(Status::invalid_argument("arch must be one of: x64, x86"));
        }

        let valid_format = ["exe", "dll", "shellcode", "service", "powershell"];
        if !valid_format.contains(&req.format.as_str()) {
            return Err(Status::invalid_argument(
                "format must be one of: exe, dll, shellcode, service, powershell",
            ));
        }

        let valid_transport = ["http", "https", "dns", "tcp", "smb"];
        if !valid_transport.contains(&req.transport.as_str()) {
            return Err(Status::invalid_argument(
                "transport must be one of: http, https, dns, tcp, smb",
            ));
        }

        let id: Vec<u8> = uuid::Uuid::new_v4().as_bytes().to_vec();
        let now_millis = chrono::Utc::now().timestamp_millis();

        tracing::info!(
            payload_name = %req.name,
            os = %req.os,
            arch = %req.arch,
            format = %req.format,
            transport = %req.transport,
            obfuscation = req.obfuscation,
            anti_debug = req.anti_debug,
            anti_sandbox = req.anti_sandbox,
            sleep_mask = req.sleep_mask,
            "payload generation requested"
        );

        let payload = Payload {
            id,
            name: req.name,
            os: req.os,
            arch: req.arch,
            format: req.format,
            transport: req.transport,
            generated_at: Some(Timestamp { millis: now_millis }),
            size: 0,
            hash: String::new(),
        };

        Ok(Response::new(GeneratePayloadResponse {
            payload: Some(payload),
            content: vec![],
        }))
    }

    async fn list_payloads(
        &self,
        _request: Request<ListPayloadsRequest>,
    ) -> Result<Response<ListPayloadsResponse>, Status> {
        Ok(Response::new(ListPayloadsResponse { payloads: vec![] }))
    }

    async fn get_payload(
        &self,
        request: Request<GetPayloadRequest>,
    ) -> Result<Response<Payload>, Status> {
        let req = request.into_inner();
        if req.payload_id.is_empty() {
            return Err(Status::invalid_argument("payload_id is required"));
        }
        Err(Status::not_found("payload not found"))
    }

    async fn delete_payload(
        &self,
        request: Request<DeletePayloadRequest>,
    ) -> Result<Response<DeletePayloadResponse>, Status> {
        let req = request.into_inner();
        if req.payload_id.is_empty() {
            return Err(Status::invalid_argument("payload_id is required"));
        }
        Err(Status::not_found("payload not found"))
    }
}
