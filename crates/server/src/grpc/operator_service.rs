//! OperatorService gRPC implementation

use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;

use db::{models::{NewOperator, OperatorUpdate}, OperatorRecord};
use kraken_rbac::Permission;
use protocol::{
    CreateOperatorRequest, DeleteOperatorRequest, DeleteOperatorResponse, GetSelfRequest,
    ListOperatorsRequest, ListOperatorsResponse, Operator as ProtoOperator, OperatorService,
    Timestamp, UpdateOperatorRequest, Uuid as ProtoUuid,
};

use crate::auth::{get_cert_identity, require_permission, resolve_operator, OperatorIdentity};
use crate::error::ServerError;
use crate::state::ServerState;

pub struct OperatorServiceImpl {
    state: Arc<ServerState>,
}

impl OperatorServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

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

/// Parse a 16-byte slice into a UUID, returning an appropriate gRPC Status on failure.
fn parse_uuid(bytes: &[u8]) -> Result<Uuid, Status> {
    if bytes.len() != 16 {
        return Err(Status::invalid_argument("operator_id must be 16 bytes"));
    }
    let arr: [u8; 16] = bytes.try_into().map_err(|_| Status::invalid_argument("operator_id must be 16 bytes"))?;
    Ok(Uuid::from_bytes(arr))
}

/// Convert a database OperatorRecord to the proto Operator message
fn record_to_proto(r: &OperatorRecord) -> ProtoOperator {
    ProtoOperator {
        id: Some(ProtoUuid {
            value: r.id.as_bytes().to_vec(),
        }),
        username: r.username.clone(),
        role: r.role.clone(),
        created_at: Some(Timestamp::from_millis(r.created_at)),
        last_seen: r.last_seen.map(Timestamp::from_millis),
        is_active: r.is_active,
        allowed_sessions: vec![],
        allowed_listeners: vec![],
        scope: "global".to_string(),
    }
}

#[tonic::async_trait]
impl OperatorService for OperatorServiceImpl {
    async fn get_self(
        &self,
        request: Request<GetSelfRequest>,
    ) -> Result<Response<ProtoOperator>, Status> {
        // Try to get the authenticated operator from the certificate
        match get_cert_identity(&request) {
            Ok(cert_id) => {
                // Look up operator by certificate fingerprint
                let record = self
                    .state
                    .db
                    .operators()
                    .get_by_cert(&cert_id.cert_fingerprint)
                    .await
                    .map_err(|e| Status::from(ServerError::from(e)))?
                    .ok_or_else(|| {
                        Status::permission_denied("operator not registered in database")
                    })?;

                // Update last_seen timestamp
                let _ = self.state.db.operators().touch(record.id).await;

                Ok(Response::new(record_to_proto(&record)))
            }
            Err(_) => {
                // No certificate — insecure/dev mode: return a placeholder operator
                let operator = ProtoOperator {
                    id: None,
                    username: "dev-operator".to_string(),
                    role: "admin".to_string(),
                    created_at: Some(Timestamp::now()),
                    last_seen: Some(Timestamp::now()),
                    is_active: true,
                    allowed_sessions: vec![],
                    allowed_listeners: vec![],
                    scope: "global".to_string(),
                };
                Ok(Response::new(operator))
            }
        }
    }

    async fn list_operators(
        &self,
        request: Request<ListOperatorsRequest>,
    ) -> Result<Response<ListOperatorsResponse>, Status> {
        // Require audit permission to list operators (admin-level access)
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::AuditView)?;

        let records = self
            .state
            .db
            .operators()
            .list()
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let operators: Vec<ProtoOperator> = records.iter().map(record_to_proto).collect();

        Ok(Response::new(ListOperatorsResponse { operators }))
    }

    async fn create_operator(
        &self,
        request: Request<CreateOperatorRequest>,
    ) -> Result<Response<ProtoOperator>, Status> {
        let caller = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&caller, Permission::OperatorCreate)?;

        let req = request.into_inner();

        // Validate role string
        let role: kraken_rbac::Role = req.role.parse().map_err(|_| {
            Status::invalid_argument(format!("invalid role '{}': must be admin, operator, or viewer", req.role))
        })?;

        if req.username.is_empty() {
            return Err(Status::invalid_argument("username must not be empty"));
        }
        if req.password.is_empty() {
            return Err(Status::invalid_argument("password must not be empty"));
        }

        // Check for duplicate username
        let existing = self
            .state
            .db
            .operators()
            .get_by_username(&req.username)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;
        if existing.is_some() {
            return Err(Status::already_exists(format!(
                "operator '{}' already exists",
                req.username
            )));
        }

        // Use password as cert_fingerprint placeholder (in a real deployment this
        // would be an X.509 cert fingerprint; for password-auth the hash is stored here)
        let new_op = NewOperator {
            username: req.username.clone(),
            role,
            cert_fingerprint: req.password,
        };

        let record = self
            .state
            .db
            .operators()
            .create(new_op)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Emit audit event
        let _ = self
            .state
            .db
            .audit()
            .log(&db::models::AuditEntry {
                timestamp: chrono::Utc::now().timestamp_millis(),
                operator_id: Some(caller.id.into()),
                implant_id: None,
                action: "operator.create".to_string(),
                details: Some(serde_json::json!({
                    "new_operator": record.username,
                    "role": record.role,
                })),
            })
            .await;

        Ok(Response::new(record_to_proto(&record)))
    }

    async fn update_operator(
        &self,
        request: Request<UpdateOperatorRequest>,
    ) -> Result<Response<ProtoOperator>, Status> {
        let caller = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&caller, Permission::OperatorModify)?;

        let req = request.into_inner();

        // Decode operator_id bytes -> Uuid
        let op_id = parse_uuid(&req.operator_id)?;

        // Resolve target operator exists
        let existing = self
            .state
            .db
            .operators()
            .get(op_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found("operator not found"))?;

        // Build the update struct
        let role = match req.role {
            Some(ref r) => {
                let parsed: kraken_rbac::Role = r.parse().map_err(|_| {
                    Status::invalid_argument(format!("invalid role '{}': must be admin, operator, or viewer", r))
                })?;
                Some(parsed)
            }
            None => None,
        };

        let is_active = req.disabled.map(|d| !d);

        self.state
            .db
            .operators()
            .update(op_id, OperatorUpdate { role, is_active })
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Fetch updated record
        let updated = self
            .state
            .db
            .operators()
            .get(op_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::internal("operator disappeared after update"))?;

        // Emit audit event
        let _ = self
            .state
            .db
            .audit()
            .log(&db::models::AuditEntry {
                timestamp: chrono::Utc::now().timestamp_millis(),
                operator_id: Some(caller.id.into()),
                implant_id: None,
                action: "operator.update".to_string(),
                details: Some(serde_json::json!({
                    "target_operator": existing.username,
                    "new_role": req.role,
                    "disabled": req.disabled,
                })),
            })
            .await;

        Ok(Response::new(record_to_proto(&updated)))
    }

    async fn delete_operator(
        &self,
        request: Request<DeleteOperatorRequest>,
    ) -> Result<Response<DeleteOperatorResponse>, Status> {
        let caller = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&caller, Permission::OperatorDelete)?;

        let req = request.into_inner();
        let op_id = parse_uuid(&req.operator_id)?;

        // Prevent self-deletion
        if op_id == caller.id {
            return Err(Status::failed_precondition("operators cannot delete themselves"));
        }

        // Resolve target operator exists
        let existing = self
            .state
            .db
            .operators()
            .get(op_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found("operator not found"))?;

        self.state
            .db
            .operators()
            .delete(op_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Emit audit event
        let _ = self
            .state
            .db
            .audit()
            .log(&db::models::AuditEntry {
                timestamp: chrono::Utc::now().timestamp_millis(),
                operator_id: Some(caller.id.into()),
                implant_id: None,
                action: "operator.delete".to_string(),
                details: Some(serde_json::json!({
                    "deleted_operator": existing.username,
                    "deleted_role": existing.role,
                })),
            })
            .await;

        Ok(Response::new(DeleteOperatorResponse { success: true }))
    }
}
