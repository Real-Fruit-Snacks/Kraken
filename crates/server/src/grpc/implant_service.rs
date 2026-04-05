//! ImplantService gRPC implementation

use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use common::ImplantId;
use db::{ImplantRecord, ImplantUpdate};
use kraken_rbac::Permission;
use protocol::{
    implant_state_from_i32, BurnImplantRequest, DeleteImplantRequest, DeleteImplantResponse,
    GetImplantRequest, Implant as ProtoImplant, ImplantEvent, ImplantService, ListImplantsRequest,
    ListImplantsResponse, RetireImplantRequest, StreamImplantEventsRequest, Timestamp,
    UpdateImplantRequest,
};

use crate::auth::{get_cert_identity, resolve_operator, require_permission, OperatorIdentity};
use crate::error::ServerError;
use crate::state::ServerState;

use super::GrpcError;

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

pub struct ImplantServiceImpl {
    state: Arc<ServerState>,
}

impl ImplantServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

/// Convert a db ImplantRecord to the proto Implant message
fn record_to_proto(r: ImplantRecord) -> ProtoImplant {
    use protocol::{ImplantState as ProtoState, SystemInfo};
    let proto_state: ProtoState = r.state.into();
    ProtoImplant {
        id: Some(r.id.into()),
        name: r.name,
        state: proto_state as i32,
        system_info: Some(SystemInfo {
            hostname: r.hostname.unwrap_or_default(),
            username: r.username.unwrap_or_default(),
            domain: r.domain.unwrap_or_default(),
            os_name: r.os_name.unwrap_or_default(),
            os_version: r.os_version.unwrap_or_default(),
            os_arch: r.os_arch.unwrap_or_default(),
            process_id: r.process_id.unwrap_or(0),
            process_name: r.process_name.unwrap_or_default(),
            process_path: r.process_path.unwrap_or_default(),
            is_elevated: r.is_elevated,
            integrity_level: r.integrity_level.unwrap_or_default(),
            local_ips: r.local_ips,
        }),
        checkin_interval: r.checkin_interval as u32,
        jitter_percent: r.jitter_percent as u32,
        registered_at: Some(Timestamp::from_millis(r.registered_at)),
        last_seen: r.last_seen.map(Timestamp::from_millis),
        tags: vec![],
        notes: String::new(),
    }
}

#[tonic::async_trait]
impl ImplantService for ImplantServiceImpl {
    async fn list_implants(
        &self,
        request: Request<ListImplantsRequest>,
    ) -> Result<Response<ListImplantsResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();
        let records = self
            .state
            .db
            .implants()
            .list()
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Apply optional state filter
        let state_filter = req
            .state_filter
            .filter(|&v| v != 0)
            .map(implant_state_from_i32);

        let implants = records
            .into_iter()
            .filter(|r| {
                if let Some(ref filter) = state_filter {
                    &r.state == filter
                } else {
                    true
                }
            })
            .map(record_to_proto)
            .collect();

        Ok(Response::new(ListImplantsResponse { implants }))
    }

    async fn get_implant(
        &self,
        request: Request<GetImplantRequest>,
    ) -> Result<Response<ProtoImplant>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();
        let id: ImplantId = req
            .implant_id
            .ok_or_else(|| GrpcError::invalid_input("implant_id", "field is required").to_status())?
            .try_into()
            .map_err(|e: common::KrakenError| GrpcError::invalid_input("implant_id", e.to_string()).to_status())?;

        let record = self
            .state
            .db
            .implants()
            .get(id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| GrpcError::not_found("Implant", id.to_string()).to_status())?;

        Ok(Response::new(record_to_proto(record)))
    }

    async fn update_implant(
        &self,
        request: Request<UpdateImplantRequest>,
    ) -> Result<Response<ProtoImplant>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionInteract)?;

        let req = request.into_inner();
        let id: ImplantId = req
            .implant_id
            .ok_or_else(|| Status::invalid_argument("missing implant_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        // Fetch existing record
        let mut record = self
            .state
            .db
            .implants()
            .get(id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", id)))?;

        let req_name = req.name;
        let req_checkin_interval = req.checkin_interval;
        let req_jitter_percent = req.jitter_percent;

        if let Some(name) = req_name {
            record.name = name;
        }

        // Persist interval/jitter changes to DB if provided
        let db_update = ImplantUpdate {
            checkin_interval: req_checkin_interval.map(|v| v as i32),
            jitter_percent: req_jitter_percent.map(|v| v as i32),
            ..Default::default()
        };

        self.state
            .db
            .implants()
            .update(id, db_update)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Reflect new values in the response record
        if let Some(v) = req_checkin_interval {
            record.checkin_interval = v as i32;
        }
        if let Some(v) = req_jitter_percent {
            record.jitter_percent = v as i32;
        }

        Ok(Response::new(record_to_proto(record)))
    }

    async fn burn_implant(
        &self,
        request: Request<BurnImplantRequest>,
    ) -> Result<Response<ProtoImplant>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionKill)?;

        let req = request.into_inner();
        let id: ImplantId = req
            .implant_id
            .ok_or_else(|| Status::invalid_argument("missing implant_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        let record = self
            .state
            .db
            .implants()
            .get(id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", id)))?;

        if record.state.is_terminal() {
            return Err(Status::failed_precondition(format!(
                "implant {} is already in terminal state",
                id
            )));
        }

        // Update state to Burned
        self.state
            .db
            .implants()
            .update_state(id, common::ImplantState::Burned)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Expire any pending/dispatched tasks for this implant
        let _ = self.state.db.tasks().expire_tasks_for_implant(id).await;

        // Publish burn event
        use protocol::{implant_event::Event, ImplantBurnedEvent};
        self.state.publish_event(ImplantEvent {
            timestamp: Some(Timestamp::now()),
            event: Some(Event::Burned(ImplantBurnedEvent {
                implant_id: Some(id.into()),
                operator_id: None,
                reason: req.reason.clone(),
            })),
        });

        tracing::warn!(implant_id = %id, reason = %req.reason, "implant burned");

        // Re-fetch updated record
        let updated = self
            .state
            .db
            .implants()
            .get(id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::internal("implant disappeared after update"))?;

        Ok(Response::new(record_to_proto(updated)))
    }

    async fn retire_implant(
        &self,
        request: Request<RetireImplantRequest>,
    ) -> Result<Response<ProtoImplant>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionKill)?;

        let req = request.into_inner();
        let id: ImplantId = req
            .implant_id
            .ok_or_else(|| Status::invalid_argument("missing implant_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        let record = self
            .state
            .db
            .implants()
            .get(id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", id)))?;

        if record.state.is_terminal() {
            return Err(Status::failed_precondition(format!(
                "implant {} is already in terminal state",
                id
            )));
        }

        // Publish retire event
        use protocol::{implant_event::Event, ImplantRetiredEvent};
        self.state.publish_event(ImplantEvent {
            timestamp: Some(Timestamp::now()),
            event: Some(Event::Retired(ImplantRetiredEvent {
                implant_id: Some(id.into()),
                operator_id: None,
            })),
        });

        Ok(Response::new(record_to_proto(record)))
    }

    async fn delete_implant(
        &self,
        request: Request<DeleteImplantRequest>,
    ) -> Result<Response<DeleteImplantResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionKill)?;

        let req = request.into_inner();
        let implant_id: ImplantId = req
            .implant_id
            .ok_or_else(|| Status::invalid_argument("missing implant_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        let deleted = self
            .state
            .db
            .implants()
            .delete(implant_id)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        if !deleted {
            return Err(Status::not_found(format!(
                "implant {} not found",
                implant_id
            )));
        }

        tracing::info!(implant_id = %implant_id, "implant deleted");

        Ok(Response::new(DeleteImplantResponse { success: true }))
    }

    type StreamImplantEventsStream = std::pin::Pin<
        Box<dyn futures_core::Stream<Item = Result<ImplantEvent, Status>> + Send + 'static>,
    >;

    async fn stream_implant_events(
        &self,
        request: Request<StreamImplantEventsRequest>,
    ) -> Result<Response<Self::StreamImplantEventsStream>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let rx = self.state.subscribe_events();
        let stream = BroadcastStream::new(rx).filter_map(|result| {
            match result {
                Ok(event) => Some(Ok(event)),
                Err(_lagged) => None, // skip lagged messages
            }
        });
        Ok(Response::new(Box::pin(stream)))
    }
}
