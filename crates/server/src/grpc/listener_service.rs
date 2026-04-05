//! ListenerService gRPC implementation

use std::sync::Arc;
use tonic::{Request, Response, Status};

use common::ListenerId;
use db::ListenerRecord;
use protocol::{
    ListListenersRequest, ListListenersResponse, Listener as ProtoListener, ListenerService,
    StartListenerRequest, StopListenerRequest, Timestamp,
};

use crate::dns::{DnsListener, DnsListenerConfig};
use crate::error::ServerError;
use crate::state::ServerState;

pub struct ListenerServiceImpl {
    state: Arc<ServerState>,
}

impl ListenerServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

fn record_to_proto(r: &ListenerRecord) -> ProtoListener {
    ProtoListener {
        id: Some(r.id.into()),
        listener_type: r.listener_type.clone(),
        bind_host: r.bind_host.clone(),
        bind_port: r.bind_port as u32,
        profile_id: String::new(),
        is_running: r.is_running,
        started_at: Some(Timestamp::from_millis(r.created_at)),
        connections_total: 0,
    }
}

#[tonic::async_trait]
impl ListenerService for ListenerServiceImpl {
    async fn start_listener(
        &self,
        request: Request<StartListenerRequest>,
    ) -> Result<Response<ProtoListener>, Status> {
        let req = request.into_inner();

        if req.bind_host.is_empty() {
            return Err(Status::invalid_argument("bind_host is required"));
        }
        if req.bind_port == 0 || req.bind_port > 65535 {
            return Err(Status::invalid_argument("bind_port must be 1-65535"));
        }

        let id = ListenerId::new();
        let now = chrono::Utc::now().timestamp_millis();

        let record = ListenerRecord {
            id,
            listener_type: req.listener_type.clone(),
            bind_host: req.bind_host.clone(),
            bind_port: req.bind_port as i32,
            is_running: true,
            created_at: now,
        };

        self.state
            .db
            .listeners()
            .create(&record)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Spawn the appropriate listener based on type
        if req.listener_type == "dns" {
            let dns_domain = req.dns_domain.unwrap_or_else(|| "c2.local".to_string());
            let bind_addr = format!("{}:{}", req.bind_host, req.bind_port)
                .parse()
                .map_err(|_| Status::invalid_argument("invalid bind address"))?;

            let dns_config = DnsListenerConfig {
                bind_addr,
                base_domain: dns_domain.clone(),
                max_subdomain_len: 63,
            };

            let dns_listener = DnsListener::new(dns_config, Arc::clone(&self.state));

            // Spawn the DNS listener in a background task
            tokio::spawn(async move {
                if let Err(e) = dns_listener.run().await {
                    tracing::error!(error = %e, "DNS listener error");
                }
            });

            tracing::info!(
                listener_id = %id,
                listener_type = "dns",
                bind = %format!("{}:{}", req.bind_host, req.bind_port),
                domain = %dns_domain,
                "DNS listener started"
            );
        } else {
            tracing::info!(
                listener_id = %id,
                listener_type = %req.listener_type,
                bind = %format!("{}:{}", req.bind_host, req.bind_port),
                "listener started"
            );
        }

        Ok(Response::new(record_to_proto(&record)))
    }

    async fn stop_listener(
        &self,
        request: Request<StopListenerRequest>,
    ) -> Result<Response<ProtoListener>, Status> {
        let req = request.into_inner();
        let id: ListenerId = req
            .listener_id
            .ok_or_else(|| Status::invalid_argument("missing listener_id"))?
            .try_into()
            .map_err(|e: common::KrakenError| Status::invalid_argument(e.to_string()))?;

        self.state
            .db
            .listeners()
            .update_running(id, false)
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        // Retrieve the (now stopped) record for the response
        let records = self
            .state
            .db
            .listeners()
            .list()
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let record = records
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| Status::not_found(format!("listener {} not found", id)))?;

        tracing::info!(listener_id = %id, "listener stopped");

        Ok(Response::new(record_to_proto(&record)))
    }

    async fn list_listeners(
        &self,
        _request: Request<ListListenersRequest>,
    ) -> Result<Response<ListListenersResponse>, Status> {
        let records = self
            .state
            .db
            .listeners()
            .list()
            .await
            .map_err(|e| Status::from(ServerError::from(e)))?;

        let listeners = records.iter().map(record_to_proto).collect();
        Ok(Response::new(ListListenersResponse { listeners }))
    }
}
