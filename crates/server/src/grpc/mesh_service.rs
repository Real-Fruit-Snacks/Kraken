//! MeshService gRPC implementation

use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use common::ImplantId;
use mesh::MeshRouter;
use protocol::{
    mesh_service_server::MeshService, ComputeRouteRequest, ComputeRouteResponse,
    ConnectPeerRequest, DisconnectPeerRequest, DispatchTaskResponse, GetTopologyRequest,
    MeshConnect, MeshDisconnect, MeshLink, MeshListen, MeshListenRequest, MeshNode,
    MeshRoute as ProtoMeshRoute, MeshSetRole, MeshTask, MeshTopology, MeshTopologyUpdate,
    SetRoleRequest, StreamTopologyRequest, Task, Timestamp, mesh_task,
};

use crate::state::ServerState;

pub struct MeshServiceImpl {
    state: Arc<ServerState>,
    router: Arc<RwLock<MeshRouter>>,
}

impl MeshServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self {
            router: Arc::new(RwLock::new(MeshRouter::new())),
            state,
        }
    }
}

/// Parse a raw implant ID bytes vec into an ImplantId, returning a gRPC Status on failure
fn parse_implant_id(bytes: &[u8]) -> Result<ImplantId, Status> {
    ImplantId::from_bytes(bytes)
        .map_err(|e| Status::invalid_argument(format!("invalid implant_id: {e}")))
}

/// Build a proto Task wrapping a MeshTask operation and queue it for the target implant
fn enqueue_mesh_task(
    state: &ServerState,
    implant_id: ImplantId,
    operation: mesh_task::Operation,
) -> Result<common::TaskId, Status> {
    let task_id = common::TaskId::new();
    let now = chrono::Utc::now().timestamp_millis();

    let mesh_task = MeshTask {
        operation: Some(operation),
    };

    let task_data = prost::Message::encode_to_vec(&mesh_task);

    let proto_task = Task {
        task_id: Some(task_id.into()),
        task_type: "mesh".to_string(),
        task_data,
        issued_at: Some(Timestamp::from_millis(now)),
        operator_id: None,
    };

    state.enqueue_task(implant_id, proto_task);
    tracing::info!(task_id = %task_id, implant_id = %implant_id, "mesh task enqueued");

    Ok(task_id)
}

#[tonic::async_trait]
impl MeshService for MeshServiceImpl {
    /// Return the current mesh topology (nodes and links) from the router
    async fn get_topology(
        &self,
        _request: Request<GetTopologyRequest>,
    ) -> Result<Response<MeshTopology>, Status> {
        let router = self.router.read().await;
        let edges = router.get_topology();

        // Collect unique node IDs
        let mut node_ids: Vec<ImplantId> = Vec::new();
        let mut links: Vec<MeshLink> = Vec::new();

        for (from, to, state) in &edges {
            if !node_ids.contains(from) {
                node_ids.push(*from);
            }
            if !node_ids.contains(to) {
                node_ids.push(*to);
            }

            let link_state = match state {
                mesh::PeerLinkState::Active => 1i32,      // MeshLinkState::Active
                mesh::PeerLinkState::Degraded => 2i32,    // MeshLinkState::Degraded
                mesh::PeerLinkState::Failed => 3i32,      // MeshLinkState::Failed
                mesh::PeerLinkState::Connecting => 4i32,  // MeshLinkState::Connecting
                mesh::PeerLinkState::Handshaking => 4i32, // treat as Connecting
            };

            links.push(MeshLink {
                from_id: from.as_bytes().to_vec(),
                to_id: to.as_bytes().to_vec(),
                transport: 0, // MeshTransportType::Unspecified — server doesn't track transport per edge
                state: link_state,
                latency_ms: 0,
            });
        }

        let nodes: Vec<MeshNode> = node_ids
            .iter()
            .map(|id| MeshNode {
                implant_id: id.as_bytes().to_vec(),
                role: 0,      // MeshRoleType::Unspecified — server doesn't track per-node role yet
                has_egress: false,
            })
            .collect();

        Ok(Response::new(MeshTopology { nodes, links }))
    }

    type StreamTopologyStream = ReceiverStream<Result<MeshTopologyUpdate, Status>>;

    /// Subscribe to mesh topology events and stream updates to the operator client.
    /// Currently sends an empty stream placeholder — full event broadcasting requires
    /// a dedicated mesh event channel (future work).
    async fn stream_topology(
        &self,
        _request: Request<StreamTopologyRequest>,
    ) -> Result<Response<Self::StreamTopologyStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        // Subscribe to the implant event broadcast and convert relevant events
        // into MeshTopologyUpdate messages.
        let _state = Arc::clone(&self.state);
        tokio::spawn(async move {
            // Keep sender alive until client disconnects; send nothing until
            // real mesh events are plumbed through the broadcast channel.
            // The channel close on drop signals the client that streaming ended.
            let _ = tx; // hold tx so the channel stays open
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Dispatch a MeshTask::Connect to the specified implant
    async fn connect_peer(
        &self,
        request: Request<ConnectPeerRequest>,
    ) -> Result<Response<DispatchTaskResponse>, Status> {
        let req = request.into_inner();

        let implant_id = parse_implant_id(&req.implant_id)?;
        let _peer_id = parse_implant_id(&req.peer_id)?;

        // Verify implant exists
        let record = self
            .state
            .db
            .implants()
            .get(implant_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", implant_id)))?;

        if !record.state.is_taskable() {
            return Err(Status::failed_precondition(format!(
                "implant {} is not in a taskable state (state={})",
                implant_id, record.state
            )));
        }

        let connect = MeshConnect {
            peer_id: req.peer_id,
            transport: req.transport,
            address: req.address,
            port: req.port,
            pipe_name: req.pipe_name,
            peer_public_key: vec![],
        };

        let task_id = enqueue_mesh_task(
            &self.state,
            implant_id,
            mesh_task::Operation::Connect(connect),
        )?;

        Ok(Response::new(DispatchTaskResponse {
            task_id: Some(task_id.into()),
        }))
    }

    /// Dispatch a MeshTask::Disconnect to the specified implant
    async fn disconnect_peer(
        &self,
        request: Request<DisconnectPeerRequest>,
    ) -> Result<Response<DispatchTaskResponse>, Status> {
        let req = request.into_inner();

        let implant_id = parse_implant_id(&req.implant_id)?;
        let _peer_id = parse_implant_id(&req.peer_id)?;

        let record = self
            .state
            .db
            .implants()
            .get(implant_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", implant_id)))?;

        if !record.state.is_taskable() {
            return Err(Status::failed_precondition(format!(
                "implant {} is not in a taskable state (state={})",
                implant_id, record.state
            )));
        }

        let disconnect = MeshDisconnect {
            peer_id: req.peer_id,
        };

        let task_id = enqueue_mesh_task(
            &self.state,
            implant_id,
            mesh_task::Operation::Disconnect(disconnect),
        )?;

        Ok(Response::new(DispatchTaskResponse {
            task_id: Some(task_id.into()),
        }))
    }

    /// Dispatch a MeshTask::SetRole to the specified implant
    async fn set_role(
        &self,
        request: Request<SetRoleRequest>,
    ) -> Result<Response<DispatchTaskResponse>, Status> {
        let req = request.into_inner();

        let implant_id = parse_implant_id(&req.implant_id)?;

        let record = self
            .state
            .db
            .implants()
            .get(implant_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", implant_id)))?;

        if !record.state.is_taskable() {
            return Err(Status::failed_precondition(format!(
                "implant {} is not in a taskable state (state={})",
                implant_id, record.state
            )));
        }

        let set_role = MeshSetRole { role: req.role };

        let task_id = enqueue_mesh_task(
            &self.state,
            implant_id,
            mesh_task::Operation::SetRole(set_role),
        )?;

        Ok(Response::new(DispatchTaskResponse {
            task_id: Some(task_id.into()),
        }))
    }

    /// Dispatch a MeshTask::Listen to start a mesh listener on the specified implant
    async fn listen(
        &self,
        request: Request<MeshListenRequest>,
    ) -> Result<Response<DispatchTaskResponse>, Status> {
        let req = request.into_inner();

        let implant_id = parse_implant_id(&req.implant_id)?;

        let record = self
            .state
            .db
            .implants()
            .get(implant_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", implant_id)))?;

        if !record.state.is_taskable() {
            return Err(Status::failed_precondition(format!(
                "implant {} is not in a taskable state (state={})",
                implant_id, record.state
            )));
        }

        let bind_address = if req.bind_address.is_empty() {
            "0.0.0.0".to_string()
        } else {
            req.bind_address
        };

        let mesh_listen = MeshListen {
            port: req.port,
            transport: req.transport,
            bind_address,
            pipe_name: String::new(),
        };

        let task_id = enqueue_mesh_task(
            &self.state,
            implant_id,
            mesh_task::Operation::Listen(mesh_listen),
        )?;

        tracing::info!(
            task_id = %task_id,
            implant_id = %implant_id,
            port = req.port,
            "mesh listen task enqueued"
        );

        Ok(Response::new(DispatchTaskResponse {
            task_id: Some(task_id.into()),
        }))
    }

    /// Compute routes using the router's Dijkstra algorithm and return paths
    async fn compute_route(
        &self,
        request: Request<ComputeRouteRequest>,
    ) -> Result<Response<ComputeRouteResponse>, Status> {
        let req = request.into_inner();

        let from = parse_implant_id(&req.from_id)?;
        let to = parse_implant_id(&req.to_id)?;

        let max_paths = if req.max_paths == 0 { 1 } else { req.max_paths as usize };

        let mut router = self.router.write().await;
        let routes = router.compute_routes(from, to, max_paths);

        let proto_routes: Vec<ProtoMeshRoute> = routes
            .into_iter()
            .map(|r| ProtoMeshRoute {
                source: r.source.as_bytes().to_vec(),
                destination: r.destination.as_bytes().to_vec(),
                hops: r.hops.iter().map(|h| h.as_bytes().to_vec()).collect(),
                computed_at: r.computed_at,
            })
            .collect();

        tracing::debug!(
            from = %from,
            to = %to,
            route_count = proto_routes.len(),
            "routes computed"
        );

        Ok(Response::new(ComputeRouteResponse {
            routes: proto_routes,
        }))
    }
}
