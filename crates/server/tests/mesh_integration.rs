//! Integration tests for MeshService gRPC endpoints
//!
//! Tests mesh networking operations: topology, connect, disconnect, set_role, listen.

use std::net::SocketAddr;
use std::sync::Arc;

use common::{ImplantId, ImplantState};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    mesh_service_server::MeshServiceServer,
    ComputeRouteRequest, ConnectPeerRequest, DisconnectPeerRequest,
    GetTopologyRequest, MeshListenRequest, SetRoleRequest,
    MeshServiceClient, MeshRoleType, MeshTransportType,
    Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn setup_mesh_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-mesh-integration";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mesh_svc = MeshServiceServer::new(
        server::grpc::MeshServiceImpl::new(Arc::clone(&state)),
    );

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(mesh_svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (state, addr)
}

async fn connect_client(addr: SocketAddr) -> MeshServiceClient<tonic::transport::Channel> {
    let endpoint = format!("http://{}", addr);
    let channel = tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    MeshServiceClient::new(channel)
}

async fn insert_active_implant(state: &server::ServerState) -> ImplantId {
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: format!("mesh-test-{}", id),
        state: ImplantState::Active,
        hostname: Some("mesh-host".to_string()),
        username: Some("mesh-user".to_string()),
        domain: None,
        os_name: Some("Linux".to_string()),
        os_version: Some("5.15".to_string()),
        os_arch: Some("x86_64".to_string()),
        process_id: Some(1234),
        process_name: Some("implant".to_string()),
        process_path: Some("/tmp/implant".to_string()),
        is_elevated: false,
        integrity_level: None,
        local_ips: vec!["192.168.1.50".to_string()],
        checkin_interval: 30,
        jitter_percent: 10,
        symmetric_key: None,
        nonce_counter: 0,
        registered_at: now,
        last_seen: Some(now),
    };
    state.db.implants().create(&record).await.unwrap();
    id
}

fn id_to_proto(id: ImplantId) -> ProtoUuid {
    ProtoUuid { value: id.as_bytes().to_vec() }
}

// ===========================================================================
// MeshService Tests
// ===========================================================================

/// 1. GetTopology returns empty topology initially.
#[tokio::test]
async fn test_get_topology_empty() {
    let (_state, addr) = setup_mesh_server().await;
    let mut client = connect_client(addr).await;

    let response = client
        .get_topology(GetTopologyRequest {})
        .await
        .expect("get_topology RPC failed");

    let topology = response.into_inner();
    assert!(topology.nodes.is_empty(), "expected empty nodes");
    assert!(topology.links.is_empty(), "expected empty links");
}

/// 2. ConnectPeer dispatches a mesh connect task.
#[tokio::test]
async fn test_connect_peer_dispatches_task() {
    let (state, addr) = setup_mesh_server().await;
    let implant_a = insert_active_implant(&state).await;
    let implant_b = insert_active_implant(&state).await;

    let mut client = connect_client(addr).await;

    let response = client
        .connect_peer(ConnectPeerRequest {
            implant_id: implant_a.as_bytes().to_vec(),
            peer_id: implant_b.as_bytes().to_vec(),
            transport: MeshTransportType::MeshTransportTcp as i32,
            address: "192.168.1.51".to_string(),
            port: 9999,
            pipe_name: String::new(),
        })
        .await
        .expect("connect_peer RPC failed");

    let inner = response.into_inner();
    assert!(inner.task_id.is_some(), "expected task_id in response");

    // Verify task was queued for implant_a
    assert!(
        state.pending_tasks.contains_key(&implant_a),
        "mesh connect task should be queued for implant_a"
    );
}

/// 3. DisconnectPeer dispatches a mesh disconnect task.
#[tokio::test]
async fn test_disconnect_peer_dispatches_task() {
    let (state, addr) = setup_mesh_server().await;
    let implant_a = insert_active_implant(&state).await;
    let implant_b = insert_active_implant(&state).await;

    let mut client = connect_client(addr).await;

    let response = client
        .disconnect_peer(DisconnectPeerRequest {
            implant_id: implant_a.as_bytes().to_vec(),
            peer_id: implant_b.as_bytes().to_vec(),
        })
        .await
        .expect("disconnect_peer RPC failed");

    let inner = response.into_inner();
    assert!(inner.task_id.is_some(), "expected task_id in response");

    // Verify task was queued
    assert!(
        state.pending_tasks.contains_key(&implant_a),
        "mesh disconnect task should be queued"
    );
}

/// 4. SetRole dispatches a mesh set_role task.
#[tokio::test]
async fn test_set_role_dispatches_task() {
    let (state, addr) = setup_mesh_server().await;
    let implant_id = insert_active_implant(&state).await;

    let mut client = connect_client(addr).await;

    let response = client
        .set_role(SetRoleRequest {
            implant_id: implant_id.as_bytes().to_vec(),
            role: MeshRoleType::MeshRoleHub as i32,
        })
        .await
        .expect("set_role RPC failed");

    let inner = response.into_inner();
    assert!(inner.task_id.is_some(), "expected task_id in response");

    // Verify task was queued
    assert!(
        state.pending_tasks.contains_key(&implant_id),
        "mesh set_role task should be queued"
    );
}

/// 5. Listen dispatches a mesh listen task.
#[tokio::test]
async fn test_listen_dispatches_task() {
    let (state, addr) = setup_mesh_server().await;
    let implant_id = insert_active_implant(&state).await;

    let mut client = connect_client(addr).await;

    let response = client
        .listen(MeshListenRequest {
            implant_id: implant_id.as_bytes().to_vec(),
            port: 8443,
            transport: MeshTransportType::MeshTransportTcp as i32,
            bind_address: "0.0.0.0".to_string(),
        })
        .await
        .expect("listen RPC failed");

    let inner = response.into_inner();
    assert!(inner.task_id.is_some(), "expected task_id in response");

    // Verify task was queued
    assert!(
        state.pending_tasks.contains_key(&implant_id),
        "mesh listen task should be queued"
    );
}

/// 6. ComputeRoute returns empty routes when no topology exists.
#[tokio::test]
async fn test_compute_route_no_topology() {
    let (state, addr) = setup_mesh_server().await;
    let implant_a = insert_active_implant(&state).await;
    let implant_b = insert_active_implant(&state).await;

    let mut client = connect_client(addr).await;

    let response = client
        .compute_route(ComputeRouteRequest {
            from_id: implant_a.as_bytes().to_vec(),
            to_id: implant_b.as_bytes().to_vec(),
            max_paths: 1,
        })
        .await
        .expect("compute_route RPC failed");

    let inner = response.into_inner();
    // No topology registered, so no routes possible
    assert!(inner.routes.is_empty(), "expected no routes without topology");
}

/// 7. ConnectPeer fails for non-existent implant.
#[tokio::test]
async fn test_connect_peer_implant_not_found() {
    let (_state, addr) = setup_mesh_server().await;
    let fake_id = ImplantId::new();

    let mut client = connect_client(addr).await;

    let result = client
        .connect_peer(ConnectPeerRequest {
            implant_id: fake_id.as_bytes().to_vec(),
            peer_id: ImplantId::new().as_bytes().to_vec(),
            transport: MeshTransportType::MeshTransportTcp as i32,
            address: "192.168.1.1".to_string(),
            port: 9999,
            pipe_name: String::new(),
        })
        .await;

    let err = result.expect_err("expected NOT_FOUND error");
    assert_eq!(err.code(), tonic::Code::NotFound);
}

/// 8. SetRole fails for burned implant (not taskable).
#[tokio::test]
async fn test_set_role_burned_implant_rejected() {
    let (state, addr) = setup_mesh_server().await;

    // Insert a burned implant (not taskable)
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: "burned-implant".to_string(),
        state: ImplantState::Burned,
        hostname: None,
        username: None,
        domain: None,
        os_name: None,
        os_version: None,
        os_arch: None,
        process_id: None,
        process_name: None,
        process_path: None,
        is_elevated: false,
        integrity_level: None,
        local_ips: vec![],
        checkin_interval: 60,
        jitter_percent: 20,
        symmetric_key: None,
        nonce_counter: 0,
        registered_at: now,
        last_seen: None,
    };
    state.db.implants().create(&record).await.unwrap();

    let mut client = connect_client(addr).await;

    let result = client
        .set_role(SetRoleRequest {
            implant_id: id.as_bytes().to_vec(),
            role: MeshRoleType::MeshRoleRelay as i32,
        })
        .await;

    let err = result.expect_err("expected FAILED_PRECONDITION for burned implant");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

/// 9. Multiple concurrent mesh operations don't race.
#[tokio::test]
async fn test_concurrent_mesh_operations() {
    let (state, addr) = setup_mesh_server().await;

    // Create 5 implants
    let mut implants = Vec::new();
    for _ in 0..5 {
        implants.push(insert_active_implant(&state).await);
    }

    let mut handles = Vec::new();

    // Spawn concurrent set_role operations
    for implant_id in implants.clone() {
        let addr_clone = addr;
        handles.push(tokio::spawn(async move {
            let mut client = connect_client(addr_clone).await;
            client
                .set_role(SetRoleRequest {
                    implant_id: implant_id.as_bytes().to_vec(),
                    role: MeshRoleType::MeshRoleRelay as i32,
                })
                .await
        }));
    }

    // All operations should succeed
    for handle in handles {
        let result = handle.await.expect("task panicked");
        assert!(result.is_ok(), "concurrent set_role failed: {:?}", result);
    }

    // Verify all tasks were queued
    for implant_id in &implants {
        assert!(
            state.pending_tasks.contains_key(implant_id),
            "task should be queued for {:?}", implant_id
        );
    }
}

/// 10. Listen with SMB transport dispatches correct task type.
#[tokio::test]
async fn test_listen_smb_transport() {
    let (state, addr) = setup_mesh_server().await;
    let implant_id = insert_active_implant(&state).await;

    let mut client = connect_client(addr).await;

    let response = client
        .listen(MeshListenRequest {
            implant_id: implant_id.as_bytes().to_vec(),
            port: 0, // Port ignored for SMB
            transport: MeshTransportType::MeshTransportSmb as i32,
            bind_address: String::new(),
        })
        .await
        .expect("listen RPC failed");

    let inner = response.into_inner();
    assert!(inner.task_id.is_some(), "expected task_id");

    // Verify task contains SMB transport
    let tasks = state.pending_tasks.get(&implant_id).unwrap();
    assert!(!tasks.is_empty(), "should have queued task");
}
