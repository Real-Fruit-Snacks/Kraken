//! Integration tests for Phase 5 gRPC services (ProxyService, BOFService)
//!
//! Tests the proxy management and BOF execution service endpoints.

use std::net::SocketAddr;
use std::sync::Arc;

use common::{ImplantId, ImplantState};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    // Proxy types
    ListProxiesRequest, StartProxyRequest, StopProxyRequest, SocksVersion,
    ProxyServiceClient,
    // BOF types
    ListBoFsRequest, GetBofRequest, ExecuteBofRequest, BofCategory,
    BofServiceClient,
    Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn setup_test_server() -> (Arc<server::ServerState>, SocketAddr) {
    // In-memory SQLite
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // Deterministic test master key
    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = std::sync::Arc::new(
        module_store::ModuleStore::new(std::sync::Arc::new(db.clone()), &signing_key).unwrap(),
    );

    // Shared state
    let audit_key = b"test-audit-key-for-integration!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    // Bind to a random OS-assigned port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Build services
    let proxy_svc = protocol::ProxyServiceServer::new(
        server::grpc::ProxyServiceImpl::new(Arc::clone(&state)),
    );
    let bof_svc = protocol::BofServiceServer::new(
        server::grpc::BOFServiceImpl::new(Arc::clone(&state)),
    );

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(proxy_svc)
            .add_service(bof_svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });

    (state, addr)
}

/// Build a tonic channel pointed at the given address.
async fn connect(addr: SocketAddr) -> tonic::transport::Channel {
    let endpoint = format!("http://{}", addr);
    tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

/// Insert a test implant into the database.
async fn insert_implant(state: &server::ServerState, implant_state: ImplantState) -> ImplantId {
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: format!("test-implant-{}", id),
        state: implant_state,
        hostname: Some("test-host".to_string()),
        username: Some("test-user".to_string()),
        domain: None,
        os_name: Some("Windows".to_string()),
        os_version: Some("10".to_string()),
        os_arch: Some("x86_64".to_string()),
        process_id: Some(1234),
        process_name: Some("test.exe".to_string()),
        process_path: Some("C:\\test\\test.exe".to_string()),
        is_elevated: false,
        integrity_level: None,
        local_ips: vec!["192.168.1.100".to_string()],
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

/// Convert an `ImplantId` (UUID wrapper) into the proto `Uuid` message.
fn implant_id_to_proto(id: ImplantId) -> ProtoUuid {
    ProtoUuid {
        value: id.as_bytes().to_vec(),
    }
}

// ===========================================================================
// ProxyService Tests
// ===========================================================================

/// 1. List proxies returns empty list when no proxies are running.
#[tokio::test]
async fn test_list_proxies_empty() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = ProxyServiceClient::new(channel);

    let response = client
        .list_proxies(ListProxiesRequest {
            implant_id: None,
            state: None,
        })
        .await
        .expect("list_proxies RPC failed");

    let inner = response.into_inner();
    assert!(inner.proxies.is_empty(), "expected empty proxy list");
    assert!(inner.port_forwards.is_empty(), "expected empty port forward list");
}

/// 2. Start a SOCKS5 proxy and verify it appears in the list.
#[tokio::test]
async fn test_start_proxy() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ProxyServiceClient::new(channel);

    // Start a SOCKS5 proxy
    let response = client
        .start_proxy(StartProxyRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            bind_host: "127.0.0.1".to_string(),
            bind_port: 1080,
            version: SocksVersion::SocksVersion5 as i32,
            username: None,
            password: None,
            reverse: false,
            connect_timeout: 10,
            allow_dns: true,
        })
        .await
        .expect("start_proxy RPC failed");

    let inner = response.into_inner();
    assert!(inner.proxy_id.is_some(), "expected proxy_id in response");

    // Verify it appears in list
    let list_response = client
        .list_proxies(ListProxiesRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            state: None,
        })
        .await
        .expect("list_proxies RPC failed");

    assert_eq!(list_response.into_inner().proxies.len(), 1);
}

/// 3. Stop a running proxy.
#[tokio::test]
async fn test_stop_proxy() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ProxyServiceClient::new(channel);

    // Start a proxy first
    let start_response = client
        .start_proxy(StartProxyRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            bind_host: "127.0.0.1".to_string(),
            bind_port: 1081,
            version: SocksVersion::SocksVersion5 as i32,
            username: None,
            password: None,
            reverse: false,
            connect_timeout: 10,
            allow_dns: true,
        })
        .await
        .expect("start_proxy RPC failed");

    let proxy_id = start_response
        .into_inner()
        .proxy_id
        .expect("no proxy id");

    // Stop the proxy
    let stop_response = client
        .stop_proxy(StopProxyRequest {
            proxy_id: Some(proxy_id),
        })
        .await
        .expect("stop_proxy RPC failed");

    assert!(stop_response.into_inner().success);
}

// ===========================================================================
// BOFService Tests
// ===========================================================================

/// 4. List BOFs returns the seed catalog.
#[tokio::test]
async fn test_list_bofs() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = BofServiceClient::new(channel);

    let response = client
        .list_bo_fs(ListBoFsRequest {
            category: None,
            search: None,
            tags: vec![],
        })
        .await
        .expect("list_bofs RPC failed");

    let bofs = response.into_inner().bofs;
    // The service seeds with some default BOFs
    assert!(!bofs.is_empty(), "expected at least one BOF in catalog");

    // Check that we have expected seed BOFs (via manifest.name)
    let names: Vec<&str> = bofs
        .iter()
        .filter_map(|b| b.manifest.as_ref())
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"whoami"), "expected whoami BOF");
}

/// 5. Get a specific BOF by ID.
#[tokio::test]
async fn test_get_bof() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = BofServiceClient::new(channel);

    // First list to get an ID
    let list_response = client
        .list_bo_fs(ListBoFsRequest {
            category: None,
            search: None,
            tags: vec![],
        })
        .await
        .expect("list_bofs RPC failed");

    let first_bof = list_response
        .into_inner()
        .bofs
        .into_iter()
        .next()
        .expect("no BOFs in catalog");

    let bof_id = first_bof.manifest.as_ref().expect("no manifest").id.clone();

    // Get the specific BOF
    let get_response = client
        .get_bof(GetBofRequest {
            bof_id: bof_id.clone(),
        })
        .await
        .expect("get_bof RPC failed");

    let manifest = get_response.into_inner().manifest.expect("no manifest");
    assert_eq!(manifest.id, bof_id);
}

/// 6. Filter BOFs by category.
#[tokio::test]
async fn test_list_bofs_by_category() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = BofServiceClient::new(channel);

    let response = client
        .list_bo_fs(ListBoFsRequest {
            category: Some(BofCategory::Recon as i32),
            search: None,
            tags: vec![],
        })
        .await
        .expect("list_bofs RPC failed");

    let bofs = response.into_inner().bofs;
    // All returned BOFs should be in the recon category
    for bof in &bofs {
        if let Some(manifest) = &bof.manifest {
            assert_eq!(
                manifest.category,
                BofCategory::Recon as i32,
                "BOF {} has wrong category",
                manifest.name
            );
        }
    }
}

/// 7. Search BOFs by name.
#[tokio::test]
async fn test_search_bofs() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = BofServiceClient::new(channel);

    let response = client
        .list_bo_fs(ListBoFsRequest {
            category: None,
            search: Some("whoami".to_string()),
            tags: vec![],
        })
        .await
        .expect("list_bofs RPC failed");

    let bofs = response.into_inner().bofs;
    assert!(!bofs.is_empty(), "expected to find whoami BOF");
    assert!(
        bofs.iter()
            .filter_map(|b| b.manifest.as_ref())
            .any(|m| m.name.contains("whoami")),
        "expected whoami in results"
    );
}

/// 8. Execute a BOF (creates execution record).
#[tokio::test]
async fn test_execute_bof() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = BofServiceClient::new(channel);

    // Get a BOF ID first
    let list_response = client
        .list_bo_fs(ListBoFsRequest {
            category: None,
            search: Some("whoami".to_string()),
            tags: vec![],
        })
        .await
        .expect("list_bofs RPC failed");

    let bof = list_response
        .into_inner()
        .bofs
        .into_iter()
        .next()
        .expect("no BOFs found");

    let bof_id = bof.manifest.as_ref().expect("no manifest").id.clone();

    // Execute the BOF
    let exec_response = client
        .execute_bof(ExecuteBofRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            bof_id: bof_id.clone(),
            arguments: vec![],
            arch_override: None,
        })
        .await
        .expect("execute_bof RPC failed");

    let inner = exec_response.into_inner();
    assert!(inner.execution_id.is_some(), "expected execution_id");
}

/// 9. Execute BOF with arguments.
#[tokio::test]
async fn test_execute_bof_with_args() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = BofServiceClient::new(channel);

    // Get the 'dir' BOF which takes a path argument
    let list_response = client
        .list_bo_fs(ListBoFsRequest {
            category: None,
            search: Some("dir".to_string()),
            tags: vec![],
        })
        .await
        .expect("list_bofs RPC failed");

    let bof = list_response
        .into_inner()
        .bofs
        .into_iter()
        .find(|b| b.manifest.as_ref().map(|m| m.name == "dir").unwrap_or(false))
        .expect("dir BOF not found");

    let bof_id = bof.manifest.as_ref().expect("no manifest").id.clone();

    // Execute with a path argument (arguments are just strings)
    let exec_response = client
        .execute_bof(ExecuteBofRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            bof_id,
            arguments: vec!["C:\\Windows".to_string()],
            arch_override: None,
        })
        .await
        .expect("execute_bof RPC failed");

    let inner = exec_response.into_inner();
    assert!(inner.execution_id.is_some(), "expected execution_id");
}

/// 10. Get BOF that doesn't exist returns NOT_FOUND.
#[tokio::test]
async fn test_get_bof_not_found() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = BofServiceClient::new(channel);

    let result = client
        .get_bof(GetBofRequest {
            bof_id: "nonexistent-bof-id".to_string(),
        })
        .await;

    let err = result.expect_err("expected NOT_FOUND error");
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "expected NOT_FOUND, got {:?}",
        err.code()
    );
}
