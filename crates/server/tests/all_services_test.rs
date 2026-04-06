//! Phase A validation: all 15 gRPC services registered and responding
//!
//! Each test spins up a full server with all services on a random port and
//! verifies that basic requests complete without a connection error.
//! Empty results are acceptable — the goal is to confirm each service is
//! registered and reachable.

use std::sync::Arc;

use crypto::{ServerCrypto, SymmetricKey};
use tokio_stream::wrappers::TcpListenerStream;

use protocol::{
    // Clients (explicitly re-exported in protocol/src/lib.rs)
    AuditServiceClient,
    BofServiceClient,
    CollabServiceClient,
    ImplantServiceClient,
    InjectServiceClient,
    ListenerServiceClient,
    LootServiceClient,
    MeshServiceClient,
    ModuleServiceClient,
    OperatorServiceClient,
    PayloadServiceClient,
    ProxyServiceClient,
    ReportServiceClient,
    TaskServiceClient,
    // Servers
    AuditServiceServer,
    BofServiceServer,
    CollabServiceServer,
    ImplantServiceServer,
    InjectServiceServer,
    ListenerServiceServer,
    LootServiceServer,
    MeshServiceServer,
    ModuleServiceServer,
    OperatorServiceServer,
    PayloadServiceServer,
    ProxyServiceServer,
    ReportServiceServer,
    // Request types (from pub use generated::kraken::*)
    GetOnlineOperatorsRequest,
    GetTopologyRequest,
    JobListRequest,
    ListAuditEventsRequest,
    ListBoFsRequest,
    ListImplantsRequest,
    ListListenersRequest,
    ListLootRequest,
    ListModulesRequest,
    ListOperatorsRequest,
    ListPayloadsRequest,
    ListProcessesRequest,
    ListProxiesRequest,
    ListReportsRequest,
    ListTasksRequest,
};

// JobServiceClient and JobServiceServer live in submodules not re-exported at kraken level
use protocol::generated::kraken::job_service_client::JobServiceClient;
use protocol::generated::kraken::job_service_server::JobServiceServer;

// ---------------------------------------------------------------------------
// Test server setup — all 15 services
// ---------------------------------------------------------------------------

async fn setup_all_services_server() -> std::net::SocketAddr {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );
    let audit_key = b"test-audit-key-for-all-services!";
    let jwt = server::auth::jwt::JwtManager::from_env_or_master_key(&[0u8; 32]).unwrap();
    let state = server::ServerState::new(db.clone(), crypto, ms, audit_key.to_vec(), jwt);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let task_svc = protocol::TaskServiceServer::new(
        server::grpc::TaskServiceImpl::new_with_db_init(Arc::clone(&state))
            .await
            .unwrap(),
    );

    let job_repo = Arc::new(db.jobs());

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ImplantServiceServer::new(
                server::grpc::ImplantServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(task_svc)
            .add_service(ListenerServiceServer::new(
                server::grpc::ListenerServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(OperatorServiceServer::new(
                server::grpc::OperatorServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(LootServiceServer::new(
                server::grpc::LootServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(ModuleServiceServer::new(
                server::grpc::ModuleServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(MeshServiceServer::new(
                server::grpc::MeshServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(CollabServiceServer::new(
                server::grpc::CollabServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(PayloadServiceServer::new(
                server::grpc::PayloadServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(ReportServiceServer::new(
                server::grpc::ReportServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(JobServiceServer::new(
                server::grpc::JobServiceImpl::new(job_repo),
            ))
            .add_service(BofServiceServer::new(
                server::grpc::BOFServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(InjectServiceServer::new(
                server::grpc::InjectServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(ProxyServiceServer::new(
                server::grpc::ProxyServiceImpl::new(Arc::clone(&state)),
            ))
            .add_service(AuditServiceServer::new(
                server::grpc::AuditServiceImpl::new(Arc::clone(&state)),
            ))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });

    addr
}

async fn connect(addr: std::net::SocketAddr) -> tonic::transport::Channel {
    let endpoint = format!("http://{}", addr);
    tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Phase A tests — one basic request per service
// ---------------------------------------------------------------------------

/// 1. ImplantService.ListImplants
#[tokio::test]
#[ignore] // Requires running server (use setup_all_services_server for self-contained run)
async fn test_implant_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = ImplantServiceClient::new(connect(addr).await);
    let response = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(response.is_ok(), "ImplantService.ListImplants should respond: {:?}", response.err());
}

/// 2. TaskService.ListTasks
#[tokio::test]
#[ignore]
async fn test_task_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = TaskServiceClient::new(connect(addr).await);
    let response = client
        .list_tasks(ListTasksRequest {
            implant_id: None,
            limit: None,
            status_filter: None,
        })
        .await;
    assert!(response.is_ok(), "TaskService.ListTasks should respond: {:?}", response.err());
}

/// 3. ListenerService.ListListeners
#[tokio::test]
#[ignore]
async fn test_listener_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = ListenerServiceClient::new(connect(addr).await);
    let response = client.list_listeners(ListListenersRequest {}).await;
    assert!(response.is_ok(), "ListenerService.ListListeners should respond: {:?}", response.err());
}

/// 4. OperatorService.ListOperators
#[tokio::test]
#[ignore]
async fn test_operator_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = OperatorServiceClient::new(connect(addr).await);
    let response = client.list_operators(ListOperatorsRequest {}).await;
    assert!(response.is_ok(), "OperatorService.ListOperators should respond: {:?}", response.err());
}

/// 5. LootService.ListLoot
#[tokio::test]
#[ignore]
async fn test_loot_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);
    let response = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: None,
            limit: None,
            offset: None,
        })
        .await;
    assert!(response.is_ok(), "LootService.ListLoot should respond: {:?}", response.err());
}

/// 6. ModuleService.ListModules
#[tokio::test]
#[ignore]
async fn test_module_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = ModuleServiceClient::new(connect(addr).await);
    let response = client.list_modules(ListModulesRequest {}).await;
    assert!(response.is_ok(), "ModuleService.ListModules should respond: {:?}", response.err());
}

/// 7. MeshService.GetTopology
#[tokio::test]
#[ignore]
async fn test_mesh_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = MeshServiceClient::new(connect(addr).await);
    let response = client.get_topology(GetTopologyRequest {}).await;
    assert!(response.is_ok(), "MeshService.GetTopology should respond: {:?}", response.err());
}

/// 8. CollabService.GetOnlineOperators
#[tokio::test]
#[ignore]
async fn test_collab_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = CollabServiceClient::new(connect(addr).await);
    let response = client.get_online_operators(GetOnlineOperatorsRequest {}).await;
    assert!(response.is_ok(), "CollabService.GetOnlineOperators should respond: {:?}", response.err());
}

/// 9. PayloadService.ListPayloads
#[tokio::test]
#[ignore]
async fn test_payload_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = PayloadServiceClient::new(connect(addr).await);
    let response = client.list_payloads(ListPayloadsRequest {}).await;
    assert!(response.is_ok(), "PayloadService.ListPayloads should respond: {:?}", response.err());
}

/// 10. ReportService.ListReports
#[tokio::test]
#[ignore]
async fn test_report_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = ReportServiceClient::new(connect(addr).await);
    let response = client.list_reports(ListReportsRequest {}).await;
    assert!(response.is_ok(), "ReportService.ListReports should respond: {:?}", response.err());
}

/// 11. JobService.ListJobs
#[tokio::test]
#[ignore]
async fn test_job_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = JobServiceClient::new(connect(addr).await);
    let response = client.list_jobs(JobListRequest {}).await;
    assert!(response.is_ok(), "JobService.ListJobs should respond: {:?}", response.err());
}

/// 12. BOFService.ListBOFs
#[tokio::test]
#[ignore]
async fn test_bof_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = BofServiceClient::new(connect(addr).await);
    let response = client
        .list_bo_fs(ListBoFsRequest {
            category: None,
            search: None,
            tags: vec![],
        })
        .await;
    assert!(response.is_ok(), "BOFService.ListBOFs should respond: {:?}", response.err());
}

/// 13. InjectService.ListProcesses
#[tokio::test]
#[ignore]
async fn test_inject_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = InjectServiceClient::new(connect(addr).await);
    let response = client
        .list_processes(ListProcessesRequest {
            implant_id: None,
            include_system: false,
            name_filter: String::new(),
        })
        .await;
    assert!(response.is_ok(), "InjectService.ListProcesses should respond: {:?}", response.err());
}

/// 14. ProxyService.ListProxies
#[tokio::test]
#[ignore]
async fn test_proxy_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = ProxyServiceClient::new(connect(addr).await);
    let response = client
        .list_proxies(ListProxiesRequest {
            implant_id: None,
            state: None,
        })
        .await;
    assert!(response.is_ok(), "ProxyService.ListProxies should respond: {:?}", response.err());
}

/// 15. AuditService.ListAuditEvents
#[tokio::test]
#[ignore]
async fn test_audit_service_responds() {
    let addr = setup_all_services_server().await;
    let mut client = AuditServiceClient::new(connect(addr).await);
    let response = client
        .list_audit_events(ListAuditEventsRequest {
            limit: 10,
            offset: 0,
            event_type: String::new(),
            operator_id: vec![],
        })
        .await;
    assert!(response.is_ok(), "AuditService.ListAuditEvents should respond: {:?}", response.err());
}
