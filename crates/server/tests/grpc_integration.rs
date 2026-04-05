//! Integration tests for gRPC services
//!
//! Each test spins up a real gRPC server bound to a random port and communicates
//! with it using the generated client stubs.

use std::net::SocketAddr;
use std::sync::Arc;

use common::{ImplantId, ImplantState};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    DispatchTaskRequest, GetImplantRequest, GetTaskRequest, ImplantServiceClient,
    ListImplantsRequest, TaskServiceClient, Uuid as ProtoUuid,
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
    let implant_svc = protocol::ImplantServiceServer::new(server::grpc::ImplantServiceImpl::new(
        Arc::clone(&state),
    ));
    let task_svc = protocol::TaskServiceServer::new(
        server::grpc::TaskServiceImpl::new_with_db_init(Arc::clone(&state))
            .await
            .unwrap(),
    );

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(implant_svc)
            .add_service(task_svc)
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

// ---------------------------------------------------------------------------
// Helper: insert a minimal implant record directly through the DB
// ---------------------------------------------------------------------------

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
        os_name: Some("Linux".to_string()),
        os_version: Some("Test".to_string()),
        os_arch: Some("x86_64".to_string()),
        process_id: Some(1234),
        process_name: Some("test".to_string()),
        process_path: Some("/usr/bin/test".to_string()),
        is_elevated: false,
        integrity_level: None,
        local_ips: vec![],
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. List implants returns an empty list when no implants exist.
#[tokio::test]
async fn test_list_implants_empty() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let response = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("list_implants RPC failed");

    assert!(
        response.into_inner().implants.is_empty(),
        "expected empty implant list"
    );
}

/// 2. After inserting an implant directly into the DB it appears in the list.
#[tokio::test]
async fn test_list_implants_with_data() {
    let (state, addr) = setup_test_server().await;
    let id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let response = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("list_implants RPC failed");

    let implants = response.into_inner().implants;
    assert_eq!(implants.len(), 1, "expected exactly one implant");

    let proto_id = implants[0].id.as_ref().expect("implant has no id");
    let returned_id = ImplantId::from_bytes(&proto_id.value).unwrap();
    assert_eq!(returned_id, id, "returned implant ID mismatch");
}

/// 3. Get a specific implant by ID.
#[tokio::test]
async fn test_get_implant() {
    let (state, addr) = setup_test_server().await;
    let id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let response = client
        .get_implant(GetImplantRequest {
            implant_id: Some(implant_id_to_proto(id)),
        })
        .await
        .expect("get_implant RPC failed");

    let implant = response.into_inner();
    let proto_id = implant.id.expect("implant has no id");
    let returned_id = ImplantId::from_bytes(&proto_id.value).unwrap();
    assert_eq!(returned_id, id);
}

/// 4. Getting a non-existent implant returns NOT_FOUND.
#[tokio::test]
async fn test_get_implant_not_found() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let nonexistent = ImplantId::new();
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(implant_id_to_proto(nonexistent)),
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

/// 5. Dispatch a task and verify it is queued in state.pending_tasks.
#[tokio::test]
async fn test_dispatch_task() {
    let (state, addr) = setup_test_server().await;
    // Implant must be Active for dispatch to succeed
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let response = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: b"id".to_vec(),
        })
        .await
        .expect("dispatch_task RPC failed");

    let task_id_proto = response
        .into_inner()
        .task_id
        .expect("dispatch response has no task_id");

    // The task must be queued for the implant
    let pending = state.pending_tasks.get(&implant_id);
    assert!(
        pending.is_some(),
        "no pending tasks for implant after dispatch"
    );
    let tasks = pending.unwrap();
    assert_eq!(tasks.len(), 1, "expected exactly one pending task");

    let queued_id_bytes = &tasks[0]
        .task_id
        .as_ref()
        .expect("queued task has no id")
        .value;
    assert_eq!(
        queued_id_bytes, &task_id_proto.value,
        "queued task ID does not match dispatch response"
    );
}

/// 6. Create a task via dispatch, then retrieve its status via get_task.
#[tokio::test]
async fn test_get_task_status() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut task_client = TaskServiceClient::new(channel);

    // Dispatch the task first
    let dispatch_resp = task_client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "whoami".to_string(),
            task_data: vec![],
        })
        .await
        .expect("dispatch_task failed");

    let task_id_proto = dispatch_resp
        .into_inner()
        .task_id
        .expect("dispatch response has no task_id");

    // Retrieve the task status
    let get_resp = task_client
        .get_task(GetTaskRequest {
            task_id: Some(task_id_proto.clone()),
        })
        .await
        .expect("get_task RPC failed");

    let task_info = get_resp.into_inner();

    // Status should be "queued" (proto value 1)
    assert_eq!(
        task_info.status,
        protocol::TaskStatus::Queued as i32,
        "expected task to be in Queued status"
    );

    // IDs must match
    let returned_task_id = task_info.task_id.expect("task_info has no task_id");
    assert_eq!(
        returned_task_id.value, task_id_proto.value,
        "returned task ID mismatch"
    );

    let returned_implant_id = task_info.implant_id.expect("task_info has no implant_id");
    let parsed = ImplantId::from_bytes(&returned_implant_id.value).unwrap();
    assert_eq!(parsed, implant_id, "task implant_id mismatch");
}

/// 7. Dispatching a task to a non-taskable implant (Lost state) returns
///    FAILED_PRECONDITION.
#[tokio::test]
async fn test_dispatch_task_to_non_taskable_implant() {
    let (state, addr) = setup_test_server().await;
    // Insert implant in Lost state — not taskable
    let implant_id = insert_implant(&state, ImplantState::Lost).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: b"id".to_vec(),
        })
        .await;

    let err = result.expect_err("expected error dispatching to non-taskable implant");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "expected FAILED_PRECONDITION, got {:?}",
        err.code()
    );
}

/// 8. Dispatching a task to a non-existent implant returns NOT_FOUND.
#[tokio::test]
async fn test_dispatch_task_implant_not_found() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(ImplantId::new())),
            task_type: "shell".to_string(),
            task_data: vec![],
        })
        .await;

    let err = result.expect_err("expected NOT_FOUND for missing implant");
    assert_eq!(err.code(), tonic::Code::NotFound);
}

/// 9. Cancelling an already-terminal task returns FAILED_PRECONDITION.
#[tokio::test]
async fn test_cancel_terminal_task_fails() {
    use protocol::{CancelTaskRequest, TaskServiceClient};

    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    // Dispatch a task first
    let dispatch_resp = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: b"id".to_vec(),
        })
        .await
        .expect("dispatch_task failed");

    let task_id_proto = dispatch_resp.into_inner().task_id.expect("no task_id");

    // Mark it completed directly in the DB
    let task_id = common::TaskId::from_bytes(&task_id_proto.value).unwrap();
    state
        .db
        .tasks()
        .update_result(task_id, "completed", Some(b"done"), None)
        .await
        .unwrap();

    // Now try to cancel — should fail with FAILED_PRECONDITION
    let result = client
        .cancel_task(CancelTaskRequest {
            task_id: Some(task_id_proto),
        })
        .await;

    let err = result.expect_err("expected error cancelling completed task");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "expected FAILED_PRECONDITION, got {:?}",
        err.code()
    );
}

/// 10. Cancelling a pending task succeeds and clears it from pending_tasks.
#[tokio::test]
async fn test_cancel_pending_task_succeeds() {
    use protocol::{CancelTaskRequest, TaskServiceClient, TaskStatus};

    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let dispatch_resp = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: b"id".to_vec(),
        })
        .await
        .expect("dispatch_task failed");

    let task_id_proto = dispatch_resp.into_inner().task_id.expect("no task_id");

    let cancel_resp = client
        .cancel_task(CancelTaskRequest {
            task_id: Some(task_id_proto.clone()),
        })
        .await
        .expect("cancel_task RPC failed");

    let task_info = cancel_resp.into_inner();
    assert_eq!(
        task_info.status,
        TaskStatus::Cancelled as i32,
        "expected Cancelled status after cancel"
    );

    // Task must no longer be in the in-memory pending queue
    assert!(
        state.pending_tasks.get(&implant_id).map(|t| t.is_empty()).unwrap_or(true),
        "pending queue should be empty after cancellation"
    );
}

/// 11. Burning an implant that is already in a terminal state returns
///     FAILED_PRECONDITION.
#[tokio::test]
async fn test_burn_terminal_implant_fails() {
    use protocol::{BurnImplantRequest, ImplantServiceClient};

    let (state, addr) = setup_test_server().await;
    // Retired implants are terminal — use Retired state
    let implant_id = insert_implant(&state, common::ImplantState::Retired).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let result = client
        .burn_implant(BurnImplantRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            reason: "test".to_string(),
        })
        .await;

    let err = result.expect_err("expected FAILED_PRECONDITION burning terminal implant");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "expected FAILED_PRECONDITION, got {:?}",
        err.code()
    );
}

/// 12. Retiring an implant that is already terminal returns FAILED_PRECONDITION.
#[tokio::test]
async fn test_retire_terminal_implant_fails() {
    use protocol::{ImplantServiceClient, RetireImplantRequest};

    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, common::ImplantState::Burned).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let result = client
        .retire_implant(RetireImplantRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
        })
        .await;

    let err = result.expect_err("expected FAILED_PRECONDITION retiring terminal implant");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "expected FAILED_PRECONDITION, got {:?}",
        err.code()
    );
}

/// 13. list_implants with a state filter only returns matching implants.
#[tokio::test]
async fn test_list_implants_state_filter() {
    use protocol::ImplantState as ProtoImplantState;

    let (state, addr) = setup_test_server().await;
    insert_implant(&state, ImplantState::Active).await;
    insert_implant(&state, ImplantState::Active).await;
    insert_implant(&state, ImplantState::Lost).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: Some(ProtoImplantState::Active as i32),
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("list_implants RPC failed");

    let implants = resp.into_inner().implants;
    assert_eq!(implants.len(), 2, "expected 2 Active implants, got {}", implants.len());
    for imp in &implants {
        assert_eq!(
            imp.state,
            ProtoImplantState::Active as i32,
            "implant state should be Active"
        );
    }
}

/// 14. get_task returns NOT_FOUND for a non-existent task ID.
#[tokio::test]
async fn test_get_task_not_found() {
    use common::TaskId;

    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let fake_task_id = ProtoUuid {
        value: TaskId::new().as_bytes().to_vec(),
    };

    let result = client
        .get_task(GetTaskRequest {
            task_id: Some(fake_task_id),
        })
        .await;

    let err = result.expect_err("expected NOT_FOUND for missing task");
    assert_eq!(err.code(), tonic::Code::NotFound);
}
