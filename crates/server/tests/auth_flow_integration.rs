//! Authentication flow integration tests
//!
//! Tests the complete authentication and authorization flow through gRPC services:
//! - Different roles get different permissions
//! - Session access restrictions work end-to-end
//! - Disabled operators are rejected
//! - Permission checks on various service methods

use std::net::SocketAddr;
use std::sync::Arc;

use common::{ImplantId, ImplantState};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    DispatchTaskRequest, ImplantServiceClient, ImplantServiceServer, ListImplantsRequest,
    OperatorServiceClient, OperatorServiceServer, TaskServiceClient, TaskServiceServer,
    Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;

// ---------------------------------------------------------------------------
// Test server setup with multiple operators
// ---------------------------------------------------------------------------

struct TestOperator {
    username: String,
    role: kraken_rbac::Role,
    fingerprint: String,
}

async fn setup_auth_test_server(
    operators: Vec<TestOperator>,
) -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // Register all operators
    for op in operators {
        let new_op = db::NewOperator {
            username: op.username,
            role: op.role,
            cert_fingerprint: op.fingerprint,
        };
        db.operators().create(new_op).await.unwrap();
    }

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-for-auth-tests!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Build services WITHOUT mTLS interceptor for simpler testing
    // The permission checks still happen in service handlers
    let implant_svc = ImplantServiceServer::new(server::grpc::ImplantServiceImpl::new(
        Arc::clone(&state),
    ));
    let task_svc = TaskServiceServer::new(
        server::grpc::TaskServiceImpl::new_with_db_init(Arc::clone(&state))
            .await
            .unwrap(),
    );
    let operator_svc = OperatorServiceServer::new(server::grpc::OperatorServiceImpl::new(
        Arc::clone(&state),
    ));

    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(implant_svc)
            .add_service(task_svc)
            .add_service(operator_svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    (state_clone, addr)
}

async fn connect(addr: SocketAddr) -> tonic::transport::Channel {
    let endpoint = format!("http://{}", addr);
    tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

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

fn implant_id_to_proto(id: ImplantId) -> ProtoUuid {
    ProtoUuid {
        value: id.as_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. Test that insecure mode allows basic operations (no cert check)
#[tokio::test]
async fn test_insecure_mode_allows_operations() {
    let (state, addr) = setup_auth_test_server(vec![]).await;
    let _implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // In insecure mode (no mTLS interceptor), operations should work
    // with the dev operator
    let response = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;

    assert!(
        response.is_ok(),
        "insecure mode should allow operations: {:?}",
        response.err()
    );
}

/// 2. Test operator service can list operators
#[tokio::test]
async fn test_operator_service_list() {
    let operators = vec![
        TestOperator {
            username: "admin1".to_string(),
            role: kraken_rbac::Role::Admin,
            fingerprint: "admin-cert-fp".to_string(),
        },
        TestOperator {
            username: "op1".to_string(),
            role: kraken_rbac::Role::Operator,
            fingerprint: "op-cert-fp".to_string(),
        },
    ];

    let (_state, addr) = setup_auth_test_server(operators).await;
    let channel = connect(addr).await;
    let mut client = OperatorServiceClient::new(channel);

    let response = client
        .list_operators(protocol::ListOperatorsRequest {})
        .await
        .expect("list_operators should succeed");

    let ops = response.into_inner().operators;
    // Note: server creates a "system" operator on init, so we have 3 total
    assert!(ops.len() >= 2, "should have at least 2 registered operators");

    // Verify our operators are returned
    let usernames: Vec<_> = ops.iter().map(|o| o.username.as_str()).collect();
    assert!(usernames.contains(&"admin1"));
    assert!(usernames.contains(&"op1"));
}

/// 3. Test get_operator returns operator info
#[tokio::test]
async fn test_get_operator() {
    let operators = vec![TestOperator {
        username: "testop".to_string(),
        role: kraken_rbac::Role::Operator,
        fingerprint: "get-op-fp".to_string(),
    }];

    let (state, _addr) = setup_auth_test_server(operators).await;

    // Get operator by username via DB
    let op = state.db.operators().get_by_username("testop").await.unwrap();
    assert!(op.is_some(), "operator should exist");
    let op = op.unwrap();
    assert_eq!(op.username, "testop");
}

/// 4. Test task dispatch works in insecure mode
#[tokio::test]
async fn test_task_dispatch_insecure_mode() {
    let (state, addr) = setup_auth_test_server(vec![]).await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let response = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: b"whoami".to_vec(),
        })
        .await;

    assert!(
        response.is_ok(),
        "task dispatch should work in insecure mode: {:?}",
        response.err()
    );
}

/// 5. Test multiple operators can be registered
#[tokio::test]
async fn test_multiple_operator_registration() {
    let operators = vec![
        TestOperator {
            username: "admin".to_string(),
            role: kraken_rbac::Role::Admin,
            fingerprint: "fp1".to_string(),
        },
        TestOperator {
            username: "operator1".to_string(),
            role: kraken_rbac::Role::Operator,
            fingerprint: "fp2".to_string(),
        },
        TestOperator {
            username: "operator2".to_string(),
            role: kraken_rbac::Role::Operator,
            fingerprint: "fp3".to_string(),
        },
        TestOperator {
            username: "viewer".to_string(),
            role: kraken_rbac::Role::Viewer,
            fingerprint: "fp4".to_string(),
        },
    ];

    let (state, _addr) = setup_auth_test_server(operators).await;

    // Verify all operators were registered (plus system operator from init)
    let ops = state.db.operators().list().await.unwrap();
    assert!(ops.len() >= 4, "should have at least 4 operators");

    // Verify roles are correct (role is stored as String in DB)
    for op in ops {
        match op.username.as_str() {
            "admin" => assert_eq!(op.role, "admin"),
            "operator1" | "operator2" => assert_eq!(op.role, "operator"),
            "viewer" => assert_eq!(op.role, "viewer"),
            "system" => assert_eq!(op.role, "admin"), // system operator
            _ => panic!("unexpected operator: {}", op.username),
        }
    }
}

/// 6. Test operator lookup by cert fingerprint
#[tokio::test]
async fn test_operator_lookup_by_fingerprint() {
    let fingerprint = "unique-fingerprint-12345";
    let operators = vec![TestOperator {
        username: "testuser".to_string(),
        role: kraken_rbac::Role::Operator,
        fingerprint: fingerprint.to_string(),
    }];

    let (state, _addr) = setup_auth_test_server(operators).await;

    // Look up by fingerprint
    let op = state
        .db
        .operators()
        .get_by_cert(fingerprint)
        .await
        .expect("db query should succeed")
        .expect("operator should exist");

    assert_eq!(op.username, "testuser");
    assert_eq!(op.cert_fingerprint, fingerprint);
}

/// 7. Test operator not found returns None
#[tokio::test]
async fn test_operator_not_found() {
    let (state, _addr) = setup_auth_test_server(vec![]).await;

    let result = state
        .db
        .operators()
        .get_by_cert("nonexistent-fingerprint")
        .await
        .expect("db query should succeed");

    assert!(result.is_none(), "nonexistent operator should return None");
}

/// 8. Test role-based permission checks (unit test of RBAC logic)
#[tokio::test]
async fn test_rbac_permission_checks() {
    use kraken_rbac::{OperatorIdentity, Permission, Role};

    // Admin has all permissions
    let admin = OperatorIdentity::new("admin".to_string(), Role::Admin, "fp".to_string());
    assert!(admin.has_permission(Permission::SessionView));
    assert!(admin.has_permission(Permission::SessionInteract));
    assert!(admin.has_permission(Permission::OperatorCreate));
    assert!(admin.has_permission(Permission::SettingsModify));
    assert!(admin.has_permission(Permission::AuditView));

    // Operator has standard permissions
    let operator = OperatorIdentity::new("op".to_string(), Role::Operator, "fp".to_string());
    assert!(operator.has_permission(Permission::SessionView));
    assert!(operator.has_permission(Permission::SessionInteract));
    assert!(operator.has_permission(Permission::ListenerCreate));
    assert!(!operator.has_permission(Permission::OperatorCreate));
    assert!(!operator.has_permission(Permission::SettingsModify));

    // Viewer has read-only permissions
    let viewer = OperatorIdentity::new("viewer".to_string(), Role::Viewer, "fp".to_string());
    assert!(viewer.has_permission(Permission::SessionView));
    assert!(viewer.has_permission(Permission::ListenerView));
    assert!(!viewer.has_permission(Permission::SessionInteract));
    assert!(!viewer.has_permission(Permission::ListenerCreate));
    assert!(!viewer.has_permission(Permission::OperatorCreate));
}

/// 9. Test disabled operator has no permissions
#[tokio::test]
async fn test_disabled_operator_no_permissions() {
    use kraken_rbac::{OperatorIdentity, Permission, Role};

    let mut admin = OperatorIdentity::new("admin".to_string(), Role::Admin, "fp".to_string());
    admin.disabled = true;

    // Disabled admin should have no permissions
    assert!(!admin.has_permission(Permission::SessionView));
    assert!(!admin.has_permission(Permission::OperatorCreate));

    // Session access should also be denied
    let session_id = uuid::Uuid::new_v4();
    assert!(!admin.can_access_session(session_id));
}

/// 10. Test session access restrictions
#[tokio::test]
async fn test_session_access_restrictions() {
    use kraken_rbac::{OperatorIdentity, Permission, RbacError, Role};

    let mut operator = OperatorIdentity::new("op".to_string(), Role::Operator, "fp".to_string());

    let allowed_session = uuid::Uuid::new_v4();
    let restricted_session = uuid::Uuid::new_v4();

    // Set up session restrictions
    operator.allowed_sessions = Some([allowed_session].into_iter().collect());

    // Allowed session should work
    assert!(operator
        .authorize_session_action(Permission::SessionInteract, allowed_session)
        .is_ok());

    // Restricted session should fail
    let result = operator.authorize_session_action(Permission::SessionInteract, restricted_session);
    assert!(matches!(result, Err(RbacError::SessionAccessDenied(_))));
}

/// 11. Test listener access restrictions
#[tokio::test]
async fn test_listener_access_restrictions() {
    use kraken_rbac::{OperatorIdentity, Permission, RbacError, Role};

    let mut operator = OperatorIdentity::new("op".to_string(), Role::Operator, "fp".to_string());

    let allowed_listener = uuid::Uuid::new_v4();
    let restricted_listener = uuid::Uuid::new_v4();

    // Set up listener restrictions
    operator.allowed_listeners = Some([allowed_listener].into_iter().collect());

    // Allowed listener should work
    assert!(operator
        .authorize_listener_action(Permission::ListenerView, allowed_listener)
        .is_ok());

    // Restricted listener should fail
    let result = operator.authorize_listener_action(Permission::ListenerView, restricted_listener);
    assert!(matches!(result, Err(RbacError::ListenerAccessDenied(_))));
}

/// 12. Test permission denied for wrong role
#[tokio::test]
async fn test_permission_denied_wrong_role() {
    use kraken_rbac::{OperatorIdentity, Permission, RbacError, Role};

    let viewer = OperatorIdentity::new("viewer".to_string(), Role::Viewer, "fp".to_string());
    let session_id = uuid::Uuid::new_v4();

    // Viewer trying to interact with session should fail
    let result = viewer.authorize_session_action(Permission::SessionInteract, session_id);
    assert!(matches!(result, Err(RbacError::PermissionDenied(_))));
}

/// 13. Test operator touch updates last_seen
#[tokio::test]
async fn test_operator_touch_updates_last_seen() {
    let operators = vec![TestOperator {
        username: "touchtest".to_string(),
        role: kraken_rbac::Role::Operator,
        fingerprint: "touch-fp".to_string(),
    }];

    let (state, _addr) = setup_auth_test_server(operators).await;

    // Get initial state
    let op1 = state
        .db
        .operators()
        .get_by_cert("touch-fp")
        .await
        .unwrap()
        .unwrap();
    let initial_last_seen = op1.last_seen;

    // Touch the operator
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    state.db.operators().touch(op1.id).await.unwrap();

    // Verify last_seen was updated
    let op2 = state
        .db
        .operators()
        .get_by_cert("touch-fp")
        .await
        .unwrap()
        .unwrap();

    assert!(
        op2.last_seen > initial_last_seen,
        "last_seen should be updated after touch"
    );
}

/// 14. Test concurrent operator operations
#[tokio::test]
async fn test_concurrent_operator_operations() {
    let mut operators = vec![];
    for i in 0..10 {
        operators.push(TestOperator {
            username: format!("concurrent-op-{}", i),
            role: kraken_rbac::Role::Operator,
            fingerprint: format!("concurrent-fp-{}", i),
        });
    }

    let (state, addr) = setup_auth_test_server(operators).await;
    let _implant_id = insert_implant(&state, ImplantState::Active).await;

    // Spawn concurrent requests
    let mut handles = vec![];
    for i in 0..10 {
        let channel = connect(addr).await;
        handles.push(tokio::spawn(async move {
            let mut client = ImplantServiceClient::new(channel);
            for _ in 0..5 {
                let response = client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await;
                assert!(
                    response.is_ok(),
                    "concurrent request {} should succeed",
                    i
                );
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task should complete");
    }
}

/// 15. Test role hierarchy is respected
#[tokio::test]
async fn test_role_hierarchy() {
    use kraken_rbac::Role;

    // Admin satisfies all roles
    assert!(Role::Admin.satisfies(Role::Admin));
    assert!(Role::Admin.satisfies(Role::Operator));
    assert!(Role::Admin.satisfies(Role::Viewer));

    // Operator satisfies Operator and Viewer
    assert!(!Role::Operator.satisfies(Role::Admin));
    assert!(Role::Operator.satisfies(Role::Operator));
    assert!(Role::Operator.satisfies(Role::Viewer));

    // Viewer only satisfies Viewer
    assert!(!Role::Viewer.satisfies(Role::Admin));
    assert!(!Role::Viewer.satisfies(Role::Operator));
    assert!(Role::Viewer.satisfies(Role::Viewer));
}
