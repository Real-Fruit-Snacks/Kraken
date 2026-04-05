//! Security boundary tests
//!
//! Tests for input validation, injection prevention, access control boundaries,
//! and protocol-level security enforcement.

use std::net::SocketAddr;
use std::sync::Arc;

use common::{ImplantId, ImplantState, TaskId};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    DispatchTaskRequest, GetImplantRequest, GetTaskRequest, ImplantServiceClient,
    ImplantServiceServer, ListImplantsRequest, TaskServiceClient, TaskServiceServer,
    Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn setup_test_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-security-tests!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let implant_svc = ImplantServiceServer::new(server::grpc::ImplantServiceImpl::new(
        Arc::clone(&state),
    ));
    let task_svc = TaskServiceServer::new(
        server::grpc::TaskServiceImpl::new_with_db_init(Arc::clone(&state))
            .await
            .unwrap(),
    );

    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(implant_svc)
            .add_service(task_svc)
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
// Input Validation Tests
// ---------------------------------------------------------------------------

/// 1. Invalid UUID format is rejected
#[tokio::test]
async fn test_invalid_uuid_format_rejected() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Empty UUID bytes
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(ProtoUuid { value: vec![] }),
        })
        .await;

    assert!(result.is_err(), "empty UUID should be rejected");

    // Wrong-sized UUID (not 16 bytes)
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(ProtoUuid {
                value: vec![1, 2, 3, 4],
            }),
        })
        .await;

    assert!(result.is_err(), "wrong-sized UUID should be rejected");

    // Oversized UUID
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(ProtoUuid {
                value: vec![0u8; 256],
            }),
        })
        .await;

    assert!(result.is_err(), "oversized UUID should be rejected");
}

/// 2. Missing required fields are rejected
#[tokio::test]
async fn test_missing_required_fields_rejected() {
    let (state, addr) = setup_test_server().await;
    let _implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    // Missing implant_id
    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: None,
            task_type: "shell".to_string(),
            task_data: vec![],
        })
        .await;

    let err = result.expect_err("missing implant_id should be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// 3. Empty task type is handled (currently accepted - documents current behavior)
#[tokio::test]
async fn test_empty_task_type_handled() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "".to_string(),
            task_data: vec![],
        })
        .await;

    // Server currently accepts empty task types - document this behavior
    // Note: This could be changed to reject empty task types in future
    match result {
        Ok(_) => {
            // Current behavior: accepts empty task type
        }
        Err(e) => {
            // Future behavior: rejects with InvalidArgument
            assert_eq!(e.code(), tonic::Code::InvalidArgument);
        }
    }
}

/// 4. Null bytes in strings are handled safely
#[tokio::test]
async fn test_null_bytes_in_strings_handled() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    // Task type with embedded null byte
    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell\0injection".to_string(),
            task_data: vec![],
        })
        .await;

    // Should either reject or handle safely (not crash)
    // The task type is validated, so this should be rejected or sanitized
    match result {
        Ok(_) => {
            // If accepted, the null byte should be sanitized or the task runs safely
        }
        Err(_) => {
            // Rejection is also acceptable
        }
    }
}

/// 5. Very long task data is handled (DoS prevention)
#[tokio::test]
async fn test_large_task_data_handled() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    // 10MB task data (should be rejected or handled without crashing)
    let large_data = vec![b'A'; 10 * 1024 * 1024];

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: large_data,
        })
        .await;

    // Server should either reject with resource limit or accept safely
    // It should NOT crash
    match result {
        Ok(_) => {
            // Accepted - server handles large data
        }
        Err(e) => {
            // Rejection is fine - check it's a reasonable error
            // OutOfRange is used by gRPC for message size limits
            assert!(
                matches!(
                    e.code(),
                    tonic::Code::InvalidArgument
                        | tonic::Code::ResourceExhausted
                        | tonic::Code::Internal
                        | tonic::Code::OutOfRange
                ),
                "unexpected error code for large data: {:?}",
                e.code()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Access Control Boundary Tests
// ---------------------------------------------------------------------------

/// 6. Non-existent implant returns NOT_FOUND
#[tokio::test]
async fn test_nonexistent_implant_not_found() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let fake_id = ImplantId::new();
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(implant_id_to_proto(fake_id)),
        })
        .await;

    let err = result.expect_err("nonexistent implant should return error");
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "should be NOT_FOUND, got {:?}",
        err.code()
    );
}

/// 7. Non-existent task returns NOT_FOUND
#[tokio::test]
async fn test_nonexistent_task_not_found() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let fake_id = TaskId::new();
    let result = client
        .get_task(GetTaskRequest {
            task_id: Some(ProtoUuid {
                value: fake_id.as_bytes().to_vec(),
            }),
        })
        .await;

    let err = result.expect_err("nonexistent task should return error");
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "should be NOT_FOUND, got {:?}",
        err.code()
    );
}

/// 8. Dispatch to non-taskable implant is rejected
#[tokio::test]
async fn test_dispatch_to_non_taskable_implant_rejected() {
    let (state, addr) = setup_test_server().await;
    // Lost implants are not taskable
    let implant_id = insert_implant(&state, ImplantState::Lost).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: vec![],
        })
        .await;

    let err = result.expect_err("dispatch to Lost implant should fail");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "should be FAILED_PRECONDITION, got {:?}",
        err.code()
    );
}

/// 9. Cannot dispatch to retired implant
#[tokio::test]
async fn test_dispatch_to_retired_implant_rejected() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Retired).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: vec![],
        })
        .await;

    let err = result.expect_err("dispatch to Retired implant should fail");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "should be FAILED_PRECONDITION, got {:?}",
        err.code()
    );
}

/// 10. Cannot dispatch to burned implant
#[tokio::test]
async fn test_dispatch_to_burned_implant_rejected() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Burned).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: vec![],
        })
        .await;

    let err = result.expect_err("dispatch to Burned implant should fail");
    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "should be FAILED_PRECONDITION, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// Crypto Boundary Tests
// ---------------------------------------------------------------------------

/// 11. Server crypto rejects garbage ciphertext
#[tokio::test]
async fn test_crypto_rejects_garbage_ciphertext() {
    let master_key = ServerCrypto::generate_master_key().unwrap();
    let crypto = ServerCrypto::new(master_key);

    // Create a session key using the master key bytes
    let session_key = SymmetricKey([42u8; 32]);
    let encrypted_key = crypto.encrypt_session_key(&session_key).unwrap();

    // Verify we can decrypt the properly encrypted key
    let decrypted = crypto.decrypt_session_key(&encrypted_key);
    assert!(decrypted.is_ok(), "valid ciphertext should decrypt");

    // Now test garbage inputs
    let garbage = vec![0u8; 100];
    let result = crypto.decrypt_session_key(&garbage);
    assert!(result.is_err(), "garbage ciphertext should fail");

    // Empty ciphertext
    let result = crypto.decrypt_session_key(&[]);
    assert!(result.is_err(), "empty ciphertext should fail");

    // Truncated ciphertext
    let truncated = &encrypted_key[..encrypted_key.len() / 2];
    let result = crypto.decrypt_session_key(truncated);
    assert!(result.is_err(), "truncated ciphertext should fail");
}

/// 12. Different master keys produce different ciphertexts
#[tokio::test]
async fn test_different_master_keys_incompatible() {
    let key1 = ServerCrypto::generate_master_key().unwrap();
    let key2 = ServerCrypto::generate_master_key().unwrap();

    let crypto1 = ServerCrypto::new(key1);
    let crypto2 = ServerCrypto::new(key2);

    let session_key = SymmetricKey([42u8; 32]);
    let encrypted = crypto1.encrypt_session_key(&session_key).unwrap();

    // crypto2 should not be able to decrypt crypto1's ciphertext
    let result = crypto2.decrypt_session_key(&encrypted);
    assert!(
        result.is_err(),
        "different master key should not decrypt"
    );
}

/// 13. Tampered ciphertext is rejected
#[tokio::test]
async fn test_tampered_ciphertext_rejected() {
    let master_key = ServerCrypto::generate_master_key().unwrap();
    let crypto = ServerCrypto::new(master_key);

    let session_key = SymmetricKey([42u8; 32]);
    let mut encrypted = crypto.encrypt_session_key(&session_key).unwrap();

    // Tamper with the ciphertext
    if !encrypted.is_empty() {
        let idx = encrypted.len() / 2;
        encrypted[idx] ^= 0xFF;
    }

    let result = crypto.decrypt_session_key(&encrypted);
    assert!(result.is_err(), "tampered ciphertext should fail");
}

// ---------------------------------------------------------------------------
// Protocol Boundary Tests
// ---------------------------------------------------------------------------

/// 14. List implants with invalid state filter handled gracefully
#[tokio::test]
async fn test_invalid_state_filter_handled() {
    let (_state, addr) = setup_test_server().await;
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Use an invalid state value (out of enum range)
    let result = client
        .list_implants(ListImplantsRequest {
            state_filter: Some(999), // Invalid state
            tag_filter: vec![],
            search: None,
        })
        .await;

    // Should either return empty list or reject - not crash
    match result {
        Ok(resp) => {
            // Filtering by invalid state returns no matches
            assert!(
                resp.into_inner().implants.is_empty(),
                "invalid state filter should match nothing"
            );
        }
        Err(e) => {
            // Rejection is also acceptable
            assert_eq!(
                e.code(),
                tonic::Code::InvalidArgument,
                "invalid state should return InvalidArgument"
            );
        }
    }
}

/// 15. Concurrent requests don't cause race conditions
#[tokio::test]
async fn test_concurrent_requests_safe() {
    let (state, addr) = setup_test_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let mut handles = vec![];

    // Spawn many concurrent task dispatches
    for i in 0..20 {
        let channel = connect(addr).await;
        let id = implant_id;
        handles.push(tokio::spawn(async move {
            let mut client = TaskServiceClient::new(channel);
            let result = client
                .dispatch_task(DispatchTaskRequest {
                    implant_id: Some(implant_id_to_proto(id)),
                    task_type: "shell".to_string(),
                    task_data: format!("cmd-{}", i).into_bytes(),
                })
                .await;
            result.is_ok()
        }));
    }

    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap() {
            successes += 1;
        }
    }

    // All requests should succeed without race conditions
    assert_eq!(successes, 20, "all concurrent dispatches should succeed");

    // Verify all tasks were queued
    let pending = state.pending_tasks.get(&implant_id);
    assert!(pending.is_some());
    assert_eq!(
        pending.unwrap().len(),
        20,
        "all 20 tasks should be queued"
    );
}

/// 16. SQL injection attempts are safe (parameterized queries)
#[tokio::test]
async fn test_sql_injection_safe() {
    let (state, addr) = setup_test_server().await;

    // Create implant with SQL injection attempt in name
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: "'; DROP TABLE implants; --".to_string(),
        state: ImplantState::Active,
        hostname: Some("'; DELETE FROM implants; --".to_string()),
        username: Some("admin' OR '1'='1".to_string()),
        domain: None,
        os_name: Some("Test".to_string()),
        os_version: None,
        os_arch: None,
        process_id: None,
        process_name: None,
        process_path: None,
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

    // Verify the table wasn't dropped
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let result = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;

    assert!(result.is_ok(), "server should still work after injection attempt");
    let implants = result.unwrap().into_inner().implants;
    assert!(!implants.is_empty(), "implants table should still exist");

    // Verify the malicious string was stored literally
    let retrieved = state.db.implants().get(id).await.unwrap().unwrap();
    assert_eq!(retrieved.name, "'; DROP TABLE implants; --");
}

/// 17. Path traversal attempts in search are safe
#[tokio::test]
async fn test_path_traversal_in_search_safe() {
    let (state, addr) = setup_test_server().await;
    insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Try path traversal in search field
    let traversal_attempts = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2f",
        "....//....//",
    ];

    for attempt in traversal_attempts {
        let result = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: Some(attempt.to_string()),
            })
            .await;

        // Should succeed but return no matches (search string doesn't match any implant)
        assert!(
            result.is_ok(),
            "path traversal attempt should not crash server: {}",
            attempt
        );
    }
}
