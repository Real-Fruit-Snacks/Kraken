//! Chaos and resilience tests
//!
//! Tests for system behavior under adverse conditions:
//! - Connection drops and reconnection
//! - Corrupted/malformed data
//! - Resource exhaustion scenarios
//! - Race conditions and concurrent stress

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{ImplantId, ImplantState, OperatorId, TaskId};
use crypto::{ServerCrypto, SymmetricKey};
use db::{ImplantRecord, NewOperator, TaskRecord};
use protocol::{
    DispatchTaskRequest, GetImplantRequest, ImplantServiceClient, ListImplantsRequest,
    TaskServiceClient, Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn setup_chaos_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-for-chaos-tests!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

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

    tokio::time::sleep(Duration::from_millis(50)).await;

    (state, addr)
}

async fn connect(addr: SocketAddr) -> Channel {
    let endpoint = format!("http://{}", addr);
    Channel::from_shared(endpoint)
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
        name: format!("chaos-{}", id),
        state: implant_state,
        hostname: Some("chaos-host".to_string()),
        username: Some("chaos-user".to_string()),
        domain: None,
        os_name: Some("Linux".to_string()),
        os_version: Some("Test".to_string()),
        os_arch: Some("x86_64".to_string()),
        process_id: Some(1234),
        process_name: Some("test".to_string()),
        process_path: Some("/test".to_string()),
        is_elevated: false,
        integrity_level: None,
        local_ips: vec!["10.0.0.1".to_string()],
        checkin_interval: 60,
        jitter_percent: 10,
        symmetric_key: Some(vec![0x42; 32]),
        nonce_counter: 0,
        registered_at: now,
        last_seen: Some(now),
    };
    state.db.implants().create(&record).await.expect("insert implant");
    id
}

// ---------------------------------------------------------------------------
// Connection Resilience Tests
// ---------------------------------------------------------------------------

/// 1. Server handles rapid connect/disconnect cycles
#[tokio::test]
async fn test_rapid_connect_disconnect() {
    let (_state, addr) = setup_chaos_server().await;

    // Rapid connection cycles
    for i in 0..20 {
        let channel_result = Channel::from_shared(format!("http://{}", addr))
            .unwrap()
            .connect_timeout(Duration::from_millis(100))
            .connect()
            .await;

        match channel_result {
            Ok(channel) => {
                let mut client = ImplantServiceClient::new(channel);
                // Quick request then drop
                let _ = client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await;
                // Channel dropped here
            }
            Err(_) => {
                // Connection failed, that's fine for stress testing
            }
        }

        if i % 5 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // Server should still be responsive
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(resp.is_ok(), "server should be responsive after stress");
}

/// 2. Concurrent requests from multiple clients
#[tokio::test]
async fn test_concurrent_multi_client_stress() {
    let (state, addr) = setup_chaos_server().await;

    // Insert test data
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let mut handles = vec![];

    // Spawn 50 concurrent clients
    for i in 0..50 {
        let addr = addr;
        let id = implant_id;
        handles.push(tokio::spawn(async move {
            let channel = Channel::from_shared(format!("http://{}", addr))
                .unwrap()
                .connect_timeout(Duration::from_secs(5))
                .connect()
                .await?;
            let mut client = ImplantServiceClient::new(channel);

            // Each client does multiple requests
            for _ in 0..10 {
                client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await?;

                client
                    .get_implant(GetImplantRequest {
                        implant_id: Some(ProtoUuid {
                            value: id.as_bytes().to_vec(),
                        }),
                    })
                    .await?;
            }

            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(i)
        }));
    }

    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            successes += 1;
        }
    }

    // At least 80% should succeed under stress
    assert!(
        successes >= 40,
        "at least 80% of concurrent clients should succeed, got {}",
        successes
    );
}

// ---------------------------------------------------------------------------
// Malformed Data Resilience Tests
// ---------------------------------------------------------------------------

/// 3. Server handles empty UUID gracefully
#[tokio::test]
async fn test_empty_uuid_handling() {
    let (_state, addr) = setup_chaos_server().await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Empty UUID
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(ProtoUuid { value: vec![] }),
        })
        .await;

    // Should return error, not crash (GetImplant returns Implant directly, so error = not found)
    assert!(result.is_err(), "empty UUID should return error");
}

/// 4. Server handles oversized UUID
#[tokio::test]
async fn test_oversized_uuid_handling() {
    let (_state, addr) = setup_chaos_server().await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // 256 bytes instead of 16
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(ProtoUuid {
                value: vec![0xAB; 256],
            }),
        })
        .await;

    // Should return error, not crash
    assert!(result.is_err(), "oversized UUID should return error");
}

/// 5. Server handles malformed protobuf in task data
#[tokio::test]
async fn test_malformed_task_data() {
    let (state, addr) = setup_chaos_server().await;

    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    // Random bytes as task data
    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(ProtoUuid {
                value: implant_id.as_bytes().to_vec(),
            }),
            task_type: "shell".to_string(),
            task_data: vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB],
        })
        .await;

    // Server may accept (stores opaque data) or reject - either is fine
    // The key is it doesn't crash
    drop(result);
}

/// 6. Server handles very long search strings
#[tokio::test]
async fn test_very_long_string_handling() {
    let (_state, addr) = setup_chaos_server().await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // 100KB search string (not 1MB to avoid gRPC limits)
    let long_string = "A".repeat(100 * 1024);

    let result = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: Some(long_string),
        })
        .await;

    // Should handle gracefully (return empty or error)
    match result {
        Ok(resp) => {
            // Search with huge string should return empty
            assert!(resp.into_inner().implants.is_empty());
        }
        Err(status) => {
            // Resource exhausted or invalid argument is acceptable
            let code = status.code();
            assert!(
                code == tonic::Code::InvalidArgument
                    || code == tonic::Code::ResourceExhausted
                    || code == tonic::Code::Internal
            );
        }
    }
}

// ---------------------------------------------------------------------------
// State Consistency Tests
// ---------------------------------------------------------------------------

/// 7. Concurrent updates to same implant
#[tokio::test]
async fn test_concurrent_same_implant_updates() {
    let (state, _addr) = setup_chaos_server().await;

    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let mut handles = vec![];

    // 20 concurrent state updates
    for i in 0..20 {
        let db = state.db.clone();
        let id = implant_id;
        handles.push(tokio::spawn(async move {
            let new_state = if i % 2 == 0 {
                ImplantState::Active
            } else {
                ImplantState::Lost
            };
            db.implants().update_state(id, new_state).await
        }));
    }

    for handle in handles {
        // All updates should succeed (SQLite handles serialization)
        handle.await.unwrap().expect("update should succeed");
    }

    // Final state should be one of the valid states
    let implant = state.db.implants().get(implant_id).await.unwrap().unwrap();
    assert!(
        implant.state == ImplantState::Active || implant.state == ImplantState::Lost,
        "final state should be valid"
    );
}

/// 8. Concurrent task creation for same implant
#[tokio::test]
async fn test_concurrent_task_creation() {
    let (state, _addr) = setup_chaos_server().await;

    let implant_id = insert_implant(&state, ImplantState::Active).await;

    // Create an operator for tasks
    let op = NewOperator {
        username: "chaos-op".to_string(),
        role: kraken_rbac::Role::Operator,
        cert_fingerprint: "chaos-fp".to_string(),
    };
    let op_record = state.db.operators().create(op).await.unwrap();
    let operator_id = OperatorId::from(op_record.id);

    let mut handles = vec![];

    // 50 concurrent task creations
    for i in 0..50 {
        let db = state.db.clone();
        let impl_id = implant_id;
        let op_id = operator_id;
        handles.push(tokio::spawn(async move {
            let task_id = TaskId::new();
            let now = chrono::Utc::now().timestamp_millis();
            let task = TaskRecord {
                id: task_id,
                implant_id: impl_id,
                operator_id: op_id,
                task_type: "shell".to_string(),
                task_data: format!("command-{}", i).into_bytes(),
                status: "queued".to_string(),
                issued_at: now,
                dispatched_at: None,
                completed_at: None,
                result_data: None,
                error_message: None,
            };
            db.tasks().create(&task).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(task_id)
        }));
    }

    let mut created = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            created += 1;
        }
    }

    assert_eq!(created, 50, "all 50 tasks should be created");

    // Verify all tasks exist (list_pending returns queued tasks)
    let tasks = state
        .db
        .tasks()
        .list_pending(implant_id)
        .await
        .unwrap();
    assert_eq!(tasks.len(), 50, "all 50 tasks should be queryable");
}

// ---------------------------------------------------------------------------
// Recovery Tests
// ---------------------------------------------------------------------------

/// 9. Database handles rapid open/close cycles (in-memory)
#[tokio::test]
async fn test_db_concurrent_access() {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // Insert initial data
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: "rapid-test".to_string(),
        state: ImplantState::Active,
        hostname: Some("host".to_string()),
        username: Some("user".to_string()),
        domain: None,
        os_name: Some("Linux".to_string()),
        os_version: None,
        os_arch: None,
        process_id: None,
        process_name: None,
        process_path: None,
        is_elevated: false,
        integrity_level: None,
        local_ips: vec![],
        checkin_interval: 60,
        jitter_percent: 10,
        symmetric_key: None,
        nonce_counter: 0,
        registered_at: now,
        last_seen: None,
    };
    db.implants().create(&record).await.expect("create");

    // Concurrent reads from same connection
    let mut handles = vec![];
    for _ in 0..50 {
        let db = db.clone();
        let target_id = id;
        handles.push(tokio::spawn(async move {
            db.implants().get(target_id).await
        }));
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "concurrent read should succeed");
        assert!(result.unwrap().is_some(), "implant should exist");
    }
}

/// 10. Server handles request flood
#[tokio::test]
async fn test_request_flood() {
    let (state, addr) = setup_chaos_server().await;

    // Insert some implants
    for _ in 0..10 {
        insert_implant(&state, ImplantState::Active).await;
    }

    let channel = connect(addr).await;
    let mut handles = vec![];

    // Flood with 500 concurrent requests
    for _ in 0..500 {
        let channel = channel.clone();
        handles.push(tokio::spawn(async move {
            let mut client = ImplantServiceClient::new(channel);
            client
                .list_implants(ListImplantsRequest {
                    state_filter: None,
                    tag_filter: vec![],
                    search: None,
                })
                .await
        }));
    }

    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            successes += 1;
        }
    }

    // At least 90% should succeed
    assert!(
        successes >= 450,
        "at least 90% of flood requests should succeed, got {}",
        successes
    );
}

// ---------------------------------------------------------------------------
// Edge Case Tests
// ---------------------------------------------------------------------------

/// 11. Server handles all implant states in filter
#[tokio::test]
async fn test_all_state_filter() {
    let (state, addr) = setup_chaos_server().await;

    // Insert implants in different states
    insert_implant(&state, ImplantState::Active).await;
    insert_implant(&state, ImplantState::Lost).await;
    insert_implant(&state, ImplantState::Burned).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Query with specific state
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: Some(protocol::ImplantState::Active as i32),
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("list");

    assert_eq!(resp.into_inner().implants.len(), 1, "should find 1 active implant");

    // Query all (no filter)
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("list");

    assert_eq!(resp.into_inner().implants.len(), 3, "should find all 3 implants");
}

/// 12. Zero-length task data
#[tokio::test]
async fn test_zero_length_task_data() {
    let (state, addr) = setup_chaos_server().await;

    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(ProtoUuid {
                value: implant_id.as_bytes().to_vec(),
            }),
            task_type: "shell".to_string(),
            task_data: vec![],
        })
        .await;

    // Empty task data may be accepted or rejected
    // Key is server doesn't crash
    drop(result);
}

/// 13. Task dispatch to non-existent implant
#[tokio::test]
async fn test_task_dispatch_nonexistent_implant() {
    let (_state, addr) = setup_chaos_server().await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let fake_id = ImplantId::new();
    let result = client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(ProtoUuid {
                value: fake_id.as_bytes().to_vec(),
            }),
            task_type: "shell".to_string(),
            task_data: vec![1, 2, 3],
        })
        .await;

    // Should return error, not crash
    assert!(result.is_err(), "dispatch to non-existent implant should fail");
}

/// 14. Repeated get on same implant
#[tokio::test]
async fn test_repeated_get_same_implant() {
    let (state, addr) = setup_chaos_server().await;

    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // 100 repeated gets
    for _ in 0..100 {
        let resp = client
            .get_implant(GetImplantRequest {
                implant_id: Some(ProtoUuid {
                    value: implant_id.as_bytes().to_vec(),
                }),
            })
            .await
            .expect("get should succeed");

        // GetImplant returns Implant directly - check it has valid ID
        assert!(resp.into_inner().id.is_some());
    }
}

/// 15. Mixed valid and invalid requests
#[tokio::test]
async fn test_mixed_valid_invalid_requests() {
    let (state, addr) = setup_chaos_server().await;

    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    for i in 0..20 {
        if i % 2 == 0 {
            // Valid request
            let resp = client
                .get_implant(GetImplantRequest {
                    implant_id: Some(ProtoUuid {
                        value: implant_id.as_bytes().to_vec(),
                    }),
                })
                .await;
            assert!(resp.is_ok(), "valid request {} should succeed", i);
        } else {
            // Invalid request (bad UUID)
            let _ = client
                .get_implant(GetImplantRequest {
                    implant_id: Some(ProtoUuid { value: vec![0xFF; 3] }),
                })
                .await;
            // May succeed or fail, just shouldn't crash
        }
    }

    // Server should still work after mixed requests
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(resp.is_ok(), "server should remain healthy");
}
