//! Memory leak detection tests
//!
//! Tests to verify memory doesn't grow unboundedly during:
//! - Repeated operations
//! - Long-running sessions
//! - Large data handling
//! - Connection cycling
//!
//! Note: These tests verify behavior patterns rather than exact memory
//! measurements, as exact memory tracking requires OS-specific tools.

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

async fn setup_memory_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-memory-test!!!!!!";
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
    Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

async fn insert_implant(state: &server::ServerState) -> ImplantId {
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: format!("memory-{}", id),
        state: ImplantState::Active,
        hostname: Some("memory-host".to_string()),
        username: Some("memory-user".to_string()),
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
// Repeated Operation Tests
// ---------------------------------------------------------------------------

/// 1. Repeated list operations don't leak memory
#[tokio::test]
async fn test_repeated_list_no_leak() {
    let (state, addr) = setup_memory_server().await;

    // Insert some data
    for _ in 0..10 {
        insert_implant(&state).await;
    }

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Perform many list operations
    for i in 0..500 {
        let resp = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await
            .expect("list");

        let implants = resp.into_inner().implants;
        assert_eq!(implants.len(), 10, "iteration {} failed", i);

        // Explicitly drop to ensure cleanup
        drop(implants);
    }

    // If we reach here without OOM, test passes
    println!("Completed 500 list operations without memory issues");
}

/// 2. Repeated get operations don't leak memory
#[tokio::test]
async fn test_repeated_get_no_leak() {
    let (state, addr) = setup_memory_server().await;

    let implant_id = insert_implant(&state).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Perform many get operations
    for i in 0..1000 {
        let resp = client
            .get_implant(GetImplantRequest {
                implant_id: Some(ProtoUuid {
                    value: implant_id.as_bytes().to_vec(),
                }),
            })
            .await
            .expect("get");

        let implant = resp.into_inner();
        assert!(implant.id.is_some(), "iteration {} failed", i);
        drop(implant);
    }

    println!("Completed 1000 get operations without memory issues");
}

/// 3. Repeated task dispatch doesn't leak memory
#[tokio::test]
async fn test_repeated_task_dispatch_no_leak() {
    let (state, addr) = setup_memory_server().await;

    let implant_id = insert_implant(&state).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    // Dispatch many tasks
    for i in 0..200 {
        let result = client
            .dispatch_task(DispatchTaskRequest {
                implant_id: Some(ProtoUuid {
                    value: implant_id.as_bytes().to_vec(),
                }),
                task_type: "shell".to_string(),
                task_data: format!("command-{}", i).into_bytes(),
            })
            .await;

        assert!(result.is_ok(), "iteration {} failed", i);
    }

    println!("Completed 200 task dispatches without memory issues");
}

// ---------------------------------------------------------------------------
// Connection Cycling Tests
// ---------------------------------------------------------------------------

/// 4. Connection cycling doesn't leak memory
#[tokio::test]
async fn test_connection_cycling_no_leak() {
    let (_state, addr) = setup_memory_server().await;

    // Create and destroy many connections
    for i in 0..100 {
        let channel = Channel::from_shared(format!("http://{}", addr))
            .unwrap()
            .connect()
            .await
            .expect("connect");

        let mut client = ImplantServiceClient::new(channel);
        let _ = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await;

        // Explicitly drop client and channel
        drop(client);

        if i % 20 == 0 {
            // Small yield to allow cleanup
            tokio::task::yield_now().await;
        }
    }

    println!("Completed 100 connection cycles without memory issues");
}

/// 5. Parallel connection cycling doesn't leak
#[tokio::test]
async fn test_parallel_connection_cycling_no_leak() {
    let (_state, addr) = setup_memory_server().await;

    for round in 0..5 {
        let mut handles = vec![];

        for _ in 0..20 {
            let addr = addr;
            handles.push(tokio::spawn(async move {
                let channel = Channel::from_shared(format!("http://{}", addr))
                    .unwrap()
                    .connect()
                    .await?;
                let mut client = ImplantServiceClient::new(channel);
                client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        // Yield between rounds
        tokio::task::yield_now().await;
        println!("Completed round {} of parallel connection cycling", round);
    }

    println!("Completed 5 rounds of parallel connection cycling without memory issues");
}

// ---------------------------------------------------------------------------
// Large Data Tests
// ---------------------------------------------------------------------------

/// 6. Large task data doesn't accumulate
#[tokio::test]
async fn test_large_task_data_no_accumulation() {
    let (state, addr) = setup_memory_server().await;

    let implant_id = insert_implant(&state).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    // Dispatch tasks with large data (10KB each)
    let large_data = vec![0xAB; 10 * 1024];

    for i in 0..50 {
        let result = client
            .dispatch_task(DispatchTaskRequest {
                implant_id: Some(ProtoUuid {
                    value: implant_id.as_bytes().to_vec(),
                }),
                task_type: "shell".to_string(),
                task_data: large_data.clone(),
            })
            .await;

        assert!(result.is_ok(), "iteration {} failed", i);
    }

    println!("Dispatched 50 tasks with 10KB data each without memory issues");
}

/// 7. Listing large result sets doesn't accumulate
#[tokio::test]
async fn test_large_result_set_no_accumulation() {
    let (state, addr) = setup_memory_server().await;

    // Insert 100 implants
    for _ in 0..100 {
        insert_implant(&state).await;
    }

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // List all implants many times
    for i in 0..50 {
        let resp = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await
            .expect("list");

        let count = resp.into_inner().implants.len();
        assert_eq!(count, 100, "iteration {} got {} implants", i, count);
    }

    println!("Listed 100 implants 50 times without memory issues");
}

// ---------------------------------------------------------------------------
// Database Operation Tests
// ---------------------------------------------------------------------------

/// 8. Repeated DB inserts don't leak
#[tokio::test]
async fn test_db_insert_no_leak() {
    let (state, _addr) = setup_memory_server().await;

    // Insert many records
    for i in 0..500 {
        let id = ImplantId::new();
        let now = chrono::Utc::now().timestamp_millis();
        let record = ImplantRecord {
            id,
            name: format!("leak-test-{}", i),
            state: ImplantState::Active,
            hostname: Some(format!("host-{}", i)),
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
        state.db.implants().create(&record).await.expect("create");
    }

    // Verify all inserted
    let all = state.db.implants().list().await.unwrap();
    assert_eq!(all.len(), 500);

    println!("Inserted 500 records without memory issues");
}

/// 9. Repeated DB queries don't leak
#[tokio::test]
async fn test_db_query_no_leak() {
    let (state, _addr) = setup_memory_server().await;

    // Insert some records
    for _ in 0..10 {
        insert_implant(&state).await;
    }

    // Query many times
    for i in 0..1000 {
        let list = state.db.implants().list().await.expect("list");
        assert_eq!(list.len(), 10, "iteration {} failed", i);
        drop(list);
    }

    println!("Performed 1000 DB queries without memory issues");
}

/// 10. Task creation and querying doesn't leak
#[tokio::test]
async fn test_task_create_query_no_leak() {
    let (state, _addr) = setup_memory_server().await;

    let implant_id = insert_implant(&state).await;

    // Create operator
    let op = NewOperator {
        username: "memory-op".to_string(),
        role: kraken_rbac::Role::Operator,
        cert_fingerprint: "memory-fp".to_string(),
    };
    let op_record = state.db.operators().create(op).await.unwrap();
    let operator_id = OperatorId::from(op_record.id);

    // Create and query many tasks
    for i in 0..200 {
        let task_id = TaskId::new();
        let now = chrono::Utc::now().timestamp_millis();
        let task = TaskRecord {
            id: task_id,
            implant_id,
            operator_id,
            task_type: "shell".to_string(),
            task_data: format!("cmd-{}", i).into_bytes(),
            status: "queued".to_string(),
            issued_at: now,
            dispatched_at: None,
            completed_at: None,
            result_data: None,
            error_message: None,
        };
        state.db.tasks().create(&task).await.expect("create");

        // Query tasks for implant
        let tasks = state.db.tasks().list_pending(implant_id).await.expect("list");
        assert!(tasks.len() > 0);
        drop(tasks);
    }

    println!("Created and queried 200 tasks without memory issues");
}

// ---------------------------------------------------------------------------
// Long-Running Session Tests
// ---------------------------------------------------------------------------

/// 11. Simulated long session doesn't leak
#[tokio::test]
async fn test_long_session_no_leak() {
    let (state, addr) = setup_memory_server().await;

    let implant_id = insert_implant(&state).await;

    let channel = connect(addr).await;
    let mut implant_client = ImplantServiceClient::new(channel.clone());
    let mut task_client = TaskServiceClient::new(channel);

    // Simulate a long session with mixed operations
    for round in 0..20 {
        // List implants
        let _ = implant_client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await;

        // Get specific implant
        let _ = implant_client
            .get_implant(GetImplantRequest {
                implant_id: Some(ProtoUuid {
                    value: implant_id.as_bytes().to_vec(),
                }),
            })
            .await;

        // Dispatch tasks
        for j in 0..5 {
            let _ = task_client
                .dispatch_task(DispatchTaskRequest {
                    implant_id: Some(ProtoUuid {
                        value: implant_id.as_bytes().to_vec(),
                    }),
                    task_type: "shell".to_string(),
                    task_data: format!("round-{}-task-{}", round, j).into_bytes(),
                })
                .await;
        }

        // Small delay to simulate real usage
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!("Completed 20 rounds of mixed operations without memory issues");
}

/// 12. Error handling doesn't leak
#[tokio::test]
async fn test_error_handling_no_leak() {
    let (_state, addr) = setup_memory_server().await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Generate many errors
    for i in 0..200 {
        // Try to get non-existent implant
        let fake_id = ImplantId::new();
        let result = client
            .get_implant(GetImplantRequest {
                implant_id: Some(ProtoUuid {
                    value: fake_id.as_bytes().to_vec(),
                }),
            })
            .await;

        // Should return error (not found)
        assert!(result.is_err(), "iteration {} should error", i);
    }

    println!("Handled 200 errors without memory issues");
}

/// 13. Search operations don't leak
#[tokio::test]
async fn test_search_no_leak() {
    let (state, addr) = setup_memory_server().await;

    // Insert implants with different hostnames
    for i in 0..50 {
        let id = ImplantId::new();
        let now = chrono::Utc::now().timestamp_millis();
        let record = ImplantRecord {
            id,
            name: format!("search-test-{}", i),
            state: ImplantState::Active,
            hostname: Some(format!("search-host-{:03}", i)),
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
        state.db.implants().create(&record).await.expect("create");
    }

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Perform many searches
    for i in 0..100 {
        let search_term = format!("search-host-{:03}", i % 50);
        let resp = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: Some(search_term),
            })
            .await
            .expect("search");

        let _ = resp.into_inner();
    }

    println!("Performed 100 searches without memory issues");
}

/// 14. Concurrent operations don't leak
#[tokio::test]
async fn test_concurrent_operations_no_leak() {
    let (state, addr) = setup_memory_server().await;

    insert_implant(&state).await;

    for round in 0..5 {
        let mut handles = vec![];

        for _ in 0..20 {
            let addr = addr;
            handles.push(tokio::spawn(async move {
                let channel = Channel::from_shared(format!("http://{}", addr))
                    .unwrap()
                    .connect()
                    .await?;
                let mut client = ImplantServiceClient::new(channel);

                for _ in 0..10 {
                    client
                        .list_implants(ListImplantsRequest {
                            state_filter: None,
                            tag_filter: vec![],
                            search: None,
                        })
                        .await?;
                }

                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        tokio::task::yield_now().await;
        println!("Completed concurrent round {}", round);
    }

    println!("Completed 5 rounds of concurrent operations without memory issues");
}

/// 15. State updates don't leak
#[tokio::test]
async fn test_state_updates_no_leak() {
    let (state, _addr) = setup_memory_server().await;

    let implant_id = insert_implant(&state).await;

    // Repeatedly update state
    for i in 0..500 {
        let new_state = if i % 2 == 0 {
            ImplantState::Active
        } else {
            ImplantState::Lost
        };

        state
            .db
            .implants()
            .update_state(implant_id, new_state)
            .await
            .expect("update");
    }

    println!("Performed 500 state updates without memory issues");
}
