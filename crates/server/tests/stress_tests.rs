//! Stress tests for server under concurrent load
//!
//! Tests server behavior with 32+ concurrent connections to verify:
//! - Connection handling under load
//! - State consistency with concurrent operations
//! - No deadlocks or resource exhaustion

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{ImplantId, ImplantState};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    DispatchTaskRequest, GetImplantRequest, ImplantServiceClient, ListImplantsRequest,
    TaskServiceClient, Uuid as ProtoUuid,
};
use tokio::sync::Barrier;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;

const CONCURRENT_CLIENTS: usize = 32;

/// Helper to join all handles (like futures::future::join_all)
async fn tokio_join_all<T>(handles: Vec<JoinHandle<T>>) -> Vec<Result<T, tokio::task::JoinError>> {
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        results.push(handle.await);
    }
    results
}
const OPERATIONS_PER_CLIENT: usize = 10;

// ---------------------------------------------------------------------------
// Test server setup (copied from grpc_integration.rs)
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

    let audit_key = b"test-audit-key-for-stress-test!";
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

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (state, addr)
}

async fn connect(addr: SocketAddr) -> tonic::transport::Channel {
    let endpoint = format!("http://{}", addr);
    tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

async fn insert_implant(state: &server::ServerState, id: u8) -> ImplantId {
    let mut id_bytes = [0u8; 16];
    id_bytes[0] = id;
    let implant_id = ImplantId::from_bytes(&id_bytes).unwrap();
    let now = chrono::Utc::now().timestamp_millis();

    let record = ImplantRecord {
        id: implant_id,
        name: format!("stress-implant-{}", id),
        state: ImplantState::Active,
        hostname: Some(format!("stress-host-{}", id)),
        username: Some(format!("stress-user-{}", id)),
        domain: None,
        os_name: Some("Linux".to_string()),
        os_version: Some("5.15".to_string()),
        os_arch: Some("x86_64".to_string()),
        process_id: Some(1000 + id as u32),
        process_name: Some("test".to_string()),
        process_path: Some("/usr/bin/test".to_string()),
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
    implant_id
}

fn implant_id_to_proto(id: ImplantId) -> ProtoUuid {
    ProtoUuid {
        value: id.as_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Stress Tests
// ---------------------------------------------------------------------------

/// Test 32 concurrent clients listing implants simultaneously
#[tokio::test]
async fn test_concurrent_list_implants() {
    let (state, addr) = setup_test_server().await;

    // Pre-populate some implants
    for i in 0..10u8 {
        insert_implant(&state, i).await;
    }

    let barrier = Arc::new(Barrier::new(CONCURRENT_CLIENTS));
    let mut handles = Vec::with_capacity(CONCURRENT_CLIENTS);

    for client_id in 0..CONCURRENT_CLIENTS {
        let barrier = Arc::clone(&barrier);
        let addr = addr;

        handles.push(tokio::spawn(async move {
            let channel = connect(addr).await;
            let mut client = ImplantServiceClient::new(channel);

            // Wait for all clients to be ready
            barrier.wait().await;

            // Each client performs multiple list operations
            for _ in 0..OPERATIONS_PER_CLIENT {
                let response = client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await;

                assert!(response.is_ok(), "Client {} list failed: {:?}", client_id, response.err());
                let implants = response.unwrap().into_inner().implants;
                assert_eq!(implants.len(), 10, "Expected 10 implants, got {}", implants.len());
            }

            client_id
        }));
    }

    // Wait for all clients to complete
    let results: Vec<_> = tokio_join_all(handles).await;
    for result in results {
        assert!(result.is_ok(), "Task panicked: {:?}", result.err());
    }
}

/// Test 32 concurrent clients dispatching tasks simultaneously
#[tokio::test]
async fn test_concurrent_task_dispatch() {
    let (state, addr) = setup_test_server().await;

    // Create target implant
    let implant_id = insert_implant(&state, 0).await;

    let barrier = Arc::new(Barrier::new(CONCURRENT_CLIENTS));
    let mut handles = Vec::with_capacity(CONCURRENT_CLIENTS);

    for client_id in 0..CONCURRENT_CLIENTS {
        let barrier = Arc::clone(&barrier);
        let addr = addr;
        let implant_id_proto = implant_id_to_proto(implant_id);

        handles.push(tokio::spawn(async move {
            let channel = connect(addr).await;
            let mut client = TaskServiceClient::new(channel);

            barrier.wait().await;

            for op in 0..OPERATIONS_PER_CLIENT {
                let response = client
                    .dispatch_task(DispatchTaskRequest {
                        implant_id: Some(implant_id_proto.clone()),
                        task_type: "sleep".to_string(),
                        task_data: vec![],
                    })
                    .await;

                assert!(
                    response.is_ok(),
                    "Client {} op {} dispatch failed: {:?}",
                    client_id,
                    op,
                    response.err()
                );
            }

            client_id
        }));
    }

    let results: Vec<_> = tokio_join_all(handles).await;
    for result in results {
        assert!(result.is_ok(), "Task panicked: {:?}", result.err());
    }

    // Verify tasks were queued (check pending_tasks in-memory store)
    let pending = state.pending_tasks.get(&implant_id);
    assert!(pending.is_some(), "No pending tasks found after dispatch");
    let task_count = pending.unwrap().len();
    assert_eq!(
        task_count,
        CONCURRENT_CLIENTS * OPERATIONS_PER_CLIENT,
        "Expected {} tasks, got {}",
        CONCURRENT_CLIENTS * OPERATIONS_PER_CLIENT,
        task_count
    );
}

/// Test mixed read/write operations concurrently
#[tokio::test]
async fn test_concurrent_mixed_operations() {
    let (state, addr) = setup_test_server().await;

    // Pre-populate implants
    let mut implant_ids = Vec::new();
    for i in 0..5u8 {
        implant_ids.push(insert_implant(&state, i).await);
    }

    let barrier = Arc::new(Barrier::new(CONCURRENT_CLIENTS));
    let mut handles = Vec::with_capacity(CONCURRENT_CLIENTS);

    for client_id in 0..CONCURRENT_CLIENTS {
        let barrier = Arc::clone(&barrier);
        let addr = addr;
        let implant_ids = implant_ids.clone();

        handles.push(tokio::spawn(async move {
            let channel = connect(addr).await;
            let mut implant_client = ImplantServiceClient::new(channel.clone());
            let mut task_client = TaskServiceClient::new(channel);

            barrier.wait().await;

            for op in 0..OPERATIONS_PER_CLIENT {
                // Alternate between different operations
                match op % 4 {
                    0 => {
                        // List implants
                        let _ = implant_client
                            .list_implants(ListImplantsRequest {
                                state_filter: None,
                                tag_filter: vec![],
                                search: None,
                            })
                            .await
                            .expect("list failed");
                    }
                    1 => {
                        // Get specific implant
                        let target = implant_ids[client_id % implant_ids.len()];
                        let _ = implant_client
                            .get_implant(GetImplantRequest {
                                implant_id: Some(implant_id_to_proto(target)),
                            })
                            .await
                            .expect("get failed");
                    }
                    2 => {
                        // Dispatch task
                        let target = implant_ids[client_id % implant_ids.len()];
                        let _ = task_client
                            .dispatch_task(DispatchTaskRequest {
                                implant_id: Some(implant_id_to_proto(target)),
                                task_type: "info".to_string(),
                                task_data: vec![],
                            })
                            .await
                            .expect("dispatch failed");
                    }
                    _ => {
                        // Small delay to vary timing
                        tokio::time::sleep(Duration::from_micros(100)).await;
                    }
                }
            }

            client_id
        }));
    }

    let results: Vec<_> = tokio_join_all(handles).await;
    let mut success_count = 0;
    for result in &results {
        if result.is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count,
        CONCURRENT_CLIENTS,
        "Only {} of {} clients succeeded",
        success_count,
        CONCURRENT_CLIENTS
    );
}

/// Test rapid connection/disconnection cycles
#[tokio::test]
async fn test_connection_churn() {
    let (_state, addr) = setup_test_server().await;

    let barrier = Arc::new(Barrier::new(CONCURRENT_CLIENTS));
    let mut handles = Vec::with_capacity(CONCURRENT_CLIENTS);

    for client_id in 0..CONCURRENT_CLIENTS {
        let barrier = Arc::clone(&barrier);
        let addr = addr;

        handles.push(tokio::spawn(async move {
            barrier.wait().await;

            // Rapidly connect, query, disconnect
            for _ in 0..5 {
                let channel = connect(addr).await;
                let mut client = ImplantServiceClient::new(channel);

                let response = client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await;

                assert!(response.is_ok(), "Client {} query failed", client_id);

                // Drop connection
                drop(client);

                // Brief pause
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            client_id
        }));
    }

    let results: Vec<_> = tokio_join_all(handles).await;
    for result in results {
        assert!(result.is_ok(), "Task panicked: {:?}", result.err());
    }
}

/// Test server handles slow clients mixed with fast clients
#[tokio::test]
async fn test_slow_client_handling() {
    let (state, addr) = setup_test_server().await;

    // Create implant for task operations
    let implant_id = insert_implant(&state, 0).await;
    let implant_id_proto = implant_id_to_proto(implant_id);

    let mut handles = Vec::new();

    // Mix of slow and fast clients
    for client_id in 0..16 {
        let addr = addr;
        let implant_id_proto = implant_id_proto.clone();
        let is_slow = client_id % 4 == 0;

        handles.push(tokio::spawn(async move {
            let channel = connect(addr).await;
            let mut client = TaskServiceClient::new(channel);

            for _ in 0..5 {
                if is_slow {
                    // Simulate slow client
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }

                let response = client
                    .dispatch_task(DispatchTaskRequest {
                        implant_id: Some(implant_id_proto.clone()),
                        task_type: "info".to_string(),
                        task_data: vec![],
                    })
                    .await;

                assert!(response.is_ok(), "Client {} failed", client_id);
            }

            client_id
        }));
    }

    let results: Vec<_> = tokio_join_all(handles).await;
    for result in results {
        assert!(result.is_ok());
    }
}
