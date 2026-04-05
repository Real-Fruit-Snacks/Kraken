//! Network resilience tests
//!
//! Tests for system behavior under adverse network conditions:
//! - Connection timeouts
//! - Slow clients
//! - Connection drops mid-request
//! - Reconnection scenarios
//! - Partial data handling

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{ImplantId, ImplantState};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    GetImplantRequest, ImplantServiceClient, ListImplantsRequest, Uuid as ProtoUuid,
};
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn setup_network_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-network-tests!!!!";
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

async fn insert_implant(state: &server::ServerState, implant_state: ImplantState) -> ImplantId {
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: format!("network-{}", id),
        state: implant_state,
        hostname: Some("network-host".to_string()),
        username: Some("network-user".to_string()),
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
// Connection Timeout Tests
// ---------------------------------------------------------------------------

/// 1. Client handles connection timeout gracefully
#[tokio::test]
async fn test_connection_timeout_to_nonexistent() {
    // Try to connect to a port that's not listening
    let result = Channel::from_static("http://127.0.0.1:59999")
        .connect_timeout(Duration::from_millis(100))
        .connect()
        .await;

    // Should timeout or fail to connect
    assert!(result.is_err(), "should fail to connect to non-existent server");
}

/// 2. Client reconnects after server becomes available
#[tokio::test]
async fn test_reconnection_after_server_start() {
    // First, verify no server is running on our port
    let port = 51234;
    let addr = format!("http://127.0.0.1:{}", port);

    // Try to connect - should fail
    let result = Channel::from_shared(addr.clone())
        .unwrap()
        .connect_timeout(Duration::from_millis(100))
        .connect()
        .await;
    assert!(result.is_err(), "should fail before server starts");

    // Now start server
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );
    let audit_key = b"test-audit-reconnect-test!!!!!!!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let implant_svc = protocol::ImplantServiceServer::new(server::grpc::ImplantServiceImpl::new(
        Arc::clone(&state),
    ));

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(implant_svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Now should connect successfully
    let channel = Channel::from_shared(addr)
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .expect("should connect after server starts");

    let mut client = ImplantServiceClient::new(channel);
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(resp.is_ok(), "request should succeed");
}

/// 3. Request timeout handling
#[tokio::test]
async fn test_request_timeout() {
    let (state, addr) = setup_network_server().await;

    // Insert some data
    for _ in 0..10 {
        insert_implant(&state, ImplantState::Active).await;
    }

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let mut client = ImplantServiceClient::new(channel);

    // Extremely short timeout - may or may not complete
    let result = timeout(Duration::from_micros(1), async {
        client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await
    })
    .await;

    // Either completes fast or times out - both are acceptable
    match result {
        Ok(Ok(_)) => println!("Request completed within timeout"),
        Ok(Err(_)) => println!("Request returned error"),
        Err(_) => println!("Request timed out as expected"),
    }
}

// ---------------------------------------------------------------------------
// Connection Drop Tests
// ---------------------------------------------------------------------------

/// 4. Server handles client disconnect gracefully
#[tokio::test]
async fn test_server_handles_client_disconnect() {
    let (state, addr) = setup_network_server().await;
    insert_implant(&state, ImplantState::Active).await;

    // Connect and immediately disconnect multiple times
    for _ in 0..10 {
        let channel = Channel::from_shared(format!("http://{}", addr))
            .unwrap()
            .connect()
            .await
            .expect("connect");

        // Just drop the channel without making a request
        drop(channel);
    }

    // Server should still be healthy
    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(resp.is_ok(), "server should remain healthy after disconnects");
}

/// 5. Server handles connection drops mid-request
#[tokio::test]
async fn test_connection_drop_mid_request() {
    let (state, addr) = setup_network_server().await;

    // Insert data
    for _ in 0..50 {
        insert_implant(&state, ImplantState::Active).await;
    }

    // Start multiple requests and cancel some mid-flight
    let mut handles = vec![];

    for i in 0..20 {
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let channel = Channel::from_shared(format!("http://{}", addr))
                .unwrap()
                .connect()
                .await?;
            let mut client = ImplantServiceClient::new(channel);

            if i % 3 == 0 {
                // Cancel request mid-flight with very short timeout
                let _ = timeout(Duration::from_micros(10), async {
                    client
                        .list_implants(ListImplantsRequest {
                            state_filter: None,
                            tag_filter: vec![],
                            search: None,
                        })
                        .await
                })
                .await;
            } else {
                // Normal request
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

    // Server should still be healthy
    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(
        resp.is_ok(),
        "server should remain healthy after mid-request drops"
    );
}

// ---------------------------------------------------------------------------
// Slow Client Tests
// ---------------------------------------------------------------------------

/// 6. Server handles slow clients
#[tokio::test]
async fn test_slow_client_handling() {
    let (state, addr) = setup_network_server().await;
    insert_implant(&state, ImplantState::Active).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    // Simulate slow client: make request, wait, make another
    for _ in 0..5 {
        let resp = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await;
        assert!(resp.is_ok());

        // Slow client delay
        sleep(Duration::from_millis(200)).await;
    }

    // Connection should still work
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(resp.is_ok(), "connection should remain valid");
}

/// 7. Multiple slow clients don't block each other
#[tokio::test]
async fn test_slow_clients_dont_block() {
    let (state, addr) = setup_network_server().await;

    for _ in 0..10 {
        insert_implant(&state, ImplantState::Active).await;
    }

    let mut handles = vec![];

    // Start 10 "slow" clients
    for i in 0..10 {
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let channel = Channel::from_shared(format!("http://{}", addr))
                .unwrap()
                .connect()
                .await?;
            let mut client = ImplantServiceClient::new(channel);

            // Each client has different "think time"
            for _ in 0..3 {
                client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await?;

                // Variable delay
                sleep(Duration::from_millis(50 + (i * 10) as u64)).await;
            }

            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(i)
        }));
    }

    // All clients should complete
    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            successes += 1;
        }
    }

    assert_eq!(successes, 10, "all slow clients should succeed");
}

// ---------------------------------------------------------------------------
// Connection Reuse Tests
// ---------------------------------------------------------------------------

/// 8. Connection can be reused for many requests
#[tokio::test]
async fn test_connection_reuse() {
    let (state, addr) = setup_network_server().await;
    insert_implant(&state, ImplantState::Active).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    // Make many requests on same connection
    for i in 0..100 {
        let resp = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await;
        assert!(resp.is_ok(), "request {} should succeed", i);
    }
}

/// 9. New connection works after previous connection closed
#[tokio::test]
async fn test_new_connection_after_close() {
    let (_state, addr) = setup_network_server().await;

    for _ in 0..5 {
        // Create connection, use it, close it
        {
            let channel = Channel::from_shared(format!("http://{}", addr))
                .unwrap()
                .connect()
                .await
                .expect("connect");
            let mut client = ImplantServiceClient::new(channel);

            let resp = client
                .list_implants(ListImplantsRequest {
                    state_filter: None,
                    tag_filter: vec![],
                    search: None,
                })
                .await;
            assert!(resp.is_ok());

            // Connection dropped here
        }

        // Small delay
        sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

/// 10. Empty response handling
#[tokio::test]
async fn test_empty_response_handling() {
    let (_state, addr) = setup_network_server().await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    // List with no implants
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("request");

    assert!(resp.into_inner().implants.is_empty());
}

/// 11. Get non-existent implant
#[tokio::test]
async fn test_get_nonexistent_implant() {
    let (_state, addr) = setup_network_server().await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    let fake_id = ImplantId::new();
    let result = client
        .get_implant(GetImplantRequest {
            implant_id: Some(ProtoUuid {
                value: fake_id.as_bytes().to_vec(),
            }),
        })
        .await;

    // Should return error (not found)
    assert!(result.is_err(), "should return error for non-existent");
}

/// 12. Rapid sequential requests
#[tokio::test]
async fn test_rapid_sequential_requests() {
    let (state, addr) = setup_network_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    // No delay between requests
    for _ in 0..50 {
        let resp = client
            .get_implant(GetImplantRequest {
                implant_id: Some(ProtoUuid {
                    value: implant_id.as_bytes().to_vec(),
                }),
            })
            .await;
        assert!(resp.is_ok());
    }
}

/// 13. Mixed request types in quick succession
#[tokio::test]
async fn test_mixed_request_types() {
    let (state, addr) = setup_network_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("connect");
    let mut client = ImplantServiceClient::new(channel);

    for i in 0..20 {
        if i % 2 == 0 {
            let _ = client
                .list_implants(ListImplantsRequest {
                    state_filter: None,
                    tag_filter: vec![],
                    search: None,
                })
                .await
                .expect("list");
        } else {
            let _ = client
                .get_implant(GetImplantRequest {
                    implant_id: Some(ProtoUuid {
                        value: implant_id.as_bytes().to_vec(),
                    }),
                })
                .await
                .expect("get");
        }
    }
}

/// 14. Parallel connections to same server
#[tokio::test]
async fn test_parallel_connections() {
    let (state, addr) = setup_network_server().await;
    insert_implant(&state, ImplantState::Active).await;

    let mut handles = vec![];

    // Create 20 parallel connections
    for _ in 0..20 {
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let channel = Channel::from_shared(format!("http://{}", addr))
                .unwrap()
                .connect()
                .await?;
            let mut client = ImplantServiceClient::new(channel);

            for _ in 0..5 {
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

    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            successes += 1;
        }
    }

    assert_eq!(successes, 20, "all parallel connections should succeed");
}

/// 15. Server remains stable after network stress
#[tokio::test]
async fn test_stability_after_network_stress() {
    let (state, addr) = setup_network_server().await;
    insert_implant(&state, ImplantState::Active).await;

    // Phase 1: Stress with rapid connections
    for _ in 0..50 {
        let channel = Channel::from_shared(format!("http://{}", addr))
            .unwrap()
            .connect_timeout(Duration::from_millis(100))
            .connect()
            .await;
        drop(channel);
    }

    // Phase 2: Stress with concurrent requests
    let mut handles = vec![];
    for _ in 0..30 {
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

    // Phase 3: Verify server is still healthy
    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("should connect after stress");
    let mut client = ImplantServiceClient::new(channel);

    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;
    assert!(resp.is_ok(), "server should be healthy after stress");
    assert_eq!(resp.unwrap().into_inner().implants.len(), 1);
}
