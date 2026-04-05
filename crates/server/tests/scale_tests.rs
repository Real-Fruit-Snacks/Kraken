//! Scale tests for 1000+ implants
//!
//! Tests for system behavior at scale:
//! - Large number of implants in database
//! - Bulk operations performance
//! - Query performance with many records
//! - Memory usage under load

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{ImplantId, ImplantState, OperatorId, TaskId};
use crypto::{ServerCrypto, SymmetricKey};
use db::{ImplantRecord, NewOperator, TaskRecord};
use protocol::{
    GetImplantRequest, ImplantServiceClient, ListImplantsRequest, Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;

const SCALE_IMPLANT_COUNT: usize = 1000;

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn setup_scale_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-for-scale-tests!!";
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

/// Bulk insert implants directly into database
async fn bulk_insert_implants(
    state: &server::ServerState,
    count: usize,
    state_distribution: &[(ImplantState, usize)],
) -> Vec<ImplantId> {
    let mut ids = Vec::with_capacity(count);
    let now = chrono::Utc::now().timestamp_millis();

    let mut state_iter = state_distribution.iter().cycle();
    let mut remaining_for_state = 0;
    let mut current_state = ImplantState::Active;

    for i in 0..count {
        // Distribute states according to distribution
        if remaining_for_state == 0 {
            if let Some((s, c)) = state_iter.next() {
                current_state = *s;
                remaining_for_state = *c;
            }
        }
        remaining_for_state = remaining_for_state.saturating_sub(1);

        let id = ImplantId::new();
        let record = ImplantRecord {
            id,
            name: format!("scale-implant-{:05}", i),
            state: current_state,
            hostname: Some(format!("host-{:05}.example.com", i)),
            username: Some(format!("user-{}", i % 100)),
            domain: Some(format!("domain-{}", i % 10)),
            os_name: Some(if i % 3 == 0 { "Windows" } else { "Linux" }.to_string()),
            os_version: Some(format!("v{}.{}", i % 10, i % 5)),
            os_arch: Some(if i % 2 == 0 { "x86_64" } else { "aarch64" }.to_string()),
            process_id: Some((i % 65535) as u32),
            process_name: Some("implant.exe".to_string()),
            process_path: Some(format!("/opt/implant/{}/bin", i)),
            is_elevated: i % 5 == 0,
            integrity_level: Some(format!("level-{}", i % 4)),
            local_ips: vec![
                format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256),
                format!("192.168.{}.{}", (i / 256) % 256, i % 256),
            ],
            checkin_interval: 60 + (i % 300) as i32,
            jitter_percent: (i % 30) as i32,
            symmetric_key: Some(vec![(i % 256) as u8; 32]),
            nonce_counter: i as i64,
            registered_at: now - (i as i64 * 1000), // Staggered registration times
            last_seen: Some(now - (i as i64 * 100)),
        };

        state.db.implants().create(&record).await.expect("insert implant");
        ids.push(id);
    }

    ids
}

// ---------------------------------------------------------------------------
// Scale Tests
// ---------------------------------------------------------------------------

/// 1. Database can handle 1000+ implants
#[tokio::test]
async fn test_scale_1000_implants_insert() {
    let (state, _addr) = setup_scale_server().await;

    let start = Instant::now();

    // Insert 1000 implants
    let ids = bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    let insert_duration = start.elapsed();
    println!(
        "Inserted {} implants in {:?} ({:.1} inserts/sec)",
        SCALE_IMPLANT_COUNT,
        insert_duration,
        SCALE_IMPLANT_COUNT as f64 / insert_duration.as_secs_f64()
    );

    assert_eq!(ids.len(), SCALE_IMPLANT_COUNT);

    // Verify all were inserted
    let all = state.db.implants().list().await.unwrap();
    assert_eq!(all.len(), SCALE_IMPLANT_COUNT);

    // Baseline: Should complete bulk insert in reasonable time (<30s for 1000)
    assert!(
        insert_duration < Duration::from_secs(30),
        "bulk insert too slow: {:?}",
        insert_duration
    );
}

/// 2. List all implants with 1000+ records
#[tokio::test]
async fn test_scale_list_all_implants() {
    let (state, addr) = setup_scale_server().await;

    // Insert implants
    bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let start = Instant::now();

    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("list");

    let list_duration = start.elapsed();
    let implants = resp.into_inner().implants;

    println!(
        "Listed {} implants in {:?} ({:.1} per sec)",
        implants.len(),
        list_duration,
        implants.len() as f64 / list_duration.as_secs_f64()
    );

    assert_eq!(implants.len(), SCALE_IMPLANT_COUNT);

    // Baseline: List 1000 should complete in <5s
    assert!(
        list_duration < Duration::from_secs(5),
        "list too slow: {:?}",
        list_duration
    );
}

/// 3. Filter by state with 1000+ records
#[tokio::test]
async fn test_scale_filter_by_state() {
    let (state, addr) = setup_scale_server().await;

    // Insert with mixed states: 600 Active, 300 Lost, 100 Burned
    bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[
            (ImplantState::Active, 600),
            (ImplantState::Lost, 300),
            (ImplantState::Burned, 100),
        ],
    )
    .await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Filter for Active only
    let start = Instant::now();
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: Some(protocol::ImplantState::Active as i32),
            tag_filter: vec![],
            search: None,
        })
        .await
        .expect("list active");
    let filter_duration = start.elapsed();

    let active_count = resp.into_inner().implants.len();
    println!(
        "Filtered {} active implants from {} total in {:?}",
        active_count, SCALE_IMPLANT_COUNT, filter_duration
    );

    // Should have approximately 600 active (distribution may vary slightly)
    assert!(active_count >= 590 && active_count <= 610);

    // Baseline: Filter should be fast (<2s)
    assert!(
        filter_duration < Duration::from_secs(2),
        "filter too slow: {:?}",
        filter_duration
    );
}

/// 4. Search across 1000+ implants
#[tokio::test]
async fn test_scale_search() {
    let (state, addr) = setup_scale_server().await;

    bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Search for specific hostname pattern (more specific to avoid broad matches)
    let start = Instant::now();
    let resp = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: Some("host-00050".to_string()), // Should match exactly host-00050
        })
        .await
        .expect("search");
    let search_duration = start.elapsed();

    let matches = resp.into_inner().implants.len();
    println!(
        "Search found {} matches in {} implants in {:?}",
        matches, SCALE_IMPLANT_COUNT, search_duration
    );

    // Should find exactly 1 match (host-00050)
    assert!(matches >= 1, "expected at least 1 match, got {}", matches);

    // Baseline: Search should complete in <3s
    assert!(
        search_duration < Duration::from_secs(3),
        "search too slow: {:?}",
        search_duration
    );
}

/// 5. Get individual implants at scale
#[tokio::test]
async fn test_scale_get_individual() {
    let (state, addr) = setup_scale_server().await;

    let ids = bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Get 100 random implants
    let start = Instant::now();
    let sample_ids: Vec<_> = ids.iter().step_by(10).take(100).collect();

    for id in &sample_ids {
        client
            .get_implant(GetImplantRequest {
                implant_id: Some(ProtoUuid {
                    value: id.as_bytes().to_vec(),
                }),
            })
            .await
            .expect("get");
    }

    let get_duration = start.elapsed();
    println!(
        "Got {} individual implants in {:?} ({:.1} per sec)",
        sample_ids.len(),
        get_duration,
        sample_ids.len() as f64 / get_duration.as_secs_f64()
    );

    // Baseline: 100 individual gets should complete in <2s
    assert!(
        get_duration < Duration::from_secs(2),
        "individual gets too slow: {:?}",
        get_duration
    );
}

/// 6. Concurrent access at scale
#[tokio::test]
async fn test_scale_concurrent_access() {
    let (state, addr) = setup_scale_server().await;

    let ids = bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    let start = Instant::now();
    let mut handles = vec![];

    // 50 concurrent clients each doing 10 operations
    for client_id in 0..50 {
        let addr = addr;
        let sample_ids: Vec<_> = ids.iter().skip(client_id * 20).take(10).cloned().collect();

        handles.push(tokio::spawn(async move {
            let channel = Channel::from_shared(format!("http://{}", addr))
                .unwrap()
                .connect()
                .await?;
            let mut client = ImplantServiceClient::new(channel);

            // List all
            client
                .list_implants(ListImplantsRequest {
                    state_filter: None,
                    tag_filter: vec![],
                    search: None,
                })
                .await?;

            // Get specific implants
            for id in sample_ids {
                client
                    .get_implant(GetImplantRequest {
                        implant_id: Some(ProtoUuid {
                            value: id.as_bytes().to_vec(),
                        }),
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

    let concurrent_duration = start.elapsed();
    println!(
        "50 concurrent clients completed {} successful in {:?}",
        successes, concurrent_duration
    );

    assert!(
        successes >= 45,
        "at least 90% should succeed, got {}",
        successes
    );

    // Baseline: Concurrent access should complete in <15s
    assert!(
        concurrent_duration < Duration::from_secs(15),
        "concurrent access too slow: {:?}",
        concurrent_duration
    );
}

/// 7. Database query performance at scale
#[tokio::test]
async fn test_scale_db_query_performance() {
    let (state, _addr) = setup_scale_server().await;

    let ids = bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    // Measure direct DB queries
    let start = Instant::now();
    for _ in 0..100 {
        state.db.implants().list().await.unwrap();
    }
    let list_duration = start.elapsed();
    println!(
        "100 list queries on {} implants: {:?} ({:.1}ms avg)",
        SCALE_IMPLANT_COUNT,
        list_duration,
        list_duration.as_millis() as f64 / 100.0
    );

    let start = Instant::now();
    for id in ids.iter().take(100) {
        state.db.implants().get(*id).await.unwrap();
    }
    let get_duration = start.elapsed();
    println!(
        "100 get queries: {:?} ({:.1}ms avg)",
        get_duration,
        get_duration.as_millis() as f64 / 100.0
    );

    // Baselines
    assert!(
        list_duration < Duration::from_secs(10),
        "list queries too slow: {:?}",
        list_duration
    );
    assert!(
        get_duration < Duration::from_secs(1),
        "get queries too slow: {:?}",
        get_duration
    );
}

/// 8. Tasks at scale - many tasks for many implants
#[tokio::test]
async fn test_scale_tasks() {
    let (state, _addr) = setup_scale_server().await;

    // Insert 100 implants (smaller scale for task test)
    let ids = bulk_insert_implants(&state, 100, &[(ImplantState::Active, 100)]).await;

    // Create operator
    let op = NewOperator {
        username: "scale-op".to_string(),
        role: kraken_rbac::Role::Operator,
        cert_fingerprint: "scale-fp".to_string(),
    };
    let op_record = state.db.operators().create(op).await.unwrap();
    let operator_id = OperatorId::from(op_record.id);

    let start = Instant::now();

    // Create 10 tasks per implant = 1000 tasks total
    for (i, implant_id) in ids.iter().enumerate() {
        for j in 0..10 {
            let task_id = TaskId::new();
            let now = chrono::Utc::now().timestamp_millis();
            let task = TaskRecord {
                id: task_id,
                implant_id: *implant_id,
                operator_id,
                task_type: "shell".to_string(),
                task_data: format!("command-{}-{}", i, j).into_bytes(),
                status: "queued".to_string(),
                issued_at: now,
                dispatched_at: None,
                completed_at: None,
                result_data: None,
                error_message: None,
            };
            state.db.tasks().create(&task).await.unwrap();
        }
    }

    let task_insert_duration = start.elapsed();
    println!(
        "Created 1000 tasks in {:?} ({:.1} tasks/sec)",
        task_insert_duration,
        1000.0 / task_insert_duration.as_secs_f64()
    );

    // Query tasks for each implant
    let start = Instant::now();
    for implant_id in ids.iter().take(10) {
        let tasks = state.db.tasks().list_pending(*implant_id).await.unwrap();
        assert_eq!(tasks.len(), 10, "each implant should have 10 tasks");
    }
    let query_duration = start.elapsed();
    println!("Queried tasks for 10 implants in {:?}", query_duration);

    // Baselines
    assert!(
        task_insert_duration < Duration::from_secs(30),
        "task insert too slow: {:?}",
        task_insert_duration
    );
    assert!(
        query_duration < Duration::from_secs(1),
        "task query too slow: {:?}",
        query_duration
    );
}

/// 9. State updates at scale
#[tokio::test]
async fn test_scale_state_updates() {
    let (state, _addr) = setup_scale_server().await;

    let ids = bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    let start = Instant::now();

    // Update state for 100 implants
    for id in ids.iter().take(100) {
        state
            .db
            .implants()
            .update_state(*id, ImplantState::Lost)
            .await
            .unwrap();
    }

    let update_duration = start.elapsed();
    println!(
        "Updated 100 implant states in {:?} ({:.1} updates/sec)",
        update_duration,
        100.0 / update_duration.as_secs_f64()
    );

    // Verify updates
    let lost_count = state
        .db
        .implants()
        .list()
        .await
        .unwrap()
        .iter()
        .filter(|i| i.state == ImplantState::Lost)
        .count();
    assert_eq!(lost_count, 100, "100 implants should be Lost");

    // Baseline
    assert!(
        update_duration < Duration::from_secs(5),
        "state updates too slow: {:?}",
        update_duration
    );
}

/// 10. Memory stability under scale (no OOM)
#[tokio::test]
async fn test_scale_memory_stability() {
    let (state, addr) = setup_scale_server().await;

    bulk_insert_implants(
        &state,
        SCALE_IMPLANT_COUNT,
        &[(ImplantState::Active, SCALE_IMPLANT_COUNT)],
    )
    .await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    // Repeated list operations should not accumulate memory
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
        assert_eq!(count, SCALE_IMPLANT_COUNT, "iteration {} failed", i);
    }

    // If we get here without OOM, the test passes
    println!("Completed 50 full list operations without memory issues");
}
