//! Performance baseline tests
//!
//! These tests establish performance baselines for critical operations.
//! They measure latencies and throughput to detect regressions.
//!
//! Run with: cargo test -p server --test performance_baseline -- --nocapture

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{ImplantId, ImplantState};
use crypto::{ServerCrypto, SymmetricKey};
use db::ImplantRecord;
use protocol::{
    DispatchTaskRequest, GetImplantRequest, ImplantServiceClient, ImplantServiceServer,
    ListImplantsRequest, TaskServiceClient, TaskServiceServer, Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

async fn setup_perf_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-for-perf-tests!";
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

    tokio::time::sleep(Duration::from_millis(50)).await;
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
        name: format!("perf-implant-{}", id),
        state: implant_state,
        hostname: Some("perf-host".to_string()),
        username: Some("perf-user".to_string()),
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

/// Measure operation latency statistics
struct LatencyStats {
    count: usize,
    min: Duration,
    max: Duration,
    total: Duration,
}

impl LatencyStats {
    fn new() -> Self {
        Self {
            count: 0,
            min: Duration::MAX,
            max: Duration::ZERO,
            total: Duration::ZERO,
        }
    }

    fn record(&mut self, d: Duration) {
        self.count += 1;
        self.total += d;
        if d < self.min {
            self.min = d;
        }
        if d > self.max {
            self.max = d;
        }
    }

    fn avg(&self) -> Duration {
        if self.count == 0 {
            Duration::ZERO
        } else {
            self.total / self.count as u32
        }
    }

    fn ops_per_sec(&self) -> f64 {
        if self.total.as_secs_f64() == 0.0 {
            0.0
        } else {
            self.count as f64 / self.total.as_secs_f64()
        }
    }
}

// ---------------------------------------------------------------------------
// Performance Baseline Tests
// ---------------------------------------------------------------------------

/// 1. Measure list_implants latency with empty database
#[tokio::test]
async fn perf_list_implants_empty() {
    let (_state, addr) = setup_perf_server().await;
    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 100;

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await
            .unwrap();
        stats.record(start.elapsed());
    }

    println!(
        "list_implants (empty): avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 10ms average
    assert!(
        stats.avg() < Duration::from_millis(10),
        "list_implants (empty) too slow: {:?}",
        stats.avg()
    );
}

/// 2. Measure list_implants latency with 100 implants
#[tokio::test]
async fn perf_list_implants_100() {
    let (state, addr) = setup_perf_server().await;

    // Insert 100 implants
    for _ in 0..100 {
        insert_implant(&state, ImplantState::Active).await;
    }

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 50;

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let resp = client
            .list_implants(ListImplantsRequest {
                state_filter: None,
                tag_filter: vec![],
                search: None,
            })
            .await
            .unwrap();
        stats.record(start.elapsed());
        assert_eq!(resp.into_inner().implants.len(), 100);
    }

    println!(
        "list_implants (100): avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 100ms average (conservative for debug builds)
    assert!(
        stats.avg() < Duration::from_millis(100),
        "list_implants (100) too slow: {:?}",
        stats.avg()
    );
}

/// 3. Measure get_implant latency
#[tokio::test]
async fn perf_get_implant() {
    let (state, addr) = setup_perf_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = ImplantServiceClient::new(channel);

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 100;

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = client
            .get_implant(GetImplantRequest {
                implant_id: Some(implant_id_to_proto(implant_id)),
            })
            .await
            .unwrap();
        stats.record(start.elapsed());
    }

    println!(
        "get_implant: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 5ms average
    assert!(
        stats.avg() < Duration::from_millis(5),
        "get_implant too slow: {:?}",
        stats.avg()
    );
}

/// 4. Measure task dispatch latency
#[tokio::test]
async fn perf_dispatch_task() {
    let (state, addr) = setup_perf_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let channel = connect(addr).await;
    let mut client = TaskServiceClient::new(channel);

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 100;

    for i in 0..ITERATIONS {
        let start = Instant::now();
        let _ = client
            .dispatch_task(DispatchTaskRequest {
                implant_id: Some(implant_id_to_proto(implant_id)),
                task_type: "shell".to_string(),
                task_data: format!("cmd-{}", i).into_bytes(),
            })
            .await
            .unwrap();
        stats.record(start.elapsed());
    }

    println!(
        "dispatch_task: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 10ms average
    assert!(
        stats.avg() < Duration::from_millis(10),
        "dispatch_task too slow: {:?}",
        stats.avg()
    );
}

/// 5. Measure crypto encrypt/decrypt latency
#[tokio::test]
async fn perf_crypto_operations() {
    let master_key = ServerCrypto::generate_master_key().unwrap();
    let crypto = ServerCrypto::new(master_key);

    let session_key = SymmetricKey([42u8; 32]);
    let mut encrypt_stats = LatencyStats::new();
    let mut decrypt_stats = LatencyStats::new();
    const ITERATIONS: usize = 1000;

    // Measure encryption
    let mut encrypted = Vec::new();
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        encrypted = crypto.encrypt_session_key(&session_key).unwrap();
        encrypt_stats.record(start.elapsed());
    }

    // Measure decryption
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = crypto.decrypt_session_key(&encrypted).unwrap();
        decrypt_stats.record(start.elapsed());
    }

    println!(
        "crypto encrypt: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        encrypt_stats.avg(),
        encrypt_stats.min,
        encrypt_stats.max,
        encrypt_stats.ops_per_sec()
    );
    println!(
        "crypto decrypt: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        decrypt_stats.avg(),
        decrypt_stats.min,
        decrypt_stats.max,
        decrypt_stats.ops_per_sec()
    );

    // Baseline: should complete in under 1ms average
    assert!(
        encrypt_stats.avg() < Duration::from_millis(1),
        "encrypt too slow: {:?}",
        encrypt_stats.avg()
    );
    assert!(
        decrypt_stats.avg() < Duration::from_millis(1),
        "decrypt too slow: {:?}",
        decrypt_stats.avg()
    );
}

/// 6. Measure database insert latency
#[tokio::test]
async fn perf_db_insert() {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 100;

    for _ in 0..ITERATIONS {
        let id = ImplantId::new();
        let now = chrono::Utc::now().timestamp_millis();
        let record = ImplantRecord {
            id,
            name: format!("perf-{}", id),
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
            checkin_interval: 30,
            jitter_percent: 10,
            symmetric_key: None,
            nonce_counter: 0,
            registered_at: now,
            last_seen: Some(now),
        };

        let start = Instant::now();
        db.implants().create(&record).await.unwrap();
        stats.record(start.elapsed());
    }

    println!(
        "db insert: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 5ms average
    assert!(
        stats.avg() < Duration::from_millis(5),
        "db insert too slow: {:?}",
        stats.avg()
    );
}

/// 7. Measure database query latency
#[tokio::test]
async fn perf_db_query() {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // Insert test implant
    let id = ImplantId::new();
    let now = chrono::Utc::now().timestamp_millis();
    let record = ImplantRecord {
        id,
        name: "query-test".to_string(),
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
        checkin_interval: 30,
        jitter_percent: 10,
        symmetric_key: None,
        nonce_counter: 0,
        registered_at: now,
        last_seen: Some(now),
    };
    db.implants().create(&record).await.unwrap();

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 1000;

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = db.implants().get(id).await.unwrap();
        stats.record(start.elapsed());
    }

    println!(
        "db query: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 5ms average (conservative for debug builds)
    assert!(
        stats.avg() < Duration::from_millis(5),
        "db query too slow: {:?}",
        stats.avg()
    );
}

/// 8. Measure concurrent gRPC request throughput
#[tokio::test]
async fn perf_concurrent_requests() {
    let (state, addr) = setup_perf_server().await;
    let implant_id = insert_implant(&state, ImplantState::Active).await;

    let start = Instant::now();
    const CONCURRENT: usize = 10;
    const REQUESTS_PER: usize = 50;

    let mut handles = vec![];
    for _ in 0..CONCURRENT {
        let channel = connect(addr).await;
        let id = implant_id;
        handles.push(tokio::spawn(async move {
            let mut client = ImplantServiceClient::new(channel);
            for _ in 0..REQUESTS_PER {
                let _ = client
                    .get_implant(GetImplantRequest {
                        implant_id: Some(implant_id_to_proto(id)),
                    })
                    .await
                    .unwrap();
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let total_requests = CONCURRENT * REQUESTS_PER;
    let rps = total_requests as f64 / elapsed.as_secs_f64();

    println!(
        "concurrent requests: {} total in {:?}, {:.1} req/sec",
        total_requests, elapsed, rps
    );

    // Baseline: should handle at least 300 requests/second (conservative for debug builds)
    assert!(
        rps > 300.0,
        "concurrent throughput too low: {:.1} req/sec",
        rps
    );
}

/// 9. Measure key exchange latency
#[tokio::test]
async fn perf_key_exchange() {
    use crypto::x25519::{diffie_hellman, generate_keypair};

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 1000;

    for _ in 0..ITERATIONS {
        let start = Instant::now();

        // Simulate full key exchange
        let (pub1, priv1) = generate_keypair().unwrap();
        let (pub2, priv2) = generate_keypair().unwrap();
        let _shared1 = diffie_hellman(&priv1, &pub2).unwrap();
        let _shared2 = diffie_hellman(&priv2, &pub1).unwrap();

        stats.record(start.elapsed());
    }

    println!(
        "key exchange: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 5ms average (conservative for debug builds)
    assert!(
        stats.avg() < Duration::from_millis(5),
        "key exchange too slow: {:?}",
        stats.avg()
    );
}

/// 10. Measure HKDF derivation latency
#[tokio::test]
async fn perf_hkdf_derive() {
    use crypto::hkdf::derive_session_key;

    let shared_secret = [0x42u8; 32];
    let context = "performance-test-context";

    let mut stats = LatencyStats::new();
    const ITERATIONS: usize = 10000;

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = derive_session_key(&shared_secret, context).unwrap();
        stats.record(start.elapsed());
    }

    println!(
        "hkdf derive: avg={:?}, min={:?}, max={:?}, ops/sec={:.1}",
        stats.avg(),
        stats.min,
        stats.max,
        stats.ops_per_sec()
    );

    // Baseline: should complete in under 100us average
    assert!(
        stats.avg() < Duration::from_micros(100),
        "hkdf derive too slow: {:?}",
        stats.avg()
    );
}
