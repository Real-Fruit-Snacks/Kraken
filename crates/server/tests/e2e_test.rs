//! End-to-end test: full implant lifecycle
//!
//! Starts both HTTP and gRPC servers, registers a simulated implant via HTTP,
//! dispatches a task via gRPC, and verifies the task is delivered on check-in.

use std::net::SocketAddr;
use std::sync::Arc;

use crypto::{types::X25519PublicKey, ImplantCrypto, ServerCrypto, SymmetricKey};
use prost::Message;
use protocol::{
    CheckIn, CheckInResponse, DispatchTaskRequest, ImplantRegistration, ImplantServiceServer,
    MessageEnvelope, MessageType, RegistrationResponse, TaskServiceClient, TaskServiceServer,
    Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;

// ---------------------------------------------------------------------------
// Test server setup (mirrors grpc_integration.rs)
// ---------------------------------------------------------------------------

async fn setup_grpc_server(state: Arc<server::ServerState>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let implant_svc =
        ImplantServiceServer::new(server::grpc::ImplantServiceImpl::new(Arc::clone(&state)));
    let task_svc = TaskServiceServer::new(
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

    addr
}

async fn setup_http_server(state: Arc<server::ServerState>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let router = server::http::handler::build_router(Arc::clone(&state));

    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("HTTP server failed");
    });

    addr
}

fn implant_id_to_proto(id: common::ImplantId) -> ProtoUuid {
    ProtoUuid {
        value: id.as_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// E2E test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_implant_lifecycle() {
    // -----------------------------------------------------------------------
    // 1. Setup server with in-memory DB
    // -----------------------------------------------------------------------
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = std::sync::Arc::new(
        module_store::ModuleStore::new(std::sync::Arc::new(db.clone()), &signing_key).unwrap(),
    );
    let audit_key = b"test-audit-key-for-e2e-tests!!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    // -----------------------------------------------------------------------
    // 2. Start HTTP and gRPC servers on random ports
    // -----------------------------------------------------------------------
    let grpc_addr = setup_grpc_server(Arc::clone(&state)).await;
    let http_addr = setup_http_server(Arc::clone(&state)).await;

    // Give servers a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // -----------------------------------------------------------------------
    // 3. Generate implant ephemeral keypair
    //    We use a dummy server public key just to initialise ImplantCrypto —
    //    the real session key will be derived from the server's response.
    // -----------------------------------------------------------------------
    // Start nonce counter at 1 so the first encrypted message uses counter 1,
    // which passes the server's replay check (received > stored 0).
    let dummy_server_pub = X25519PublicKey([0u8; 32]);
    let mut implant_crypto = ImplantCrypto::with_nonce_counter(dummy_server_pub, 1);
    let (implant_pub, implant_priv) = implant_crypto.generate_keypair().unwrap();

    // -----------------------------------------------------------------------
    // 4. Build and send registration message to HTTP /c
    // -----------------------------------------------------------------------
    let registration = ImplantRegistration {
        ephemeral_public_key: implant_pub.as_bytes().to_vec(),
        system_info: Some(protocol::SystemInfo {
            hostname: "test-host".to_string(),
            username: "test-user".to_string(),
            domain: String::new(),
            os_name: "Linux".to_string(),
            os_version: String::new(),
            os_arch: String::new(),
            process_id: 1234,
            process_name: String::new(),
            process_path: String::new(),
            is_elevated: false,
            integrity_level: String::new(),
            local_ips: vec![],
        }),
        config_hash: vec![],
        protocol_version: None,
    };

    let envelope = MessageEnvelope {
        message_type: MessageType::Registration as i32,
        payload: registration.encode_to_vec(),
    };

    let http_client = reqwest::Client::new();
    let url = format!("http://{}/c", http_addr);

    let resp = http_client
        .post(&url)
        .body(envelope.encode_to_vec())
        .send()
        .await
        .expect("HTTP registration request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "registration should return 200"
    );

    // -----------------------------------------------------------------------
    // 5. Parse RegistrationResponse, derive session key
    // -----------------------------------------------------------------------
    let resp_bytes = resp.bytes().await.expect("failed to read response body");
    let reg_response = RegistrationResponse::decode(resp_bytes.as_ref())
        .expect("failed to decode RegistrationResponse");

    assert!(
        !reg_response.server_public_key.is_empty(),
        "server_public_key missing"
    );

    let server_ephemeral_pub = X25519PublicKey::from_bytes(&reg_response.server_public_key)
        .expect("invalid server ephemeral public key");

    let shared_secret = implant_crypto
        .key_exchange(&implant_priv, &server_ephemeral_pub)
        .expect("key exchange failed");

    implant_crypto
        .derive_session_key(&shared_secret)
        .expect("session key derivation failed");

    assert!(
        implant_crypto.is_session_established(),
        "session not established"
    );

    // Extract the assigned implant ID
    let implant_id_proto = reg_response.implant_id.expect("no implant_id in response");
    let implant_id =
        common::ImplantId::from_bytes(&implant_id_proto.value).expect("invalid implant_id bytes");

    // -----------------------------------------------------------------------
    // 6. Dispatch a task via gRPC TaskService
    // -----------------------------------------------------------------------
    let grpc_endpoint = format!("http://{}", grpc_addr);
    let channel = tonic::transport::Channel::from_shared(grpc_endpoint)
        .unwrap()
        .connect()
        .await
        .expect("gRPC connect failed");

    let mut task_client = TaskServiceClient::new(channel);

    let dispatch_resp = task_client
        .dispatch_task(DispatchTaskRequest {
            implant_id: Some(implant_id_to_proto(implant_id)),
            task_type: "shell".to_string(),
            task_data: b"whoami".to_vec(),
        })
        .await
        .expect("dispatch_task RPC failed");

    let task_id_proto = dispatch_resp
        .into_inner()
        .task_id
        .expect("no task_id in dispatch response");

    // Verify the task is pending in server state
    assert!(
        state.pending_tasks.contains_key(&implant_id),
        "no pending tasks for implant after dispatch"
    );

    // -----------------------------------------------------------------------
    // 7. Send encrypted check-in to HTTP /c
    // -----------------------------------------------------------------------
    let checkin = CheckIn {
        implant_id: Some(implant_id_to_proto(implant_id)),
        local_time: None,
        task_responses: vec![],
        loaded_modules: vec![],
    };

    let checkin_plaintext = checkin.encode_to_vec();
    let encrypted_payload = implant_crypto
        .encrypt_message(&checkin_plaintext, implant_id)
        .expect("failed to encrypt check-in");

    let checkin_envelope = MessageEnvelope {
        message_type: MessageType::Checkin as i32,
        payload: encrypted_payload,
    };

    let checkin_resp = http_client
        .post(&url)
        .body(checkin_envelope.encode_to_vec())
        .send()
        .await
        .expect("HTTP check-in request failed");

    assert_eq!(
        checkin_resp.status().as_u16(),
        200,
        "check-in should return 200"
    );

    // -----------------------------------------------------------------------
    // 8. Decrypt response, verify task is present
    // -----------------------------------------------------------------------
    let checkin_resp_bytes = checkin_resp
        .bytes()
        .await
        .expect("failed to read check-in response body");

    assert!(
        !checkin_resp_bytes.is_empty(),
        "check-in response body is empty"
    );

    let decrypted = implant_crypto
        .decrypt_message(&checkin_resp_bytes)
        .expect("failed to decrypt check-in response");

    let checkin_response =
        CheckInResponse::decode(decrypted.as_slice()).expect("failed to decode CheckInResponse");

    assert_eq!(
        checkin_response.tasks.len(),
        1,
        "expected exactly one task in check-in response, got {}",
        checkin_response.tasks.len()
    );

    let delivered_task = &checkin_response.tasks[0];
    let delivered_task_id = delivered_task
        .task_id
        .as_ref()
        .expect("task has no task_id");

    assert_eq!(
        delivered_task_id.value, task_id_proto.value,
        "delivered task ID does not match dispatched task ID"
    );

    // Pending tasks should now be cleared
    assert!(
        !state.pending_tasks.contains_key(&implant_id),
        "pending tasks not drained after check-in"
    );
}
