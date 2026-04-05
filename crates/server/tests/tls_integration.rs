//! TLS/mTLS integration tests for the gRPC server
//!
//! These tests verify that the server properly enforces mutual TLS authentication.
//! The mTLS enforcement has two layers:
//! 1. TLS layer: validates certificate chain against trusted CA
//! 2. Interceptor layer: requires client cert present and extracts identity
//!
//! Note: The interceptor also checks if the operator is registered in the DB,
//! which is tested separately in auth tests.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use crypto::{ServerCrypto, SymmetricKey};
use protocol::{ImplantServiceClient, ListImplantsRequest, ImplantServiceServer};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, ServerTlsConfig};

// ---------------------------------------------------------------------------
// Certificate generation helpers
// ---------------------------------------------------------------------------

/// Test PKI for mTLS testing
struct TestPki {
    dir: PathBuf,
    ca_cert_pem: Vec<u8>,
    #[allow(dead_code)]
    ca_key_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    client_cn: String,
    /// SHA-256 fingerprint of client cert (hex)
    client_fingerprint: String,
}

impl TestPki {
    /// Generate a complete test PKI with CA, server, and client certificates
    fn generate(suffix: &str) -> Self {
        let dir = std::env::temp_dir()
            .join(format!("kraken-tls-test-{}-{}", suffix, std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        // Generate CA key and self-signed cert
        let ca_key_path = dir.join("ca.key");
        let ca_cert_path = dir.join("ca.crt");

        run_openssl(&[
            "genrsa", "-out", ca_key_path.to_str().unwrap(), "2048"
        ]);

        run_openssl(&[
            "req", "-new", "-x509", "-days", "1",
            "-key", ca_key_path.to_str().unwrap(),
            "-out", ca_cert_path.to_str().unwrap(),
            "-subj", "/CN=Test CA/O=Kraken Test",
        ]);

        // Create OpenSSL config for server cert with SANs
        let server_ext_path = dir.join("server_ext.cnf");
        std::fs::write(
            &server_ext_path,
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )
        .expect("write server ext config");

        // Generate server key and CSR
        let server_key_path = dir.join("server.key");
        let server_csr_path = dir.join("server.csr");
        let server_cert_path = dir.join("server.crt");

        run_openssl(&[
            "genrsa", "-out", server_key_path.to_str().unwrap(), "2048"
        ]);

        run_openssl(&[
            "req", "-new",
            "-key", server_key_path.to_str().unwrap(),
            "-out", server_csr_path.to_str().unwrap(),
            "-subj", "/CN=localhost/O=Kraken Server",
        ]);

        // Sign server cert with CA, including SANs
        run_openssl(&[
            "x509", "-req", "-days", "1",
            "-in", server_csr_path.to_str().unwrap(),
            "-CA", ca_cert_path.to_str().unwrap(),
            "-CAkey", ca_key_path.to_str().unwrap(),
            "-CAcreateserial",
            "-extfile", server_ext_path.to_str().unwrap(),
            "-out", server_cert_path.to_str().unwrap(),
        ]);

        // Generate client key and CSR
        let client_cn = "test-operator";
        let client_key_path = dir.join("client.key");
        let client_csr_path = dir.join("client.csr");
        let client_cert_path = dir.join("client.crt");

        run_openssl(&[
            "genrsa", "-out", client_key_path.to_str().unwrap(), "2048"
        ]);

        run_openssl(&[
            "req", "-new",
            "-key", client_key_path.to_str().unwrap(),
            "-out", client_csr_path.to_str().unwrap(),
            "-subj", &format!("/CN={}/O=Kraken Operators", client_cn),
        ]);

        // Sign client cert with CA
        run_openssl(&[
            "x509", "-req", "-days", "1",
            "-in", client_csr_path.to_str().unwrap(),
            "-CA", ca_cert_path.to_str().unwrap(),
            "-CAkey", ca_key_path.to_str().unwrap(),
            "-CAcreateserial",
            "-out", client_cert_path.to_str().unwrap(),
        ]);

        // Get client cert fingerprint
        let client_der_path = dir.join("client.der");
        run_openssl(&[
            "x509",
            "-in", client_cert_path.to_str().unwrap(),
            "-out", client_der_path.to_str().unwrap(),
            "-outform", "DER",
        ]);
        let client_der = std::fs::read(&client_der_path).unwrap();
        let fingerprint = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&client_der);
            hex::encode(hasher.finalize())
        };

        Self {
            ca_cert_pem: std::fs::read(&ca_cert_path).unwrap(),
            ca_key_pem: std::fs::read(&ca_key_path).unwrap(),
            server_cert_pem: std::fs::read(&server_cert_path).unwrap(),
            server_key_pem: std::fs::read(&server_key_path).unwrap(),
            client_cert_pem: std::fs::read(&client_cert_path).unwrap(),
            client_key_pem: std::fs::read(&client_key_path).unwrap(),
            client_cn: client_cn.to_string(),
            client_fingerprint: fingerprint,
            dir,
        }
    }

    /// Generate a certificate signed by a different (untrusted) CA
    fn generate_untrusted_client(&self, cn: &str) -> (Vec<u8>, Vec<u8>) {
        // Generate a separate CA
        let rogue_ca_key = self.dir.join("rogue_ca.key");
        let rogue_ca_cert = self.dir.join("rogue_ca.crt");

        run_openssl(&[
            "genrsa", "-out", rogue_ca_key.to_str().unwrap(), "2048"
        ]);

        run_openssl(&[
            "req", "-new", "-x509", "-days", "1",
            "-key", rogue_ca_key.to_str().unwrap(),
            "-out", rogue_ca_cert.to_str().unwrap(),
            "-subj", "/CN=Rogue CA/O=Evil Corp",
        ]);

        // Generate client cert signed by rogue CA
        let rogue_key = self.dir.join("rogue_client.key");
        let rogue_csr = self.dir.join("rogue_client.csr");
        let rogue_cert = self.dir.join("rogue_client.crt");

        run_openssl(&[
            "genrsa", "-out", rogue_key.to_str().unwrap(), "2048"
        ]);

        run_openssl(&[
            "req", "-new",
            "-key", rogue_key.to_str().unwrap(),
            "-out", rogue_csr.to_str().unwrap(),
            "-subj", &format!("/CN={}/O=Evil Operators", cn),
        ]);

        run_openssl(&[
            "x509", "-req", "-days", "1",
            "-in", rogue_csr.to_str().unwrap(),
            "-CA", rogue_ca_cert.to_str().unwrap(),
            "-CAkey", rogue_ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-out", rogue_cert.to_str().unwrap(),
        ]);

        (
            std::fs::read(&rogue_cert).unwrap(),
            std::fs::read(&rogue_key).unwrap(),
        )
    }

    /// Build server TLS config requiring client certificates
    fn server_tls_config(&self) -> ServerTlsConfig {
        let identity = Identity::from_pem(&self.server_cert_pem, &self.server_key_pem);
        let client_ca = Certificate::from_pem(&self.ca_cert_pem);

        ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(client_ca)
    }

    /// Build client TLS config with valid client certificate
    fn client_tls_config(&self) -> ClientTlsConfig {
        let ca = Certificate::from_pem(&self.ca_cert_pem);
        let identity = Identity::from_pem(&self.client_cert_pem, &self.client_key_pem);

        ClientTlsConfig::new()
            .ca_certificate(ca)
            .identity(identity)
            .domain_name("localhost")
    }

    /// Build client TLS config without client certificate
    fn client_tls_config_no_cert(&self) -> ClientTlsConfig {
        let ca = Certificate::from_pem(&self.ca_cert_pem);

        ClientTlsConfig::new()
            .ca_certificate(ca)
            .domain_name("localhost")
    }

    /// Build client TLS config with untrusted certificate
    fn client_tls_config_untrusted(&self, cert_pem: &[u8], key_pem: &[u8]) -> ClientTlsConfig {
        let ca = Certificate::from_pem(&self.ca_cert_pem);
        let identity = Identity::from_pem(cert_pem, key_pem);

        ClientTlsConfig::new()
            .ca_certificate(ca)
            .identity(identity)
            .domain_name("localhost")
    }
}

impl Drop for TestPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_openssl(args: &[&str]) {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .expect("failed to run openssl");
    assert!(
        output.status.success(),
        "openssl command failed: {:?}\nstderr: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

/// Setup a TLS server and register the test operator in the DB
async fn setup_tls_server_with_operator(pki: &TestPki) -> (Arc<server::ServerState>, SocketAddr) {
    // In-memory SQLite
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // Register the test operator using the cert fingerprint
    let op = db::NewOperator {
        username: pki.client_cn.clone(),
        role: kraken_rbac::Role::Admin,
        cert_fingerprint: pki.client_fingerprint.clone(),
    };
    db.operators().create(op).await.unwrap();

    // Deterministic test master key
    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-for-tls-tests!!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    // Bind to a random OS-assigned port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Build mTLS-protected service
    let implant_svc = ImplantServiceServer::with_interceptor(
        server::grpc::ImplantServiceImpl::new(Arc::clone(&state)),
        server::auth::require_client_cert,
    );

    let tls_config = pki.server_tls_config();

    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls_config)
            .expect("invalid TLS config")
            .add_service(implant_svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    (state_clone, addr)
}

/// Setup a TLS server WITHOUT registering the operator
async fn setup_tls_server_no_operator(pki: &TestPki) -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let ms = Arc::new(
        module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
    );

    let audit_key = b"test-audit-key-for-tls-tests!!";
    let state = server::ServerState::new(db, crypto, ms, audit_key.to_vec());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let implant_svc = ImplantServiceServer::with_interceptor(
        server::grpc::ImplantServiceImpl::new(Arc::clone(&state)),
        server::auth::require_client_cert,
    );

    let tls_config = pki.server_tls_config();

    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls_config)
            .expect("invalid TLS config")
            .add_service(implant_svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    (state_clone, addr)
}

async fn connect_with_tls(
    addr: SocketAddr,
    tls_config: ClientTlsConfig,
) -> Result<Channel, tonic::transport::Error> {
    let endpoint = format!("https://{}", addr);
    Channel::from_shared(endpoint)
        .unwrap()
        .tls_config(tls_config)?
        .connect()
        .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. Valid client certificate with registered operator succeeds
#[tokio::test]
async fn test_mtls_valid_cert_registered_operator_succeeds() {
    let pki = TestPki::generate("valid_reg");
    let (_state, addr) = setup_tls_server_with_operator(&pki).await;

    let channel = connect_with_tls(addr, pki.client_tls_config())
        .await
        .expect("connection with valid cert should succeed");

    let mut client = ImplantServiceClient::new(channel);

    let response = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;

    assert!(
        response.is_ok(),
        "RPC with valid cert and registered operator should succeed: {:?}",
        response.err()
    );
}

/// 2. Valid client certificate but unregistered operator gets PermissionDenied
#[tokio::test]
async fn test_mtls_valid_cert_unregistered_operator_rejected() {
    let pki = TestPki::generate("valid_unreg");
    let (_state, addr) = setup_tls_server_no_operator(&pki).await;

    let channel = connect_with_tls(addr, pki.client_tls_config())
        .await
        .expect("TLS connection should succeed even without DB registration");

    let mut client = ImplantServiceClient::new(channel);

    let response = client
        .list_implants(ListImplantsRequest {
            state_filter: None,
            tag_filter: vec![],
            search: None,
        })
        .await;

    let err = response.expect_err("unregistered operator should be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "expected PermissionDenied for unregistered operator, got {:?}",
        err.code()
    );
    assert!(
        err.message().contains("not registered"),
        "error should mention registration: {}",
        err.message()
    );
}

/// 3. Connection without client certificate is rejected by interceptor
#[tokio::test]
async fn test_mtls_no_client_cert_rejected() {
    let pki = TestPki::generate("nocert");
    let (_state, addr) = setup_tls_server_with_operator(&pki).await;

    // Try to connect without a client certificate
    let connect_result = connect_with_tls(addr, pki.client_tls_config_no_cert()).await;

    match connect_result {
        Err(_) => {
            // TLS handshake failed - this is expected behavior
        }
        Ok(channel) => {
            // Connection succeeded but RPC should fail
            let mut client = ImplantServiceClient::new(channel);
            let result = client
                .list_implants(ListImplantsRequest {
                    state_filter: None,
                    tag_filter: vec![],
                    search: None,
                })
                .await;

            let err = result.expect_err("RPC without client cert should fail");
            // The error code may be Unauthenticated (from interceptor) or Unknown (transport error)
            // depending on how/when the TLS layer rejects the connection
            assert!(
                matches!(err.code(), tonic::Code::Unauthenticated | tonic::Code::Unknown | tonic::Code::Unavailable),
                "expected Unauthenticated/Unknown/Unavailable for missing cert, got {:?}",
                err.code()
            );
        }
    }
}

/// 4. Client certificate signed by untrusted CA is rejected
#[tokio::test]
async fn test_mtls_untrusted_ca_rejected() {
    let pki = TestPki::generate("untrusted");
    let (_state, addr) = setup_tls_server_with_operator(&pki).await;

    // Generate a cert signed by a different CA
    let (rogue_cert, rogue_key) = pki.generate_untrusted_client("rogue-operator");

    // Try to connect with the untrusted cert
    let connect_result = connect_with_tls(
        addr,
        pki.client_tls_config_untrusted(&rogue_cert, &rogue_key),
    )
    .await;

    match connect_result {
        Err(_) => {
            // TLS rejected the untrusted cert - expected
        }
        Ok(channel) => {
            // If TLS somehow accepted, the RPC should still fail
            let mut client = ImplantServiceClient::new(channel);
            let result = client
                .list_implants(ListImplantsRequest {
                    state_filter: None,
                    tag_filter: vec![],
                    search: None,
                })
                .await;

            // Either TLS or interceptor should reject
            assert!(
                result.is_err(),
                "untrusted cert should be rejected somewhere in the chain"
            );
        }
    }
}

/// 5. Test that plain HTTP connection to TLS server fails
#[tokio::test]
async fn test_plain_http_to_tls_server_fails() {
    let pki = TestPki::generate("plain");
    let (_state, addr) = setup_tls_server_with_operator(&pki).await;

    // Try to connect without TLS
    let endpoint = format!("http://{}", addr);
    let channel_result = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await;

    match channel_result {
        Err(_) => {
            // Connection failed - expected
        }
        Ok(channel) => {
            // Channel connected, but RPC should fail
            let mut client = ImplantServiceClient::new(channel);
            let result = client
                .list_implants(ListImplantsRequest {
                    state_filter: None,
                    tag_filter: vec![],
                    search: None,
                })
                .await;

            assert!(
                result.is_err(),
                "plain HTTP RPC to TLS server should fail"
            );
        }
    }
}

/// 6. Test multiple concurrent TLS connections
#[tokio::test]
async fn test_concurrent_tls_connections() {
    let pki = TestPki::generate("concurrent");
    let (_state, addr) = setup_tls_server_with_operator(&pki).await;

    // Spawn multiple concurrent connections
    let mut handles = vec![];
    for i in 0..5 {
        let tls_config = pki.client_tls_config();
        handles.push(tokio::spawn(async move {
            let channel = connect_with_tls(addr, tls_config)
                .await
                .expect("connection should succeed");

            let mut client = ImplantServiceClient::new(channel);

            for j in 0..3 {
                let response = client
                    .list_implants(ListImplantsRequest {
                        state_filter: None,
                        tag_filter: vec![],
                        search: None,
                    })
                    .await;
                assert!(
                    response.is_ok(),
                    "concurrent request {}-{} should succeed: {:?}",
                    i, j,
                    response.err()
                );
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task should complete");
    }
}

/// 7. Test CertIdentity extraction from valid certificate
#[tokio::test]
async fn test_cert_identity_extraction() {
    use server::auth::CertIdentity;

    let pki = TestPki::generate("identity");

    // Convert PEM to DER for CertIdentity testing
    let der_path = pki.dir.join("client.der");
    run_openssl(&[
        "x509",
        "-in", pki.dir.join("client.crt").to_str().unwrap(),
        "-out", der_path.to_str().unwrap(),
        "-outform", "DER",
    ]);

    let cert_der = std::fs::read(&der_path).unwrap();
    let identity = CertIdentity::from_cert(&cert_der)
        .expect("should parse valid certificate");

    assert_eq!(
        identity.username, pki.client_cn,
        "extracted CN should match"
    );

    // Fingerprint should be SHA-256 (64 hex chars)
    assert_eq!(
        identity.cert_fingerprint.len(),
        64,
        "fingerprint should be 64 hex chars"
    );

    // Fingerprint should match what we computed
    assert_eq!(
        identity.cert_fingerprint, pki.client_fingerprint,
        "fingerprint should match computed value"
    );

    // Fingerprint should be deterministic
    let identity2 = CertIdentity::from_cert(&cert_der).unwrap();
    assert_eq!(
        identity.cert_fingerprint, identity2.cert_fingerprint,
        "fingerprint should be deterministic"
    );
}

/// 8. Test AuthConfig loads and builds valid TLS config
#[tokio::test]
async fn test_auth_config_builds_valid_tls_config() {
    let pki = TestPki::generate("authconfig");

    // Write certs to files for AuthConfig::load
    let ca_path = pki.dir.join("load_ca.crt");
    let cert_path = pki.dir.join("load_server.crt");
    let key_path = pki.dir.join("load_server.key");

    std::fs::write(&ca_path, &pki.ca_cert_pem).unwrap();
    std::fs::write(&cert_path, &pki.server_cert_pem).unwrap();
    std::fs::write(&key_path, &pki.server_key_pem).unwrap();

    // Load via AuthConfig
    let auth_config = server::auth::AuthConfig::load(&ca_path, &cert_path, &key_path)
        .expect("AuthConfig::load should succeed");

    assert_eq!(auth_config.ca_cert, pki.ca_cert_pem);
    assert_eq!(auth_config.server_cert, pki.server_cert_pem);
    assert_eq!(auth_config.server_key, pki.server_key_pem);

    // Build TLS config - should not error
    let _tls_config = auth_config
        .server_tls_config()
        .expect("server_tls_config should succeed");
}

/// 9. Test CertIdentity rejects invalid inputs
#[tokio::test]
async fn test_cert_identity_rejects_invalid() {
    use server::auth::CertIdentity;

    // Empty bytes
    assert!(
        CertIdentity::from_cert(&[]).is_none(),
        "empty bytes should return None"
    );

    // Random garbage
    let garbage: Vec<u8> = (0..128).map(|i| (i * 7 + 13) as u8).collect();
    assert!(
        CertIdentity::from_cert(&garbage).is_none(),
        "garbage bytes should return None"
    );

    // PEM instead of DER
    let fake_pem = b"-----BEGIN CERTIFICATE-----\nZmFrZQo=\n-----END CERTIFICATE-----\n";
    assert!(
        CertIdentity::from_cert(fake_pem).is_none(),
        "PEM (not DER) should return None"
    );
}
