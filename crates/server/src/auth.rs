//! mTLS operator authentication
//!
//! Handles server-side TLS configuration and operator identity extraction
//! from client certificates. Integrates with the RBAC system for permission
//! checking.

pub mod jwt;

use std::path::Path;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::{Request, Status};

// Re-export RBAC types for convenience
pub use kraken_rbac::{Permission, Role, RbacError};

/// Full operator identity with RBAC permissions
pub type OperatorIdentity = kraken_rbac::OperatorIdentity;

/// TLS authentication configuration
pub struct AuthConfig {
    pub ca_cert: Vec<u8>,
    pub server_cert: Vec<u8>,
    pub server_key: Vec<u8>,
}

impl AuthConfig {
    /// Load certificates from files
    pub fn load(
        ca_path: impl AsRef<Path>,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            ca_cert: std::fs::read(ca_path)?,
            server_cert: std::fs::read(cert_path)?,
            server_key: std::fs::read(key_path)?,
        })
    }

    /// Build tonic ServerTlsConfig for mTLS
    pub fn server_tls_config(&self) -> Result<ServerTlsConfig, Box<dyn std::error::Error>> {
        let identity = Identity::from_pem(&self.server_cert, &self.server_key);
        let client_ca = Certificate::from_pem(&self.ca_cert);

        Ok(ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(client_ca))
    }
}

/// Certificate identity extracted from mTLS client certificate.
/// This is the minimal identity extracted synchronously by the interceptor.
/// Use `resolve_operator` to get the full RBAC identity from the database.
#[derive(Clone, Debug)]
pub struct CertIdentity {
    pub username: String,
    pub cert_fingerprint: String,
}

impl CertIdentity {
    /// Extract identity from certificate bytes
    pub fn from_cert(cert_der: &[u8]) -> Option<Self> {
        // Parse X.509 certificate
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;

        // Extract CN from subject
        let cn = cert
            .subject()
            .iter_common_name()
            .next()?
            .as_str()
            .ok()?;

        // Compute SHA-256 fingerprint
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let fingerprint = hex::encode(hasher.finalize());

        Some(Self {
            username: cn.to_string(),
            cert_fingerprint: fingerprint,
        })
    }
}

/// Resolve the full operator identity from the database.
/// Returns the RBAC-aware identity with role, permissions, and access restrictions.
pub async fn resolve_operator(
    db: &db::Database,
    cert_identity: &CertIdentity,
) -> Result<OperatorIdentity, Status> {
    db.operators()
        .get_identity_by_cert(&cert_identity.cert_fingerprint)
        .await
        .map_err(|e| Status::internal(format!("database error: {}", e)))?
        .ok_or_else(|| Status::permission_denied("operator not registered"))
}

/// Extract CertIdentity from a gRPC request that has passed through `require_client_cert`.
pub fn get_cert_identity<T>(request: &Request<T>) -> Result<&CertIdentity, Status> {
    request
        .extensions()
        .get::<CertIdentity>()
        .ok_or_else(|| Status::unauthenticated("missing operator identity"))
}

/// Check if the operator has the required permission.
/// Returns an error status if the permission is denied.
pub fn require_permission(
    operator: &OperatorIdentity,
    permission: Permission,
) -> Result<(), Status> {
    if operator.has_permission(permission) {
        Ok(())
    } else {
        Err(Status::permission_denied(format!(
            "permission denied: {:?} required",
            permission
        )))
    }
}

/// Check if the operator has access to a specific session.
/// Returns an error status if access is denied.
pub fn require_session_access(
    operator: &OperatorIdentity,
    session_id: uuid::Uuid,
) -> Result<(), Status> {
    if operator.can_access_session(session_id) {
        Ok(())
    } else {
        Err(Status::permission_denied(format!(
            "access denied: no access to session {}",
            session_id
        )))
    }
}

/// Check if the operator has access to a specific listener.
/// Returns an error status if access is denied.
pub fn require_listener_access(
    operator: &OperatorIdentity,
    listener_id: uuid::Uuid,
) -> Result<(), Status> {
    if operator.can_access_listener(listener_id) {
        Ok(())
    } else {
        Err(Status::permission_denied(format!(
            "access denied: no access to listener {}",
            listener_id
        )))
    }
}

/// gRPC interceptor that enforces mTLS client certificate authentication.
///
/// Every inbound request must carry a valid TLS client certificate signed by
/// the trusted CA (as configured via `AuthConfig::server_tls_config`).
/// Requests that arrive without a peer certificate are rejected with
/// `UNAUTHENTICATED`.  On success the resolved `CertIdentity` is inserted
/// into the request extensions so downstream handlers can read it.
///
/// To get the full RBAC-aware `OperatorIdentity`, use `resolve_operator()`
/// with the database in your service handler.
///
/// # Usage
///
/// ```rust,ignore
/// use tonic::transport::Server;
/// use server::auth::{require_client_cert, resolve_operator, get_cert_identity};
///
/// Server::builder()
///     .tls_config(tls_cfg)?
///     .add_service(MyServiceServer::with_interceptor(svc, require_client_cert))
///     .serve(addr)
///     .await?;
///
/// // In your service handler:
/// async fn my_handler(&self, request: Request<MyRequest>) -> Result<Response<MyResponse>, Status> {
///     let cert_id = get_cert_identity(&request)?;
///     let operator = resolve_operator(&self.db, cert_id).await?;
///     require_permission(&operator, Permission::SessionsRead)?;
///     // ...
/// }
/// ```
pub fn require_client_cert(mut request: Request<()>) -> Result<Request<()>, Status> {
    // The peer certificates are injected by tonic into the request extensions
    // as `TlsConnectInfo<TcpConnectInfo>` for every TLS connection.
    let peer_certs = request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .and_then(|tls| tls.peer_certs());

    let certs = peer_certs.ok_or_else(|| {
        Status::unauthenticated("mTLS client certificate is required")
    })?;

    if certs.is_empty() {
        return Err(Status::unauthenticated("mTLS client certificate is required"));
    }

    // Use the first (leaf) certificate to derive operator identity.
    // tonic stores peer_certificates() bytes from rustls, which are DER-encoded
    // even though the wrapper type is named Certificate::from_pem.
    let der = certs[0].get_ref();
    let cert_identity = CertIdentity::from_cert(der).ok_or_else(|| {
        Status::unauthenticated("client certificate is invalid or missing CN field")
    })?;

    tracing::debug!(
        username = %cert_identity.username,
        fingerprint = %cert_identity.cert_fingerprint,
        "operator authenticated via mTLS"
    );

    request.extensions_mut().insert(cert_identity);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Generate a minimal self-signed certificate with the given CN and return
    /// the PEM bytes for the cert and key.  Uses the system `openssl` binary so
    /// that no extra Rust crypto crates are required in dev-dependencies.
    fn gen_self_signed_pem(cn: &str, dir: &PathBuf) -> (Vec<u8>, Vec<u8>) {
        let key_path = dir.join("test.key");
        let cert_path = dir.join("test.crt");

        // Generate private key
        let status = Command::new("openssl")
            .args(["genrsa", "-out", key_path.to_str().unwrap(), "2048"])
            .output()
            .expect("openssl genrsa failed");
        assert!(status.status.success(), "openssl genrsa exited non-zero");

        // Generate self-signed cert
        let subj = format!("/CN={cn}/O=Test");
        let status = Command::new("openssl")
            .args([
                "req", "-new", "-x509", "-days", "1",
                "-key", key_path.to_str().unwrap(),
                "-out", cert_path.to_str().unwrap(),
                "-subj", &subj,
            ])
            .output()
            .expect("openssl req failed");
        assert!(status.status.success(), "openssl req exited non-zero");

        let cert_pem = std::fs::read(&cert_path).expect("read cert");
        let key_pem = std::fs::read(&key_path).expect("read key");
        (cert_pem, key_pem)
    }

    /// Convert a PEM certificate to DER bytes via openssl.
    fn pem_to_der(cert_pem: &[u8], dir: &PathBuf) -> Vec<u8> {
        let pem_path = dir.join("conv.crt");
        let der_path = dir.join("conv.der");
        std::fs::write(&pem_path, cert_pem).unwrap();

        let status = Command::new("openssl")
            .args([
                "x509", "-in", pem_path.to_str().unwrap(),
                "-out", der_path.to_str().unwrap(),
                "-outform", "DER",
            ])
            .output()
            .expect("openssl x509 conversion failed");
        assert!(status.status.success(), "openssl x509 DER conversion failed");

        std::fs::read(&der_path).expect("read DER")
    }

    /// Create a unique temporary directory under the system temp dir and return
    /// its path.  The caller is responsible for cleanup.
    fn make_temp_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kraken-auth-test-{suffix}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // -----------------------------------------------------------------------
    // test_auth_config_load
    // -----------------------------------------------------------------------

    /// AuthConfig::load() reads three files and stores their raw bytes.
    #[test]
    fn test_auth_config_load() {
        let dir = make_temp_dir("load");

        // Write dummy PEM-like content (AuthConfig::load just does fs::read,
        // it doesn't validate the bytes).
        let ca_content = b"CA CERT DATA";
        let cert_content = b"SERVER CERT DATA";
        let key_content = b"SERVER KEY DATA";

        let ca_path = dir.join("ca.crt");
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");

        std::fs::write(&ca_path, ca_content).unwrap();
        std::fs::write(&cert_path, cert_content).unwrap();
        std::fs::write(&key_path, key_content).unwrap();

        let config = AuthConfig::load(&ca_path, &cert_path, &key_path)
            .expect("AuthConfig::load should succeed when all files exist");

        assert_eq!(config.ca_cert, ca_content, "ca_cert bytes mismatch");
        assert_eq!(config.server_cert, cert_content, "server_cert bytes mismatch");
        assert_eq!(config.server_key, key_content, "server_key bytes mismatch");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // test_auth_config_load_missing_file
    // -----------------------------------------------------------------------

    /// AuthConfig::load() returns an Err when the CA file does not exist.
    #[test]
    fn test_auth_config_load_missing_file() {
        let dir = make_temp_dir("missing");

        let missing = dir.join("nonexistent.crt");
        let dummy = dir.join("dummy.crt");
        std::fs::write(&dummy, b"data").unwrap();

        // Missing CA cert
        let result = AuthConfig::load(&missing, &dummy, &dummy);
        assert!(
            result.is_err(),
            "expected Err when CA cert file is missing, got Ok"
        );

        // Missing server cert
        let result = AuthConfig::load(&dummy, &missing, &dummy);
        assert!(
            result.is_err(),
            "expected Err when server cert file is missing, got Ok"
        );

        // Missing server key
        let result = AuthConfig::load(&dummy, &dummy, &missing);
        assert!(
            result.is_err(),
            "expected Err when server key file is missing, got Ok"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // test_server_tls_config
    // -----------------------------------------------------------------------

    /// server_tls_config() builds a ServerTlsConfig without error when given
    /// valid PEM-encoded certificates.
    #[test]
    fn test_server_tls_config() {
        let dir = make_temp_dir("tlscfg");
        let (cert_pem, key_pem) = gen_self_signed_pem("kraken-server", &dir);

        // For the CA cert we reuse the self-signed cert itself — the config
        // builder only checks that the bytes parse as PEM, not chain validity.
        let config = AuthConfig {
            ca_cert: cert_pem.clone(),
            server_cert: cert_pem,
            server_key: key_pem,
        };

        let result = config.server_tls_config();
        assert!(
            result.is_ok(),
            "server_tls_config() should succeed with valid PEM: {:?}",
            result.err()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // test_cert_identity_from_cert
    // -----------------------------------------------------------------------

    /// CertIdentity::from_cert() extracts the CN and a non-empty SHA-256
    /// fingerprint from a valid DER-encoded certificate.
    #[test]
    fn test_cert_identity_from_cert() {
        let dir = make_temp_dir("identity");
        let expected_cn = "alice";
        let (cert_pem, _key_pem) = gen_self_signed_pem(expected_cn, &dir);
        let cert_der = pem_to_der(&cert_pem, &dir);

        let identity = CertIdentity::from_cert(&cert_der)
            .expect("from_cert should return Some for a valid DER certificate");

        assert_eq!(
            identity.username, expected_cn,
            "username should match the certificate CN"
        );

        // Fingerprint must be a 64-character lowercase hex string (SHA-256).
        assert_eq!(
            identity.cert_fingerprint.len(),
            64,
            "fingerprint should be 64 hex chars (SHA-256)"
        );
        assert!(
            identity.cert_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint should contain only hex digits"
        );

        // Fingerprint must be deterministic: calling again yields identical result.
        let identity2 = CertIdentity::from_cert(&cert_der).unwrap();
        assert_eq!(
            identity.cert_fingerprint, identity2.cert_fingerprint,
            "fingerprint must be deterministic"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // test_cert_identity_invalid_cert
    // -----------------------------------------------------------------------

    /// CertIdentity::from_cert() returns None for malformed/garbage input.
    #[test]
    fn test_cert_identity_invalid_cert() {
        // Completely empty slice
        assert!(
            CertIdentity::from_cert(&[]).is_none(),
            "empty bytes should return None"
        );

        // Random garbage bytes
        let garbage: Vec<u8> = (0..128).map(|i| (i * 7 + 13) as u8).collect();
        assert!(
            CertIdentity::from_cert(&garbage).is_none(),
            "garbage bytes should return None"
        );

        // A PEM string (not DER) — from_cert expects DER, not PEM
        let fake_pem = b"-----BEGIN CERTIFICATE-----\nZmFrZQo=\n-----END CERTIFICATE-----\n";
        assert!(
            CertIdentity::from_cert(fake_pem).is_none(),
            "raw PEM (not DER) should return None"
        );
    }
}
