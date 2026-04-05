//! mTLS HTTPS listener for implant check-ins
//!
//! Wraps the existing Axum HTTP router in a rustls `ServerConfig` that
//! enforces mutual TLS — only implants presenting a certificate signed by the
//! operator CA are accepted.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use common::KrakenError;
use crypto::mtls::build_mtls_server_config;

/// A TCP listener wrapped with mutual-TLS enforcement.
///
/// Callers obtain a `TlsAcceptor` via [`MtlsListener::into_acceptor`] and use
/// it to upgrade raw `TcpStream`s before handing them to Axum (or any other
/// service).
pub struct MtlsListener {
    listener: TcpListener,
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
}

impl MtlsListener {
    /// Bind to `bind_addr` and configure mTLS using the supplied PEM blobs.
    ///
    /// - `server_cert` / `server_key` — PEM-encoded server leaf certificate and
    ///   PKCS#8 private key.
    /// - `ca_cert` — PEM-encoded CA certificate used to verify client (implant)
    ///   certificates.
    pub async fn new(
        bind_addr: SocketAddr,
        server_cert: &[u8],
        server_key: &[u8],
        ca_cert: &[u8],
    ) -> Result<Self, KrakenError> {
        let tls_config = build_mtls_server_config(server_cert, server_key, ca_cert)?;

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| KrakenError::Transport(format!("bind failed: {}", e)))?;

        Ok(Self {
            listener,
            tls_config: Arc::new(tls_config),
        })
    }

    /// Return the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, KrakenError> {
        self.listener
            .local_addr()
            .map_err(|e| KrakenError::Transport(format!("local_addr failed: {}", e)))
    }

    /// Consume the listener and return the underlying `TcpListener` together
    /// with a `TlsAcceptor` ready to upgrade incoming connections.
    pub fn into_parts(self) -> (TcpListener, TlsAcceptor) {
        let acceptor = TlsAcceptor::from(self.tls_config);
        (self.listener, acceptor)
    }

    /// Accept a single mTLS connection and return the upgraded stream.
    ///
    /// This is a convenience wrapper; for production use prefer
    /// `into_parts()` so you can drive an accept loop yourself.
    pub async fn accept(
        &self,
    ) -> Result<
        (
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            SocketAddr,
        ),
        KrakenError,
    > {
        let (stream, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| KrakenError::Transport(format!("accept failed: {}", e)))?;

        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| KrakenError::Transport(format!("TLS handshake failed: {}", e)))?;

        Ok((tls_stream, peer_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::mtls::{generate_ca, generate_implant_cert, generate_server_cert};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_crypto_provider() {
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Helper: generate a full CA + server cert set.
    fn make_server_pems() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (ca_cert, ca_key) = generate_ca().unwrap();
        let ca_pem = ca_cert.pem().into_bytes();
        let (server_cert_pem, server_key_pem) =
            generate_server_cert(&ca_cert, &ca_key, "localhost").unwrap();
        (server_cert_pem, server_key_pem, ca_pem)
    }

    #[tokio::test]
    async fn bind_on_random_port_succeeds() {
        init_crypto_provider();
        let (server_cert, server_key, ca_pem) = make_server_pems();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let listener = MtlsListener::new(addr, &server_cert, &server_key, &ca_pem)
            .await
            .unwrap();
        let bound = listener.local_addr().unwrap();
        // Port 0 means OS assigned a free port — it should be non-zero.
        assert_ne!(bound.port(), 0);
    }

    #[tokio::test]
    async fn into_parts_returns_acceptor() {
        init_crypto_provider();
        let (server_cert, server_key, ca_pem) = make_server_pems();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let listener = MtlsListener::new(addr, &server_cert, &server_key, &ca_pem)
            .await
            .unwrap();
        let (_tcp, _acceptor) = listener.into_parts();
        // Just verifying the types destructure without panic.
    }
}
