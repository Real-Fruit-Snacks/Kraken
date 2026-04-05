//! TCP transport for mesh peer-to-peer links.
//!
//! Provides:
//! - `TcpServer` — binds a listening socket and accepts incoming peer connections.
//! - `TcpConnection` — framed send/recv over a `TcpStream` using a 4-byte big-endian
//!   length prefix.  Implements the `Transport` trait so it can be used directly with
//!   the handshake functions.
//! - Module-level connection registry keyed by `ImplantId`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use common::{ImplantId, KrakenError};

use crate::handshake::Transport;

// ---------------------------------------------------------------------------
// Static connection registry
// ---------------------------------------------------------------------------

static CONNECTIONS: OnceLock<RwLock<HashMap<ImplantId, TcpConnection>>> = OnceLock::new();

fn connections() -> &'static RwLock<HashMap<ImplantId, TcpConnection>> {
    CONNECTIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// TcpConnection
// ---------------------------------------------------------------------------

/// A framed TCP connection that uses a 4-byte big-endian length prefix.
pub struct TcpConnection {
    stream: TcpStream,
}

impl TcpConnection {
    /// Wrap an existing `TcpStream`.
    pub fn new(stream: TcpStream) -> Result<Self, KrakenError> {
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self { stream })
    }

    /// Send a length-prefixed message: 4-byte big-endian length followed by payload.
    pub fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
        let len = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len)?;
        self.stream.write_all(data)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive a length-prefixed message.  Rejects payloads larger than 1 MiB.
    pub fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1024 * 1024 {
            return Err(KrakenError::Transport("message too large".into()));
        }

        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

impl Transport for TcpConnection {
    fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
        TcpConnection::send(self, data)
    }

    fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
        TcpConnection::recv(self)
    }
}

// ---------------------------------------------------------------------------
// TcpServer
// ---------------------------------------------------------------------------

/// Listening TCP server that tracks accepted peer connections.
#[allow(dead_code)]
pub struct TcpServer {
    listener: TcpListener,
    connections: Arc<RwLock<HashMap<ImplantId, TcpConnection>>>,
}

impl TcpServer {
    /// Bind to `addr:port` and start listening.
    pub fn bind(addr: &str, port: u16) -> Result<Self, KrakenError> {
        let bind_addr = format!("{}:{}", addr, port);
        let listener = TcpListener::bind(&bind_addr)
            .map_err(|e| KrakenError::Transport(format!("bind failed on {}: {}", bind_addr, e)))?;
        Ok(Self {
            listener,
            connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Accept the next incoming connection (non-blocking wrapper returns `None` on
    /// `WouldBlock`).  Call repeatedly in a loop to service multiple peers.
    pub fn accept(&self) -> Result<Option<TcpStream>, KrakenError> {
        match self.listener.accept() {
            Ok((stream, _addr)) => Ok(Some(stream)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(KrakenError::Transport(format!("accept failed: {}", e))),
        }
    }

    /// Stop accepting new connections.  Existing connections are unaffected.
    pub fn stop(&self) {
        // Dropping the listener would close it; here we simply signal intent.
        // In practice, the caller drops `TcpServer` when done.
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, KrakenError> {
        self.listener.local_addr()
            .map_err(|e| KrakenError::Transport(format!("failed to get local addr: {}", e)))
    }
}

// ---------------------------------------------------------------------------
// Module-level connection helpers
// ---------------------------------------------------------------------------

/// Connect to a remote peer and return a framed `TcpConnection`.
pub fn connect(address: &str, port: u16) -> Result<TcpConnection, KrakenError> {
    let addr = format!("{}:{}", address, port);
    let socket_addr = addr
        .parse()
        .map_err(|_| KrakenError::Transport(format!("invalid address: {}", addr)))?;

    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .map_err(|e| KrakenError::Transport(format!("connect failed: {}", e)))?;

    TcpConnection::new(stream)
}

/// Store a connection in the module-level registry.
pub fn register(peer_id: ImplantId, conn: TcpConnection) {
    if let Ok(mut map) = connections().write() {
        map.insert(peer_id, conn);
    }
}

/// Send data to a previously registered peer.
pub fn send(peer_id: ImplantId, data: &[u8]) -> Result<(), KrakenError> {
    let mut map = connections()
        .write()
        .map_err(|_| KrakenError::Transport("connections lock poisoned".into()))?;

    match map.get_mut(&peer_id) {
        Some(conn) => conn.send(data),
        None => Err(KrakenError::Transport(format!(
            "no connection for peer {}",
            peer_id
        ))),
    }
}

/// Remove and drop the connection for a peer.
pub fn disconnect(peer_id: ImplantId) {
    if let Ok(mut map) = connections().write() {
        map.remove(&peer_id);
    }
}

/// Check whether a connection to `peer_id` is currently registered.
pub fn is_connected(peer_id: &ImplantId) -> bool {
    connections()
        .read()
        .map(|map| map.contains_key(peer_id))
        .unwrap_or(false)
}

/// List all currently connected peer IDs.
pub fn list_peers() -> Vec<ImplantId> {
    connections()
        .read()
        .map(|map| map.keys().copied().collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    fn loopback_pair() -> (TcpConnection, TcpConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client_handle = thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            TcpConnection::new(stream).unwrap()
        });

        let (server_stream, _) = listener.accept().unwrap();
        let server_conn = TcpConnection::new(server_stream).unwrap();
        let client_conn = client_handle.join().unwrap();

        (client_conn, server_conn)
    }

    #[test]
    fn test_send_recv_roundtrip() {
        let (mut client, mut server) = loopback_pair();

        let payload = b"hello mesh";
        client.send(payload).unwrap();
        let received = server.recv().unwrap();
        assert_eq!(received, payload);
    }

    #[test]
    fn test_empty_message() {
        let (mut client, mut server) = loopback_pair();

        client.send(&[]).unwrap();
        let received = server.recv().unwrap();
        assert!(received.is_empty());
    }

    #[test]
    fn test_multiple_messages_in_sequence() {
        let (mut client, mut server) = loopback_pair();

        for i in 0u8..5 {
            let msg = vec![i; i as usize + 1];
            client.send(&msg).unwrap();
            let received = server.recv().unwrap();
            assert_eq!(received, msg);
        }
    }

    #[test]
    fn test_server_bind_and_accept() {
        let srv = TcpServer::bind("127.0.0.1", 0).unwrap();
        let addr = srv.listener.local_addr().unwrap();

        let handle = thread::spawn(move || TcpStream::connect(addr).unwrap());

        let stream = srv.accept().unwrap();
        assert!(stream.is_some());
        handle.join().unwrap();
    }

    #[test]
    fn test_connect_helper() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            listener.accept().unwrap();
        });

        let conn = connect("127.0.0.1", port).unwrap();
        drop(conn);
        handle.join().unwrap();
    }

    #[test]
    fn test_oversized_message_rejected() {
        let (mut client, mut server) = loopback_pair();

        // Manually write a length prefix claiming 2 MiB without sending the body.
        let fake_len: u32 = 2 * 1024 * 1024;
        client.stream.write_all(&fake_len.to_be_bytes()).unwrap();
        client.stream.flush().unwrap();

        let result = server.recv();
        assert!(matches!(result, Err(KrakenError::Transport(_))));
    }

    /// Stress test: 100 clients connect simultaneously, each performs a send/recv
    /// exchange, and all must complete without errors within 30 seconds.
    #[test]
    fn test_tcp_100_concurrent_connections() {
        const NUM_CLIENTS: usize = 100;
        const TEST_TIMEOUT: Duration = Duration::from_secs(30);

        // Bind the server on a random port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener
            .set_nonblocking(false)
            .expect("set_nonblocking failed");
        let server_addr = listener.local_addr().unwrap();

        // Barrier ensures all client threads attempt to connect before any
        // proceeds, maximising concurrency pressure on the server accept loop.
        let barrier = Arc::new(Barrier::new(NUM_CLIENTS + 1));

        // Spawn client threads.
        let mut client_handles = Vec::with_capacity(NUM_CLIENTS);
        for i in 0..NUM_CLIENTS {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || -> Result<(), String> {
                // Wait until all clients (and the test thread) are ready.
                barrier.wait();

                let stream = TcpStream::connect_timeout(&server_addr, TEST_TIMEOUT)
                    .map_err(|e| format!("client {} connect: {}", i, e))?;
                let mut conn =
                    TcpConnection::new(stream).map_err(|e| format!("client {} wrap: {}", i, e))?;

                let payload = format!("ping-{}", i);
                conn.send(payload.as_bytes())
                    .map_err(|e| format!("client {} send: {}", i, e))?;

                let response = conn
                    .recv()
                    .map_err(|e| format!("client {} recv: {}", i, e))?;

                let expected = format!("pong-{}", i);
                if response != expected.as_bytes() {
                    return Err(format!(
                        "client {} got wrong response: {:?}",
                        i, response
                    ));
                }
                Ok(())
            });
            client_handles.push(handle);
        }

        // Server-side: accept NUM_CLIENTS connections and echo pong-N back.
        // Release the barrier so clients and server race together.
        barrier.wait();

        let mut server_handles = Vec::with_capacity(NUM_CLIENTS);
        for _ in 0..NUM_CLIENTS {
            let (stream, _) = listener.accept().expect("server accept failed");
            let handle = thread::spawn(move || {
                let mut conn = TcpConnection::new(stream).expect("server wrap");
                let msg = conn.recv().expect("server recv");

                // Replace "ping-" prefix with "pong-".
                let response = String::from_utf8_lossy(&msg).replace("ping-", "pong-");
                conn.send(response.as_bytes()).expect("server send");
            });
            server_handles.push(handle);
        }

        // Collect server threads — all must finish cleanly.
        for h in server_handles {
            h.join().expect("server thread panicked");
        }

        // Collect client threads — all must succeed.
        let mut errors: Vec<String> = Vec::new();
        for h in client_handles {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => errors.push(e),
                Err(_) => errors.push("client thread panicked".into()),
            }
        }

        assert!(
            errors.is_empty(),
            "{} client(s) failed:\n{}",
            errors.len(),
            errors.join("\n")
        );
    }

    /// Full-stack integration test: TCP → X25519 handshake → AES-256-GCM encryption.
    ///
    /// 1. Server binds on a random port.
    /// 2. Client thread connects via `TcpConnection`.
    /// 3. Both sides generate ephemeral keypairs and run the X25519 handshake
    ///    (`initiate_handshake` / `respond_handshake`).
    /// 4. Both wrap their connections in `EncryptedConnection`.
    /// 5. Multiple messages are exchanged in both directions.
    /// 6. Every decrypted message is verified to exactly match the original.
    #[test]
    fn test_full_stack_tcp_handshake_encrypted() {
        use crate::encrypted::EncryptedConnection;
        use crate::handshake::{initiate_handshake, respond_handshake};

        // Server binds on a random OS-assigned port.
        let server = TcpServer::bind("127.0.0.1", 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Messages the client will send to the server.
        let client_messages: Vec<&[u8]> = vec![
            b"hello from client",
            b"second client message",
            b"third client message with more data: [1,2,3,4,5]",
        ];

        // Messages the server will send back to the client.
        let server_messages: Vec<&[u8]> = vec![
            b"hello from server",
            b"server reply two",
            b"server reply three with extra payload: abcdefgh",
        ];

        // Clone message content so the thread can own them.
        let client_msgs_owned: Vec<Vec<u8>> =
            client_messages.iter().map(|m| m.to_vec()).collect();
        let server_msgs_owned: Vec<Vec<u8>> =
            server_messages.iter().map(|m| m.to_vec()).collect();

        // --- Client thread ---
        // Generates its own keypair, connects, performs the initiator half of
        // the handshake, then exercises the encrypted channel.
        let client_handle = thread::spawn(move || -> Result<(), String> {
            // Generate client ephemeral keypair.
            let client_kp = crypto::generate_keypair()
                .map_err(|e| format!("client keygen: {}", e))?;

            // Connect.
            let stream = TcpStream::connect(server_addr)
                .map_err(|e| format!("client connect: {}", e))?;
            let mut tcp_conn = TcpConnection::new(stream)
                .map_err(|e| format!("client wrap: {}", e))?;

            // Initiate handshake (sends our pubkey first, then reads peer's).
            let hs = initiate_handshake(&mut tcp_conn, &client_kp, None)
                .map_err(|e| format!("client handshake: {}", e))?;

            // Wrap in encrypted layer.
            let mut enc = EncryptedConnection::new(tcp_conn, hs.session_key, true);

            // Send all client messages.
            for msg in &client_msgs_owned {
                enc.send_encrypted(msg)
                    .map_err(|e| format!("client send: {}", e))?;
            }

            // Receive all server messages and verify.
            let mut received_from_server: Vec<Vec<u8>> = Vec::new();
            for _ in 0..server_msgs_owned.len() {
                let data = enc.recv_encrypted()
                    .map_err(|e| format!("client recv: {}", e))?;
                received_from_server.push(data);
            }

            // Verify every message matches the expected content.
            for (i, (got, want)) in received_from_server.iter().zip(server_msgs_owned.iter()).enumerate() {
                if got != want {
                    return Err(format!(
                        "client: server message {} mismatch — got {:?}, want {:?}",
                        i, got, want
                    ));
                }
            }

            Ok(())
        });

        // --- Server side (runs on the test thread) ---
        // Accept exactly one connection, generate its keypair, respond to the
        // handshake, then exercise the encrypted channel in the opposite direction.

        // Generate server ephemeral keypair.
        let server_kp = crypto::generate_keypair().unwrap();

        // Accept the client's connection.
        let server_stream = loop {
            match server.accept().unwrap() {
                Some(s) => break s,
                None => thread::yield_now(),
            }
        };
        let mut server_tcp = TcpConnection::new(server_stream).unwrap();

        // Respond to handshake (reads initiator's pubkey, then sends ours).
        let hs = respond_handshake(&mut server_tcp, &server_kp).unwrap();

        // Wrap in encrypted layer.
        let mut enc_server = EncryptedConnection::new(server_tcp, hs.session_key, false);

        // Receive all client messages and verify.
        for (i, expected) in client_messages.iter().enumerate() {
            let got = enc_server.recv_encrypted()
                .unwrap_or_else(|e| panic!("server recv message {}: {}", i, e));
            assert_eq!(
                got.as_slice(),
                *expected,
                "server: client message {} mismatch",
                i
            );
        }

        // Send all server messages.
        for msg in &server_messages {
            enc_server.send_encrypted(msg).unwrap();
        }

        // Join client thread and propagate any errors.
        match client_handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("client thread error: {}", e),
            Err(_) => panic!("client thread panicked"),
        }
    }

    /// Verify that the static CONNECTIONS registry handles many simultaneous
    /// registrations correctly: list_peers() and is_connected() must be
    /// consistent under load, and disconnect() must clean up entries.
    #[test]
    fn test_tcp_connection_pool_limits() {
        const NUM_PEERS: usize = 200;

        // Build NUM_PEERS loopback pairs and register the client side of each.
        let mut peer_ids: Vec<ImplantId> = Vec::with_capacity(NUM_PEERS);

        for _ in 0..NUM_PEERS {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();

            // Accept in a background thread so the connect below doesn't block.
            let accept_handle = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                // Keep the server-side stream alive until the handle is dropped.
                stream
            });

            let client_stream = TcpStream::connect(addr).unwrap();
            let conn = TcpConnection::new(client_stream).unwrap();

            let id = ImplantId::new();
            register(id, conn);
            peer_ids.push(id);

            // Drop the server-side stream; we only need the registry entry.
            drop(accept_handle.join().unwrap());
        }

        // Every registered ID must be visible in list_peers().
        let peers = list_peers();
        for id in &peer_ids {
            assert!(
                peers.contains(id),
                "list_peers missing registered id {}",
                id
            );
        }

        // is_connected() must return true for every registered peer.
        for id in &peer_ids {
            assert!(
                is_connected(id),
                "is_connected returned false for registered id {}",
                id
            );
        }

        // Disconnect all peers and verify removal.
        for id in &peer_ids {
            disconnect(*id);
        }

        for id in &peer_ids {
            assert!(
                !is_connected(id),
                "is_connected still true after disconnect for id {}",
                id
            );
        }

        // list_peers() must not contain any of the removed IDs.
        let remaining = list_peers();
        for id in &peer_ids {
            assert!(
                !remaining.contains(id),
                "list_peers still contains disconnected id {}",
                id
            );
        }
    }
}
