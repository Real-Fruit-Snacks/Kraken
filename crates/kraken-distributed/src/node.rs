use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a node in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(Uuid);

impl NodeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of node in the distributed system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Handles operator connections
    Teamserver,
    /// Handles implant traffic
    Listener,
    /// Shared state storage
    Database,
}

/// Current health status of a node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is functioning normally
    Healthy,
    /// Node is under high load
    Degraded,
    /// Node has not responded recently
    Unhealthy,
    /// Node is not reachable
    Offline,
}

/// Performance metrics for a node
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub active_connections: u32,
    pub tasks_processed: u64,
}

/// Complete information about a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub node_type: NodeType,
    pub address: String,
    pub status: NodeStatus,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub metrics: NodeMetrics,
}

impl NodeInfo {
    pub fn new(id: NodeId, node_type: NodeType, address: String) -> Self {
        Self {
            id,
            node_type,
            address,
            status: NodeStatus::Healthy,
            last_heartbeat: chrono::Utc::now(),
            metrics: NodeMetrics::default(),
        }
    }

    /// Update heartbeat timestamp
    pub fn heartbeat(&mut self) {
        self.last_heartbeat = chrono::Utc::now();
    }

    /// Update metrics
    pub fn update_metrics(&mut self, metrics: NodeMetrics) {
        self.metrics = metrics;
        self.heartbeat();
    }
}
