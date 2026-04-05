use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::error::DistributedError;
use crate::node::{NodeId, NodeInfo, NodeMetrics, NodeStatus, NodeType};
use crate::raft::RaftNode;
use crate::sync::{StateChange, SyncEntry};

/// Configuration for the controller
#[derive(Debug, Clone)]
pub struct ControllerConfig {
    /// Address to bind gRPC server
    pub bind_address: String,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Unhealthy threshold (seconds since last heartbeat)
    pub unhealthy_threshold_secs: i64,
    /// Offline threshold (seconds since last heartbeat)
    pub offline_threshold_secs: i64,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:9090".to_string(),
            health_check_interval: Duration::from_secs(10),
            unhealthy_threshold_secs: 30,
            offline_threshold_secs: 60,
        }
    }
}

/// Central controller for distributed Kraken deployment
pub struct Controller {
    nodes: Arc<RwLock<HashMap<NodeId, NodeInfo>>>,
    config: ControllerConfig,
    raft: Arc<RwLock<RaftNode>>,
}

impl Controller {
    /// Create a new controller
    pub fn new(config: ControllerConfig) -> Self {
        let node_id = NodeId::new();
        let mut raft = RaftNode::new(node_id, vec![]);
        // Single-node cluster: become leader immediately
        raft.become_leader();

        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            config,
            raft: Arc::new(RwLock::new(raft)),
        }
    }

    /// Register a new node
    pub async fn register_node(&self, info: NodeInfo) -> Result<(), DistributedError> {
        let mut nodes = self.nodes.write().await;
        tracing::info!(
            node_id = ?info.id,
            node_type = ?info.node_type,
            address = %info.address,
            "Registering node"
        );
        nodes.insert(info.id, info);
        Ok(())
    }

    /// Remove a node
    pub async fn unregister_node(&self, id: NodeId) -> Result<(), DistributedError> {
        let mut nodes = self.nodes.write().await;
        if nodes.remove(&id).is_some() {
            tracing::info!(node_id = ?id, "Unregistered node");
            Ok(())
        } else {
            Err(DistributedError::NodeNotFound(format!("{:?}", id)))
        }
    }

    /// Update node heartbeat
    pub async fn heartbeat(&self, id: NodeId, metrics: Option<NodeMetrics>) -> Result<(), DistributedError> {
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(&id)
            .ok_or_else(|| DistributedError::NodeNotFound(format!("{:?}", id)))?;

        if let Some(m) = metrics {
            node.update_metrics(m);
        } else {
            node.heartbeat();
        }

        Ok(())
    }

    /// Get node info
    pub async fn get_node(&self, id: NodeId) -> Option<NodeInfo> {
        self.nodes.read().await.get(&id).cloned()
    }

    /// List all nodes
    pub async fn list_nodes(&self) -> Vec<NodeInfo> {
        self.nodes.read().await.values().cloned().collect()
    }

    /// List nodes of a specific type
    pub async fn list_nodes_by_type(&self, node_type: NodeType) -> Vec<NodeInfo> {
        self.nodes
            .read()
            .await
            .values()
            .filter(|n| n.node_type == node_type)
            .cloned()
            .collect()
    }

    /// List healthy nodes
    pub async fn list_healthy_nodes(&self) -> Vec<NodeInfo> {
        self.nodes
            .read()
            .await
            .values()
            .filter(|n| n.status == NodeStatus::Healthy)
            .cloned()
            .collect()
    }

    /// Check and update node health status
    pub async fn check_node_health(&self, id: NodeId) -> Option<NodeStatus> {
        let mut nodes = self.nodes.write().await;
        let node = nodes.get_mut(&id)?;

        let age = chrono::Utc::now() - node.last_heartbeat;
        let new_status = if age > chrono::Duration::seconds(self.config.offline_threshold_secs) {
            NodeStatus::Offline
        } else if age > chrono::Duration::seconds(self.config.unhealthy_threshold_secs) {
            NodeStatus::Unhealthy
        } else if node.metrics.cpu_percent > 90.0 || node.metrics.memory_percent > 90.0 {
            NodeStatus::Degraded
        } else {
            NodeStatus::Healthy
        };

        if node.status != new_status {
            tracing::warn!(
                node_id = ?id,
                old_status = ?node.status,
                new_status = ?new_status,
                "Node status changed"
            );
            node.status = new_status;
        }

        Some(new_status)
    }

    /// Run health check on all nodes
    pub async fn health_check_all(&self) {
        let node_ids: Vec<NodeId> = self.nodes.read().await.keys().copied().collect();

        for id in node_ids {
            if let Some(status) = self.check_node_health(id).await {
                if status == NodeStatus::Unhealthy || status == NodeStatus::Offline {
                    self.trigger_failover(id).await;
                }
            }
        }
    }

    /// Trigger failover for a failed node
    async fn trigger_failover(&self, failed_node: NodeId) {
        let nodes = self.nodes.read().await;
        let failed = match nodes.get(&failed_node) {
            Some(n) => n.clone(),
            None => return,
        };
        drop(nodes);

        tracing::warn!(
            node_id = ?failed_node,
            node_type = ?failed.node_type,
            "Triggering failover"
        );

        match failed.node_type {
            NodeType::Listener => {
                // Find healthy listener to take over
                let nodes = self.nodes.read().await;
                let replacement = nodes
                    .values()
                    .filter(|n| n.node_type == NodeType::Listener)
                    .filter(|n| n.status == NodeStatus::Healthy)
                    .filter(|n| n.id != failed_node)
                    .min_by_key(|n| n.metrics.active_connections);

                if let Some(new_listener) = replacement {
                    tracing::info!(
                        from = ?failed_node,
                        to = ?new_listener.id,
                        "Migrating sessions to new listener"
                    );
                    // In a real implementation, would migrate sessions here
                }
            }
            NodeType::Teamserver => {
                tracing::info!(
                    node_id = ?failed_node,
                    "Teamserver failed - operators should reconnect"
                );
                // In a real implementation, would broadcast reconnect notification
            }
            NodeType::Database => {
                tracing::error!(
                    node_id = ?failed_node,
                    "Database node failed - manual intervention may be required"
                );
                // In a real implementation, would trigger database failover
            }
        }
    }

    /// Replicate a state change
    pub async fn replicate(&self, change: StateChange) -> Result<(), DistributedError> {
        let mut raft = self.raft.write().await;
        let entry = SyncEntry::new(change, raft.current_term());
        raft.propose(entry).await
    }

    /// Start the health check loop
    pub async fn start_health_check_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.health_check_interval);

        loop {
            interval.tick().await;
            self.health_check_all().await;
        }
    }
}
