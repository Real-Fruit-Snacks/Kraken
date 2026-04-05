//! Kraken Distributed - Multi-server coordination for Kraken C2
//!
//! This crate provides distributed deployment capabilities including:
//! - Node registration and health monitoring
//! - State synchronization across nodes
//! - Automatic failover handling

pub mod controller;
pub mod error;
pub mod node;
pub mod raft;
pub mod sync;

pub use controller::{Controller, ControllerConfig};
pub use error::DistributedError;
pub use node::{NodeId, NodeInfo, NodeMetrics, NodeStatus, NodeType};
pub use sync::{StateChange, SyncEntry};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_controller_register_node() {
        let controller = Controller::new(ControllerConfig::default());
        let node_id = NodeId::new();
        let info = NodeInfo::new(node_id, NodeType::Listener, "127.0.0.1:8080".to_string());

        controller.register_node(info).await.unwrap();

        let retrieved = controller.get_node(node_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().node_type, NodeType::Listener);
    }

    #[tokio::test]
    async fn test_controller_heartbeat() {
        let controller = Controller::new(ControllerConfig::default());
        let node_id = NodeId::new();
        let info = NodeInfo::new(node_id, NodeType::Teamserver, "127.0.0.1:9000".to_string());

        controller.register_node(info).await.unwrap();

        let metrics = NodeMetrics {
            cpu_percent: 50.0,
            memory_percent: 60.0,
            active_connections: 5,
            tasks_processed: 100,
        };

        controller.heartbeat(node_id, Some(metrics)).await.unwrap();

        let node = controller.get_node(node_id).await.unwrap();
        assert_eq!(node.metrics.cpu_percent, 50.0);
    }

    #[tokio::test]
    async fn test_node_status_transitions() {
        let config = ControllerConfig {
            unhealthy_threshold_secs: 1,
            offline_threshold_secs: 2,
            ..Default::default()
        };
        let controller = Controller::new(config);
        let node_id = NodeId::new();
        let info = NodeInfo::new(node_id, NodeType::Listener, "127.0.0.1:8080".to_string());

        controller.register_node(info).await.unwrap();

        // Initially healthy
        let status = controller.check_node_health(node_id).await;
        assert_eq!(status, Some(NodeStatus::Healthy));

        // Wait for unhealthy threshold
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let status = controller.check_node_health(node_id).await;
        assert!(matches!(status, Some(NodeStatus::Unhealthy | NodeStatus::Offline)));
    }

    #[tokio::test]
    async fn test_list_nodes_by_type() {
        let controller = Controller::new(ControllerConfig::default());

        let listener1 = NodeInfo::new(NodeId::new(), NodeType::Listener, "127.0.0.1:8080".to_string());
        let listener2 = NodeInfo::new(NodeId::new(), NodeType::Listener, "127.0.0.1:8081".to_string());
        let teamserver = NodeInfo::new(NodeId::new(), NodeType::Teamserver, "127.0.0.1:9000".to_string());

        controller.register_node(listener1).await.unwrap();
        controller.register_node(listener2).await.unwrap();
        controller.register_node(teamserver).await.unwrap();

        let listeners = controller.list_nodes_by_type(NodeType::Listener).await;
        assert_eq!(listeners.len(), 2);

        let teamservers = controller.list_nodes_by_type(NodeType::Teamserver).await;
        assert_eq!(teamservers.len(), 1);
    }

    #[tokio::test]
    async fn test_replicate_state_change() {
        let controller = Controller::new(ControllerConfig::default());

        let change = StateChange::SessionRegistered {
            session_id: uuid::Uuid::new_v4(),
            data: serde_json::json!({"hostname": "test-host"}),
        };

        let result = controller.replicate(change).await;
        assert!(result.is_ok());
    }
}
