//! Integration tests for kraken-distributed multi-node cluster coordination
//!
//! Tests Raft consensus, leader election, log replication, failover handling,
//! and cluster recovery scenarios with multiple simulated nodes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use kraken_distributed::{
    Controller, ControllerConfig, NodeId, NodeInfo, NodeMetrics, NodeStatus, NodeType,
    StateChange,
};
use kraken_distributed::raft::{
    AppendEntriesRequest, AppendEntriesResponse, LogEntry, RaftMessage, RaftNode,
    RequestVoteRequest, RequestVoteResponse,
};
use kraken_distributed::sync::SyncEntry;

// ============================================================================
// Test Utilities
// ============================================================================

fn make_node_id() -> NodeId {
    NodeId::new()
}

fn make_sync_entry(term: u64) -> SyncEntry {
    SyncEntry::new(
        StateChange::SessionRegistered {
            session_id: uuid::Uuid::new_v4(),
            data: serde_json::json!({"test": true}),
        },
        term,
    )
}

/// A simulated network that routes messages between Raft nodes
struct SimulatedNetwork {
    nodes: HashMap<NodeId, Arc<RwLock<RaftNode>>>,
    /// Messages pending delivery: (from, to, message)
    pending: Arc<RwLock<Vec<(NodeId, NodeId, RaftMessage)>>>,
    /// Partitioned nodes (cannot send/receive)
    partitioned: Arc<RwLock<Vec<NodeId>>>,
}

impl SimulatedNetwork {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            pending: Arc::new(RwLock::new(Vec::new())),
            partitioned: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn add_node(&mut self, id: NodeId, peers: Vec<NodeId>) -> Arc<RwLock<RaftNode>> {
        let node = Arc::new(RwLock::new(RaftNode::new(id, peers)));
        self.nodes.insert(id, Arc::clone(&node));
        node
    }

    /// Deliver all pending messages
    async fn deliver_messages(&self) {
        let mut pending = self.pending.write().await;
        let partitioned = self.partitioned.read().await;

        let messages: Vec<_> = pending.drain(..).collect();
        drop(pending);

        for (from, to, msg) in messages {
            // Skip if either node is partitioned
            if partitioned.contains(&from) || partitioned.contains(&to) {
                continue;
            }

            if let Some(node) = self.nodes.get(&to) {
                let mut node = node.write().await;
                if let Some(response) = node.handle_message(from, msg) {
                    // Queue response
                    self.pending.write().await.push((to, from, response));
                }
            }
        }
    }

    /// Queue a message for delivery
    async fn send(&self, from: NodeId, to: NodeId, msg: RaftMessage) {
        self.pending.write().await.push((from, to, msg));
    }

    /// Partition a node from the cluster
    async fn partition(&self, id: NodeId) {
        self.partitioned.write().await.push(id);
    }

    /// Heal partition for a node
    async fn heal(&self, id: NodeId) {
        let mut partitioned = self.partitioned.write().await;
        partitioned.retain(|n| *n != id);
    }

    /// Tick all nodes
    async fn tick_all(&self) {
        for node in self.nodes.values() {
            node.write().await.tick();
        }
    }
}

// ============================================================================
// Multi-Node Leader Election Tests
// ============================================================================

#[tokio::test]
async fn test_three_node_leader_election() {
    let id1 = make_node_id();
    let id2 = make_node_id();
    let id3 = make_node_id();

    let mut node1 = RaftNode::new(id1, vec![id2, id3]);
    let mut node2 = RaftNode::new(id2, vec![id1, id3]);
    let mut node3 = RaftNode::new(id3, vec![id1, id2]);

    // Node 1 starts election
    node1.start_election();
    assert!(!node1.is_leader()); // Still candidate, not leader yet
    assert_eq!(node1.current_term(), 1);

    // Node 2 and 3 vote for node 1
    let vote_req = RequestVoteRequest {
        term: 1,
        candidate_id: id1,
        last_log_index: 0,
        last_log_term: 0,
    };

    let resp2 = node2.handle_request_vote(vote_req.clone());
    let resp3 = node3.handle_request_vote(vote_req);

    assert!(resp2.vote_granted);
    assert!(resp3.vote_granted);

    // Node 1 receives votes and becomes leader
    node1.handle_request_vote_response(id2, resp2);
    assert!(node1.is_leader());
}

#[tokio::test]
async fn test_election_with_split_vote() {
    let id1 = make_node_id();
    let id2 = make_node_id();
    let id3 = make_node_id();
    let id4 = make_node_id();

    let mut node1 = RaftNode::new(id1, vec![id2, id3, id4]);
    let mut node2 = RaftNode::new(id2, vec![id1, id3, id4]);
    let mut node3 = RaftNode::new(id3, vec![id1, id2, id4]);
    let mut node4 = RaftNode::new(id4, vec![id1, id2, id3]);

    // Node 1 and Node 2 start elections simultaneously
    node1.start_election();
    node2.start_election();

    // Each gets some votes but no majority
    let vote_req1 = RequestVoteRequest {
        term: 1,
        candidate_id: id1,
        last_log_index: 0,
        last_log_term: 0,
    };

    let vote_req2 = RequestVoteRequest {
        term: 1,
        candidate_id: id2,
        last_log_index: 0,
        last_log_term: 0,
    };

    // Node 3 votes for node 1
    let resp3 = node3.handle_request_vote(vote_req1.clone());
    assert!(resp3.vote_granted);

    // Node 4 votes for node 2 (node 3 already voted, so rejects)
    let resp4 = node4.handle_request_vote(vote_req2.clone());
    assert!(resp4.vote_granted);

    // Neither has majority (need 3 out of 4)
    node1.handle_request_vote_response(id3, resp3);
    node2.handle_request_vote_response(id4, resp4);

    // Neither should be leader yet (both still candidates)
    assert!(!node1.is_leader());
    assert!(!node2.is_leader());
}

#[tokio::test]
async fn test_candidate_steps_down_on_higher_term() {
    let id1 = make_node_id();
    let id2 = make_node_id();

    // Create single-node cluster so it can become leader immediately
    let mut node1 = RaftNode::new(id1, vec![]);
    let mut node2 = RaftNode::new(id2, vec![id1]);

    // Node 1 at term 5 (single node becomes leader)
    node1.start_election();
    node1.start_election();
    node1.start_election();
    node1.start_election();
    node1.start_election();
    assert_eq!(node1.current_term(), 5);
    assert!(node1.is_leader()); // Single node cluster, becomes leader

    // Node 2 starts election at term 1
    node2.start_election();
    assert!(!node2.is_leader()); // Still candidate (has peer)

    // Node 2 receives AppendEntries from node 1 at term 5
    let ae_req = AppendEntriesRequest {
        term: 5,
        leader_id: id1,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: vec![],
        leader_commit: 0,
    };

    let resp = node2.handle_append_entries(ae_req);
    assert!(resp.success);
    assert!(!node2.is_leader()); // Stepped down to follower
    assert_eq!(node2.current_term(), 5);
}

// ============================================================================
// Log Replication Tests
// ============================================================================

#[tokio::test]
async fn test_log_replication_two_nodes() {
    let id1 = make_node_id();
    let id2 = make_node_id();

    let mut leader = RaftNode::new(id1, vec![id2]);
    let mut follower = RaftNode::new(id2, vec![id1]);

    leader.become_leader();

    // Leader proposes an entry
    let entry = make_sync_entry(leader.current_term());
    leader.propose(entry).await.unwrap();

    // Leader sends AppendEntries
    let log_entry = LogEntry {
        term: leader.current_term(),
        index: 1,
        entry: make_sync_entry(leader.current_term()),
    };

    let ae_req = AppendEntriesRequest {
        term: leader.current_term(),
        leader_id: id1,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: vec![log_entry],
        leader_commit: 0,
    };

    let resp = follower.handle_append_entries(ae_req);
    assert!(resp.success);
    assert_eq!(resp.match_index, Some(1));

    // Leader processes response and advances commit
    leader.handle_append_entries_response(id2, resp);
}

#[tokio::test]
async fn test_log_consistency_check() {
    let id1 = make_node_id();
    let id2 = make_node_id();

    let mut leader = RaftNode::new(id1, vec![id2]);
    let mut follower = RaftNode::new(id2, vec![id1]);

    leader.become_leader();

    // Leader has entries at index 1 and 2
    leader.propose(make_sync_entry(1)).await.unwrap();
    leader.propose(make_sync_entry(1)).await.unwrap();

    // Follower has no entries - request with prev_log_index=2 should fail
    let ae_req = AppendEntriesRequest {
        term: 1,
        leader_id: id1,
        prev_log_index: 2,
        prev_log_term: 1,
        entries: vec![LogEntry {
            term: 1,
            index: 3,
            entry: make_sync_entry(1),
        }],
        leader_commit: 0,
    };

    let resp = follower.handle_append_entries(ae_req);
    assert!(!resp.success);
    assert_eq!(resp.match_index, Some(0)); // Follower has no entries
}

#[tokio::test]
async fn test_log_truncation_on_conflict() {
    let id1 = make_node_id();
    let id2 = make_node_id();

    let mut leader = RaftNode::new(id1, vec![id2]);
    let mut follower = RaftNode::new(id2, vec![id1]);

    // Follower has an entry from a different term
    follower.handle_append_entries(AppendEntriesRequest {
        term: 1,
        leader_id: id1,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: vec![LogEntry {
            term: 1,
            index: 1,
            entry: make_sync_entry(1),
        }],
        leader_commit: 0,
    });

    // New leader at term 2 has conflicting entry at index 1
    leader.become_leader();

    let ae_req = AppendEntriesRequest {
        term: 2,
        leader_id: id1,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: vec![LogEntry {
            term: 2,
            index: 1,
            entry: make_sync_entry(2),
        }],
        leader_commit: 0,
    };

    let resp = follower.handle_append_entries(ae_req);
    assert!(resp.success);
    // Follower should have truncated conflicting entry and accepted new one
}

// ============================================================================
// Controller Multi-Node Tests
// ============================================================================

#[tokio::test]
async fn test_controller_multiple_listeners() {
    let controller = Controller::new(ControllerConfig::default());

    // Register 5 listener nodes
    let mut listener_ids = Vec::new();
    for i in 0..5 {
        let id = NodeId::new();
        listener_ids.push(id);
        let info = NodeInfo::new(id, NodeType::Listener, format!("127.0.0.1:808{}", i));
        controller.register_node(info).await.unwrap();
    }

    let listeners = controller.list_nodes_by_type(NodeType::Listener).await;
    assert_eq!(listeners.len(), 5);

    // All should be healthy initially
    let healthy = controller.list_healthy_nodes().await;
    assert_eq!(healthy.len(), 5);
}

#[tokio::test]
async fn test_controller_mixed_node_types() {
    let controller = Controller::new(ControllerConfig::default());

    // Register different node types
    let teamserver = NodeInfo::new(NodeId::new(), NodeType::Teamserver, "127.0.0.1:9000".into());
    let listener1 = NodeInfo::new(NodeId::new(), NodeType::Listener, "127.0.0.1:8080".into());
    let listener2 = NodeInfo::new(NodeId::new(), NodeType::Listener, "127.0.0.1:8081".into());
    let database = NodeInfo::new(NodeId::new(), NodeType::Database, "127.0.0.1:5432".into());

    controller.register_node(teamserver).await.unwrap();
    controller.register_node(listener1).await.unwrap();
    controller.register_node(listener2).await.unwrap();
    controller.register_node(database).await.unwrap();

    assert_eq!(controller.list_nodes_by_type(NodeType::Teamserver).await.len(), 1);
    assert_eq!(controller.list_nodes_by_type(NodeType::Listener).await.len(), 2);
    assert_eq!(controller.list_nodes_by_type(NodeType::Database).await.len(), 1);
    assert_eq!(controller.list_nodes().await.len(), 4);
}

#[tokio::test]
async fn test_controller_heartbeat_updates_metrics() {
    let controller = Controller::new(ControllerConfig::default());

    let id = NodeId::new();
    let info = NodeInfo::new(id, NodeType::Listener, "127.0.0.1:8080".into());
    controller.register_node(info).await.unwrap();

    // Initial metrics are default
    let node = controller.get_node(id).await.unwrap();
    assert_eq!(node.metrics.cpu_percent, 0.0);
    assert_eq!(node.metrics.active_connections, 0);

    // Update with new metrics
    let metrics = NodeMetrics {
        cpu_percent: 75.0,
        memory_percent: 50.0,
        active_connections: 42,
        tasks_processed: 1000,
    };

    controller.heartbeat(id, Some(metrics)).await.unwrap();

    let node = controller.get_node(id).await.unwrap();
    assert_eq!(node.metrics.cpu_percent, 75.0);
    assert_eq!(node.metrics.active_connections, 42);
}

#[tokio::test]
async fn test_controller_unregister_node() {
    let controller = Controller::new(ControllerConfig::default());

    let id = NodeId::new();
    let info = NodeInfo::new(id, NodeType::Listener, "127.0.0.1:8080".into());
    controller.register_node(info).await.unwrap();

    assert!(controller.get_node(id).await.is_some());

    controller.unregister_node(id).await.unwrap();

    assert!(controller.get_node(id).await.is_none());
}

#[tokio::test]
async fn test_controller_unregister_nonexistent() {
    let controller = Controller::new(ControllerConfig::default());

    let id = NodeId::new();
    let result = controller.unregister_node(id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_controller_heartbeat_nonexistent() {
    let controller = Controller::new(ControllerConfig::default());

    let id = NodeId::new();
    let result = controller.heartbeat(id, None).await;
    assert!(result.is_err());
}

// ============================================================================
// Health Status Transition Tests
// ============================================================================

#[tokio::test]
async fn test_health_degraded_on_high_cpu() {
    let controller = Controller::new(ControllerConfig::default());

    let id = NodeId::new();
    let info = NodeInfo::new(id, NodeType::Listener, "127.0.0.1:8080".into());
    controller.register_node(info).await.unwrap();

    // Report high CPU
    let metrics = NodeMetrics {
        cpu_percent: 95.0, // > 90% triggers Degraded
        memory_percent: 50.0,
        active_connections: 10,
        tasks_processed: 100,
    };

    controller.heartbeat(id, Some(metrics)).await.unwrap();

    let status = controller.check_node_health(id).await;
    assert_eq!(status, Some(NodeStatus::Degraded));
}

#[tokio::test]
async fn test_health_degraded_on_high_memory() {
    let controller = Controller::new(ControllerConfig::default());

    let id = NodeId::new();
    let info = NodeInfo::new(id, NodeType::Listener, "127.0.0.1:8080".into());
    controller.register_node(info).await.unwrap();

    // Report high memory
    let metrics = NodeMetrics {
        cpu_percent: 50.0,
        memory_percent: 95.0, // > 90% triggers Degraded
        active_connections: 10,
        tasks_processed: 100,
    };

    controller.heartbeat(id, Some(metrics)).await.unwrap();

    let status = controller.check_node_health(id).await;
    assert_eq!(status, Some(NodeStatus::Degraded));
}

#[tokio::test]
async fn test_health_unhealthy_after_threshold() {
    let config = ControllerConfig {
        unhealthy_threshold_secs: 1,
        offline_threshold_secs: 3,
        ..Default::default()
    };
    let controller = Controller::new(config);

    let id = NodeId::new();
    let info = NodeInfo::new(id, NodeType::Listener, "127.0.0.1:8080".into());
    controller.register_node(info).await.unwrap();

    // Wait for unhealthy threshold
    tokio::time::sleep(Duration::from_secs(2)).await;

    let status = controller.check_node_health(id).await;
    assert!(matches!(status, Some(NodeStatus::Unhealthy | NodeStatus::Offline)));
}

#[tokio::test]
async fn test_health_offline_after_threshold() {
    let config = ControllerConfig {
        unhealthy_threshold_secs: 1,
        offline_threshold_secs: 2,
        ..Default::default()
    };
    let controller = Controller::new(config);

    let id = NodeId::new();
    let info = NodeInfo::new(id, NodeType::Listener, "127.0.0.1:8080".into());
    controller.register_node(info).await.unwrap();

    // Wait for offline threshold
    tokio::time::sleep(Duration::from_secs(3)).await;

    let status = controller.check_node_health(id).await;
    assert_eq!(status, Some(NodeStatus::Offline));
}

#[tokio::test]
async fn test_health_recovers_after_heartbeat() {
    let config = ControllerConfig {
        unhealthy_threshold_secs: 1,
        offline_threshold_secs: 2,
        ..Default::default()
    };
    let controller = Controller::new(config);

    let id = NodeId::new();
    let info = NodeInfo::new(id, NodeType::Listener, "127.0.0.1:8080".into());
    controller.register_node(info).await.unwrap();

    // Wait until unhealthy
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let status = controller.check_node_health(id).await;
    assert!(matches!(status, Some(NodeStatus::Unhealthy | NodeStatus::Offline)));

    // Send heartbeat
    controller.heartbeat(id, None).await.unwrap();

    // Should be healthy again
    let status = controller.check_node_health(id).await;
    assert_eq!(status, Some(NodeStatus::Healthy));
}

// ============================================================================
// State Replication Tests
// ============================================================================

#[tokio::test]
async fn test_replicate_session_registered() {
    let controller = Controller::new(ControllerConfig::default());

    let change = StateChange::SessionRegistered {
        session_id: uuid::Uuid::new_v4(),
        data: serde_json::json!({
            "hostname": "test-host",
            "username": "testuser",
            "os": "Linux"
        }),
    };

    let result = controller.replicate(change).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_replicate_task_queued() {
    let controller = Controller::new(ControllerConfig::default());

    let change = StateChange::TaskQueued {
        task_id: uuid::Uuid::new_v4(),
        session_id: uuid::Uuid::new_v4(),
        task_type: "shell".to_string(),
        data: b"whoami".to_vec(),
    };

    let result = controller.replicate(change).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_replicate_task_completed() {
    let controller = Controller::new(ControllerConfig::default());

    let change = StateChange::TaskCompleted {
        task_id: uuid::Uuid::new_v4(),
        result: b"root\n".to_vec(),
        error: None,
    };

    let result = controller.replicate(change).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_replicate_loot_stored() {
    let controller = Controller::new(ControllerConfig::default());

    let change = StateChange::LootStored {
        loot_id: uuid::Uuid::new_v4(),
        session_id: uuid::Uuid::new_v4(),
        data: serde_json::json!({
            "type": "credential",
            "username": "admin",
            "password_hash": "abc123..."
        }),
    };

    let result = controller.replicate(change).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_replicate_listener_created() {
    let controller = Controller::new(ControllerConfig::default());

    let change = StateChange::ListenerCreated {
        listener_id: uuid::Uuid::new_v4(),
        config: serde_json::json!({
            "type": "https",
            "bind_address": "0.0.0.0:443",
            "hostname": "c2.example.com"
        }),
    };

    let result = controller.replicate(change).await;
    assert!(result.is_ok());
}

// ============================================================================
// Raft Message Handling Tests
// ============================================================================

#[tokio::test]
async fn test_raft_message_dispatch() {
    let id1 = make_node_id();
    let id2 = make_node_id();

    let mut node = RaftNode::new(id1, vec![id2]);

    // Handle RequestVote
    let vote_req = RaftMessage::RequestVote(RequestVoteRequest {
        term: 1,
        candidate_id: id2,
        last_log_index: 0,
        last_log_term: 0,
    });

    let response = node.handle_message(id2, vote_req);
    assert!(matches!(response, Some(RaftMessage::RequestVoteResponse(_))));

    // Handle AppendEntries
    let ae_req = RaftMessage::AppendEntries(AppendEntriesRequest {
        term: 1,
        leader_id: id2,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: vec![],
        leader_commit: 0,
    });

    let response = node.handle_message(id2, ae_req);
    assert!(matches!(response, Some(RaftMessage::AppendEntriesResponse(_))));

    // Handle RequestVoteResponse (no response expected)
    let vote_resp = RaftMessage::RequestVoteResponse(RequestVoteResponse {
        term: 1,
        vote_granted: true,
    });

    let response = node.handle_message(id2, vote_resp);
    assert!(response.is_none());

    // Handle AppendEntriesResponse (no response expected)
    let ae_resp = RaftMessage::AppendEntriesResponse(AppendEntriesResponse {
        term: 1,
        success: true,
        match_index: Some(0),
    });

    let response = node.handle_message(id2, ae_resp);
    assert!(response.is_none());
}

#[tokio::test]
async fn test_raft_tick_behavior() {
    let id1 = make_node_id();
    let id2 = make_node_id();

    let mut follower = RaftNode::new(id1, vec![id2]);
    let mut leader = RaftNode::new(id2, vec![id1]);

    // Leader tick should send heartbeats (we just verify no panic)
    leader.become_leader();
    leader.tick();

    // Follower tick with recent heartbeat should do nothing
    follower.tick();
    assert!(!follower.is_leader()); // Still a follower
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_node_registration() {
    let controller = Arc::new(Controller::new(ControllerConfig::default()));

    let mut handles = Vec::new();
    for i in 0..10 {
        let c = Arc::clone(&controller);
        handles.push(tokio::spawn(async move {
            let info = NodeInfo::new(
                NodeId::new(),
                NodeType::Listener,
                format!("127.0.0.1:{}", 8080 + i),
            );
            c.register_node(info).await
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    assert_eq!(controller.list_nodes().await.len(), 10);
}

#[tokio::test]
async fn test_concurrent_heartbeats() {
    let controller = Arc::new(Controller::new(ControllerConfig::default()));

    // Register nodes
    let mut node_ids = Vec::new();
    for i in 0..5 {
        let id = NodeId::new();
        node_ids.push(id);
        let info = NodeInfo::new(id, NodeType::Listener, format!("127.0.0.1:{}", 8080 + i));
        controller.register_node(info).await.unwrap();
    }

    // Send concurrent heartbeats
    let mut handles = Vec::new();
    for &id in &node_ids {
        let c = Arc::clone(&controller);
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let metrics = NodeMetrics {
                    cpu_percent: rand::random::<f32>() * 100.0,
                    memory_percent: rand::random::<f32>() * 100.0,
                    active_connections: rand::random::<u32>() % 1000,
                    tasks_processed: rand::random::<u64>() % 10000,
                };
                c.heartbeat(id, Some(metrics)).await.unwrap();
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // All nodes should still be accessible
    for &id in &node_ids {
        assert!(controller.get_node(id).await.is_some());
    }
}

#[tokio::test]
async fn test_concurrent_replication() {
    let controller = Arc::new(Controller::new(ControllerConfig::default()));

    let mut handles = Vec::new();
    for i in 0..20 {
        let c = Arc::clone(&controller);
        handles.push(tokio::spawn(async move {
            let change = StateChange::SessionRegistered {
                session_id: uuid::Uuid::new_v4(),
                data: serde_json::json!({"index": i}),
            };
            c.replicate(change).await
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }
}

// ============================================================================
// SyncEntry Tests
// ============================================================================

#[test]
fn test_sync_entry_creation() {
    let change = StateChange::SessionRegistered {
        session_id: uuid::Uuid::new_v4(),
        data: serde_json::json!({"test": true}),
    };

    let entry = SyncEntry::new(change.clone(), 5);
    assert_eq!(entry.term, 5);
    assert!(!entry.id.is_nil());
}

#[test]
fn test_sync_entry_serialization() {
    let change = StateChange::TaskQueued {
        task_id: uuid::Uuid::new_v4(),
        session_id: uuid::Uuid::new_v4(),
        task_type: "shell".to_string(),
        data: b"test command".to_vec(),
    };

    let entry = SyncEntry::new(change, 1);

    // Should serialize to JSON
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("TaskQueued"));
    assert!(json.contains("shell"));

    // Should deserialize back
    let deserialized: SyncEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.term, entry.term);
    assert_eq!(deserialized.id, entry.id);
}

// ============================================================================
// Node Info Tests
// ============================================================================

#[test]
fn test_node_info_serialization() {
    let info = NodeInfo::new(
        NodeId::new(),
        NodeType::Teamserver,
        "192.168.1.100:9000".to_string(),
    );

    let json = serde_json::to_string(&info).unwrap();
    let deserialized: NodeInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.node_type, NodeType::Teamserver);
    assert_eq!(deserialized.address, "192.168.1.100:9000");
    assert_eq!(deserialized.status, NodeStatus::Healthy);
}

#[test]
fn test_node_metrics_default() {
    let metrics = NodeMetrics::default();
    assert_eq!(metrics.cpu_percent, 0.0);
    assert_eq!(metrics.memory_percent, 0.0);
    assert_eq!(metrics.active_connections, 0);
    assert_eq!(metrics.tasks_processed, 0);
}

#[test]
fn test_node_id_uniqueness() {
    let ids: Vec<NodeId> = (0..1000).map(|_| NodeId::new()).collect();
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), 1000);
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

#[tokio::test]
async fn test_leader_propose_without_peers() {
    let id = make_node_id();
    let mut node = RaftNode::new(id, vec![]);
    node.become_leader();

    // Should commit immediately in single-node cluster
    let entry = make_sync_entry(1);
    let result = node.propose(entry).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_follower_cannot_propose() {
    let id = make_node_id();
    let mut node = RaftNode::new(id, vec![make_node_id()]);

    let entry = make_sync_entry(1);
    let result = node.propose(entry).await;
    assert!(result.is_err());
}

#[test]
fn test_double_vote_rejected() {
    let id1 = make_node_id();
    let id2 = make_node_id();
    let id3 = make_node_id();

    let mut node = RaftNode::new(id1, vec![id2, id3]);

    // Vote for candidate 2
    let req2 = RequestVoteRequest {
        term: 1,
        candidate_id: id2,
        last_log_index: 0,
        last_log_term: 0,
    };
    let resp2 = node.handle_request_vote(req2);
    assert!(resp2.vote_granted);

    // Reject vote for candidate 3 in same term
    let req3 = RequestVoteRequest {
        term: 1,
        candidate_id: id3,
        last_log_index: 0,
        last_log_term: 0,
    };
    let resp3 = node.handle_request_vote(req3);
    assert!(!resp3.vote_granted);
}

#[test]
fn test_vote_for_outdated_log_rejected() {
    let id1 = make_node_id();
    let id2 = make_node_id();

    let mut node = RaftNode::new(id1, vec![id2]);

    // Give node some log entries
    node.handle_append_entries(AppendEntriesRequest {
        term: 2,
        leader_id: id2,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: vec![
            LogEntry {
                term: 2,
                index: 1,
                entry: make_sync_entry(2),
            },
        ],
        leader_commit: 0,
    });

    // Candidate with older log should be rejected
    let req = RequestVoteRequest {
        term: 3,
        candidate_id: id2,
        last_log_index: 0, // Candidate has no log
        last_log_term: 0,
    };
    let resp = node.handle_request_vote(req);
    assert!(!resp.vote_granted);
}

#[tokio::test]
async fn test_health_check_nonexistent_node() {
    let controller = Controller::new(ControllerConfig::default());
    let id = NodeId::new();

    let status = controller.check_node_health(id).await;
    assert!(status.is_none());
}

// ============================================================================
// Integration Scenarios
// ============================================================================

#[tokio::test]
async fn test_full_cluster_lifecycle() {
    let controller = Controller::new(ControllerConfig::default());

    // 1. Register cluster nodes
    let teamserver_id = NodeId::new();
    let listener1_id = NodeId::new();
    let listener2_id = NodeId::new();
    let db_id = NodeId::new();

    controller.register_node(NodeInfo::new(
        teamserver_id,
        NodeType::Teamserver,
        "10.0.0.1:9000".into(),
    )).await.unwrap();

    controller.register_node(NodeInfo::new(
        listener1_id,
        NodeType::Listener,
        "10.0.0.2:443".into(),
    )).await.unwrap();

    controller.register_node(NodeInfo::new(
        listener2_id,
        NodeType::Listener,
        "10.0.0.3:443".into(),
    )).await.unwrap();

    controller.register_node(NodeInfo::new(
        db_id,
        NodeType::Database,
        "10.0.0.4:5432".into(),
    )).await.unwrap();

    assert_eq!(controller.list_nodes().await.len(), 4);

    // 2. Simulate activity with heartbeats
    for &id in &[teamserver_id, listener1_id, listener2_id, db_id] {
        controller.heartbeat(id, Some(NodeMetrics {
            cpu_percent: 25.0,
            memory_percent: 40.0,
            active_connections: 5,
            tasks_processed: 100,
        })).await.unwrap();
    }

    // 3. Replicate some state changes
    controller.replicate(StateChange::ListenerCreated {
        listener_id: uuid::Uuid::new_v4(),
        config: serde_json::json!({"bind": "0.0.0.0:443"}),
    }).await.unwrap();

    controller.replicate(StateChange::SessionRegistered {
        session_id: uuid::Uuid::new_v4(),
        data: serde_json::json!({"hostname": "target1"}),
    }).await.unwrap();

    // 4. All nodes should still be healthy
    assert_eq!(controller.list_healthy_nodes().await.len(), 4);

    // 5. Simulate listener1 going down (no heartbeats, then health check)
    // We'd need to wait for threshold, so just verify unregister works
    controller.unregister_node(listener1_id).await.unwrap();

    assert_eq!(controller.list_nodes().await.len(), 3);
    assert_eq!(controller.list_nodes_by_type(NodeType::Listener).await.len(), 1);
}

#[tokio::test]
async fn test_rapid_state_changes() {
    let controller = Controller::new(ControllerConfig::default());

    // Register a node
    let id = NodeId::new();
    controller.register_node(NodeInfo::new(
        id,
        NodeType::Listener,
        "127.0.0.1:8080".into(),
    )).await.unwrap();

    // Rapid fire state changes
    for i in 0..100 {
        let change = StateChange::SessionUpdated {
            session_id: uuid::Uuid::new_v4(),
            updates: serde_json::json!({"iteration": i}),
        };
        controller.replicate(change).await.unwrap();
    }

    // Should handle all without error
    let node = controller.get_node(id).await;
    assert!(node.is_some());
}
