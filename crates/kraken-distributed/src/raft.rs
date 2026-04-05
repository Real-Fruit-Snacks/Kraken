//! Raft consensus implementation for distributed Kraken deployment
//!
//! Implements the Raft consensus protocol for:
//! - Leader election with randomized timeouts
//! - Log replication across cluster nodes
//! - Term-based consistency guarantees
//!
//! Reference: <https://raft.github.io/raft.pdf>

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;

use crate::error::DistributedError;
use crate::node::NodeId;
use crate::sync::SyncEntry;

/// Election timeout range (randomized to prevent split votes)
const ELECTION_TIMEOUT_MIN_MS: u64 = 150;
const ELECTION_TIMEOUT_MAX_MS: u64 = 300;

/// Heartbeat interval (must be << election timeout)
const HEARTBEAT_INTERVAL_MS: u64 = 50;

/// Raft node state (role in the cluster)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

/// Log entry stored in the Raft log
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Term when entry was received by leader
    pub term: u64,
    /// Index in the log (1-based)
    pub index: u64,
    /// The actual state change
    pub entry: SyncEntry,
}

/// RequestVote RPC request
#[derive(Debug, Clone)]
pub struct RequestVoteRequest {
    /// Candidate's term
    pub term: u64,
    /// Candidate requesting vote
    pub candidate_id: NodeId,
    /// Index of candidate's last log entry
    pub last_log_index: u64,
    /// Term of candidate's last log entry
    pub last_log_term: u64,
}

/// RequestVote RPC response
#[derive(Debug, Clone)]
pub struct RequestVoteResponse {
    /// Current term, for candidate to update itself
    pub term: u64,
    /// True means candidate received vote
    pub vote_granted: bool,
}

/// AppendEntries RPC request (also used for heartbeats)
#[derive(Debug, Clone)]
pub struct AppendEntriesRequest {
    /// Leader's term
    pub term: u64,
    /// Leader's ID for followers to redirect clients
    pub leader_id: NodeId,
    /// Index of log entry immediately preceding new ones
    pub prev_log_index: u64,
    /// Term of prev_log_index entry
    pub prev_log_term: u64,
    /// Log entries to store (empty for heartbeat)
    pub entries: Vec<LogEntry>,
    /// Leader's commit index
    pub leader_commit: u64,
}

/// AppendEntries RPC response
#[derive(Debug, Clone)]
pub struct AppendEntriesResponse {
    /// Current term, for leader to update itself
    pub term: u64,
    /// True if follower contained entry matching prev_log_index/term
    pub success: bool,
    /// Hint for leader to decrement next_index (optimization)
    pub match_index: Option<u64>,
}

/// RPC message types for Raft communication
#[derive(Debug, Clone)]
pub enum RaftMessage {
    RequestVote(RequestVoteRequest),
    RequestVoteResponse(RequestVoteResponse),
    AppendEntries(AppendEntriesRequest),
    AppendEntriesResponse(AppendEntriesResponse),
}

/// Callback for applying committed entries to the state machine
pub type ApplyCallback = Box<dyn Fn(SyncEntry) + Send + Sync>;

/// Callback for sending RPC to a peer
pub type RpcCallback = Box<dyn Fn(NodeId, RaftMessage) -> bool + Send + Sync>;

/// Persistent state on all servers (must survive restarts)
#[derive(Debug, Clone)]
struct PersistentState {
    /// Latest term server has seen
    current_term: u64,
    /// Candidate that received vote in current term
    voted_for: Option<NodeId>,
    /// Log entries
    log: Vec<LogEntry>,
}

/// Volatile state on all servers
#[derive(Debug)]
struct VolatileState {
    /// Index of highest log entry known to be committed
    commit_index: u64,
    /// Index of highest log entry applied to state machine
    last_applied: u64,
}

/// Volatile state on leaders (reinitialized after election)
#[derive(Debug)]
struct LeaderState {
    /// For each server, index of next log entry to send
    next_index: HashMap<NodeId, u64>,
    /// For each server, index of highest log entry known to be replicated
    match_index: HashMap<NodeId, u64>,
}

/// Raft consensus node
pub struct RaftNode {
    /// This node's ID
    id: NodeId,
    /// Current role
    role: RaftRole,
    /// Peer node IDs
    peers: Vec<NodeId>,
    /// Persistent state
    persistent: PersistentState,
    /// Volatile state
    volatile: VolatileState,
    /// Leader-only state
    leader_state: Option<LeaderState>,
    /// Last time we heard from a leader (or granted a vote)
    last_heartbeat: Instant,
    /// Current leader (if known)
    current_leader: Option<NodeId>,
    /// Votes received in current election
    votes_received: HashMap<NodeId, bool>,
    /// Callback to apply committed entries
    apply_callback: Option<ApplyCallback>,
    /// Callback to send RPCs
    rpc_callback: Option<RpcCallback>,
}

impl RaftNode {
    /// Create a new Raft node
    pub fn new(id: NodeId, peers: Vec<NodeId>) -> Self {
        Self {
            id,
            role: RaftRole::Follower,
            peers,
            persistent: PersistentState {
                current_term: 0,
                voted_for: None,
                log: Vec::new(),
            },
            volatile: VolatileState {
                commit_index: 0,
                last_applied: 0,
            },
            leader_state: None,
            last_heartbeat: Instant::now(),
            current_leader: None,
            votes_received: HashMap::new(),
            apply_callback: None,
            rpc_callback: None,
        }
    }

    /// Set the callback for applying committed entries
    pub fn set_apply_callback(&mut self, callback: ApplyCallback) {
        self.apply_callback = Some(callback);
    }

    /// Set the callback for sending RPCs
    pub fn set_rpc_callback(&mut self, callback: RpcCallback) {
        self.rpc_callback = Some(callback);
    }

    /// Get current term
    pub fn current_term(&self) -> u64 {
        self.persistent.current_term
    }

    /// Check if this node is the leader
    pub fn is_leader(&self) -> bool {
        self.role == RaftRole::Leader
    }

    /// Get current leader (if known)
    pub fn leader(&self) -> Option<NodeId> {
        if self.is_leader() {
            Some(self.id)
        } else {
            self.current_leader
        }
    }

    /// Get the last log index
    fn last_log_index(&self) -> u64 {
        self.persistent.log.last().map(|e| e.index).unwrap_or(0)
    }

    /// Get the last log term
    fn last_log_term(&self) -> u64 {
        self.persistent.log.last().map(|e| e.term).unwrap_or(0)
    }

    /// Get log entry at index (1-based)
    fn log_at(&self, index: u64) -> Option<&LogEntry> {
        if index == 0 || index as usize > self.persistent.log.len() {
            None
        } else {
            self.persistent.log.get((index - 1) as usize)
        }
    }

    /// Get term at log index (0 if index is 0 or doesn't exist)
    fn term_at(&self, index: u64) -> u64 {
        self.log_at(index).map(|e| e.term).unwrap_or(0)
    }

    /// Generate randomized election timeout
    fn random_election_timeout() -> Duration {
        use rand::Rng;
        let ms = rand::thread_rng().gen_range(ELECTION_TIMEOUT_MIN_MS..=ELECTION_TIMEOUT_MAX_MS);
        Duration::from_millis(ms)
    }

    /// Check if election timeout has elapsed
    pub fn election_timeout_elapsed(&self) -> bool {
        self.last_heartbeat.elapsed() > Self::random_election_timeout()
    }

    /// Become leader (for single-node mode or after winning election)
    pub fn become_leader(&mut self) {
        self.role = RaftRole::Leader;
        self.current_leader = Some(self.id);

        // Initialize leader state
        let next_idx = self.last_log_index() + 1;
        let mut leader_state = LeaderState {
            next_index: HashMap::new(),
            match_index: HashMap::new(),
        };
        for peer in &self.peers {
            leader_state.next_index.insert(*peer, next_idx);
            leader_state.match_index.insert(*peer, 0);
        }
        self.leader_state = Some(leader_state);

        tracing::info!(
            node_id = ?self.id,
            term = self.persistent.current_term,
            "Became leader"
        );
    }

    /// Step down to follower
    fn step_down(&mut self, term: u64) {
        self.persistent.current_term = term;
        self.role = RaftRole::Follower;
        self.persistent.voted_for = None;
        self.leader_state = None;
        self.votes_received.clear();
    }

    /// Start an election
    pub fn start_election(&mut self) {
        self.persistent.current_term += 1;
        self.role = RaftRole::Candidate;
        self.persistent.voted_for = Some(self.id);
        self.votes_received.clear();
        self.votes_received.insert(self.id, true); // Vote for self
        self.last_heartbeat = Instant::now();

        tracing::info!(
            node_id = ?self.id,
            term = self.persistent.current_term,
            "Starting election"
        );

        // Single-node cluster: become leader immediately
        if self.peers.is_empty() {
            self.become_leader();
            return;
        }

        // Send RequestVote to all peers
        let request = RequestVoteRequest {
            term: self.persistent.current_term,
            candidate_id: self.id,
            last_log_index: self.last_log_index(),
            last_log_term: self.last_log_term(),
        };

        if let Some(ref rpc) = self.rpc_callback {
            for peer in &self.peers {
                rpc(*peer, RaftMessage::RequestVote(request.clone()));
            }
        }
    }

    /// Handle incoming RequestVote RPC
    pub fn handle_request_vote(&mut self, req: RequestVoteRequest) -> RequestVoteResponse {
        // If term is stale, reject
        if req.term < self.persistent.current_term {
            return RequestVoteResponse {
                term: self.persistent.current_term,
                vote_granted: false,
            };
        }

        // If newer term, step down
        if req.term > self.persistent.current_term {
            self.step_down(req.term);
        }

        // Grant vote if we haven't voted yet (or voted for this candidate)
        // AND candidate's log is at least as up-to-date as ours
        let can_vote = self.persistent.voted_for.is_none()
            || self.persistent.voted_for == Some(req.candidate_id);

        let log_ok = req.last_log_term > self.last_log_term()
            || (req.last_log_term == self.last_log_term()
                && req.last_log_index >= self.last_log_index());

        let vote_granted = can_vote && log_ok;

        if vote_granted {
            self.persistent.voted_for = Some(req.candidate_id);
            self.last_heartbeat = Instant::now();
            tracing::debug!(
                node_id = ?self.id,
                candidate = ?req.candidate_id,
                term = req.term,
                "Granted vote"
            );
        }

        RequestVoteResponse {
            term: self.persistent.current_term,
            vote_granted,
        }
    }

    /// Handle incoming RequestVote response
    pub fn handle_request_vote_response(&mut self, from: NodeId, resp: RequestVoteResponse) {
        // Ignore if we're not a candidate or term doesn't match
        if self.role != RaftRole::Candidate || resp.term != self.persistent.current_term {
            if resp.term > self.persistent.current_term {
                self.step_down(resp.term);
            }
            return;
        }

        self.votes_received.insert(from, resp.vote_granted);

        // Count votes
        let votes: usize = self.votes_received.values().filter(|&&v| v).count();
        let majority = (self.peers.len() + 1) / 2 + 1;

        if votes >= majority {
            self.become_leader();
        }
    }

    /// Handle incoming AppendEntries RPC
    pub fn handle_append_entries(&mut self, req: AppendEntriesRequest) -> AppendEntriesResponse {
        // If term is stale, reject
        if req.term < self.persistent.current_term {
            return AppendEntriesResponse {
                term: self.persistent.current_term,
                success: false,
                match_index: None,
            };
        }

        // Valid leader contact - reset election timer
        self.last_heartbeat = Instant::now();
        self.current_leader = Some(req.leader_id);

        // If newer term, step down
        if req.term > self.persistent.current_term {
            self.step_down(req.term);
        }

        // If we were a candidate, step down
        if self.role == RaftRole::Candidate {
            self.role = RaftRole::Follower;
            self.votes_received.clear();
        }

        // Check log consistency
        if req.prev_log_index > 0 {
            let prev_term = self.term_at(req.prev_log_index);
            if prev_term != req.prev_log_term {
                // Log doesn't contain entry at prev_log_index with prev_log_term
                return AppendEntriesResponse {
                    term: self.persistent.current_term,
                    success: false,
                    match_index: Some(self.last_log_index()),
                };
            }
        }

        // Append new entries (truncate conflicting entries first)
        for entry in req.entries {
            let idx = entry.index as usize;
            if idx <= self.persistent.log.len() {
                // Check for conflict
                if let Some(existing) = self.persistent.log.get(idx - 1) {
                    if existing.term != entry.term {
                        // Truncate from here
                        self.persistent.log.truncate(idx - 1);
                    }
                }
            }
            // Append if not already present
            if entry.index as usize > self.persistent.log.len() {
                self.persistent.log.push(entry);
            }
        }

        // Update commit index
        if req.leader_commit > self.volatile.commit_index {
            self.volatile.commit_index = std::cmp::min(
                req.leader_commit,
                self.last_log_index(),
            );
        }

        // Apply committed entries
        self.apply_committed();

        AppendEntriesResponse {
            term: self.persistent.current_term,
            success: true,
            match_index: Some(self.last_log_index()),
        }
    }

    /// Handle incoming AppendEntries response (leader only)
    pub fn handle_append_entries_response(&mut self, from: NodeId, resp: AppendEntriesResponse) {
        if resp.term > self.persistent.current_term {
            self.step_down(resp.term);
            return;
        }

        if self.role != RaftRole::Leader {
            return;
        }

        let leader_state = match &mut self.leader_state {
            Some(s) => s,
            None => return,
        };

        if resp.success {
            if let Some(match_idx) = resp.match_index {
                leader_state.match_index.insert(from, match_idx);
                leader_state.next_index.insert(from, match_idx + 1);
            }
            // Try to advance commit index
            self.try_advance_commit();
        } else {
            // Decrement next_index and retry
            if let Some(next) = leader_state.next_index.get_mut(&from) {
                if let Some(hint) = resp.match_index {
                    *next = hint + 1;
                } else if *next > 1 {
                    *next -= 1;
                }
            }
        }
    }

    /// Try to advance commit index based on majority
    fn try_advance_commit(&mut self) {
        if self.role != RaftRole::Leader {
            return;
        }

        let leader_state = match &self.leader_state {
            Some(s) => s,
            None => return,
        };

        // Find the highest index replicated on a majority
        for n in (self.volatile.commit_index + 1)..=self.last_log_index() {
            if self.term_at(n) != self.persistent.current_term {
                continue; // Only commit entries from current term
            }

            let mut replicated = 1; // Count self
            for match_idx in leader_state.match_index.values() {
                if *match_idx >= n {
                    replicated += 1;
                }
            }

            let majority = (self.peers.len() + 1) / 2 + 1;
            if replicated >= majority {
                self.volatile.commit_index = n;
            }
        }

        self.apply_committed();
    }

    /// Apply committed entries to the state machine
    fn apply_committed(&mut self) {
        while self.volatile.last_applied < self.volatile.commit_index {
            self.volatile.last_applied += 1;
            if let Some(entry) = self.log_at(self.volatile.last_applied) {
                tracing::debug!(
                    index = entry.index,
                    term = entry.term,
                    "Applying committed entry"
                );
                if let Some(ref callback) = self.apply_callback {
                    callback(entry.entry.clone());
                }
            }
        }
    }

    /// Propose an entry to be replicated (leader only)
    pub async fn propose(&mut self, entry: SyncEntry) -> Result<(), DistributedError> {
        if !self.is_leader() {
            return Err(DistributedError::ConsensusError(
                "Not the leader".to_string(),
            ));
        }

        let log_entry = LogEntry {
            term: self.persistent.current_term,
            index: self.last_log_index() + 1,
            entry,
        };

        tracing::debug!(
            index = log_entry.index,
            term = log_entry.term,
            "Proposing entry"
        );

        self.persistent.log.push(log_entry.clone());

        // Single-node cluster: commit immediately
        if self.peers.is_empty() {
            self.volatile.commit_index = log_entry.index;
            self.apply_committed();
            return Ok(());
        }

        // Send AppendEntries to all peers
        self.send_append_entries();

        Ok(())
    }

    /// Send AppendEntries to all peers (leader only)
    pub fn send_append_entries(&self) {
        if self.role != RaftRole::Leader {
            return;
        }

        let leader_state = match &self.leader_state {
            Some(s) => s,
            None => return,
        };

        if let Some(ref rpc) = self.rpc_callback {
            for peer in &self.peers {
                let next_idx = *leader_state.next_index.get(peer).unwrap_or(&1);
                let prev_idx = if next_idx > 0 { next_idx - 1 } else { 0 };

                let entries: Vec<LogEntry> = self.persistent.log
                    .iter()
                    .filter(|e| e.index >= next_idx)
                    .cloned()
                    .collect();

                let request = AppendEntriesRequest {
                    term: self.persistent.current_term,
                    leader_id: self.id,
                    prev_log_index: prev_idx,
                    prev_log_term: self.term_at(prev_idx),
                    entries,
                    leader_commit: self.volatile.commit_index,
                };

                rpc(*peer, RaftMessage::AppendEntries(request));
            }
        }
    }

    /// Send heartbeats (empty AppendEntries)
    pub fn send_heartbeats(&self) {
        if self.role != RaftRole::Leader {
            return;
        }

        let leader_state = match &self.leader_state {
            Some(s) => s,
            None => return,
        };

        if let Some(ref rpc) = self.rpc_callback {
            for peer in &self.peers {
                let next_idx = *leader_state.next_index.get(peer).unwrap_or(&1);
                let prev_idx = if next_idx > 0 { next_idx - 1 } else { 0 };

                let request = AppendEntriesRequest {
                    term: self.persistent.current_term,
                    leader_id: self.id,
                    prev_log_index: prev_idx,
                    prev_log_term: self.term_at(prev_idx),
                    entries: vec![], // Empty for heartbeat
                    leader_commit: self.volatile.commit_index,
                };

                rpc(*peer, RaftMessage::AppendEntries(request));
            }
        }
    }

    /// Handle an incoming RPC message
    pub fn handle_message(&mut self, from: NodeId, msg: RaftMessage) -> Option<RaftMessage> {
        match msg {
            RaftMessage::RequestVote(req) => {
                Some(RaftMessage::RequestVoteResponse(self.handle_request_vote(req)))
            }
            RaftMessage::RequestVoteResponse(resp) => {
                self.handle_request_vote_response(from, resp);
                None
            }
            RaftMessage::AppendEntries(req) => {
                Some(RaftMessage::AppendEntriesResponse(self.handle_append_entries(req)))
            }
            RaftMessage::AppendEntriesResponse(resp) => {
                self.handle_append_entries_response(from, resp);
                None
            }
        }
    }

    /// Periodic tick - should be called regularly
    pub fn tick(&mut self) {
        match self.role {
            RaftRole::Follower | RaftRole::Candidate => {
                if self.election_timeout_elapsed() {
                    self.start_election();
                }
            }
            RaftRole::Leader => {
                self.send_heartbeats();
            }
        }
    }
}

/// Thread-safe wrapper for RaftNode
pub struct RaftHandle {
    inner: Arc<RwLock<RaftNode>>,
}

impl RaftHandle {
    pub fn new(id: NodeId, peers: Vec<NodeId>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RaftNode::new(id, peers))),
        }
    }

    /// Start the Raft background task
    pub fn start(&self, mut shutdown: mpsc::Receiver<()>) -> tokio::task::JoinHandle<()> {
        let inner = Arc::clone(&self.inner);

        tokio::spawn(async move {
            let mut tick_interval = interval(Duration::from_millis(HEARTBEAT_INTERVAL_MS));

            loop {
                tokio::select! {
                    _ = tick_interval.tick() => {
                        let mut node = inner.write().await;
                        node.tick();
                    }
                    _ = shutdown.recv() => {
                        tracing::info!("Raft node shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Propose an entry
    pub async fn propose(&self, entry: SyncEntry) -> Result<(), DistributedError> {
        let mut node = self.inner.write().await;
        node.propose(entry).await
    }

    /// Check if this node is the leader
    pub async fn is_leader(&self) -> bool {
        let node = self.inner.read().await;
        node.is_leader()
    }

    /// Get current term
    pub async fn current_term(&self) -> u64 {
        let node = self.inner.read().await;
        node.current_term()
    }

    /// Handle incoming message
    pub async fn handle_message(&self, from: NodeId, msg: RaftMessage) -> Option<RaftMessage> {
        let mut node = self.inner.write().await;
        node.handle_message(from, msg)
    }

    /// Force become leader (for single-node mode)
    pub async fn become_leader(&self) {
        let mut node = self.inner.write().await;
        node.become_leader();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_node_id() -> NodeId {
        NodeId::from_uuid(Uuid::new_v4())
    }

    fn make_sync_entry(term: u64) -> SyncEntry {
        use crate::sync::StateChange;
        SyncEntry::new(
            StateChange::SessionRegistered {
                session_id: Uuid::new_v4(),
                data: serde_json::json!({}),
            },
            term,
        )
    }

    #[test]
    fn test_single_node_becomes_leader() {
        let id = make_node_id();
        let mut node = RaftNode::new(id, vec![]);

        assert_eq!(node.role, RaftRole::Follower);
        node.start_election();
        assert_eq!(node.role, RaftRole::Leader);
    }

    #[tokio::test]
    async fn test_single_node_propose() {
        let id = make_node_id();
        let mut node = RaftNode::new(id, vec![]);
        node.become_leader();

        let entry = make_sync_entry(1);
        let result = node.propose(entry).await;
        assert!(result.is_ok());
        assert_eq!(node.volatile.commit_index, 1);
    }

    #[test]
    fn test_request_vote_granted() {
        let id1 = make_node_id();
        let id2 = make_node_id();
        let mut node = RaftNode::new(id1, vec![id2]);

        let request = RequestVoteRequest {
            term: 1,
            candidate_id: id2,
            last_log_index: 0,
            last_log_term: 0,
        };

        let response = node.handle_request_vote(request);
        assert!(response.vote_granted);
        assert_eq!(node.persistent.voted_for, Some(id2));
    }

    #[test]
    fn test_request_vote_rejected_stale_term() {
        let id1 = make_node_id();
        let id2 = make_node_id();
        let mut node = RaftNode::new(id1, vec![id2]);
        node.persistent.current_term = 5;

        let request = RequestVoteRequest {
            term: 3, // Stale term
            candidate_id: id2,
            last_log_index: 0,
            last_log_term: 0,
        };

        let response = node.handle_request_vote(request);
        assert!(!response.vote_granted);
        assert_eq!(response.term, 5);
    }

    #[test]
    fn test_append_entries_heartbeat() {
        let id1 = make_node_id();
        let id2 = make_node_id();
        let mut node = RaftNode::new(id1, vec![id2]);

        let request = AppendEntriesRequest {
            term: 1,
            leader_id: id2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };

        let response = node.handle_append_entries(request);
        assert!(response.success);
        assert_eq!(node.current_leader, Some(id2));
    }

    #[test]
    fn test_append_entries_with_entries() {
        let id1 = make_node_id();
        let id2 = make_node_id();
        let mut node = RaftNode::new(id1, vec![id2]);

        let entry = LogEntry {
            term: 1,
            index: 1,
            entry: make_sync_entry(1),
        };

        let request = AppendEntriesRequest {
            term: 1,
            leader_id: id2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![entry],
            leader_commit: 1,
        };

        let response = node.handle_append_entries(request);
        assert!(response.success);
        assert_eq!(node.persistent.log.len(), 1);
        assert_eq!(node.volatile.commit_index, 1);
    }

    #[test]
    fn test_step_down_on_higher_term() {
        let id1 = make_node_id();
        let id2 = make_node_id();
        let mut node = RaftNode::new(id1, vec![id2]);
        node.become_leader();
        assert_eq!(node.role, RaftRole::Leader);

        let request = AppendEntriesRequest {
            term: 5, // Higher term
            leader_id: id2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };

        node.handle_append_entries(request);
        assert_eq!(node.role, RaftRole::Follower);
        assert_eq!(node.persistent.current_term, 5);
    }

    #[tokio::test]
    async fn test_raft_handle() {
        let id = make_node_id();
        let handle = RaftHandle::new(id, vec![]);

        handle.become_leader().await;
        assert!(handle.is_leader().await);

        let entry = make_sync_entry(1);
        let result = handle.propose(entry).await;
        assert!(result.is_ok());
    }
}
