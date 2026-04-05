use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// State changes that need to be replicated across nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateChange {
    /// New session registered
    SessionRegistered {
        session_id: Uuid,
        data: serde_json::Value,
    },
    /// Session state updated
    SessionUpdated {
        session_id: Uuid,
        updates: serde_json::Value,
    },
    /// Task queued for execution
    TaskQueued {
        task_id: Uuid,
        session_id: Uuid,
        task_type: String,
        data: Vec<u8>,
    },
    /// Task completed
    TaskCompleted {
        task_id: Uuid,
        result: Vec<u8>,
        error: Option<String>,
    },
    /// Loot stored
    LootStored {
        loot_id: Uuid,
        session_id: Uuid,
        data: serde_json::Value,
    },
    /// Listener created
    ListenerCreated {
        listener_id: Uuid,
        config: serde_json::Value,
    },
}

/// Entry in the replication log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEntry {
    pub id: Uuid,
    pub change: StateChange,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub term: u64,
}

impl SyncEntry {
    pub fn new(change: StateChange, term: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            change,
            timestamp: chrono::Utc::now(),
            term,
        }
    }
}
