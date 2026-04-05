//! Database models

use common::{ImplantId, ImplantState, ListenerId, OperatorId, TaskId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImplantRecord {
    pub id: ImplantId,
    pub name: String,
    pub state: ImplantState,
    // System info
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_arch: Option<String>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub is_elevated: bool,
    pub integrity_level: Option<String>,
    pub local_ips: Vec<String>,
    // Config
    pub checkin_interval: i32,
    pub jitter_percent: i32,
    pub symmetric_key: Option<Vec<u8>>,
    pub nonce_counter: i64,
    pub registered_at: i64,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ImplantUpdate {
    pub state: Option<ImplantState>,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os_name: Option<String>,
    pub checkin_interval: Option<i32>,
    pub jitter_percent: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: TaskId,
    pub implant_id: ImplantId,
    pub operator_id: OperatorId,
    pub task_type: String,
    pub task_data: Vec<u8>,
    pub status: String,
    pub issued_at: i64,
    pub dispatched_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub result_data: Option<Vec<u8>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerRecord {
    pub id: ListenerId,
    pub listener_type: String,
    pub bind_host: String,
    pub bind_port: i32,
    pub is_running: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub operator_id: Option<OperatorId>,
    pub implant_id: Option<ImplantId>,
    pub action: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub id: String,
    pub platform: String,
    pub version: String,
    pub name: String,
    pub description: Option<String>,
    pub hash: Vec<u8>,
    pub size: i64,
    pub blob: Vec<u8>,
    pub compiled_at: i64,
    pub created_at: i64,
}

impl AuditEntry {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp_millis(),
            operator_id: None,
            implant_id: None,
            action: action.into(),
            details: None,
        }
    }
}

/// Database record for an operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRecord {
    pub id: uuid::Uuid,
    pub username: String,
    pub role: String,
    pub cert_fingerprint: String,
    pub created_at: i64,
    pub last_seen: Option<i64>,
    pub is_active: bool,
}

impl OperatorRecord {
    /// Convert to RBAC OperatorIdentity
    pub fn to_identity(
        &self,
        allowed_sessions: Option<std::collections::HashSet<uuid::Uuid>>,
        allowed_listeners: Option<std::collections::HashSet<uuid::Uuid>>,
    ) -> Result<kraken_rbac::OperatorIdentity, kraken_rbac::RbacError> {
        let role: kraken_rbac::Role = self.role.parse()?;
        Ok(kraken_rbac::OperatorIdentity {
            id: self.id,
            username: self.username.clone(),
            role,
            cert_fingerprint: self.cert_fingerprint.clone(),
            allowed_sessions,
            allowed_listeners,
            created_at: chrono::DateTime::from_timestamp_millis(self.created_at)
                .unwrap_or_default(),
            last_seen: self.last_seen.and_then(chrono::DateTime::from_timestamp_millis),
            disabled: !self.is_active,
        })
    }
}

/// Parameters for creating a new operator
#[derive(Debug, Clone)]
pub struct NewOperator {
    pub username: String,
    pub role: kraken_rbac::Role,
    pub cert_fingerprint: String,
}

/// Parameters for updating an operator
#[derive(Debug, Clone, Default)]
pub struct OperatorUpdate {
    pub role: Option<kraken_rbac::Role>,
    pub is_active: Option<bool>,
}

/// Database record for a chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessageRecord {
    pub id: uuid::Uuid,
    pub from_operator_id: uuid::Uuid,
    pub from_username: String,
    pub message: String,
    pub session_id: Option<uuid::Uuid>,
    pub created_at: i64,
}
