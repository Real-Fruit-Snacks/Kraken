//! Tamper-evident audit logging
//!
//! Provides cryptographically chained audit events using HMAC to detect
//! any tampering with the audit log. Each event includes the hash of the
//! previous event, creating a verifiable chain.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Errors that can occur during audit operations
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("chain verification failed at sequence {sequence}: expected {expected}, got {actual}")]
    ChainBroken {
        sequence: u64,
        expected: String,
        actual: String,
    },
    #[error("missing previous hash for non-genesis event")]
    MissingPreviousHash,
    #[error("invalid HMAC key")]
    InvalidKey,
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Category of audit event for filtering and analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Authentication events (login, logout, cert validation)
    Authentication,
    /// Authorization events (permission checks, access grants/denials)
    Authorization,
    /// Session management (implant registration, state changes)
    Session,
    /// Task operations (task creation, completion, results)
    Task,
    /// Listener management (start, stop, configuration)
    Listener,
    /// Loot operations (credential capture, file exfiltration)
    Loot,
    /// Module operations (load, unload, execution)
    Module,
    /// Administrative actions (config changes, user management)
    Admin,
    /// Mesh operations (peer connections, routing)
    Mesh,
    /// System events (startup, shutdown, errors)
    System,
}

/// Severity level of audit event
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    /// Informational events
    Info,
    /// Notable events that may require attention
    Warning,
    /// Security-relevant events
    Alert,
    /// Critical security events
    Critical,
}

/// Outcome of the audited action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
    Error,
}

/// A single audit event in the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: Uuid,
    /// Sequence number in the chain
    pub sequence: u64,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Event category
    pub category: AuditCategory,
    /// Event severity
    pub severity: AuditSeverity,
    /// Outcome of the action
    pub outcome: AuditOutcome,
    /// Action that was performed
    pub action: String,
    /// Operator who performed the action (if applicable)
    pub operator_id: Option<Uuid>,
    /// Operator username (for display)
    pub operator_name: Option<String>,
    /// Session/implant involved (if applicable)
    pub session_id: Option<Uuid>,
    /// Target resource identifier
    pub target: Option<String>,
    /// Additional structured details
    pub details: Option<serde_json::Value>,
    /// Source IP address
    pub source_ip: Option<String>,
    /// HMAC of previous event (hex encoded)
    pub previous_hash: Option<String>,
    /// HMAC of this event (hex encoded, computed after creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event builder
    pub fn builder(category: AuditCategory, action: impl Into<String>) -> AuditEventBuilder {
        AuditEventBuilder {
            category,
            action: action.into(),
            severity: AuditSeverity::Info,
            outcome: AuditOutcome::Success,
            operator_id: None,
            operator_name: None,
            session_id: None,
            target: None,
            details: None,
            source_ip: None,
        }
    }

    /// Compute the HMAC of this event's content
    fn compute_hash(&self, key: &[u8]) -> Result<String, AuditError> {
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|_| AuditError::InvalidKey)?;

        // Hash the deterministic content (excluding event_hash itself)
        let content = serde_json::json!({
            "id": self.id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "category": self.category,
            "severity": self.severity,
            "outcome": self.outcome,
            "action": self.action,
            "operator_id": self.operator_id,
            "operator_name": self.operator_name,
            "session_id": self.session_id,
            "target": self.target,
            "details": self.details,
            "source_ip": self.source_ip,
            "previous_hash": self.previous_hash,
        });

        let content_bytes = serde_json::to_vec(&content)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        mac.update(&content_bytes);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Verify this event's hash
    pub fn verify_hash(&self, key: &[u8]) -> Result<bool, AuditError> {
        match &self.event_hash {
            Some(stored_hash) => {
                let computed = self.compute_hash(key)?;
                Ok(stored_hash == &computed)
            }
            None => Ok(false),
        }
    }
}

/// Builder for creating audit events
pub struct AuditEventBuilder {
    category: AuditCategory,
    action: String,
    severity: AuditSeverity,
    outcome: AuditOutcome,
    operator_id: Option<Uuid>,
    operator_name: Option<String>,
    session_id: Option<Uuid>,
    target: Option<String>,
    details: Option<serde_json::Value>,
    source_ip: Option<String>,
}

impl AuditEventBuilder {
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn operator(mut self, id: Uuid, name: impl Into<String>) -> Self {
        self.operator_id = Some(id);
        self.operator_name = Some(name.into());
        self
    }

    pub fn session(mut self, id: Uuid) -> Self {
        self.session_id = Some(id);
        self
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Build the event (internal use - sequence and previous_hash set by AuditChain)
    fn build_internal(self, sequence: u64, previous_hash: Option<String>) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            sequence,
            timestamp: Utc::now(),
            category: self.category,
            severity: self.severity,
            outcome: self.outcome,
            action: self.action,
            operator_id: self.operator_id,
            operator_name: self.operator_name,
            session_id: self.session_id,
            target: self.target,
            details: self.details,
            source_ip: self.source_ip,
            previous_hash,
            event_hash: None,
        }
    }
}

/// Thread-safe audit chain manager
#[derive(Clone)]
pub struct AuditChain {
    inner: Arc<Mutex<AuditChainInner>>,
}

struct AuditChainInner {
    /// HMAC key for chain verification
    key: Vec<u8>,
    /// Current sequence number
    sequence: u64,
    /// Hash of the last event
    last_hash: Option<String>,
    /// Recent events buffer (for quick access)
    recent_events: VecDeque<AuditEvent>,
    /// Maximum events to keep in memory
    max_recent: usize,
}

impl AuditChain {
    /// Create a new audit chain with the given HMAC key
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuditChainInner {
                key: key.into(),
                sequence: 0,
                last_hash: None,
                recent_events: VecDeque::new(),
                max_recent: 1000,
            })),
        }
    }

    /// Create a new audit chain, resuming from a known state
    pub fn resume(key: impl Into<Vec<u8>>, last_sequence: u64, last_hash: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuditChainInner {
                key: key.into(),
                sequence: last_sequence,
                last_hash: Some(last_hash),
                recent_events: VecDeque::new(),
                max_recent: 1000,
            })),
        }
    }

    /// Record a new audit event
    pub fn record(&self, builder: AuditEventBuilder) -> Result<AuditEvent, AuditError> {
        let mut inner = self.inner.lock().unwrap();

        inner.sequence += 1;
        let mut event = builder.build_internal(inner.sequence, inner.last_hash.clone());

        // Compute and store the hash
        let hash = event.compute_hash(&inner.key)?;
        event.event_hash = Some(hash.clone());
        inner.last_hash = Some(hash);

        // Store in recent buffer
        inner.recent_events.push_back(event.clone());
        while inner.recent_events.len() > inner.max_recent {
            inner.recent_events.pop_front();
        }

        tracing::debug!(
            event_id = %event.id,
            sequence = event.sequence,
            category = ?event.category,
            action = %event.action,
            "audit event recorded"
        );

        Ok(event)
    }

    /// Get the current sequence number
    pub fn current_sequence(&self) -> u64 {
        self.inner.lock().unwrap().sequence
    }

    /// Get the hash of the last event
    pub fn last_hash(&self) -> Option<String> {
        self.inner.lock().unwrap().last_hash.clone()
    }

    /// Get recent events (most recent first)
    pub fn recent_events(&self, limit: usize) -> Vec<AuditEvent> {
        let inner = self.inner.lock().unwrap();
        inner
            .recent_events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Verify a sequence of events forms a valid chain
    pub fn verify_chain(&self, events: &[AuditEvent]) -> Result<(), AuditError> {
        let inner = self.inner.lock().unwrap();

        let mut expected_prev: Option<String> = None;

        for event in events {
            // Check previous hash matches
            if event.previous_hash != expected_prev {
                return Err(AuditError::ChainBroken {
                    sequence: event.sequence,
                    expected: expected_prev.unwrap_or_else(|| "(genesis)".to_string()),
                    actual: event
                        .previous_hash
                        .clone()
                        .unwrap_or_else(|| "(none)".to_string()),
                });
            }

            // Verify the event hash
            if !event.verify_hash(&inner.key)? {
                return Err(AuditError::ChainBroken {
                    sequence: event.sequence,
                    expected: "(valid hash)".to_string(),
                    actual: "(invalid hash)".to_string(),
                });
            }

            expected_prev = event.event_hash.clone();
        }

        Ok(())
    }
}

/// Convenience functions for common audit events
impl AuditChain {
    /// Record an authentication event
    pub fn auth_event(
        &self,
        action: impl Into<String>,
        outcome: AuditOutcome,
        operator_id: Option<Uuid>,
        operator_name: Option<String>,
        source_ip: Option<String>,
    ) -> Result<AuditEvent, AuditError> {
        let mut builder = AuditEvent::builder(AuditCategory::Authentication, action)
            .outcome(outcome)
            .severity(match outcome {
                AuditOutcome::Success => AuditSeverity::Info,
                AuditOutcome::Failure | AuditOutcome::Denied => AuditSeverity::Warning,
                AuditOutcome::Error => AuditSeverity::Alert,
            });

        if let (Some(id), Some(name)) = (operator_id, operator_name) {
            builder = builder.operator(id, name);
        }
        if let Some(ip) = source_ip {
            builder = builder.source_ip(ip);
        }

        self.record(builder)
    }

    /// Record a task event
    pub fn task_event(
        &self,
        action: impl Into<String>,
        outcome: AuditOutcome,
        operator_id: Uuid,
        operator_name: impl Into<String>,
        session_id: Uuid,
        task_type: impl Into<String>,
    ) -> Result<AuditEvent, AuditError> {
        self.record(
            AuditEvent::builder(AuditCategory::Task, action)
                .outcome(outcome)
                .operator(operator_id, operator_name)
                .session(session_id)
                .details(serde_json::json!({ "task_type": task_type.into() })),
        )
    }

    /// Record a session event
    pub fn session_event(
        &self,
        action: impl Into<String>,
        session_id: Uuid,
        details: Option<serde_json::Value>,
    ) -> Result<AuditEvent, AuditError> {
        let mut builder = AuditEvent::builder(AuditCategory::Session, action).session(session_id);

        if let Some(d) = details {
            builder = builder.details(d);
        }

        self.record(builder)
    }

    /// Record a permission denied event
    pub fn permission_denied(
        &self,
        operator_id: Uuid,
        operator_name: impl Into<String>,
        permission: impl Into<String>,
        target: Option<String>,
    ) -> Result<AuditEvent, AuditError> {
        let mut builder = AuditEvent::builder(AuditCategory::Authorization, "permission_check")
            .outcome(AuditOutcome::Denied)
            .severity(AuditSeverity::Warning)
            .operator(operator_id, operator_name)
            .details(serde_json::json!({ "permission": permission.into() }));

        if let Some(t) = target {
            builder = builder.target(t);
        }

        self.record(builder)
    }

    /// Record an admin action
    pub fn admin_action(
        &self,
        action: impl Into<String>,
        operator_id: Uuid,
        operator_name: impl Into<String>,
        details: serde_json::Value,
    ) -> Result<AuditEvent, AuditError> {
        self.record(
            AuditEvent::builder(AuditCategory::Admin, action)
                .severity(AuditSeverity::Alert)
                .operator(operator_id, operator_name)
                .details(details),
        )
    }

    /// Record a system event
    pub fn system_event(
        &self,
        action: impl Into<String>,
        severity: AuditSeverity,
        details: Option<serde_json::Value>,
    ) -> Result<AuditEvent, AuditError> {
        let mut builder = AuditEvent::builder(AuditCategory::System, action).severity(severity);

        if let Some(d) = details {
            builder = builder.details(d);
        }

        self.record(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain() -> AuditChain {
        AuditChain::new(b"test-hmac-key-32-bytes-long!!!!!")
    }

    #[test]
    fn test_record_event() {
        let chain = test_chain();

        let event = chain
            .record(
                AuditEvent::builder(AuditCategory::Authentication, "login")
                    .outcome(AuditOutcome::Success)
                    .operator(Uuid::new_v4(), "testuser"),
            )
            .unwrap();

        assert_eq!(event.sequence, 1);
        assert!(event.event_hash.is_some());
        assert!(event.previous_hash.is_none()); // First event has no previous
    }

    #[test]
    fn test_chain_linking() {
        let chain = test_chain();

        let event1 = chain
            .record(AuditEvent::builder(AuditCategory::System, "startup"))
            .unwrap();

        let event2 = chain
            .record(AuditEvent::builder(AuditCategory::Authentication, "login"))
            .unwrap();

        let event3 = chain
            .record(AuditEvent::builder(AuditCategory::Task, "execute"))
            .unwrap();

        // Check chain linking
        assert!(event1.previous_hash.is_none());
        assert_eq!(event2.previous_hash, event1.event_hash);
        assert_eq!(event3.previous_hash, event2.event_hash);

        // Sequence numbers are correct
        assert_eq!(event1.sequence, 1);
        assert_eq!(event2.sequence, 2);
        assert_eq!(event3.sequence, 3);
    }

    #[test]
    fn test_verify_chain_valid() {
        let chain = test_chain();

        let events: Vec<_> = (0..5)
            .map(|i| {
                chain
                    .record(AuditEvent::builder(
                        AuditCategory::System,
                        format!("event_{}", i),
                    ))
                    .unwrap()
            })
            .collect();

        // Should verify successfully
        chain.verify_chain(&events).unwrap();
    }

    #[test]
    fn test_verify_chain_tampered_hash() {
        let chain = test_chain();

        let mut events: Vec<_> = (0..3)
            .map(|i| {
                chain
                    .record(AuditEvent::builder(
                        AuditCategory::System,
                        format!("event_{}", i),
                    ))
                    .unwrap()
            })
            .collect();

        // Tamper with the second event's hash
        events[1].event_hash = Some("tampered".to_string());

        let result = chain.verify_chain(&events);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_chain_tampered_content() {
        let chain = test_chain();

        let mut events: Vec<_> = (0..3)
            .map(|i| {
                chain
                    .record(AuditEvent::builder(
                        AuditCategory::System,
                        format!("event_{}", i),
                    ))
                    .unwrap()
            })
            .collect();

        // Tamper with the second event's content (but keep hash)
        events[1].action = "malicious_action".to_string();

        let result = chain.verify_chain(&events);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_chain_broken_link() {
        let chain = test_chain();

        let mut events: Vec<_> = (0..3)
            .map(|i| {
                chain
                    .record(AuditEvent::builder(
                        AuditCategory::System,
                        format!("event_{}", i),
                    ))
                    .unwrap()
            })
            .collect();

        // Break the chain by modifying previous_hash
        events[2].previous_hash = Some("wrong_hash".to_string());

        let result = chain.verify_chain(&events);
        assert!(result.is_err());
    }

    #[test]
    fn test_event_builder() {
        let chain = test_chain();
        let op_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let event = chain
            .record(
                AuditEvent::builder(AuditCategory::Task, "shell_exec")
                    .severity(AuditSeverity::Alert)
                    .outcome(AuditOutcome::Success)
                    .operator(op_id, "admin")
                    .session(session_id)
                    .target("implant-001")
                    .details(serde_json::json!({ "command": "whoami" }))
                    .source_ip("192.168.1.100"),
            )
            .unwrap();

        assert_eq!(event.category, AuditCategory::Task);
        assert_eq!(event.severity, AuditSeverity::Alert);
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert_eq!(event.operator_id, Some(op_id));
        assert_eq!(event.operator_name.as_deref(), Some("admin"));
        assert_eq!(event.session_id, Some(session_id));
        assert_eq!(event.target.as_deref(), Some("implant-001"));
        assert_eq!(event.source_ip.as_deref(), Some("192.168.1.100"));
    }

    #[test]
    fn test_recent_events() {
        let chain = test_chain();

        for i in 0..5 {
            chain
                .record(AuditEvent::builder(
                    AuditCategory::System,
                    format!("event_{}", i),
                ))
                .unwrap();
        }

        let recent = chain.recent_events(3);
        assert_eq!(recent.len(), 3);
        // Most recent first
        assert_eq!(recent[0].action, "event_4");
        assert_eq!(recent[1].action, "event_3");
        assert_eq!(recent[2].action, "event_2");
    }

    #[test]
    fn test_resume_chain() {
        let key = b"test-hmac-key-32-bytes-long!!!!!";

        // Create initial chain and record some events
        let chain1 = AuditChain::new(key.to_vec());
        for i in 0..3 {
            chain1
                .record(AuditEvent::builder(
                    AuditCategory::System,
                    format!("event_{}", i),
                ))
                .unwrap();
        }

        let last_seq = chain1.current_sequence();
        let last_hash = chain1.last_hash().unwrap();

        // Resume the chain
        let chain2 = AuditChain::resume(key.to_vec(), last_seq, last_hash.clone());

        let event = chain2
            .record(AuditEvent::builder(AuditCategory::System, "resumed_event"))
            .unwrap();

        assert_eq!(event.sequence, 4);
        assert_eq!(event.previous_hash, Some(last_hash));
    }

    #[test]
    fn test_auth_event_helper() {
        let chain = test_chain();
        let op_id = Uuid::new_v4();

        let event = chain
            .auth_event(
                "login",
                AuditOutcome::Success,
                Some(op_id),
                Some("testuser".to_string()),
                Some("10.0.0.1".to_string()),
            )
            .unwrap();

        assert_eq!(event.category, AuditCategory::Authentication);
        assert_eq!(event.action, "login");
        assert_eq!(event.outcome, AuditOutcome::Success);
    }

    #[test]
    fn test_task_event_helper() {
        let chain = test_chain();
        let op_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let event = chain
            .task_event(
                "execute",
                AuditOutcome::Success,
                op_id,
                "operator1",
                session_id,
                "shell",
            )
            .unwrap();

        assert_eq!(event.category, AuditCategory::Task);
        assert_eq!(event.session_id, Some(session_id));
    }

    #[test]
    fn test_permission_denied_helper() {
        let chain = test_chain();
        let op_id = Uuid::new_v4();

        let event = chain
            .permission_denied(op_id, "lowpriv", "sessions:write", Some("session-123".to_string()))
            .unwrap();

        assert_eq!(event.category, AuditCategory::Authorization);
        assert_eq!(event.outcome, AuditOutcome::Denied);
        assert_eq!(event.severity, AuditSeverity::Warning);
    }

    #[test]
    fn test_admin_action_helper() {
        let chain = test_chain();
        let op_id = Uuid::new_v4();

        let event = chain
            .admin_action(
                "create_operator",
                op_id,
                "admin",
                serde_json::json!({ "new_user": "newop", "role": "operator" }),
            )
            .unwrap();

        assert_eq!(event.category, AuditCategory::Admin);
        assert_eq!(event.severity, AuditSeverity::Alert);
    }

    #[test]
    fn test_system_event_helper() {
        let chain = test_chain();

        let event = chain
            .system_event(
                "server_startup",
                AuditSeverity::Info,
                Some(serde_json::json!({ "version": "1.0.0" })),
            )
            .unwrap();

        assert_eq!(event.category, AuditCategory::System);
        assert_eq!(event.action, "server_startup");
    }

    #[test]
    fn test_concurrent_recording() {
        use std::thread;

        let chain = test_chain();
        let mut handles = vec![];

        // Spawn multiple threads recording events
        for t in 0..4 {
            let chain_clone = chain.clone();
            handles.push(thread::spawn(move || {
                for i in 0..10 {
                    chain_clone
                        .record(AuditEvent::builder(
                            AuditCategory::System,
                            format!("thread_{}_event_{}", t, i),
                        ))
                        .unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Should have 40 events total
        assert_eq!(chain.current_sequence(), 40);

        // Get events in chronological order (recent_events returns most recent first)
        let mut events = chain.recent_events(40);
        events.reverse(); // Now in chronological order

        // Chain should still be valid
        chain.verify_chain(&events).unwrap();
    }
}
