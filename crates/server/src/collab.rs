//! Real-time collaboration hub
//!
//! Manages operator presence, session locks, and event broadcasting for
//! multi-operator coordination.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Capacity for the collaboration event broadcast channel
const COLLAB_CHANNEL_CAPACITY: usize = 512;

/// Events broadcast to all connected operators
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CollabEvent {
    /// Operator came online
    OperatorOnline {
        operator_id: Uuid,
        username: String,
        timestamp: DateTime<Utc>,
    },
    /// Operator went offline
    OperatorOffline {
        operator_id: Uuid,
        username: String,
        timestamp: DateTime<Utc>,
    },
    /// Operator acquired a session lock
    SessionLocked {
        session_id: Uuid,
        operator_id: Uuid,
        username: String,
        timestamp: DateTime<Utc>,
    },
    /// Operator released a session lock
    SessionUnlocked {
        session_id: Uuid,
        operator_id: Uuid,
        username: String,
        timestamp: DateTime<Utc>,
    },
    /// Operator is actively working on a session
    SessionActivity {
        session_id: Uuid,
        operator_id: Uuid,
        activity: String,
        timestamp: DateTime<Utc>,
    },
    /// Chat message from an operator
    ChatMessage {
        from_operator_id: Uuid,
        from_username: String,
        message: String,
        /// Optional target session context
        session_id: Option<Uuid>,
        timestamp: DateTime<Utc>,
    },
    /// Task was dispatched to a session
    TaskDispatched {
        task_id: Uuid,
        session_id: Uuid,
        operator_id: Uuid,
        task_type: String,
        timestamp: DateTime<Utc>,
    },
    /// Task completed
    TaskCompleted {
        task_id: Uuid,
        session_id: Uuid,
        success: bool,
        timestamp: DateTime<Utc>,
    },
    /// New session registered
    SessionRegistered {
        session_id: Uuid,
        hostname: Option<String>,
        username: Option<String>,
        timestamp: DateTime<Utc>,
    },
    /// Session state changed
    SessionStateChanged {
        session_id: Uuid,
        old_state: String,
        new_state: String,
        timestamp: DateTime<Utc>,
    },
}

/// Operator presence information
#[derive(Debug, Clone, Serialize)]
pub struct OperatorPresence {
    pub operator_id: Uuid,
    pub username: String,
    pub connected_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    /// Session currently being viewed/worked on
    pub active_session: Option<Uuid>,
}

/// Session lock information
#[derive(Debug, Clone, Serialize)]
pub struct SessionLock {
    pub session_id: Uuid,
    pub operator_id: Uuid,
    pub username: String,
    pub locked_at: DateTime<Utc>,
    /// Optional reason for the lock
    pub reason: Option<String>,
}

/// Real-time collaboration hub
#[derive(Clone)]
pub struct CollabHub {
    /// Active operator presence
    presence: Arc<DashMap<Uuid, OperatorPresence>>,
    /// Session locks (session_id -> lock info)
    session_locks: Arc<DashMap<Uuid, SessionLock>>,
    /// Broadcast channel for collaboration events
    event_tx: broadcast::Sender<CollabEvent>,
}

impl Default for CollabHub {
    fn default() -> Self {
        Self::new()
    }
}

impl CollabHub {
    /// Create a new collaboration hub
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(COLLAB_CHANNEL_CAPACITY);
        Self {
            presence: Arc::new(DashMap::new()),
            session_locks: Arc::new(DashMap::new()),
            event_tx,
        }
    }

    /// Subscribe to collaboration events
    pub fn subscribe(&self) -> broadcast::Receiver<CollabEvent> {
        self.event_tx.subscribe()
    }

    /// Broadcast an event to all subscribers
    pub fn broadcast(&self, event: CollabEvent) {
        let _ = self.event_tx.send(event);
    }

    // -------------------------------------------------------------------------
    // Presence management
    // -------------------------------------------------------------------------

    /// Register an operator as online
    pub fn operator_online(&self, operator_id: Uuid, username: String) {
        let now = Utc::now();
        self.presence.insert(
            operator_id,
            OperatorPresence {
                operator_id,
                username: username.clone(),
                connected_at: now,
                last_activity: now,
                active_session: None,
            },
        );

        self.broadcast(CollabEvent::OperatorOnline {
            operator_id,
            username,
            timestamp: now,
        });

        tracing::info!(operator_id = %operator_id, "operator online");
    }

    /// Mark an operator as offline
    pub fn operator_offline(&self, operator_id: Uuid) {
        if let Some((_, presence)) = self.presence.remove(&operator_id) {
            // Release any locks held by this operator
            self.release_all_locks(operator_id);

            self.broadcast(CollabEvent::OperatorOffline {
                operator_id,
                username: presence.username,
                timestamp: Utc::now(),
            });

            tracing::info!(operator_id = %operator_id, "operator offline");
        }
    }

    /// Update operator's last activity timestamp
    pub fn touch_activity(&self, operator_id: Uuid) {
        if let Some(mut presence) = self.presence.get_mut(&operator_id) {
            presence.last_activity = Utc::now();
        }
    }

    /// Set the session an operator is actively working on
    pub fn set_active_session(&self, operator_id: Uuid, session_id: Option<Uuid>) {
        if let Some(mut presence) = self.presence.get_mut(&operator_id) {
            presence.active_session = session_id;
            presence.last_activity = Utc::now();
        }
    }

    /// Get list of online operators
    pub fn online_operators(&self) -> Vec<OperatorPresence> {
        self.presence.iter().map(|r| r.value().clone()).collect()
    }

    /// Check if an operator is online
    pub fn is_online(&self, operator_id: Uuid) -> bool {
        self.presence.contains_key(&operator_id)
    }

    /// Get operators currently viewing a specific session
    pub fn operators_on_session(&self, session_id: Uuid) -> Vec<OperatorPresence> {
        self.presence
            .iter()
            .filter(|r| r.active_session == Some(session_id))
            .map(|r| r.value().clone())
            .collect()
    }

    // -------------------------------------------------------------------------
    // Session locking
    // -------------------------------------------------------------------------

    /// Attempt to acquire a lock on a session
    pub fn try_lock_session(
        &self,
        session_id: Uuid,
        operator_id: Uuid,
        username: String,
        reason: Option<String>,
    ) -> Result<(), SessionLockError> {
        // Check if already locked by someone else
        if let Some(existing) = self.session_locks.get(&session_id) {
            if existing.operator_id != operator_id {
                return Err(SessionLockError::AlreadyLocked {
                    session_id,
                    holder_id: existing.operator_id,
                    holder_name: existing.username.clone(),
                });
            }
            // Already locked by this operator - refresh
        }

        let now = Utc::now();
        self.session_locks.insert(
            session_id,
            SessionLock {
                session_id,
                operator_id,
                username: username.clone(),
                locked_at: now,
                reason,
            },
        );

        self.broadcast(CollabEvent::SessionLocked {
            session_id,
            operator_id,
            username,
            timestamp: now,
        });

        tracing::debug!(session_id = %session_id, operator_id = %operator_id, "session locked");
        Ok(())
    }

    /// Release a session lock
    pub fn unlock_session(
        &self,
        session_id: Uuid,
        operator_id: Uuid,
    ) -> Result<(), SessionLockError> {
        match self.session_locks.get(&session_id) {
            Some(lock) if lock.operator_id == operator_id => {
                let username = lock.username.clone();
                drop(lock);
                self.session_locks.remove(&session_id);

                self.broadcast(CollabEvent::SessionUnlocked {
                    session_id,
                    operator_id,
                    username,
                    timestamp: Utc::now(),
                });

                tracing::debug!(session_id = %session_id, "session unlocked");
                Ok(())
            }
            Some(lock) => Err(SessionLockError::NotOwner {
                session_id,
                holder_id: lock.operator_id,
            }),
            None => Err(SessionLockError::NotLocked { session_id }),
        }
    }

    /// Force-release a lock (admin only)
    pub fn force_unlock_session(&self, session_id: Uuid) -> bool {
        if let Some((_, lock)) = self.session_locks.remove(&session_id) {
            self.broadcast(CollabEvent::SessionUnlocked {
                session_id,
                operator_id: lock.operator_id,
                username: lock.username,
                timestamp: Utc::now(),
            });
            tracing::warn!(session_id = %session_id, "session force-unlocked");
            true
        } else {
            false
        }
    }

    /// Release all locks held by an operator
    fn release_all_locks(&self, operator_id: Uuid) {
        let to_remove: Vec<Uuid> = self
            .session_locks
            .iter()
            .filter(|r| r.operator_id == operator_id)
            .map(|r| *r.key())
            .collect();

        for session_id in to_remove {
            if let Some((_, lock)) = self.session_locks.remove(&session_id) {
                self.broadcast(CollabEvent::SessionUnlocked {
                    session_id,
                    operator_id: lock.operator_id,
                    username: lock.username,
                    timestamp: Utc::now(),
                });
            }
        }
    }

    /// Get lock status for a session
    pub fn get_lock(&self, session_id: Uuid) -> Option<SessionLock> {
        self.session_locks.get(&session_id).map(|r| r.clone())
    }

    /// Get all active session locks
    pub fn all_locks(&self) -> Vec<SessionLock> {
        self.session_locks.iter().map(|r| r.value().clone()).collect()
    }

    /// Check if a session is locked
    pub fn is_locked(&self, session_id: Uuid) -> bool {
        self.session_locks.contains_key(&session_id)
    }

    /// Check if operator can modify a session (unlocked or owns the lock)
    pub fn can_modify_session(&self, session_id: Uuid, operator_id: Uuid) -> bool {
        match self.session_locks.get(&session_id) {
            Some(lock) => lock.operator_id == operator_id,
            None => true, // Unlocked sessions can be modified by anyone
        }
    }

    // -------------------------------------------------------------------------
    // Activity broadcasting
    // -------------------------------------------------------------------------

    /// Broadcast that an operator is working on a session
    pub fn broadcast_activity(&self, session_id: Uuid, operator_id: Uuid, activity: String) {
        self.touch_activity(operator_id);
        self.broadcast(CollabEvent::SessionActivity {
            session_id,
            operator_id,
            activity,
            timestamp: Utc::now(),
        });
    }

    /// Send a chat message
    pub fn send_chat(
        &self,
        from_operator_id: Uuid,
        from_username: String,
        message: String,
        session_id: Option<Uuid>,
    ) {
        self.touch_activity(from_operator_id);
        self.broadcast(CollabEvent::ChatMessage {
            from_operator_id,
            from_username,
            message,
            session_id,
            timestamp: Utc::now(),
        });
    }

    // -------------------------------------------------------------------------
    // Stats
    // -------------------------------------------------------------------------

    /// Get collaboration statistics
    pub fn stats(&self) -> CollabStats {
        let operators: HashMap<Uuid, OperatorPresence> = self
            .presence
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect();

        let sessions_with_activity: Vec<Uuid> = operators
            .values()
            .filter_map(|p| p.active_session)
            .collect();

        CollabStats {
            online_operators: operators.len(),
            active_sessions: sessions_with_activity.len(),
            locked_sessions: self.session_locks.len(),
        }
    }
}

/// Collaboration statistics
#[derive(Debug, Clone, Serialize)]
pub struct CollabStats {
    pub online_operators: usize,
    pub active_sessions: usize,
    pub locked_sessions: usize,
}

/// Errors related to session locking
#[derive(Debug, thiserror::Error)]
pub enum SessionLockError {
    #[error("session {session_id} is already locked by {holder_name} ({holder_id})")]
    AlreadyLocked {
        session_id: Uuid,
        holder_id: Uuid,
        holder_name: String,
    },
    #[error("session {session_id} is not locked")]
    NotLocked { session_id: Uuid },
    #[error("session {session_id} is locked by {holder_id}, not you")]
    NotOwner { session_id: Uuid, holder_id: Uuid },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_presence() {
        let hub = CollabHub::new();
        let op_id = Uuid::new_v4();

        assert!(!hub.is_online(op_id));

        hub.operator_online(op_id, "alice".to_string());
        assert!(hub.is_online(op_id));

        let online = hub.online_operators();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].username, "alice");

        hub.operator_offline(op_id);
        assert!(!hub.is_online(op_id));
        assert!(hub.online_operators().is_empty());
    }

    #[test]
    fn test_session_locking() {
        let hub = CollabHub::new();
        let session_id = Uuid::new_v4();
        let op1 = Uuid::new_v4();
        let op2 = Uuid::new_v4();

        // First operator can lock
        hub.try_lock_session(session_id, op1, "alice".to_string(), None)
            .unwrap();
        assert!(hub.is_locked(session_id));

        // Second operator cannot lock
        let err = hub
            .try_lock_session(session_id, op2, "bob".to_string(), None)
            .unwrap_err();
        assert!(matches!(err, SessionLockError::AlreadyLocked { .. }));

        // First operator can unlock
        hub.unlock_session(session_id, op1).unwrap();
        assert!(!hub.is_locked(session_id));

        // Second operator can now lock
        hub.try_lock_session(session_id, op2, "bob".to_string(), Some("testing".to_string()))
            .unwrap();
        assert!(hub.is_locked(session_id));
    }

    #[test]
    fn test_unlock_not_owner() {
        let hub = CollabHub::new();
        let session_id = Uuid::new_v4();
        let op1 = Uuid::new_v4();
        let op2 = Uuid::new_v4();

        hub.try_lock_session(session_id, op1, "alice".to_string(), None)
            .unwrap();

        // Op2 cannot unlock
        let err = hub.unlock_session(session_id, op2).unwrap_err();
        assert!(matches!(err, SessionLockError::NotOwner { .. }));
    }

    #[test]
    fn test_force_unlock() {
        let hub = CollabHub::new();
        let session_id = Uuid::new_v4();
        let op1 = Uuid::new_v4();

        hub.try_lock_session(session_id, op1, "alice".to_string(), None)
            .unwrap();
        assert!(hub.is_locked(session_id));

        // Force unlock works
        assert!(hub.force_unlock_session(session_id));
        assert!(!hub.is_locked(session_id));
    }

    #[test]
    fn test_locks_released_on_offline() {
        let hub = CollabHub::new();
        let session1 = Uuid::new_v4();
        let session2 = Uuid::new_v4();
        let op_id = Uuid::new_v4();

        hub.operator_online(op_id, "alice".to_string());
        hub.try_lock_session(session1, op_id, "alice".to_string(), None)
            .unwrap();
        hub.try_lock_session(session2, op_id, "alice".to_string(), None)
            .unwrap();

        assert!(hub.is_locked(session1));
        assert!(hub.is_locked(session2));

        // Going offline releases all locks
        hub.operator_offline(op_id);

        assert!(!hub.is_locked(session1));
        assert!(!hub.is_locked(session2));
    }

    #[test]
    fn test_can_modify_session() {
        let hub = CollabHub::new();
        let session_id = Uuid::new_v4();
        let op1 = Uuid::new_v4();
        let op2 = Uuid::new_v4();

        // Unlocked - both can modify
        assert!(hub.can_modify_session(session_id, op1));
        assert!(hub.can_modify_session(session_id, op2));

        hub.try_lock_session(session_id, op1, "alice".to_string(), None)
            .unwrap();

        // Locked - only owner can modify
        assert!(hub.can_modify_session(session_id, op1));
        assert!(!hub.can_modify_session(session_id, op2));
    }

    #[test]
    fn test_active_session_tracking() {
        let hub = CollabHub::new();
        let session_id = Uuid::new_v4();
        let op1 = Uuid::new_v4();
        let op2 = Uuid::new_v4();

        hub.operator_online(op1, "alice".to_string());
        hub.operator_online(op2, "bob".to_string());

        hub.set_active_session(op1, Some(session_id));

        let on_session = hub.operators_on_session(session_id);
        assert_eq!(on_session.len(), 1);
        assert_eq!(on_session[0].operator_id, op1);
    }

    #[test]
    fn test_event_subscription() {
        let hub = CollabHub::new();
        let mut rx = hub.subscribe();

        let op_id = Uuid::new_v4();
        hub.operator_online(op_id, "alice".to_string());

        let event = rx.try_recv().unwrap();
        match event {
            CollabEvent::OperatorOnline { username, .. } => {
                assert_eq!(username, "alice");
            }
            _ => panic!("expected OperatorOnline event"),
        }
    }

    #[test]
    fn test_stats() {
        let hub = CollabHub::new();
        let session_id = Uuid::new_v4();
        let op1 = Uuid::new_v4();
        let op2 = Uuid::new_v4();

        hub.operator_online(op1, "alice".to_string());
        hub.operator_online(op2, "bob".to_string());
        hub.set_active_session(op1, Some(session_id));
        hub.try_lock_session(session_id, op1, "alice".to_string(), None)
            .unwrap();

        let stats = hub.stats();
        assert_eq!(stats.online_operators, 2);
        assert_eq!(stats.active_sessions, 1);
        assert_eq!(stats.locked_sessions, 1);
    }

    #[test]
    fn test_chat_message() {
        let hub = CollabHub::new();
        let mut rx = hub.subscribe();

        let op_id = Uuid::new_v4();
        hub.operator_online(op_id, "alice".to_string());
        let _ = rx.try_recv(); // consume online event

        hub.send_chat(op_id, "alice".to_string(), "Hello team!".to_string(), None);

        let event = rx.try_recv().unwrap();
        match event {
            CollabEvent::ChatMessage { message, .. } => {
                assert_eq!(message, "Hello team!");
            }
            _ => panic!("expected ChatMessage event"),
        }
    }
}
