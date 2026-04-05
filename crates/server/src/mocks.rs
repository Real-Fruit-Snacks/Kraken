//! Mock implementations for testing
//!
//! Uses mockall for async trait mocking. Add `#[cfg(test)]` to usages in test
//! modules; the traits themselves are public so integration tests can also use
//! them.

use async_trait::async_trait;
use mockall::automock;

use crate::error::ServerError;

// ---------------------------------------------------------------------------
// Shared result type alias used across the mock traits
// ---------------------------------------------------------------------------
pub type MockResult<T> = Result<T, ServerError>;

// ---------------------------------------------------------------------------
// ImplantConnection — abstracts the send/receive lifecycle of a single implant
// ---------------------------------------------------------------------------

/// Represents a task result received from an implant.
#[derive(Debug, Clone)]
pub struct TaskResult {
    pub task_id: u64,
    pub status: i32,
    pub data: Vec<u8>,
    pub error: Option<String>,
}

/// Abstracts the bidirectional connection to a single implant, allowing tests
/// to stub out network behaviour without a real listener.
#[automock]
#[async_trait]
pub trait ImplantConnection: Send + Sync {
    /// Deliver a task to the implant.
    async fn send_task(
        &self,
        task_id: u64,
        command: &str,
        payload: &[u8],
    ) -> MockResult<()>;

    /// Block until the implant sends back a result.
    async fn recv_result(&self) -> MockResult<TaskResult>;

    /// Gracefully close the connection.
    async fn close(&self) -> MockResult<()>;
}

// ---------------------------------------------------------------------------
// Session — lightweight description of a connected implant session
// ---------------------------------------------------------------------------

/// Lightweight view of a live implant session.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: String,
    pub implant_id: String,
    pub remote_addr: String,
}

/// Abstracts persistent session storage, enabling tests to inject canned
/// session state without hitting a real database.
#[automock]
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Retrieve a session by its opaque ID, or `None` if not found.
    async fn get_session(&self, id: &str) -> MockResult<Option<Session>>;

    /// Return all currently-active sessions.
    async fn list_sessions(&self) -> MockResult<Vec<Session>>;

    /// Remove a session by ID.  Returns `Ok(())` even if the session did not
    /// exist (idempotent).
    async fn remove_session(&self, id: &str) -> MockResult<()>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    // -----------------------------------------------------------------------
    // ImplantConnection mock tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mock_send_task_returns_ok() {
        let mut conn = MockImplantConnection::new();
        conn.expect_send_task()
            .with(eq(42u64), eq("shell"), eq(b"whoami".as_ref()))
            .times(1)
            .returning(|_, _, _| Ok(()));

        let result = conn.send_task(42, "shell", b"whoami").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_send_task_returns_error_on_failure() {
        let mut conn = MockImplantConnection::new();
        conn.expect_send_task()
            .returning(|_, _, _| Err(ServerError::Internal("send failed".to_string())));

        let result = conn.send_task(1, "ping", b"").await;
        assert!(matches!(result, Err(ServerError::Internal(_))));
    }

    #[tokio::test]
    async fn mock_recv_result_returns_task_result() {
        let mut conn = MockImplantConnection::new();
        conn.expect_recv_result()
            .times(1)
            .returning(|| {
                Ok(TaskResult {
                    task_id: 42,
                    status: 0,
                    data: b"uid=0(root)".to_vec(),
                    error: None,
                })
            });

        let result = conn.recv_result().await.unwrap();
        assert_eq!(result.task_id, 42);
        assert_eq!(result.data, b"uid=0(root)");
        assert_eq!(result.status, 0);
    }

    #[tokio::test]
    async fn mock_close_called_exactly_once() {
        let mut conn = MockImplantConnection::new();
        conn.expect_close().times(1).returning(|| Ok(()));

        conn.close().await.unwrap();
        // mockall asserts `times(1)` on drop
    }

    #[tokio::test]
    async fn mock_close_propagates_error() {
        let mut conn = MockImplantConnection::new();
        conn.expect_close()
            .returning(|| Err(ServerError::Internal("close error".to_string())));

        let err = conn.close().await.unwrap_err();
        assert!(err.to_string().contains("close error"));
    }

    // -----------------------------------------------------------------------
    // SessionStore mock tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mock_get_session_returns_some() {
        let mut store = MockSessionStore::new();
        store
            .expect_get_session()
            .with(eq("sess-1"))
            .times(1)
            .returning(|id| {
                Ok(Some(Session {
                    id: id.to_string(),
                    implant_id: "implant-abc".to_string(),
                    remote_addr: "10.0.0.1:4444".to_string(),
                }))
            });

        let session = store.get_session("sess-1").await.unwrap();
        assert!(session.is_some());
        let s = session.unwrap();
        assert_eq!(s.id, "sess-1");
        assert_eq!(s.implant_id, "implant-abc");
    }

    #[tokio::test]
    async fn mock_get_session_returns_none_for_unknown_id() {
        let mut store = MockSessionStore::new();
        store
            .expect_get_session()
            .returning(|_| Ok(None));

        let result = store.get_session("no-such-session").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mock_list_sessions_returns_all() {
        let mut store = MockSessionStore::new();
        store.expect_list_sessions().times(1).returning(|| {
            Ok(vec![
                Session {
                    id: "s1".to_string(),
                    implant_id: "i1".to_string(),
                    remote_addr: "1.2.3.4:80".to_string(),
                },
                Session {
                    id: "s2".to_string(),
                    implant_id: "i2".to_string(),
                    remote_addr: "5.6.7.8:443".to_string(),
                },
            ])
        });

        let sessions = store.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "s1");
        assert_eq!(sessions[1].id, "s2");
    }

    #[tokio::test]
    async fn mock_list_sessions_empty_returns_empty_vec() {
        let mut store = MockSessionStore::new();
        store
            .expect_list_sessions()
            .returning(|| Ok(vec![]));

        let sessions = store.list_sessions().await.unwrap();
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn mock_remove_session_ok() {
        let mut store = MockSessionStore::new();
        store
            .expect_remove_session()
            .with(eq("sess-1"))
            .times(1)
            .returning(|_| Ok(()));

        store.remove_session("sess-1").await.unwrap();
    }

    #[tokio::test]
    async fn mock_remove_session_returns_error_on_db_failure() {
        let mut store = MockSessionStore::new();
        store
            .expect_remove_session()
            .returning(|_| Err(ServerError::Database("delete failed".to_string())));

        let err = store.remove_session("bad-id").await.unwrap_err();
        assert!(matches!(err, ServerError::Database(_)));
    }

    // -----------------------------------------------------------------------
    // Composition: using both mocks together in a higher-level scenario
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_task_lifecycle_with_mocks() {
        // Set up a session store that confirms the session exists
        let mut store = MockSessionStore::new();
        store
            .expect_get_session()
            .with(eq("sess-42"))
            .returning(|id| {
                Ok(Some(Session {
                    id: id.to_string(),
                    implant_id: "implant-xyz".to_string(),
                    remote_addr: "192.168.1.100:4444".to_string(),
                }))
            });

        // Set up a connection that accepts one task and returns a result
        let mut conn = MockImplantConnection::new();
        conn.expect_send_task()
            .times(1)
            .returning(|_, _, _| Ok(()));
        conn.expect_recv_result().times(1).returning(|| {
            Ok(TaskResult {
                task_id: 99,
                status: 0,
                data: b"done".to_vec(),
                error: None,
            })
        });
        conn.expect_close().times(1).returning(|| Ok(()));

        // Exercise the mock pipeline
        let session = store.get_session("sess-42").await.unwrap().unwrap();
        assert_eq!(session.implant_id, "implant-xyz");

        conn.send_task(99, "shell", b"id").await.unwrap();
        let result = conn.recv_result().await.unwrap();
        assert_eq!(result.task_id, 99);
        assert_eq!(result.data, b"done");

        conn.close().await.unwrap();
    }
}
