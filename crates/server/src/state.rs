//! Shared server state

use crate::collab::CollabHub;
use crate::webhook::{WebhookConfig, WebhookEvent, WebhookService};
use common::ImplantId;
use crypto::ServerCrypto;
use dashmap::DashMap;
use kraken_audit::AuditChain;
use module_store::ModuleStore;
use protocol::{ImplantEvent, TaskResultEvent};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Broadcast channel capacity for implant events
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Loot event for real-time WebSocket updates
#[derive(Debug, Clone)]
pub struct LootEvent {
    pub loot_id: Vec<u8>,
    pub implant_id: Vec<u8>,
    pub loot_type: String,
    pub description: String,
}

/// Shared state for the Kraken server, wrapped in Arc for cheap cloning
pub struct ServerState {
    pub db: db::Database,
    pub crypto: ServerCrypto,
    pub module_store: Arc<ModuleStore>,
    pub event_tx: broadcast::Sender<ImplantEvent>,
    pub task_result_tx: broadcast::Sender<TaskResultEvent>,
    pub loot_tx: broadcast::Sender<LootEvent>,
    /// Pending tasks keyed by implant ID — populated by TaskService, drained on check-in
    pub pending_tasks: DashMap<ImplantId, Vec<protocol::Task>>,
    /// Tamper-evident audit log chain
    pub audit: AuditChain,
    /// Real-time collaboration hub for operator coordination
    pub collab: CollabHub,
    /// Webhook / SOAR notification service
    pub webhooks: RwLock<WebhookService>,
    /// Required modules to push to implants on check-in (module IDs)
    /// When an implant checks in missing any of these, a ModuleTask(Load) is queued
    pub required_modules: RwLock<Vec<String>>,
    /// JWT token manager for WebSocket authentication
    pub jwt: crate::auth::jwt::JwtManager,
}

impl ServerState {
    pub fn new(
        db: db::Database,
        crypto: ServerCrypto,
        module_store: Arc<ModuleStore>,
        audit_key: impl Into<Vec<u8>>,
        jwt: crate::auth::jwt::JwtManager,
    ) -> Arc<Self> {
        Self::new_with_webhooks(db, crypto, module_store, audit_key, jwt, vec![])
    }

    /// Create state with a pre-configured set of webhook endpoints.
    pub fn new_with_webhooks(
        db: db::Database,
        crypto: ServerCrypto,
        module_store: Arc<ModuleStore>,
        audit_key: impl Into<Vec<u8>>,
        jwt: crate::auth::jwt::JwtManager,
        webhook_configs: Vec<WebhookConfig>,
    ) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (task_result_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (loot_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Arc::new(Self {
            db,
            crypto,
            module_store,
            event_tx,
            task_result_tx,
            loot_tx,
            pending_tasks: DashMap::new(),
            audit: AuditChain::new(audit_key),
            collab: CollabHub::new(),
            webhooks: RwLock::new(WebhookService::new(webhook_configs)),
            required_modules: RwLock::new(Vec::new()),
            jwt,
        })
    }

    /// Fire a webhook notification (non-blocking).
    pub async fn notify_webhook(&self, event: WebhookEvent, data: serde_json::Value) {
        self.webhooks.read().await.notify(&event, &data).await;
    }

    /// Subscribe to implant events
    pub fn subscribe_events(&self) -> broadcast::Receiver<ImplantEvent> {
        self.event_tx.subscribe()
    }

    /// Publish an implant event (silently ignores send errors when no subscribers)
    pub fn publish_event(&self, event: ImplantEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Subscribe to task result events
    pub fn subscribe_task_results(&self) -> broadcast::Receiver<TaskResultEvent> {
        self.task_result_tx.subscribe()
    }

    /// Publish a task result event (silently ignores send errors when no subscribers)
    pub fn publish_task_result(&self, event: TaskResultEvent) {
        let _ = self.task_result_tx.send(event);
    }

    /// Subscribe to loot events
    pub fn subscribe_loot(&self) -> broadcast::Receiver<LootEvent> {
        self.loot_tx.subscribe()
    }

    /// Publish a loot event (silently ignores send errors when no subscribers)
    pub fn publish_loot(&self, event: LootEvent) {
        let _ = self.loot_tx.send(event);
    }

    /// Queue a task for delivery to an implant on next check-in
    pub fn enqueue_task(&self, implant_id: ImplantId, task: protocol::Task) {
        self.pending_tasks.entry(implant_id).or_default().push(task);
    }

    /// Drain all pending tasks for an implant (called during check-in)
    pub fn drain_tasks(&self, implant_id: ImplantId) -> Vec<protocol::Task> {
        self.pending_tasks
            .remove(&implant_id)
            .map(|(_, tasks)| tasks)
            .unwrap_or_default()
    }

    /// Set the list of required modules to push to implants
    pub async fn set_required_modules(&self, modules: Vec<String>) {
        let mut required = self.required_modules.write().await;
        *required = modules;
    }

    /// Get the list of required modules
    pub async fn get_required_modules(&self) -> Vec<String> {
        self.required_modules.read().await.clone()
    }

    /// Check for missing modules and queue load tasks
    ///
    /// Compares the implant's loaded modules against required modules.
    /// For each missing module, queues a ModuleTask(Load) if the module
    /// blob is available in the module store.
    ///
    /// OPSEC: Only queues one module per check-in to avoid traffic spikes.
    /// Returns the number of modules queued.
    ///
    /// `platform` should be the implant's target platform (e.g., "x86_64-linux")
    pub async fn queue_missing_modules(
        &self,
        implant_id: ImplantId,
        loaded_modules: &[String],
        platform: &str,
    ) -> usize {
        let required = self.required_modules.read().await;
        if required.is_empty() {
            return 0;
        }

        // Find missing modules
        let missing: Vec<&String> = required
            .iter()
            .filter(|m| !loaded_modules.contains(m))
            .collect();

        if missing.is_empty() {
            return 0;
        }

        // OPSEC: Only push one module per check-in to spread traffic
        // This makes the loading less detectable via traffic analysis
        let module_id = missing[0];

        // Try to get the module blob from the store (latest version)
        if let Ok(blob) = self.module_store.get_blob(module_id, platform, None).await {
            use protocol::{module_task::Operation, ModuleLoad, ModuleTask, Task, Uuid as ProtoUuid};

            let module_task = ModuleTask {
                operation: Some(Operation::Load(ModuleLoad { module_blob: blob })),
            };

            let task_id = common::TaskId::new();
            let task = Task {
                task_id: Some(ProtoUuid { value: task_id.as_bytes().to_vec() }),
                task_type: "module".to_string(),
                task_data: protocol::encode(&module_task),
                issued_at: Some(protocol::Timestamp::now()),
                operator_id: None, // System-generated task
            };

            self.enqueue_task(implant_id, task);
            return 1;
        }

        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ImplantId;

    async fn make_state() -> Arc<ServerState> {
        let db = db::Database::connect_memory().await.unwrap();
        db.migrate().await.unwrap();
        let master_key = crypto::SymmetricKey([0u8; 32]);
        let crypto = crypto::ServerCrypto::new(master_key);
        let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
        let ms = Arc::new(
            module_store::ModuleStore::new(Arc::new(db.clone()), &signing_key).unwrap(),
        );
        let audit_key = b"test-audit-key-for-unit-tests!!";
        let jwt = crate::auth::jwt::JwtManager::from_env_or_master_key(&[0u8; 32]).unwrap();
        ServerState::new(db, crypto, ms, audit_key.to_vec(), jwt)
    }

    // ------------------------------------------------------------------
    // enqueue_task / drain_tasks
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn drain_tasks_returns_empty_for_unknown_implant() {
        let state = make_state().await;
        let id = ImplantId::new();
        let tasks = state.drain_tasks(id);
        assert!(tasks.is_empty(), "expected no tasks for unknown implant");
    }

    #[tokio::test]
    async fn enqueue_then_drain_returns_tasks_in_order() {
        let state = make_state().await;
        let id = ImplantId::new();

        let task_a = protocol::Task {
            task_id: None,
            task_type: "shell".to_string(),
            task_data: b"id".to_vec(),
            issued_at: None,
            operator_id: None,
        };
        let task_b = protocol::Task {
            task_id: None,
            task_type: "whoami".to_string(),
            task_data: vec![],
            issued_at: None,
            operator_id: None,
        };

        state.enqueue_task(id, task_a.clone());
        state.enqueue_task(id, task_b.clone());

        let drained = state.drain_tasks(id);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].task_type, "shell");
        assert_eq!(drained[1].task_type, "whoami");
    }

    #[tokio::test]
    async fn drain_tasks_clears_the_queue() {
        let state = make_state().await;
        let id = ImplantId::new();

        state.enqueue_task(id, protocol::Task {
            task_id: None,
            task_type: "ping".to_string(),
            task_data: vec![],
            issued_at: None,
            operator_id: None,
        });

        let first = state.drain_tasks(id);
        assert_eq!(first.len(), 1);

        // Second drain must be empty — queue was cleared
        let second = state.drain_tasks(id);
        assert!(second.is_empty(), "queue should be empty after drain");
    }

    #[tokio::test]
    async fn enqueue_for_different_implants_are_isolated() {
        let state = make_state().await;
        let id_a = ImplantId::new();
        let id_b = ImplantId::new();

        state.enqueue_task(id_a, protocol::Task {
            task_id: None,
            task_type: "a".to_string(),
            task_data: vec![],
            issued_at: None,
            operator_id: None,
        });

        // id_b has no tasks
        assert!(state.drain_tasks(id_b).is_empty());
        // id_a still has its task
        assert_eq!(state.drain_tasks(id_a).len(), 1);
    }

    // ------------------------------------------------------------------
    // publish_event / subscribe_events
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn publish_event_received_by_subscriber() {
        let state = make_state().await;
        let mut rx = state.subscribe_events();

        use protocol::{implant_event::Event, ImplantCheckedInEvent, ImplantEvent, Timestamp};
        let implant_id = ImplantId::new();
        state.publish_event(ImplantEvent {
            timestamp: Some(Timestamp::now()),
            event: Some(Event::CheckedIn(ImplantCheckedInEvent {
                implant_id: Some(implant_id.into()),
            })),
        });

        let received = rx.try_recv().expect("expected event on channel");
        match received.event {
            Some(Event::CheckedIn(e)) => {
                let id = ImplantId::from_bytes(&e.implant_id.unwrap().value).unwrap();
                assert_eq!(id, implant_id);
            }
            other => panic!("unexpected event variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn publish_event_with_no_subscribers_does_not_panic() {
        let state = make_state().await;
        // No subscriber — send should be silently ignored
        use protocol::{implant_event::Event, ImplantCheckedInEvent, ImplantEvent, Timestamp};
        state.publish_event(ImplantEvent {
            timestamp: Some(Timestamp::now()),
            event: Some(Event::CheckedIn(ImplantCheckedInEvent {
                implant_id: None,
            })),
        });
        // If we reach here without panic, the test passes
    }

    // ------------------------------------------------------------------
    // publish_task_result / subscribe_task_results
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn publish_task_result_received_by_subscriber() {
        let state = make_state().await;
        let mut rx = state.subscribe_task_results();

        use protocol::{TaskResultEvent, Timestamp};
        state.publish_task_result(TaskResultEvent {
            task_id: None,
            implant_id: None,
            status: 0,
            result_data: b"output".to_vec(),
            error: None,
            completed_at: Some(Timestamp::now()),
        });

        let event = rx.try_recv().expect("expected task result on channel");
        assert_eq!(event.result_data, b"output");
    }
}
