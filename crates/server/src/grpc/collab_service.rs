//! CollabService gRPC implementation
//!
//! Provides real-time collaboration features for operators including
//! presence tracking, session locking, and event streaming.

use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use crate::auth::{get_cert_identity, resolve_operator, require_permission, Permission, OperatorIdentity};
use crate::collab::{CollabEvent as InternalCollabEvent, SessionLockError};
use crate::state::ServerState;
use protocol::{
    ChatMessageEvent, ChatMessageRecord as ProtoChatRecord, CollabEvent, CollabService,
    CollabStatsResponse, GetChatHistoryRequest, GetChatHistoryResponse,
    GetCollabStatsRequest, GetOnlineOperatorsRequest, GetOnlineOperatorsResponse,
    GetSessionLocksRequest, GetSessionLocksResponse, LockSessionRequest,
    OperatorOfflineEvent, OperatorOnlineEvent, OperatorPresence as ProtoPresence,
    SendChatRequest, SessionActivityEvent, SessionLock as ProtoLock,
    SessionLockedEvent, SessionUnlockedEvent, SetActiveSessionRequest,
    StreamCollabEventsRequest, TaskCompletedEvent, TaskDispatchedEvent,
    Timestamp, UnlockSessionRequest, Uuid as ProtoUuid,
};

/// Returns the authenticated operator, or a mock dev/admin operator when running
/// in insecure mode (no client certificate present).
async fn get_operator_or_dev<T>(db: &db::Database, request: &Request<T>) -> Result<OperatorIdentity, Status> {
    match get_cert_identity(request) {
        Ok(cert_id) => resolve_operator(db, cert_id).await,
        Err(_) => {
            // No client certificate — insecure/dev mode: return a mock admin operator.
            tracing::debug!("no client cert present, using dev operator (insecure mode)");
            Ok(OperatorIdentity {
                id: uuid::Uuid::from_bytes([0u8; 16]),
                username: "dev".to_string(),
                role: kraken_rbac::Role::Admin,
                cert_fingerprint: String::new(),
                allowed_sessions: None,
                allowed_listeners: None,
                created_at: chrono::DateTime::from_timestamp(0, 0)
                    .unwrap_or_default(),
                last_seen: None,
                disabled: false,
            })
        }
    }
}

pub struct CollabServiceImpl {
    state: Arc<ServerState>,
}

impl CollabServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    fn uuid_to_proto(id: uuid::Uuid) -> ProtoUuid {
        ProtoUuid {
            value: id.as_bytes().to_vec(),
        }
    }

    fn proto_to_uuid(proto: Option<ProtoUuid>) -> Result<uuid::Uuid, Status> {
        let proto = proto.ok_or_else(|| Status::invalid_argument("missing uuid"))?;
        if proto.value.len() != 16 {
            return Err(Status::invalid_argument("invalid uuid length"));
        }
        let bytes: [u8; 16] = proto.value.try_into().unwrap();
        Ok(uuid::Uuid::from_bytes(bytes))
    }

    fn internal_to_proto_event(event: InternalCollabEvent) -> CollabEvent {
        use protocol::collab_event::Event;

        let timestamp = match &event {
            InternalCollabEvent::OperatorOnline { timestamp, .. } => *timestamp,
            InternalCollabEvent::OperatorOffline { timestamp, .. } => *timestamp,
            InternalCollabEvent::SessionLocked { timestamp, .. } => *timestamp,
            InternalCollabEvent::SessionUnlocked { timestamp, .. } => *timestamp,
            InternalCollabEvent::SessionActivity { timestamp, .. } => *timestamp,
            InternalCollabEvent::ChatMessage { timestamp, .. } => *timestamp,
            InternalCollabEvent::TaskDispatched { timestamp, .. } => *timestamp,
            InternalCollabEvent::TaskCompleted { timestamp, .. } => *timestamp,
            InternalCollabEvent::SessionRegistered { timestamp, .. } => *timestamp,
            InternalCollabEvent::SessionStateChanged { timestamp, .. } => *timestamp,
        };

        let event = match event {
            InternalCollabEvent::OperatorOnline {
                operator_id,
                username,
                ..
            } => Event::OperatorOnline(OperatorOnlineEvent {
                operator_id: Some(Self::uuid_to_proto(operator_id)),
                username,
            }),
            InternalCollabEvent::OperatorOffline {
                operator_id,
                username,
                ..
            } => Event::OperatorOffline(OperatorOfflineEvent {
                operator_id: Some(Self::uuid_to_proto(operator_id)),
                username,
            }),
            InternalCollabEvent::SessionLocked {
                session_id,
                operator_id,
                username,
                ..
            } => Event::SessionLocked(SessionLockedEvent {
                session_id: Some(Self::uuid_to_proto(session_id)),
                operator_id: Some(Self::uuid_to_proto(operator_id)),
                username,
            }),
            InternalCollabEvent::SessionUnlocked {
                session_id,
                operator_id,
                username,
                ..
            } => Event::SessionUnlocked(SessionUnlockedEvent {
                session_id: Some(Self::uuid_to_proto(session_id)),
                operator_id: Some(Self::uuid_to_proto(operator_id)),
                username,
            }),
            InternalCollabEvent::SessionActivity {
                session_id,
                operator_id,
                activity,
                ..
            } => Event::SessionActivity(SessionActivityEvent {
                session_id: Some(Self::uuid_to_proto(session_id)),
                operator_id: Some(Self::uuid_to_proto(operator_id)),
                activity,
            }),
            InternalCollabEvent::ChatMessage {
                from_operator_id,
                from_username,
                message,
                session_id,
                ..
            } => Event::ChatMessage(ChatMessageEvent {
                from_operator_id: Some(Self::uuid_to_proto(from_operator_id)),
                from_username,
                message,
                session_id: session_id.map(Self::uuid_to_proto),
            }),
            InternalCollabEvent::TaskDispatched {
                task_id,
                session_id,
                operator_id,
                task_type,
                ..
            } => Event::TaskDispatched(TaskDispatchedEvent {
                task_id: Some(Self::uuid_to_proto(task_id)),
                session_id: Some(Self::uuid_to_proto(session_id)),
                operator_id: Some(Self::uuid_to_proto(operator_id)),
                task_type,
            }),
            InternalCollabEvent::TaskCompleted {
                task_id,
                session_id,
                success,
                ..
            } => Event::TaskCompleted(TaskCompletedEvent {
                task_id: Some(Self::uuid_to_proto(task_id)),
                session_id: Some(Self::uuid_to_proto(session_id)),
                success,
            }),
            // These events don't have direct proto equivalents yet
            InternalCollabEvent::SessionRegistered { .. } |
            InternalCollabEvent::SessionStateChanged { .. } => {
                // Skip these for now - could add proto messages later
                return CollabEvent {
                    timestamp: Some(Timestamp::from_millis(timestamp.timestamp_millis())),
                    event: None,
                };
            }
        };

        CollabEvent {
            timestamp: Some(Timestamp::from_millis(timestamp.timestamp_millis())),
            event: Some(event),
        }
    }
}

#[tonic::async_trait]
impl CollabService for CollabServiceImpl {
    type StreamEventsStream =
        Pin<Box<dyn Stream<Item = Result<CollabEvent, Status>> + Send + 'static>>;

    async fn stream_events(
        &self,
        request: Request<StreamCollabEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        // Register operator as online
        self.state.collab.operator_online(operator.id, operator.username.clone());

        let rx = self.state.collab.subscribe();
        let stream = BroadcastStream::new(rx)
            .filter_map(|result| {
                result.ok().map(|event| {
                    let proto_event = Self::internal_to_proto_event(event);
                    Ok(proto_event)
                })
            });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_online_operators(
        &self,
        request: Request<GetOnlineOperatorsRequest>,
    ) -> Result<Response<GetOnlineOperatorsResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let operators: Vec<ProtoPresence> = self
            .state
            .collab
            .online_operators()
            .into_iter()
            .map(|p| ProtoPresence {
                operator_id: Some(Self::uuid_to_proto(p.operator_id)),
                username: p.username,
                connected_at: Some(Timestamp::from_millis(p.connected_at.timestamp_millis())),
                last_activity: Some(Timestamp::from_millis(p.last_activity.timestamp_millis())),
                active_session: p.active_session.map(Self::uuid_to_proto),
            })
            .collect();

        Ok(Response::new(GetOnlineOperatorsResponse { operators }))
    }

    async fn set_active_session(
        &self,
        request: Request<SetActiveSessionRequest>,
    ) -> Result<Response<ProtoPresence>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();
        let session_id = req.session_id.map(|u| Self::proto_to_uuid(Some(u))).transpose()?;

        self.state.collab.set_active_session(operator.id, session_id);

        // Return updated presence
        let presence = self
            .state
            .collab
            .online_operators()
            .into_iter()
            .find(|p| p.operator_id == operator.id)
            .ok_or_else(|| Status::not_found("operator not online"))?;

        Ok(Response::new(ProtoPresence {
            operator_id: Some(Self::uuid_to_proto(presence.operator_id)),
            username: presence.username,
            connected_at: Some(Timestamp::from_millis(presence.connected_at.timestamp_millis())),
            last_activity: Some(Timestamp::from_millis(presence.last_activity.timestamp_millis())),
            active_session: presence.active_session.map(Self::uuid_to_proto),
        }))
    }

    async fn lock_session(
        &self,
        request: Request<LockSessionRequest>,
    ) -> Result<Response<ProtoLock>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionInteract)?;

        let req = request.into_inner();
        let session_id = Self::proto_to_uuid(req.session_id)?;

        self.state
            .collab
            .try_lock_session(session_id, operator.id, operator.username.clone(), req.reason)
            .map_err(|e| match e {
                SessionLockError::AlreadyLocked { holder_name, .. } => {
                    Status::already_exists(format!("session locked by {}", holder_name))
                }
                _ => Status::internal(e.to_string()),
            })?;

        let lock = self
            .state
            .collab
            .get_lock(session_id)
            .ok_or_else(|| Status::internal("lock not found after creation"))?;

        Ok(Response::new(ProtoLock {
            session_id: Some(Self::uuid_to_proto(lock.session_id)),
            operator_id: Some(Self::uuid_to_proto(lock.operator_id)),
            username: lock.username,
            locked_at: Some(Timestamp::from_millis(lock.locked_at.timestamp_millis())),
            reason: lock.reason,
        }))
    }

    async fn unlock_session(
        &self,
        request: Request<UnlockSessionRequest>,
    ) -> Result<Response<ProtoLock>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionInteract)?;

        let req = request.into_inner();
        let session_id = Self::proto_to_uuid(req.session_id)?;

        // Get lock info before unlocking
        let lock = self
            .state
            .collab
            .get_lock(session_id)
            .ok_or_else(|| Status::not_found("session not locked"))?;

        self.state
            .collab
            .unlock_session(session_id, operator.id)
            .map_err(|e| match e {
                SessionLockError::NotOwner { .. } => {
                    Status::permission_denied("you don't own this lock")
                }
                SessionLockError::NotLocked { .. } => Status::not_found("session not locked"),
                _ => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(ProtoLock {
            session_id: Some(Self::uuid_to_proto(lock.session_id)),
            operator_id: Some(Self::uuid_to_proto(lock.operator_id)),
            username: lock.username,
            locked_at: Some(Timestamp::from_millis(lock.locked_at.timestamp_millis())),
            reason: lock.reason,
        }))
    }

    async fn get_session_locks(
        &self,
        request: Request<GetSessionLocksRequest>,
    ) -> Result<Response<GetSessionLocksResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let locks: Vec<ProtoLock> = self
            .state
            .collab
            .all_locks()
            .into_iter()
            .map(|lock| ProtoLock {
                session_id: Some(Self::uuid_to_proto(lock.session_id)),
                operator_id: Some(Self::uuid_to_proto(lock.operator_id)),
                username: lock.username,
                locked_at: Some(Timestamp::from_millis(lock.locked_at.timestamp_millis())),
                reason: lock.reason,
            })
            .collect();

        Ok(Response::new(GetSessionLocksResponse { locks }))
    }

    async fn send_chat(
        &self,
        request: Request<SendChatRequest>,
    ) -> Result<Response<ChatMessageEvent>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();
        let session_id = req.session_id.map(|u| Self::proto_to_uuid(Some(u))).transpose()?;

        // Generate message ID and timestamp
        let msg_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();

        // Persist to database
        let record = db::ChatMessageRecord {
            id: msg_id,
            from_operator_id: operator.id,
            from_username: operator.username.clone(),
            message: req.message.clone(),
            session_id,
            created_at: now.timestamp_millis(),
        };
        self.state.db.chat().insert(&record).await
            .map_err(|e| Status::internal(format!("failed to persist chat: {}", e)))?;

        // Broadcast to connected operators
        self.state.collab.send_chat(
            operator.id,
            operator.username.clone(),
            req.message.clone(),
            session_id,
        );

        Ok(Response::new(ChatMessageEvent {
            from_operator_id: Some(Self::uuid_to_proto(operator.id)),
            from_username: operator.username,
            message: req.message,
            session_id: session_id.map(Self::uuid_to_proto),
        }))
    }

    async fn get_chat_history(
        &self,
        request: Request<GetChatHistoryRequest>,
    ) -> Result<Response<GetChatHistoryResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let req = request.into_inner();
        let session_id = req.session_id.map(|u| Self::proto_to_uuid(Some(u))).transpose()?;
        let limit = if req.limit == 0 { 100 } else { req.limit };
        let before = req.before.map(|t| t.millis);

        let messages = self.state.db.chat()
            .get_history(session_id, limit + 1, before) // +1 to check has_more
            .await
            .map_err(|e| Status::internal(format!("failed to fetch chat history: {}", e)))?;

        let has_more = messages.len() > limit as usize;
        let messages: Vec<ProtoChatRecord> = messages
            .into_iter()
            .take(limit as usize)
            .map(|m| ProtoChatRecord {
                id: Some(Self::uuid_to_proto(m.id)),
                from_operator_id: Some(Self::uuid_to_proto(m.from_operator_id)),
                from_username: m.from_username,
                message: m.message,
                session_id: m.session_id.map(Self::uuid_to_proto),
                created_at: Some(Timestamp::from_millis(m.created_at)),
            })
            .collect();

        Ok(Response::new(GetChatHistoryResponse { messages, has_more }))
    }

    async fn get_stats(
        &self,
        request: Request<GetCollabStatsRequest>,
    ) -> Result<Response<CollabStatsResponse>, Status> {
        let operator = get_operator_or_dev(&self.state.db, &request).await?;
        require_permission(&operator, Permission::SessionView)?;

        let stats = self.state.collab.stats();

        Ok(Response::new(CollabStatsResponse {
            online_operators: stats.online_operators as u32,
            active_sessions: stats.active_sessions as u32,
            locked_sessions: stats.locked_sessions as u32,
        }))
    }
}
