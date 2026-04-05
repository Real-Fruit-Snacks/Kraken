//! WebSocket real-time event streaming for web UI
//!
//! Subscribes to the server's broadcast channels (ImplantEvent, TaskResultEvent)
//! and forwards events to connected WebSocket clients as JSON.

use std::sync::Arc;

use axum::{
    extract::{ws::WebSocket, Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::ServerState;
use protocol::{implant_event::Event as ProtoEvent, ImplantEvent, TaskResultEvent};

/// WebSocket event sent to clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketEvent {
    /// Event type (SessionNew, TaskComplete, etc.)
    #[serde(rename = "type")]
    pub event_type: String,
    /// Unix timestamp (milliseconds)
    pub timestamp: i64,
    /// Event-specific data
    pub data: serde_json::Value,
}

/// Query parameters for WebSocket connection
#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// JWT authentication token
    token: Option<String>,
}

/// WebSocket upgrade handler with JWT authentication
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
    Query(query): Query<WsQuery>,
) -> Response {
    // Extract and validate JWT token
    let token = match query.token {
        Some(t) => t,
        None => {
            tracing::warn!("WebSocket connection rejected: missing token");
            return (StatusCode::UNAUTHORIZED, "Missing authentication token").into_response();
        }
    };

    // Validate token
    let claims = match state.jwt.validate_token(&token) {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!(error = %e, "WebSocket connection rejected: invalid token");
            return (StatusCode::UNAUTHORIZED, "Invalid authentication token").into_response();
        }
    };

    // Log successful authentication
    tracing::info!(
        operator_id = %claims.sub,
        username = %claims.username,
        role = %claims.role,
        "WebSocket client authenticated"
    );

    // Upgrade connection
    ws.on_upgrade(|socket| handle_websocket(socket, state, claims))
}

/// Handle an active WebSocket connection
async fn handle_websocket(
    mut socket: WebSocket,
    state: Arc<ServerState>,
    claims: crate::auth::jwt::Claims,
) {
    tracing::info!(
        operator_id = %claims.sub,
        username = %claims.username,
        "WebSocket client connected"
    );

    // Subscribe to broadcast channels
    let events_rx = state.subscribe_events();
    let task_results_rx = state.subscribe_task_results();
    let loot_rx = state.subscribe_loot();

    // Convert to streams
    let events_stream = BroadcastStream::new(events_rx);
    let task_results_stream = BroadcastStream::new(task_results_rx);
    let loot_stream = BroadcastStream::new(loot_rx);

    // Merge all streams
    let mut merged = events_stream
        .filter_map(|r| r.ok())
        .map(implant_event_to_ws)
        .merge(task_results_stream.filter_map(|r| r.ok()).map(task_result_to_ws))
        .merge(loot_stream.filter_map(|r| r.ok()).map(loot_event_to_ws));

    // Forward events to WebSocket
    while let Some(event) = merged.next().await {
        let json = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize WebSocket event");
                continue;
            }
        };

        if socket
            .send(axum::extract::ws::Message::Text(json))
            .await
            .is_err()
        {
            tracing::info!("WebSocket client disconnected");
            break;
        }
    }
}

/// Convert ImplantEvent to WebSocketEvent
fn implant_event_to_ws(event: ImplantEvent) -> WebSocketEvent {
    let timestamp = event
        .timestamp
        .map(|t| t.millis)
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    let (event_type, data) = match event.event {
        Some(ProtoEvent::Registered(e)) => {
            let implant_id = e
                .implant_id
                .map(|id| hex::encode(id.value))
                .unwrap_or_default();
            (
                "SessionNew".to_string(),
                serde_json::json!({
                    "implant_id": implant_id,
                }),
            )
        }
        Some(ProtoEvent::CheckedIn(e)) => {
            let implant_id = e
                .implant_id
                .map(|id| hex::encode(id.value))
                .unwrap_or_default();
            (
                "SessionCheckin".to_string(),
                serde_json::json!({
                    "implant_id": implant_id,
                }),
            )
        }
        Some(ProtoEvent::Lost(e)) => {
            let implant_id = e
                .implant_id
                .map(|id| hex::encode(id.value))
                .unwrap_or_default();
            (
                "SessionLost".to_string(),
                serde_json::json!({
                    "implant_id": implant_id,
                }),
            )
        }
        Some(ProtoEvent::Recovered(e)) => {
            let implant_id = e
                .implant_id
                .map(|id| hex::encode(id.value))
                .unwrap_or_default();
            (
                "SessionRecovered".to_string(),
                serde_json::json!({
                    "implant_id": implant_id,
                }),
            )
        }
        Some(ProtoEvent::Burned(e)) => {
            let implant_id = e
                .implant_id
                .map(|id| hex::encode(id.value))
                .unwrap_or_default();
            (
                "SessionBurned".to_string(),
                serde_json::json!({
                    "implant_id": implant_id,
                }),
            )
        }
        Some(ProtoEvent::Retired(e)) => {
            let implant_id = e
                .implant_id
                .map(|id| hex::encode(id.value))
                .unwrap_or_default();
            (
                "SessionRetired".to_string(),
                serde_json::json!({
                    "implant_id": implant_id,
                }),
            )
        }
        None => (
            "Unknown".to_string(),
            serde_json::json!({}),
        ),
    };

    WebSocketEvent {
        event_type,
        timestamp,
        data,
    }
}

/// Convert TaskResultEvent to WebSocketEvent
fn task_result_to_ws(event: TaskResultEvent) -> WebSocketEvent {
    let timestamp = event
        .completed_at
        .map(|t| t.millis)
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    let task_id = event
        .task_id
        .map(|id| hex::encode(id.value))
        .unwrap_or_default();
    let implant_id = event
        .implant_id
        .map(|id| hex::encode(id.value))
        .unwrap_or_default();

    let event_type = match event.status {
        1 => "TaskComplete",    // Completed
        2 => "TaskFailed",      // Failed
        _ => "TaskUpdate",      // Other statuses
    };

    let mut data = serde_json::json!({
        "task_id": task_id,
        "implant_id": implant_id,
        "status": event.status,
    });

    if let Some(error) = event.error {
        data["error"] = serde_json::json!({
            "code": error.code,
            "message": error.message,
        });
    }

    WebSocketEvent {
        event_type: event_type.to_string(),
        timestamp,
        data,
    }
}

/// Convert LootEvent to WebSocketEvent
fn loot_event_to_ws(event: crate::state::LootEvent) -> WebSocketEvent {
    let timestamp = chrono::Utc::now().timestamp_millis();

    let data = serde_json::json!({
        "loot_id": hex::encode(&event.loot_id),
        "implant_id": hex::encode(&event.implant_id),
        "type": event.loot_type,
        "description": event.description,
    });

    WebSocketEvent {
        event_type: "LootCaptured".to_string(),
        timestamp,
        data,
    }
}
