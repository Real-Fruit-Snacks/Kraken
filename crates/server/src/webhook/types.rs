//! Webhook types for SOAR integration

use serde::{Deserialize, Serialize};

/// Configuration for a single webhook endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Destination URL to POST payloads to.
    pub url: String,
    /// Which events this webhook should receive. Empty means all events.
    pub events: Vec<WebhookEvent>,
    /// Optional HMAC-SHA256 signing secret. When set, each request includes
    /// an `X-Kraken-Signature` header of the form `sha256=<hex>`.
    pub secret: Option<String>,
    /// Whether this webhook is active.
    pub enabled: bool,
}

/// Discrete events that can trigger webhook notifications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    ImplantCheckin,
    ImplantRegistered,
    ImplantDead,
    TaskQueued,
    TaskCompleted,
    TaskFailed,
    CredentialCaptured,
    FileDownloaded,
    SessionElevated,
    ModuleLoaded,
}

impl WebhookEvent {
    /// Return the canonical string name used in `X-Kraken-Event` headers.
    pub fn as_str(&self) -> &'static str {
        match self {
            WebhookEvent::ImplantCheckin => "ImplantCheckin",
            WebhookEvent::ImplantRegistered => "ImplantRegistered",
            WebhookEvent::ImplantDead => "ImplantDead",
            WebhookEvent::TaskQueued => "TaskQueued",
            WebhookEvent::TaskCompleted => "TaskCompleted",
            WebhookEvent::TaskFailed => "TaskFailed",
            WebhookEvent::CredentialCaptured => "CredentialCaptured",
            WebhookEvent::FileDownloaded => "FileDownloaded",
            WebhookEvent::SessionElevated => "SessionElevated",
            WebhookEvent::ModuleLoaded => "ModuleLoaded",
        }
    }
}

/// The JSON body delivered to webhook endpoints.
#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    /// The event that triggered this notification.
    pub event: WebhookEvent,
    /// RFC3339 timestamp of when the event occurred.
    pub timestamp: String,
    /// Event-specific data.
    pub data: serde_json::Value,
}
