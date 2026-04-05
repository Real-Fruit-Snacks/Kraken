//! Webhook / SOAR integration module.
//!
//! # Overview
//!
//! [`WebhookService`] delivers HTTP POST notifications to external endpoints
//! whenever key C2 events occur (implant registration, check-in, task
//! completion, credential capture, etc.).
//!
//! # Payload format
//!
//! ```json
//! {
//!   "event": "ImplantCheckin",
//!   "timestamp": "2026-04-02T15:30:00Z",
//!   "data": { ... }
//! }
//! ```
//!
//! # Security
//!
//! When a `secret` is configured, each request includes an
//! `X-Kraken-Signature: sha256=<hmac>` header so the receiver can verify
//! authenticity.

mod service;
mod types;

pub use service::WebhookService;
pub use types::{WebhookConfig, WebhookEvent, WebhookPayload};
