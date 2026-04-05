//! Kraken Server — gRPC operator interface and HTTP implant listener

pub mod auth;
pub mod collab;
pub mod dns;
pub mod error;
pub mod grpc;
pub mod http;
pub mod listener;
pub mod services;
pub mod socks_server;
pub mod state;
pub mod webhook;
pub mod websocket;

pub use collab::CollabHub;
pub use dns::{DnsListener, DnsListenerConfig, DnsError};
pub use error::{ServerError, ServerResult};
pub use state::ServerState;
pub use webhook::{WebhookConfig, WebhookEvent, WebhookService};

#[cfg(test)]
pub mod mocks;
