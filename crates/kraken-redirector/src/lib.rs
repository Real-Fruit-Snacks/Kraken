//! kraken-redirector library interface
//!
//! Re-exports the redirector modules for use in integration tests and
//! other crates that need programmatic access to config generation.

pub mod azure;
pub mod certs;
pub mod cloudflare;
pub mod lambda;
pub mod nginx;
