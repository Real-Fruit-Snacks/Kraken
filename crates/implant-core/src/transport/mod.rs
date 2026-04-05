//! Transport layer for implant-server communication
//!
//! Provides resilient communication through TransportChain with automatic
//! fallback when primary transports fail.

mod chain;
mod dns;
mod http;

pub use chain::TransportChain;
#[allow(unused_imports)]
pub use dns::DnsTransport;
pub use http::HttpTransport;
