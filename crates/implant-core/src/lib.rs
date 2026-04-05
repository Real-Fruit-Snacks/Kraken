//! Kraken Implant Core - Runtime and task execution for implants

pub mod error;
pub mod jobs;
pub mod registry;
pub mod runtime;
pub mod sysinfo;
pub mod tasks;
pub mod transport;

// Evasion module included unconditionally (stubs on non-Windows) for testing
pub mod evasion;

pub use error::ImplantError;
pub use runtime::ImplantRuntime;
pub use transport::{HttpTransport, TransportChain};
