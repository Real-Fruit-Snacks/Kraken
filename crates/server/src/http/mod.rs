//! HTTP listener for implant check-ins

pub mod handler;
pub mod profile;

pub use handler::build_router;
pub use profile::{decode_request, encode_response, validate_request};
