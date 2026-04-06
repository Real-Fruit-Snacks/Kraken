//! gRPC service implementations

use tonic::{Code, Status};

pub mod audit_service;
pub mod bof_service;
pub mod inject_service;
pub mod collab_service;
pub mod implant_service;
pub mod job_service;
pub mod listener_service;
pub mod loot_service;
pub mod mesh_service;
pub mod module_service;
pub mod operator_service;
pub mod payload_service;
pub mod proxy_service;
pub mod report_service;
pub mod task_service;

pub use audit_service::AuditServiceImpl;
pub use bof_service::BOFServiceImpl;
pub use inject_service::InjectServiceImpl;
pub use collab_service::CollabServiceImpl;
pub use implant_service::ImplantServiceImpl;
pub use job_service::JobServiceImpl;
pub use listener_service::ListenerServiceImpl;
pub use loot_service::LootServiceImpl;
pub use mesh_service::MeshServiceImpl;
pub use module_service::ModuleServiceImpl;
pub use operator_service::OperatorServiceImpl;
pub use payload_service::PayloadServiceImpl;
pub use proxy_service::ProxyServiceImpl;
pub use report_service::ReportServiceImpl;
pub use task_service::TaskServiceImpl;

/// Structured error types for gRPC services
#[derive(Debug, Clone)]
pub enum GrpcError {
    /// Resource not found (404)
    NotFound { resource: String, id: String },
    /// Permission denied (403)
    PermissionDenied { action: String, reason: String },
    /// Invalid input/parameters (400)
    InvalidInput { field: String, reason: String },
    /// Internal server error (500)
    Internal { operation: String, details: String },
    /// Resource already exists (409)
    AlreadyExists { resource: String, id: String },
    /// Precondition failed (412)
    PreconditionFailed { condition: String },
    /// Operation unavailable (503)
    Unavailable { service: String, reason: String },
}

impl GrpcError {
    /// Convert to tonic Status with appropriate error code and user-friendly message
    pub fn to_status(self) -> Status {
        match self {
            GrpcError::NotFound { resource, id } => {
                Status::new(
                    Code::NotFound,
                    format!("{} '{}' not found", resource, id),
                )
            }
            GrpcError::PermissionDenied { action, reason } => {
                Status::new(
                    Code::PermissionDenied,
                    format!("Permission denied for {}: {}", action, reason),
                )
            }
            GrpcError::InvalidInput { field, reason } => {
                Status::new(
                    Code::InvalidArgument,
                    format!("Invalid input for '{}': {}", field, reason),
                )
            }
            GrpcError::Internal { operation, details } => {
                Status::new(
                    Code::Internal,
                    format!("Internal error during {}: {}", operation, details),
                )
            }
            GrpcError::AlreadyExists { resource, id } => {
                Status::new(
                    Code::AlreadyExists,
                    format!("{} '{}' already exists", resource, id),
                )
            }
            GrpcError::PreconditionFailed { condition } => {
                Status::new(
                    Code::FailedPrecondition,
                    format!("Precondition failed: {}", condition),
                )
            }
            GrpcError::Unavailable { service, reason } => {
                Status::new(
                    Code::Unavailable,
                    format!("Service '{}' unavailable: {}", service, reason),
                )
            }
        }
    }
}

/// Helper functions for common error scenarios
impl GrpcError {
    /// Create a not found error for a resource
    pub fn not_found(resource: impl Into<String>, id: impl Into<String>) -> Self {
        GrpcError::NotFound {
            resource: resource.into(),
            id: id.into(),
        }
    }

    /// Create a permission denied error
    pub fn permission_denied(action: impl Into<String>, reason: impl Into<String>) -> Self {
        GrpcError::PermissionDenied {
            action: action.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid input error
    pub fn invalid_input(field: impl Into<String>, reason: impl Into<String>) -> Self {
        GrpcError::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Create an internal error
    pub fn internal(operation: impl Into<String>, details: impl Into<String>) -> Self {
        GrpcError::Internal {
            operation: operation.into(),
            details: details.into(),
        }
    }

    /// Create an already exists error
    pub fn already_exists(resource: impl Into<String>, id: impl Into<String>) -> Self {
        GrpcError::AlreadyExists {
            resource: resource.into(),
            id: id.into(),
        }
    }

    /// Create a precondition failed error
    pub fn precondition_failed(condition: impl Into<String>) -> Self {
        GrpcError::PreconditionFailed {
            condition: condition.into(),
        }
    }

    /// Create an unavailable error
    pub fn unavailable(service: impl Into<String>, reason: impl Into<String>) -> Self {
        GrpcError::Unavailable {
            service: service.into(),
            reason: reason.into(),
        }
    }
}
