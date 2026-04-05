//! Kraken Protocol - Generated protobuf types and gRPC services

pub mod convert;
pub mod generated;
pub mod helpers;

// Re-export generated types
pub use generated::kraken::*;

// Re-export service clients and servers (only when grpc feature is enabled)
#[cfg(feature = "grpc")]
pub use generated::kraken::implant_service_client::ImplantServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::implant_service_server::{ImplantService, ImplantServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::listener_service_client::ListenerServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::listener_service_server::{ListenerService, ListenerServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::operator_service_client::OperatorServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::operator_service_server::{OperatorService, OperatorServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::task_service_client::TaskServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::task_service_server::{TaskService, TaskServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::loot_service_client::LootServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::loot_service_server::{LootService, LootServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::module_service_client::ModuleServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::module_service_server::{ModuleService, ModuleServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::mesh_service_client::MeshServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::mesh_service_server::{MeshService, MeshServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::collab_service_client::CollabServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::collab_service_server::{CollabService, CollabServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::proxy_service_client::ProxyServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::proxy_service_server::{ProxyService, ProxyServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::bof_service_client::BofServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::bof_service_server::{BofService, BofServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::inject_service_client::InjectServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::inject_service_server::{InjectService, InjectServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::payload_service_client::PayloadServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::payload_service_server::{PayloadService, PayloadServiceServer};
#[cfg(feature = "grpc")]
pub use generated::kraken::report_service_client::ReportServiceClient;
#[cfg(feature = "grpc")]
pub use generated::kraken::report_service_server::{ReportService, ReportServiceServer};

// Re-export conversion helpers
pub use convert::{
    implant_id_from_opt, implant_state_from_i32, listener_id_from_opt, operator_id_from_opt,
    task_id_from_opt,
};
pub use helpers::{decode, decode_with_length, encode, encode_with_length};

#[cfg(test)]
mod proptests;

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use insta::assert_debug_snapshot;

    #[test]
    fn test_checkin_default() {
        let checkin = CheckIn::default();
        assert_debug_snapshot!("checkin_default", checkin);
    }

    #[test]
    fn test_checkin_populated() {
        let checkin = CheckIn {
            implant_id: Some(Uuid {
                value: vec![0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0x12, 0x34,
                           0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
            }),
            local_time: Some(Timestamp {
                millis: 1711843200000, // Unix millis
            }),
            task_responses: vec![],
            loaded_modules: vec!["mod-shell".to_string(), "mod-file".to_string()],
        };
        assert_debug_snapshot!("checkin_populated", checkin);
    }

    #[test]
    fn test_checkin_response_default() {
        let response = CheckInResponse::default();
        assert_debug_snapshot!("checkin_response_default", response);
    }

    #[test]
    fn test_checkin_response_with_tasks() {
        let response = CheckInResponse {
            new_checkin_interval: Some(60),
            new_jitter_percent: Some(20),
            tasks: vec![
                Task {
                    task_id: Some(Uuid {
                        value: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
                    }),
                    task_type: "shell".to_string(),
                    task_data: b"whoami".to_vec(),
                    issued_at: None,
                    operator_id: None,
                },
                Task {
                    task_id: Some(Uuid {
                        value: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
                    }),
                    task_type: "file_list".to_string(),
                    task_data: b"C:\\Users".to_vec(),
                    issued_at: None,
                    operator_id: None,
                },
            ],
            commands: vec![],
        };
        assert_debug_snapshot!("checkin_response_with_tasks", response);
    }

    #[test]
    fn test_task_status_enum() {
        // Verify all task status values
        let statuses = vec![
            ("unspecified", TaskStatus::Unspecified as i32),
            ("queued", TaskStatus::Queued as i32),
            ("dispatched", TaskStatus::Dispatched as i32),
            ("completed", TaskStatus::Completed as i32),
            ("failed", TaskStatus::Failed as i32),
            ("cancelled", TaskStatus::Cancelled as i32),
            ("expired", TaskStatus::Expired as i32),
        ];
        assert_debug_snapshot!("task_statuses", statuses);
    }

    #[test]
    fn test_task_response() {
        let response = TaskResponse {
            task_id: Some(Uuid {
                value: vec![0xab, 0xcd, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            }),
            status: TaskStatus::Completed as i32,
            completed_at: Some(Timestamp {
                millis: 1711843300500, // Unix millis
            }),
            result: Some(task_response::Result::Success(TaskSuccess {
                result_data: b"command output here".to_vec(),
            })),
        };
        assert_debug_snapshot!("task_response_success", response);
    }
}
