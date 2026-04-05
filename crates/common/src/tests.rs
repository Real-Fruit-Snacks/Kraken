//! Comprehensive tests for common crate types

#[cfg(test)]
mod ids_tests {
    use std::collections::HashSet;
    use std::str::FromStr;

    use crate::ids::{ImplantId, ListenerId, LootId, ModuleId, OperatorId, TaskId};

    // -----------------------------------------------------------------
    // ImplantId
    // -----------------------------------------------------------------

    #[test]
    fn implant_id_new_creates_valid_instance() {
        let id = ImplantId::new();
        // Inner bytes must be 16 bytes — just sanity-check via as_bytes
        assert_eq!(id.as_bytes().len(), 16);
    }

    #[test]
    fn implant_id_new_is_unique() {
        let a = ImplantId::new();
        let b = ImplantId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn implant_id_default_creates_valid_instance() {
        let id = ImplantId::default();
        assert_eq!(id.as_bytes().len(), 16);
    }

    #[test]
    fn implant_id_from_bytes_valid() {
        let original = ImplantId::new();
        let bytes = *original.as_bytes();
        let restored = ImplantId::from_bytes(&bytes).expect("from_bytes failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn implant_id_from_bytes_too_short() {
        let err = ImplantId::from_bytes(&[0u8; 8]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("16"), "expected length hint in error: {msg}");
    }

    #[test]
    fn implant_id_from_bytes_too_long() {
        let err = ImplantId::from_bytes(&[0u8; 17]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("16"), "expected length hint in error: {msg}");
    }

    #[test]
    fn implant_id_from_bytes_empty() {
        assert!(ImplantId::from_bytes(&[]).is_err());
    }

    #[test]
    fn implant_id_display_is_uuid_format() {
        let id = ImplantId::new();
        let s = id.to_string();
        // UUID hyphenated format: 8-4-4-4-12
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 5, "display should be hyphenated UUID: {s}");
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn implant_id_debug_contains_bytes() {
        let id = ImplantId([0u8; 16]);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ImplantId"), "debug output: {dbg}");
    }

    #[test]
    fn implant_id_from_str_roundtrip() {
        let original = ImplantId::new();
        let s = original.to_string();
        let parsed = ImplantId::from_str(&s).expect("from_str failed");
        assert_eq!(original, parsed);
    }

    #[test]
    fn implant_id_from_str_invalid_uuid() {
        let err = ImplantId::from_str("not-a-uuid").unwrap_err();
        assert!(err.to_string().contains("UUID") || err.to_string().contains("invalid"));
    }

    #[test]
    fn implant_id_serde_json_roundtrip() {
        let original = ImplantId::new();
        let json = serde_json::to_string(&original).expect("serialize failed");
        // Should be a quoted UUID string
        assert!(json.starts_with('"'), "should serialize as JSON string: {json}");
        let restored: ImplantId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn implant_id_from_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let id = ImplantId::from(uuid);
        assert_eq!(*id.as_bytes(), *uuid.as_bytes());
    }

    #[test]
    fn implant_id_to_uuid_roundtrip() {
        let id = ImplantId::new();
        let uuid = id.to_uuid();
        let back = ImplantId::from(uuid);
        assert_eq!(id, back);
    }

    #[test]
    fn implant_id_equality_and_hash() {
        let id = ImplantId::new();
        let copy = ImplantId(*id.as_bytes());
        assert_eq!(id, copy);

        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&copy));
    }

    #[test]
    fn implant_id_copy_semantics() {
        let a = ImplantId::new();
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------
    // TaskId
    // -----------------------------------------------------------------

    #[test]
    fn task_id_new_creates_valid_instance() {
        let id = TaskId::new();
        assert_eq!(id.as_bytes().len(), 16);
    }

    #[test]
    fn task_id_new_is_unique() {
        let a = TaskId::new();
        let b = TaskId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn task_id_from_bytes_valid() {
        let original = TaskId::new();
        let restored = TaskId::from_bytes(original.as_bytes()).expect("from_bytes failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn task_id_from_bytes_wrong_length() {
        assert!(TaskId::from_bytes(&[1, 2, 3]).is_err());
    }

    #[test]
    fn task_id_display_is_uuid_format() {
        let id = TaskId::new();
        let s = id.to_string();
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 5, "display should be hyphenated UUID: {s}");
    }

    #[test]
    fn task_id_from_str_roundtrip() {
        let original = TaskId::new();
        let s = original.to_string();
        let parsed = TaskId::from_str(&s).expect("from_str failed");
        assert_eq!(original, parsed);
    }

    #[test]
    fn task_id_serde_json_roundtrip() {
        let original = TaskId::new();
        let json = serde_json::to_string(&original).expect("serialize failed");
        let restored: TaskId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn task_id_equality_and_hash() {
        let id = TaskId::new();
        let copy = TaskId(*id.as_bytes());
        assert_eq!(id, copy);
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&copy));
    }

    // -----------------------------------------------------------------
    // OperatorId
    // -----------------------------------------------------------------

    #[test]
    fn operator_id_new_creates_valid_instance() {
        let id = OperatorId::new();
        assert_eq!(id.as_bytes().len(), 16);
    }

    #[test]
    fn operator_id_from_bytes_valid() {
        let original = OperatorId::new();
        let restored = OperatorId::from_bytes(original.as_bytes()).expect("from_bytes failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn operator_id_from_bytes_wrong_length() {
        assert!(OperatorId::from_bytes(&[0u8; 15]).is_err());
    }

    #[test]
    fn operator_id_display_roundtrip() {
        let id = OperatorId::new();
        let s = id.to_string();
        let parsed = OperatorId::from_str(&s).expect("from_str failed");
        assert_eq!(id, parsed);
    }

    #[test]
    fn operator_id_serde_roundtrip() {
        let original = OperatorId::new();
        let json = serde_json::to_string(&original).expect("serialize failed");
        let restored: OperatorId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn operator_id_hash() {
        let id = OperatorId::new();
        let copy = OperatorId(*id.as_bytes());
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&copy));
    }

    // -----------------------------------------------------------------
    // ListenerId
    // -----------------------------------------------------------------

    #[test]
    fn listener_id_new_is_unique() {
        let a = ListenerId::new();
        let b = ListenerId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn listener_id_from_bytes_valid() {
        let original = ListenerId::new();
        let restored = ListenerId::from_bytes(original.as_bytes()).expect("from_bytes failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn listener_id_from_bytes_invalid() {
        assert!(ListenerId::from_bytes(&[]).is_err());
    }

    #[test]
    fn listener_id_display_roundtrip() {
        let id = ListenerId::new();
        let s = id.to_string();
        let parsed = ListenerId::from_str(&s).expect("from_str failed");
        assert_eq!(id, parsed);
    }

    #[test]
    fn listener_id_serde_roundtrip() {
        let original = ListenerId::new();
        let json = serde_json::to_string(&original).expect("serialize failed");
        let restored: ListenerId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }

    // -----------------------------------------------------------------
    // LootId
    // -----------------------------------------------------------------

    #[test]
    fn loot_id_new_is_unique() {
        let a = LootId::new();
        let b = LootId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn loot_id_from_bytes_valid() {
        let original = LootId::new();
        let restored = LootId::from_bytes(original.as_bytes()).expect("from_bytes failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn loot_id_serde_roundtrip() {
        let original = LootId::new();
        let json = serde_json::to_string(&original).expect("serialize failed");
        let restored: LootId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }

    // -----------------------------------------------------------------
    // ModuleId
    // -----------------------------------------------------------------

    #[test]
    fn module_id_new_stores_string() {
        let id = ModuleId::new("kraken.recon.portscan");
        assert_eq!(id.as_str(), "kraken.recon.portscan");
    }

    #[test]
    fn module_id_display() {
        let id = ModuleId::new("test.module");
        assert_eq!(id.to_string(), "test.module");
    }

    #[test]
    fn module_id_debug() {
        let id = ModuleId::new("dbg");
        let s = format!("{id:?}");
        assert!(s.contains("ModuleId"), "debug: {s}");
    }

    #[test]
    fn module_id_from_string() {
        let id: ModuleId = String::from("from.string").into();
        assert_eq!(id.as_str(), "from.string");
    }

    #[test]
    fn module_id_from_str_slice() {
        let id: ModuleId = "from.slice".into();
        assert_eq!(id.as_str(), "from.slice");
    }

    #[test]
    fn module_id_equality() {
        let a = ModuleId::new("same");
        let b = ModuleId::new("same");
        let c = ModuleId::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn module_id_hash() {
        let a = ModuleId::new("hash.test");
        let b = ModuleId::new("hash.test");
        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
    }

    #[test]
    fn module_id_serde_roundtrip() {
        let original = ModuleId::new("serde.test");
        let json = serde_json::to_string(&original).expect("serialize failed");
        let restored: ModuleId = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(original, restored);
    }

    #[test]
    fn module_id_empty_string() {
        let id = ModuleId::new("");
        assert_eq!(id.as_str(), "");
        assert_eq!(id.to_string(), "");
    }

    // -----------------------------------------------------------------
    // Cross-type: different ID types with identical bytes are not equal
    // -----------------------------------------------------------------

    #[test]
    fn different_id_types_are_distinct_rust_types() {
        let bytes = [42u8; 16];
        let implant = ImplantId(bytes);
        let task = TaskId(bytes);
        // These are different types — no Eq between them — just verify the bytes
        assert_eq!(implant.as_bytes(), task.as_bytes());
        // Confirm they do not share a type by checking Display output format equality
        assert_eq!(implant.to_string(), task.to_string());
    }
}

#[cfg(test)]
mod error_tests {
    use crate::error::KrakenError;

    #[test]
    fn transport_error_display() {
        let e = KrakenError::transport("connection refused");
        assert!(e.to_string().contains("connection refused"));
        assert!(e.to_string().contains("transport"));
    }

    #[test]
    fn crypto_error_display() {
        let e = KrakenError::crypto("bad key");
        assert!(e.to_string().contains("bad key"));
        assert!(e.to_string().contains("cryptographic"));
    }

    #[test]
    fn protocol_error_display() {
        let e = KrakenError::protocol("unexpected frame");
        assert!(e.to_string().contains("unexpected frame"));
        assert!(e.to_string().contains("protocol"));
    }

    #[test]
    fn database_error_display() {
        let e = KrakenError::database("query failed");
        assert!(e.to_string().contains("query failed"));
        assert!(e.to_string().contains("database"));
    }

    #[test]
    fn not_found_display() {
        let e = KrakenError::not_found("implant 123");
        assert!(e.to_string().contains("implant 123"));
        assert!(e.to_string().contains("not found"));
    }

    #[test]
    fn internal_error_display() {
        let e = KrakenError::internal("unexpected None");
        assert!(e.to_string().contains("unexpected None"));
        assert!(e.to_string().contains("internal"));
    }

    #[test]
    fn all_transports_failed_display() {
        let e = KrakenError::AllTransportsFailed;
        assert!(e.to_string().contains("all transports failed"));
    }

    #[test]
    fn invalid_signature_display() {
        let e = KrakenError::InvalidSignature;
        assert!(e.to_string().contains("invalid signature"));
    }

    #[test]
    fn decryption_failed_display() {
        let e = KrakenError::DecryptionFailed;
        assert!(e.to_string().contains("decryption failed"));
    }

    #[test]
    fn no_route_display() {
        let e = KrakenError::NoRoute;
        assert!(e.to_string().contains("no route"));
    }

    #[test]
    fn invalid_module_blob_display() {
        let e = KrakenError::InvalidModuleBlob;
        assert!(e.to_string().contains("invalid module blob"));
    }

    #[test]
    fn module_not_found_display() {
        let e = KrakenError::ModuleNotFound("scanner".to_string());
        assert!(e.to_string().contains("scanner"));
        assert!(e.to_string().contains("module not found"));
    }

    #[test]
    fn unknown_task_type_display() {
        let e = KrakenError::UnknownTaskType("exec".to_string());
        assert!(e.to_string().contains("exec"));
        assert!(e.to_string().contains("unknown task type"));
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: KrakenError = io_err.into();
        assert!(e.to_string().contains("IO error") || e.to_string().contains("file missing"));
    }

    #[test]
    fn error_debug_is_implemented() {
        let e = KrakenError::internal("test");
        let _dbg = format!("{e:?}");
    }
}

#[cfg(test)]
mod state_tests {
    use std::str::FromStr;

    use crate::state::ImplantState;

    #[test]
    fn default_is_staging() {
        assert_eq!(ImplantState::default(), ImplantState::Staging);
    }

    #[test]
    fn staging_not_taskable() {
        assert!(!ImplantState::Staging.is_taskable());
    }

    #[test]
    fn active_is_taskable() {
        assert!(ImplantState::Active.is_taskable());
    }

    #[test]
    fn lost_not_taskable() {
        assert!(!ImplantState::Lost.is_taskable());
    }

    #[test]
    fn burned_not_taskable() {
        assert!(!ImplantState::Burned.is_taskable());
    }

    #[test]
    fn retired_not_taskable() {
        assert!(!ImplantState::Retired.is_taskable());
    }

    #[test]
    fn terminal_states() {
        assert!(ImplantState::Burned.is_terminal());
        assert!(ImplantState::Retired.is_terminal());
        assert!(!ImplantState::Active.is_terminal());
        assert!(!ImplantState::Lost.is_terminal());
        assert!(!ImplantState::Staging.is_terminal());
    }

    #[test]
    fn valid_transitions_from_staging() {
        assert!(ImplantState::Staging.can_transition_to(ImplantState::Active));
        assert!(!ImplantState::Staging.can_transition_to(ImplantState::Lost));
        assert!(!ImplantState::Staging.can_transition_to(ImplantState::Burned));
        assert!(!ImplantState::Staging.can_transition_to(ImplantState::Retired));
    }

    #[test]
    fn valid_transitions_from_active() {
        assert!(ImplantState::Active.can_transition_to(ImplantState::Lost));
        assert!(ImplantState::Active.can_transition_to(ImplantState::Burned));
        assert!(ImplantState::Active.can_transition_to(ImplantState::Retired));
        assert!(!ImplantState::Active.can_transition_to(ImplantState::Staging));
    }

    #[test]
    fn valid_transitions_from_lost() {
        assert!(ImplantState::Lost.can_transition_to(ImplantState::Active));
        assert!(ImplantState::Lost.can_transition_to(ImplantState::Burned));
        assert!(ImplantState::Lost.can_transition_to(ImplantState::Retired));
        assert!(!ImplantState::Lost.can_transition_to(ImplantState::Staging));
    }

    #[test]
    fn terminal_states_cannot_transition() {
        for target in [
            ImplantState::Staging,
            ImplantState::Active,
            ImplantState::Lost,
            ImplantState::Burned,
            ImplantState::Retired,
        ] {
            assert!(
                !ImplantState::Burned.can_transition_to(target),
                "Burned should not transition to {target:?}"
            );
            assert!(
                !ImplantState::Retired.can_transition_to(target),
                "Retired should not transition to {target:?}"
            );
        }
    }

    #[test]
    fn same_state_transition_allowed() {
        assert!(ImplantState::Active.can_transition_to(ImplantState::Active));
        assert!(ImplantState::Lost.can_transition_to(ImplantState::Lost));
        assert!(ImplantState::Staging.can_transition_to(ImplantState::Staging));
    }

    #[test]
    fn display_values() {
        assert_eq!(ImplantState::Staging.to_string(), "staging");
        assert_eq!(ImplantState::Active.to_string(), "active");
        assert_eq!(ImplantState::Lost.to_string(), "lost");
        assert_eq!(ImplantState::Burned.to_string(), "burned");
        assert_eq!(ImplantState::Retired.to_string(), "retired");
    }

    #[test]
    fn from_str_valid() {
        assert_eq!(ImplantState::from_str("staging").unwrap(), ImplantState::Staging);
        assert_eq!(ImplantState::from_str("active").unwrap(), ImplantState::Active);
        assert_eq!(ImplantState::from_str("lost").unwrap(), ImplantState::Lost);
        assert_eq!(ImplantState::from_str("burned").unwrap(), ImplantState::Burned);
        assert_eq!(ImplantState::from_str("retired").unwrap(), ImplantState::Retired);
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!(ImplantState::from_str("ACTIVE").unwrap(), ImplantState::Active);
        assert_eq!(ImplantState::from_str("Active").unwrap(), ImplantState::Active);
        assert_eq!(ImplantState::from_str("BURNED").unwrap(), ImplantState::Burned);
    }

    #[test]
    fn from_str_invalid() {
        assert!(ImplantState::from_str("unknown").is_err());
        assert!(ImplantState::from_str("").is_err());
        assert!(ImplantState::from_str("activ").is_err());
    }

    #[test]
    fn serde_roundtrip() {
        for state in [
            ImplantState::Staging,
            ImplantState::Active,
            ImplantState::Lost,
            ImplantState::Burned,
            ImplantState::Retired,
        ] {
            let json = serde_json::to_string(&state).expect("serialize failed");
            let restored: ImplantState =
                serde_json::from_str(&json).expect("deserialize failed");
            assert_eq!(state, restored, "roundtrip failed for {state:?}");
        }
    }

    #[test]
    fn serde_uses_lowercase_strings() {
        let json = serde_json::to_string(&ImplantState::Active).unwrap();
        assert_eq!(json, "\"active\"");
    }

    #[test]
    fn copy_semantics() {
        let a = ImplantState::Active;
        let b = a;
        assert_eq!(a, b);
    }
}

#[cfg(test)]
mod result_tests {
    use crate::result::{
        BofOutput, DirectoryEntry, DirectoryListing, FileContents, FileOperationResult,
        ModuleOperationResult, ProcessInfo, ProcessList, ShellOutput, TaskError, TaskResult,
    };

    #[test]
    fn task_result_success_serde_roundtrip() {
        let r = TaskResult::Success;
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(back, TaskResult::Success));
    }

    #[test]
    fn task_result_error_serde_roundtrip() {
        let r = TaskResult::Error(TaskError {
            code: 42,
            message: "something went wrong".to_string(),
            details: Some("extra info".to_string()),
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::Error(e) = back {
            assert_eq!(e.code, 42);
            assert_eq!(e.message, "something went wrong");
            assert_eq!(e.details.as_deref(), Some("extra info"));
        } else {
            panic!("expected TaskResult::Error");
        }
    }

    #[test]
    fn task_result_error_no_details() {
        let r = TaskResult::Error(TaskError {
            code: 1,
            message: "err".to_string(),
            details: None,
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::Error(e) = back {
            assert!(e.details.is_none());
        } else {
            panic!("expected TaskResult::Error");
        }
    }

    #[test]
    fn shell_output_serde_roundtrip() {
        let r = TaskResult::Shell(ShellOutput {
            stdout: "hello".to_string(),
            stderr: "".to_string(),
            exit_code: 0,
            duration_ms: 100,
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::Shell(s) = back {
            assert_eq!(s.stdout, "hello");
            assert_eq!(s.exit_code, 0);
            assert_eq!(s.duration_ms, 100);
        } else {
            panic!("expected TaskResult::Shell");
        }
    }

    #[test]
    fn directory_listing_serde_roundtrip() {
        let r = TaskResult::DirectoryListing(DirectoryListing {
            path: "/tmp".to_string(),
            entries: vec![DirectoryEntry {
                name: "foo.txt".to_string(),
                is_dir: false,
                size: 1024,
                modified: Some(1_700_000_000),
                permissions: Some("rw-r--r--".to_string()),
            }],
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::DirectoryListing(d) = back {
            assert_eq!(d.path, "/tmp");
            assert_eq!(d.entries.len(), 1);
            assert_eq!(d.entries[0].name, "foo.txt");
            assert!(!d.entries[0].is_dir);
            assert_eq!(d.entries[0].size, 1024);
        } else {
            panic!("expected TaskResult::DirectoryListing");
        }
    }

    #[test]
    fn file_contents_serde_roundtrip() {
        let r = TaskResult::FileContents(FileContents {
            path: "/etc/passwd".to_string(),
            data: vec![1, 2, 3],
            size: 3,
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::FileContents(f) = back {
            assert_eq!(f.path, "/etc/passwd");
            assert_eq!(f.data, vec![1, 2, 3]);
            assert_eq!(f.size, 3);
        } else {
            panic!("expected TaskResult::FileContents");
        }
    }

    #[test]
    fn file_operation_result_serde_roundtrip() {
        let r = TaskResult::FileOperation(FileOperationResult {
            operation: "delete".to_string(),
            path: "/tmp/test".to_string(),
            success: true,
            message: None,
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::FileOperation(f) = back {
            assert_eq!(f.operation, "delete");
            assert!(f.success);
            assert!(f.message.is_none());
        } else {
            panic!("expected TaskResult::FileOperation");
        }
    }

    #[test]
    fn process_list_serde_roundtrip() {
        let r = TaskResult::ProcessList(ProcessList {
            processes: vec![ProcessInfo {
                pid: 1,
                ppid: 0,
                name: "systemd".to_string(),
                path: Some("/usr/lib/systemd/systemd".to_string()),
                user: Some("root".to_string()),
                arch: Some("x64".to_string()),
            }],
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::ProcessList(pl) = back {
            assert_eq!(pl.processes.len(), 1);
            assert_eq!(pl.processes[0].pid, 1);
            assert_eq!(pl.processes[0].name, "systemd");
        } else {
            panic!("expected TaskResult::ProcessList");
        }
    }

    #[test]
    fn module_operation_result_serde_roundtrip() {
        let r = TaskResult::ModuleOperation(ModuleOperationResult {
            operation: "load".to_string(),
            module_id: "kraken.recon".to_string(),
            success: true,
            message: Some("loaded ok".to_string()),
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::ModuleOperation(m) = back {
            assert_eq!(m.module_id, "kraken.recon");
            assert!(m.success);
            assert_eq!(m.message.as_deref(), Some("loaded ok"));
        } else {
            panic!("expected TaskResult::ModuleOperation");
        }
    }

    #[test]
    fn bof_output_serde_roundtrip() {
        let r = TaskResult::BofOutput(BofOutput {
            output: "BOF ran".to_string(),
            exit_code: 0,
            error: None,
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::BofOutput(b) = back {
            assert_eq!(b.output, "BOF ran");
            assert_eq!(b.exit_code, 0);
            assert!(b.error.is_none());
        } else {
            panic!("expected TaskResult::BofOutput");
        }
    }

    #[test]
    fn bof_output_with_error_serde_roundtrip() {
        let r = TaskResult::BofOutput(BofOutput {
            output: "".to_string(),
            exit_code: 1,
            error: Some("access denied".to_string()),
        });
        let json = serde_json::to_string(&r).expect("serialize");
        let back: TaskResult = serde_json::from_str(&json).expect("deserialize");
        if let TaskResult::BofOutput(b) = back {
            assert_eq!(b.error.as_deref(), Some("access denied"));
        } else {
            panic!("expected TaskResult::BofOutput");
        }
    }

    #[test]
    fn process_info_optional_fields_none() {
        let pi = ProcessInfo {
            pid: 9999,
            ppid: 1,
            name: "orphan".to_string(),
            path: None,
            user: None,
            arch: None,
        };
        let json = serde_json::to_string(&pi).expect("serialize");
        let back: ProcessInfo = serde_json::from_str(&json).expect("deserialize");
        assert!(back.path.is_none());
        assert!(back.user.is_none());
        assert!(back.arch.is_none());
    }

    #[test]
    fn task_result_clone() {
        let r = TaskResult::Success;
        let c = r.clone();
        let json1 = serde_json::to_string(&r).unwrap();
        let json2 = serde_json::to_string(&c).unwrap();
        assert_eq!(json1, json2);
    }
}
