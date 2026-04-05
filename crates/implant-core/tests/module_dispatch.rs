//! Integration tests for module dispatch through registry
//!
//! Verifies the full path from task receipt to module execution.

#[allow(unused_imports)]
use common::Module;
use implant_core::registry;

/// Test that shell module can be retrieved and has correct metadata
#[test]
fn test_shell_module_accessible() {
    let reg = registry::registry();
    let module = reg.get("shell");
    assert!(module.is_some(), "shell module should be accessible");

    let module = module.unwrap();
    assert_eq!(module.id().as_str(), "shell");
    assert_eq!(module.name(), "Shell");
    assert!(!module.version().is_empty(), "version should not be empty");
}

/// Test that file module can be retrieved and has correct metadata
#[test]
fn test_file_module_accessible() {
    let reg = registry::registry();
    let module = reg.get("file");
    assert!(module.is_some(), "file module should be accessible");

    let module = module.unwrap();
    assert_eq!(module.id().as_str(), "file");
    assert_eq!(module.name(), "File");
}

/// Test that requesting unknown task type returns None
#[test]
fn test_unknown_task_type_returns_none() {
    let reg = registry::registry();
    assert!(reg.get("nonexistent_module").is_none());
    assert!(reg.get("").is_none());
    assert!(reg.get("SHELL").is_none()); // Case sensitive
}

/// Test that all expected static modules are available
#[test]
fn test_all_static_modules_available() {
    let reg = registry::registry();
    let expected_modules = ["shell", "file", "bof", "inject", "token", "socks", "mesh"];

    for module_name in &expected_modules {
        assert!(
            reg.get(module_name).is_some(),
            "module '{}' should be available",
            module_name
        );
    }
}

/// Test that module handle returns error for invalid task data
#[test]
fn test_module_handle_invalid_data() {
    use common::TaskId;

    let reg = registry::registry();
    let module = reg.get("shell").expect("shell module should exist");

    let task_id = TaskId::new();
    let invalid_data = &[0xFF, 0xFE, 0x00, 0x01]; // Invalid protobuf

    let result = module.handle(task_id, invalid_data);
    assert!(result.is_err(), "invalid data should return error");
}

/// Test that concurrent module access is safe
#[test]
fn test_concurrent_module_access() {
    use std::thread;

    let _reg = registry::registry();
    let handles: Vec<_> = (0..10)
        .map(|i| {
            thread::spawn(move || {
                let reg = registry::registry();
                let module_name = match i % 3 {
                    0 => "shell",
                    1 => "file",
                    _ => "bof",
                };
                let module = reg.get(module_name);
                assert!(module.is_some());
                module.unwrap().name().to_string()
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join();
        assert!(result.is_ok());
    }
}
