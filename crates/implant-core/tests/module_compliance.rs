//! Module trait compliance tests
//!
//! Verifies all modules correctly implement the Module trait with
//! consistent behavior.

#[allow(unused_imports)]
use common::Module;
use implant_core::registry;

/// All module IDs should follow the lowercase pattern
#[test]
fn test_module_id_format() {
    let reg = registry::registry();
    let module_names = ["shell", "file", "bof", "inject", "token", "socks", "mesh"];

    for name in &module_names {
        let module = reg.get(name).expect(&format!("module '{}' should exist", name));
        let id = module.id().as_str();

        // ID should match the lookup key
        assert_eq!(id, *name, "module id should match lookup key");

        // ID should be lowercase
        assert_eq!(
            id,
            id.to_lowercase(),
            "module id '{}' should be lowercase",
            id
        );

        // ID should not be empty
        assert!(!id.is_empty(), "module id should not be empty");

        // ID should not contain spaces
        assert!(
            !id.contains(' '),
            "module id '{}' should not contain spaces",
            id
        );
    }
}

/// All module names should be non-empty and title case
#[test]
fn test_module_name_non_empty() {
    let reg = registry::registry();
    let module_names = ["shell", "file", "bof", "inject", "token", "socks", "mesh"];

    for name in &module_names {
        let module = reg.get(name).expect(&format!("module '{}' should exist", name));
        let display_name = module.name();

        // Name should not be empty
        assert!(
            !display_name.is_empty(),
            "module '{}' name should not be empty",
            name
        );

        // Name should start with uppercase (title case convention)
        assert!(
            display_name.chars().next().unwrap().is_uppercase(),
            "module '{}' name '{}' should start with uppercase",
            name,
            display_name
        );
    }
}

/// All module versions should be valid semver-ish
#[test]
fn test_module_version_valid() {
    let reg = registry::registry();
    let module_names = ["shell", "file", "bof", "inject", "token", "socks", "mesh"];

    for name in &module_names {
        let module = reg.get(name).expect(&format!("module '{}' should exist", name));
        let version = module.version();

        // Version should not be empty
        assert!(
            !version.is_empty(),
            "module '{}' version should not be empty",
            name
        );

        // Version should contain at least one digit
        assert!(
            version.chars().any(|c| c.is_ascii_digit()),
            "module '{}' version '{}' should contain digits",
            name,
            version
        );

        // Version should start with a digit (standard semver)
        assert!(
            version.chars().next().unwrap().is_ascii_digit(),
            "module '{}' version '{}' should start with digit",
            name,
            version
        );
    }
}

/// All modules should handle empty task data gracefully (not panic)
#[test]
fn test_module_handle_empty_data_no_panic() {
    use common::TaskId;

    let reg = registry::registry();
    let module_names = ["shell", "file", "bof", "inject", "token", "socks", "mesh"];

    for name in &module_names {
        let module = reg.get(name).expect(&format!("module '{}' should exist", name));
        let task_id = TaskId::new();

        // Empty data should not panic - Ok or Err are both acceptable
        let _result = module.handle(task_id, &[]);
        // Test passes if we reach here without panicking
    }
}

/// All modules should handle garbage data gracefully (not panic)
#[test]
fn test_module_handle_garbage_data_no_panic() {
    use common::TaskId;

    let reg = registry::registry();
    let module_names = ["shell", "file", "bof", "inject", "token", "socks", "mesh"];
    let garbage_data = &[0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0x02, 0x03];

    for name in &module_names {
        let module = reg.get(name).expect(&format!("module '{}' should exist", name));
        let task_id = TaskId::new();

        // Garbage data should not panic - Ok or Err are both acceptable
        let _result = module.handle(task_id, garbage_data);
        // Test passes if we reach here without panicking
    }
}

/// Module caching should return the same instance
#[test]
fn test_module_instance_caching() {
    use std::sync::Arc;

    let reg = registry::registry();
    let module_names = ["shell", "file", "bof"];

    for name in &module_names {
        let module1 = reg.get(name).expect(&format!("module '{}' should exist", name));
        let module2 = reg.get(name).expect(&format!("module '{}' should exist", name));

        // Same Arc instance should be returned
        assert!(
            Arc::ptr_eq(&module1, &module2),
            "module '{}' should return same cached instance",
            name
        );
    }
}
