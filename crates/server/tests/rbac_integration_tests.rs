//! RBAC Integration Tests
//!
//! Tests permission enforcement across server gRPC services.
//! Verifies that:
//! - Role hierarchy is properly enforced
//! - Resource access restrictions work
//! - Disabled operators are rejected
//! - Permission checks are applied consistently

use std::collections::HashSet;

use kraken_rbac::{OperatorIdentity, Permission, Role, RbacError, role_permissions};

// ---------------------------------------------------------------------------
// Role Hierarchy Tests
// ---------------------------------------------------------------------------

mod role_hierarchy {
    use super::*;

    #[test]
    fn test_admin_has_all_permissions() {
        let admin = OperatorIdentity::new("admin".into(), Role::Admin, "cert".into());

        // Admin should have all defined permissions
        for perm in all_permissions() {
            assert!(
                admin.has_permission(perm),
                "Admin should have {:?} permission",
                perm
            );
        }
    }

    #[test]
    fn test_operator_permission_subset() {
        let operator = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());
        let admin = OperatorIdentity::new("admin".into(), Role::Admin, "cert".into());

        let operator_perms = role_permissions(Role::Operator);
        let admin_perms = role_permissions(Role::Admin);

        // All operator permissions should be subset of admin
        for perm in &operator_perms {
            assert!(
                admin_perms.contains(perm),
                "Operator perm {:?} should be in admin perms",
                perm
            );
        }

        // Operator should not have admin-only permissions
        assert!(!operator.has_permission(Permission::OperatorCreate));
        assert!(!operator.has_permission(Permission::OperatorModify));
        assert!(!operator.has_permission(Permission::OperatorDelete));
        assert!(!operator.has_permission(Permission::SettingsModify));
        assert!(!operator.has_permission(Permission::AuditView));
        assert!(!operator.has_permission(Permission::ListenerDelete));
        assert!(!operator.has_permission(Permission::ModuleUpload));
        assert!(!operator.has_permission(Permission::LootDelete));
    }

    #[test]
    fn test_viewer_permission_subset() {
        let viewer = OperatorIdentity::new("viewer".into(), Role::Viewer, "cert".into());
        let operator = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());

        let viewer_perms = role_permissions(Role::Viewer);
        let operator_perms = role_permissions(Role::Operator);

        // All viewer permissions should be subset of operator
        for perm in &viewer_perms {
            assert!(
                operator_perms.contains(perm),
                "Viewer perm {:?} should be in operator perms",
                perm
            );
        }

        // Viewer should only have view permissions
        assert!(viewer.has_permission(Permission::SessionView));
        assert!(viewer.has_permission(Permission::ListenerView));
        assert!(viewer.has_permission(Permission::ModuleView));
        assert!(viewer.has_permission(Permission::LootView));
        assert!(viewer.has_permission(Permission::ReportView));
        assert!(viewer.has_permission(Permission::MeshView));

        // Viewer should not have action permissions
        assert!(!viewer.has_permission(Permission::SessionInteract));
        assert!(!viewer.has_permission(Permission::SessionKill));
        assert!(!viewer.has_permission(Permission::ListenerCreate));
        assert!(!viewer.has_permission(Permission::ModuleExecute));
    }
}

// ---------------------------------------------------------------------------
// Resource Access Tests
// ---------------------------------------------------------------------------

mod resource_access {
    use super::*;

    #[test]
    fn test_unrestricted_access_all_sessions() {
        let op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());

        // Should have access to any session
        for _ in 0..10 {
            let session_id = uuid::Uuid::new_v4();
            assert!(op.can_access_session(session_id));
        }
    }

    #[test]
    fn test_unrestricted_access_all_listeners() {
        let op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());

        // Should have access to any listener
        for _ in 0..10 {
            let listener_id = uuid::Uuid::new_v4();
            assert!(op.can_access_listener(listener_id));
        }
    }

    #[test]
    fn test_restricted_session_access() {
        let mut op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());

        let allowed1 = uuid::Uuid::new_v4();
        let allowed2 = uuid::Uuid::new_v4();
        let denied = uuid::Uuid::new_v4();

        op.allowed_sessions = Some([allowed1, allowed2].into_iter().collect());

        assert!(op.can_access_session(allowed1));
        assert!(op.can_access_session(allowed2));
        assert!(!op.can_access_session(denied));
    }

    #[test]
    fn test_restricted_listener_access() {
        let mut op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());

        let allowed = uuid::Uuid::new_v4();
        let denied = uuid::Uuid::new_v4();

        op.allowed_listeners = Some([allowed].into_iter().collect());

        assert!(op.can_access_listener(allowed));
        assert!(!op.can_access_listener(denied));
    }

    #[test]
    fn test_session_access_with_permission_check() {
        let mut op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());
        let session = uuid::Uuid::new_v4();
        op.allowed_sessions = Some([session].into_iter().collect());

        // Should succeed: has permission AND access
        let result = op.authorize_session_action(Permission::SessionInteract, session);
        assert!(result.is_ok());

        // Should fail: has access but not permission (viewer-level)
        let viewer = {
            let mut v = OperatorIdentity::new("v".into(), Role::Viewer, "cert".into());
            v.allowed_sessions = Some([session].into_iter().collect());
            v
        };
        let result = viewer.authorize_session_action(Permission::SessionInteract, session);
        assert!(matches!(result, Err(RbacError::PermissionDenied(_))));

        // Should fail: has permission but not access
        let other_session = uuid::Uuid::new_v4();
        let result = op.authorize_session_action(Permission::SessionInteract, other_session);
        assert!(matches!(result, Err(RbacError::SessionAccessDenied(_))));
    }

    #[test]
    fn test_listener_access_with_permission_check() {
        let mut op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());
        let listener = uuid::Uuid::new_v4();
        op.allowed_listeners = Some([listener].into_iter().collect());

        // Operator can create listeners but...
        // Should succeed: has permission AND access
        let result = op.authorize_listener_action(Permission::ListenerCreate, listener);
        assert!(result.is_ok());

        // Should fail: no access to other listener
        let other_listener = uuid::Uuid::new_v4();
        let result = op.authorize_listener_action(Permission::ListenerCreate, other_listener);
        assert!(matches!(result, Err(RbacError::ListenerAccessDenied(_))));
    }
}

// ---------------------------------------------------------------------------
// Disabled Operator Tests
// ---------------------------------------------------------------------------

mod disabled_operators {
    use super::*;

    #[test]
    fn test_disabled_admin_has_no_permissions() {
        let mut admin = OperatorIdentity::new("admin".into(), Role::Admin, "cert".into());
        admin.disabled = true;

        // Should have no permissions when disabled
        for perm in all_permissions() {
            assert!(
                !admin.has_permission(perm),
                "Disabled admin should not have {:?}",
                perm
            );
        }
    }

    #[test]
    fn test_disabled_operator_cannot_access_sessions() {
        let mut op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());
        op.disabled = true;

        let session = uuid::Uuid::new_v4();
        assert!(!op.can_access_session(session));
    }

    #[test]
    fn test_disabled_operator_cannot_access_listeners() {
        let mut op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());
        op.disabled = true;

        let listener = uuid::Uuid::new_v4();
        assert!(!op.can_access_listener(listener));
    }

    #[test]
    fn test_disabled_operator_authorize_fails() {
        let mut op = OperatorIdentity::new("op".into(), Role::Admin, "cert".into());
        op.disabled = true;

        let session = uuid::Uuid::new_v4();
        let result = op.authorize_session_action(Permission::SessionView, session);
        assert!(matches!(result, Err(RbacError::OperatorDisabled)));

        let listener = uuid::Uuid::new_v4();
        let result = op.authorize_listener_action(Permission::ListenerView, listener);
        assert!(matches!(result, Err(RbacError::OperatorDisabled)));
    }

    #[test]
    fn test_disabled_with_restrictions_still_denied() {
        let mut op = OperatorIdentity::new("op".into(), Role::Operator, "cert".into());
        let session = uuid::Uuid::new_v4();
        op.allowed_sessions = Some([session].into_iter().collect());
        op.disabled = true;

        // Even with explicit access, disabled should deny
        assert!(!op.can_access_session(session));
    }
}

// ---------------------------------------------------------------------------
// Permission Consistency Tests
// ---------------------------------------------------------------------------

mod permission_consistency {
    use super::*;

    #[test]
    fn test_all_permissions_covered_by_admin() {
        let admin_perms = role_permissions(Role::Admin);
        let all = all_permissions();

        for perm in all {
            assert!(
                admin_perms.contains(&perm),
                "Admin should have {:?}",
                perm
            );
        }
    }

    #[test]
    fn test_permission_sets_are_disjoint_additions() {
        let viewer_perms = role_permissions(Role::Viewer);
        let operator_perms = role_permissions(Role::Operator);
        let admin_perms = role_permissions(Role::Admin);

        // Viewer is subset of operator
        assert!(viewer_perms.is_subset(&operator_perms));

        // Operator is subset of admin
        assert!(operator_perms.is_subset(&admin_perms));

        // Operator has more than viewer
        assert!(operator_perms.len() > viewer_perms.len());

        // Admin has more than operator
        assert!(admin_perms.len() > operator_perms.len());
    }

    #[test]
    fn test_view_permissions_in_all_roles() {
        let view_perms = [
            Permission::SessionView,
            Permission::ListenerView,
            Permission::ModuleView,
            Permission::LootView,
            Permission::ReportView,
            Permission::MeshView,
        ];

        for role in [Role::Viewer, Role::Operator, Role::Admin] {
            let perms = role_permissions(role);
            for view_perm in &view_perms {
                assert!(
                    perms.contains(view_perm),
                    "{:?} should have {:?}",
                    role,
                    view_perm
                );
            }
        }
    }

    #[test]
    fn test_admin_only_permissions() {
        let admin_only = [
            Permission::OperatorCreate,
            Permission::OperatorModify,
            Permission::OperatorDelete,
            Permission::SettingsModify,
            Permission::AuditView,
            Permission::ListenerModify,
            Permission::ListenerDelete,
            Permission::ModuleUpload,
            Permission::LootDelete,
        ];

        let operator_perms = role_permissions(Role::Operator);
        let viewer_perms = role_permissions(Role::Viewer);

        for perm in admin_only {
            assert!(!operator_perms.contains(&perm), "Operator should not have {:?}", perm);
            assert!(!viewer_perms.contains(&perm), "Viewer should not have {:?}", perm);
        }
    }
}

// ---------------------------------------------------------------------------
// Error Type Tests
// ---------------------------------------------------------------------------

mod error_types {
    use super::*;

    #[test]
    fn test_rbac_error_display() {
        let errors = vec![
            RbacError::InvalidRole("bad".into()),
            RbacError::OperatorDisabled,
            RbacError::PermissionDenied(Permission::SessionKill),
            RbacError::SessionAccessDenied(uuid::Uuid::nil()),
            RbacError::ListenerAccessDenied(uuid::Uuid::nil()),
            RbacError::OperatorNotFound("user".into()),
            RbacError::AuthenticationFailed("reason".into()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Error should have display message");
        }
    }

    #[test]
    fn test_error_from_role_parsing() {
        let result: Result<Role, _> = "invalid_role".parse();
        assert!(matches!(result, Err(RbacError::InvalidRole(_))));
    }
}

// ---------------------------------------------------------------------------
// Identity Lifecycle Tests
// ---------------------------------------------------------------------------

mod identity_lifecycle {
    use super::*;

    #[test]
    fn test_new_identity_defaults() {
        let op = OperatorIdentity::new("user".into(), Role::Operator, "fingerprint".into());

        assert!(!op.disabled);
        assert!(op.allowed_sessions.is_none());
        assert!(op.allowed_listeners.is_none());
        assert!(op.last_seen.is_none());
        assert!(!op.id.is_nil());
    }

    #[test]
    fn test_identity_touch_updates_last_seen() {
        let mut op = OperatorIdentity::new("user".into(), Role::Operator, "cert".into());
        assert!(op.last_seen.is_none());

        op.touch();
        let first = op.last_seen.expect("last_seen should be set");

        std::thread::sleep(std::time::Duration::from_millis(10));
        op.touch();
        let second = op.last_seen.expect("last_seen should be set");

        assert!(second > first);
    }

    #[test]
    fn test_identity_serde_roundtrip() {
        let op = OperatorIdentity::new("user".into(), Role::Admin, "cert123".into());

        let json = serde_json::to_string(&op).expect("serialize");
        let restored: OperatorIdentity = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(op.id, restored.id);
        assert_eq!(op.username, restored.username);
        assert_eq!(op.role, restored.role);
        assert_eq!(op.cert_fingerprint, restored.cert_fingerprint);
    }

    #[test]
    fn test_identity_with_restrictions_serde() {
        let mut op = OperatorIdentity::new("user".into(), Role::Operator, "cert".into());
        let session = uuid::Uuid::new_v4();
        let listener = uuid::Uuid::new_v4();
        op.allowed_sessions = Some([session].into_iter().collect());
        op.allowed_listeners = Some([listener].into_iter().collect());
        op.disabled = true;

        let json = serde_json::to_string(&op).expect("serialize");
        let restored: OperatorIdentity = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(op.allowed_sessions, restored.allowed_sessions);
        assert_eq!(op.allowed_listeners, restored.allowed_listeners);
        assert_eq!(op.disabled, restored.disabled);
    }
}

// ---------------------------------------------------------------------------
// Concurrency Tests
// ---------------------------------------------------------------------------

mod concurrency {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_permission_checks_thread_safe() {
        let op = Arc::new(OperatorIdentity::new("user".into(), Role::Operator, "cert".into()));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let op = Arc::clone(&op);
                thread::spawn(move || {
                    for _ in 0..100 {
                        assert!(op.has_permission(Permission::SessionView));
                        assert!(op.has_permission(Permission::SessionInteract));
                        assert!(!op.has_permission(Permission::OperatorCreate));
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_access_checks_thread_safe() {
        let op = Arc::new(OperatorIdentity::new("user".into(), Role::Operator, "cert".into()));
        let session = uuid::Uuid::new_v4();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let op = Arc::clone(&op);
                thread::spawn(move || {
                    for _ in 0..100 {
                        assert!(op.can_access_session(session));
                        assert!(op.can_access_listener(session)); // Using same UUID
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn all_permissions() -> Vec<Permission> {
    vec![
        Permission::SessionView,
        Permission::SessionInteract,
        Permission::SessionKill,
        Permission::ListenerView,
        Permission::ListenerCreate,
        Permission::ListenerModify,
        Permission::ListenerDelete,
        Permission::ModuleView,
        Permission::ModuleExecute,
        Permission::ModuleUpload,
        Permission::LootView,
        Permission::LootExport,
        Permission::LootDelete,
        Permission::ReportView,
        Permission::ReportGenerate,
        Permission::ReportExport,
        Permission::MeshView,
        Permission::MeshConnect,
        Permission::MeshDisconnect,
        Permission::OperatorCreate,
        Permission::OperatorModify,
        Permission::OperatorDelete,
        Permission::SettingsModify,
        Permission::AuditView,
    ]
}
