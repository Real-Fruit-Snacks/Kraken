//! Role-Based Access Control for Kraken C2 Framework
//!
//! Provides role hierarchy, fine-grained permissions, and operator identity management.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Role hierarchy: Admin > Operator > Viewer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full access: manage operators, listeners, settings
    Admin,
    /// Standard access: interact with implants, run modules
    Operator,
    /// Read-only: view sessions, logs, reports
    Viewer,
}

impl Role {
    /// Check if this role can perform actions requiring `required`
    pub fn satisfies(&self, required: Role) -> bool {
        match (self, required) {
            (Role::Admin, _) => true,
            (Role::Operator, Role::Operator | Role::Viewer) => true,
            (Role::Viewer, Role::Viewer) => true,
            _ => false,
        }
    }

    /// Get the display name for this role
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Viewer => "viewer",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = RbacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "operator" => Ok(Role::Operator),
            "viewer" => Ok(Role::Viewer),
            _ => Err(RbacError::InvalidRole(s.to_string())),
        }
    }
}

/// Fine-grained permission for specific actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Session permissions
    SessionView,
    SessionInteract,
    SessionKill,

    // Listener permissions
    ListenerView,
    ListenerCreate,
    ListenerModify,
    ListenerDelete,

    // Module permissions
    ModuleView,
    ModuleExecute,
    ModuleUpload,

    // Loot permissions
    LootView,
    LootExport,
    LootDelete,

    // Report permissions
    ReportView,
    ReportGenerate,
    ReportExport,

    // Mesh permissions
    MeshView,
    MeshConnect,
    MeshDisconnect,

    // Admin permissions
    OperatorCreate,
    OperatorModify,
    OperatorDelete,
    SettingsModify,
    AuditView,
}

impl Permission {
    /// Get the display name for this permission
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::SessionView => "session_view",
            Permission::SessionInteract => "session_interact",
            Permission::SessionKill => "session_kill",
            Permission::ListenerView => "listener_view",
            Permission::ListenerCreate => "listener_create",
            Permission::ListenerModify => "listener_modify",
            Permission::ListenerDelete => "listener_delete",
            Permission::ModuleView => "module_view",
            Permission::ModuleExecute => "module_execute",
            Permission::ModuleUpload => "module_upload",
            Permission::LootView => "loot_view",
            Permission::LootExport => "loot_export",
            Permission::LootDelete => "loot_delete",
            Permission::ReportView => "report_view",
            Permission::ReportGenerate => "report_generate",
            Permission::ReportExport => "report_export",
            Permission::MeshView => "mesh_view",
            Permission::MeshConnect => "mesh_connect",
            Permission::MeshDisconnect => "mesh_disconnect",
            Permission::OperatorCreate => "operator_create",
            Permission::OperatorModify => "operator_modify",
            Permission::OperatorDelete => "operator_delete",
            Permission::SettingsModify => "settings_modify",
            Permission::AuditView => "audit_view",
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Get the permission set for a given role
pub fn role_permissions(role: Role) -> HashSet<Permission> {
    use Permission::*;

    let mut perms = HashSet::new();

    // Viewer permissions (base level)
    perms.extend([
        SessionView,
        ListenerView,
        ModuleView,
        LootView,
        ReportView,
        MeshView,
    ]);

    if role.satisfies(Role::Operator) {
        perms.extend([
            SessionInteract,
            SessionKill,
            ListenerCreate,
            ModuleExecute,
            LootExport,
            ReportGenerate,
            ReportExport,
            MeshConnect,
            MeshDisconnect,
        ]);
    }

    if role.satisfies(Role::Admin) {
        perms.extend([
            ListenerModify,
            ListenerDelete,
            ModuleUpload,
            LootDelete,
            OperatorCreate,
            OperatorModify,
            OperatorDelete,
            SettingsModify,
            AuditView,
        ]);
    }

    perms
}

/// Operator identity with assigned role and optional restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub id: uuid::Uuid,
    pub username: String,
    pub role: Role,
    pub cert_fingerprint: String,
    /// If Some, restricts access to only these sessions. None = all sessions.
    pub allowed_sessions: Option<HashSet<uuid::Uuid>>,
    /// If Some, restricts access to only these listeners. None = all listeners.
    pub allowed_listeners: Option<HashSet<uuid::Uuid>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub disabled: bool,
}

impl OperatorIdentity {
    /// Create a new operator identity
    pub fn new(username: String, role: Role, cert_fingerprint: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            username,
            role,
            cert_fingerprint,
            allowed_sessions: None,
            allowed_listeners: None,
            created_at: chrono::Utc::now(),
            last_seen: None,
            disabled: false,
        }
    }

    /// Check if operator has a specific permission
    pub fn has_permission(&self, perm: Permission) -> bool {
        if self.disabled {
            return false;
        }
        role_permissions(self.role).contains(&perm)
    }

    /// Check if operator can access a specific session
    pub fn can_access_session(&self, session_id: uuid::Uuid) -> bool {
        if self.disabled {
            return false;
        }
        match &self.allowed_sessions {
            Some(allowed) => allowed.contains(&session_id),
            None => true,
        }
    }

    /// Check if operator can access a specific listener
    pub fn can_access_listener(&self, listener_id: uuid::Uuid) -> bool {
        if self.disabled {
            return false;
        }
        match &self.allowed_listeners {
            Some(allowed) => allowed.contains(&listener_id),
            None => true,
        }
    }

    /// Check both permission and resource access in one call
    pub fn authorize_session_action(
        &self,
        perm: Permission,
        session_id: uuid::Uuid,
    ) -> Result<(), RbacError> {
        if self.disabled {
            return Err(RbacError::OperatorDisabled);
        }
        if !self.has_permission(perm) {
            return Err(RbacError::PermissionDenied(perm));
        }
        if !self.can_access_session(session_id) {
            return Err(RbacError::SessionAccessDenied(session_id));
        }
        Ok(())
    }

    /// Check both permission and listener access in one call
    pub fn authorize_listener_action(
        &self,
        perm: Permission,
        listener_id: uuid::Uuid,
    ) -> Result<(), RbacError> {
        if self.disabled {
            return Err(RbacError::OperatorDisabled);
        }
        if !self.has_permission(perm) {
            return Err(RbacError::PermissionDenied(perm));
        }
        if !self.can_access_listener(listener_id) {
            return Err(RbacError::ListenerAccessDenied(listener_id));
        }
        Ok(())
    }

    /// Update last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen = Some(chrono::Utc::now());
    }
}

/// RBAC-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum RbacError {
    #[error("invalid role: {0}")]
    InvalidRole(String),

    #[error("operator is disabled")]
    OperatorDisabled,

    #[error("permission denied: {0}")]
    PermissionDenied(Permission),

    #[error("session access denied: {0}")]
    SessionAccessDenied(uuid::Uuid),

    #[error("listener access denied: {0}")]
    ListenerAccessDenied(uuid::Uuid),

    #[error("operator not found: {0}")]
    OperatorNotFound(String),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
}

/// Macro for checking permissions in service handlers
#[macro_export]
macro_rules! require_perm {
    ($operator:expr, $perm:expr) => {
        if !$operator.has_permission($perm) {
            return Err(tonic::Status::permission_denied(format!(
                "permission denied: {}",
                $perm
            )));
        }
    };
}

/// Macro for checking session access
#[macro_export]
macro_rules! require_session_access {
    ($operator:expr, $perm:expr, $session_id:expr) => {
        $operator
            .authorize_session_action($perm, $session_id)
            .map_err(|e| tonic::Status::permission_denied(e.to_string()))?;
    };
}

/// Macro for checking listener access
#[macro_export]
macro_rules! require_listener_access {
    ($operator:expr, $perm:expr, $listener_id:expr) => {
        $operator
            .authorize_listener_action($perm, $listener_id)
            .map_err(|e| tonic::Status::permission_denied(e.to_string()))?;
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_hierarchy_admin() {
        assert!(Role::Admin.satisfies(Role::Admin));
        assert!(Role::Admin.satisfies(Role::Operator));
        assert!(Role::Admin.satisfies(Role::Viewer));
    }

    #[test]
    fn test_role_hierarchy_operator() {
        assert!(!Role::Operator.satisfies(Role::Admin));
        assert!(Role::Operator.satisfies(Role::Operator));
        assert!(Role::Operator.satisfies(Role::Viewer));
    }

    #[test]
    fn test_role_hierarchy_viewer() {
        assert!(!Role::Viewer.satisfies(Role::Admin));
        assert!(!Role::Viewer.satisfies(Role::Operator));
        assert!(Role::Viewer.satisfies(Role::Viewer));
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("ADMIN".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("operator".parse::<Role>().unwrap(), Role::Operator);
        assert_eq!("viewer".parse::<Role>().unwrap(), Role::Viewer);
        assert!("invalid".parse::<Role>().is_err());
    }

    #[test]
    fn test_role_display() {
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Operator.to_string(), "operator");
        assert_eq!(Role::Viewer.to_string(), "viewer");
    }

    #[test]
    fn test_viewer_permissions() {
        let perms = role_permissions(Role::Viewer);

        // Viewer should have view permissions
        assert!(perms.contains(&Permission::SessionView));
        assert!(perms.contains(&Permission::ListenerView));
        assert!(perms.contains(&Permission::ModuleView));
        assert!(perms.contains(&Permission::LootView));
        assert!(perms.contains(&Permission::ReportView));
        assert!(perms.contains(&Permission::MeshView));

        // Viewer should NOT have action permissions
        assert!(!perms.contains(&Permission::SessionInteract));
        assert!(!perms.contains(&Permission::SessionKill));
        assert!(!perms.contains(&Permission::ListenerCreate));
        assert!(!perms.contains(&Permission::ModuleExecute));

        // Viewer should NOT have admin permissions
        assert!(!perms.contains(&Permission::OperatorCreate));
        assert!(!perms.contains(&Permission::SettingsModify));
        assert!(!perms.contains(&Permission::AuditView));
    }

    #[test]
    fn test_operator_permissions() {
        let perms = role_permissions(Role::Operator);

        // Operator should have all viewer permissions
        assert!(perms.contains(&Permission::SessionView));
        assert!(perms.contains(&Permission::ListenerView));

        // Operator should have action permissions
        assert!(perms.contains(&Permission::SessionInteract));
        assert!(perms.contains(&Permission::SessionKill));
        assert!(perms.contains(&Permission::ListenerCreate));
        assert!(perms.contains(&Permission::ModuleExecute));
        assert!(perms.contains(&Permission::LootExport));
        assert!(perms.contains(&Permission::ReportGenerate));
        assert!(perms.contains(&Permission::MeshConnect));

        // Operator should NOT have admin permissions
        assert!(!perms.contains(&Permission::OperatorCreate));
        assert!(!perms.contains(&Permission::SettingsModify));
        assert!(!perms.contains(&Permission::AuditView));
        assert!(!perms.contains(&Permission::ListenerDelete));
    }

    #[test]
    fn test_admin_permissions() {
        let perms = role_permissions(Role::Admin);

        // Admin should have all permissions
        assert!(perms.contains(&Permission::SessionView));
        assert!(perms.contains(&Permission::SessionInteract));
        assert!(perms.contains(&Permission::SessionKill));
        assert!(perms.contains(&Permission::ListenerCreate));
        assert!(perms.contains(&Permission::ListenerModify));
        assert!(perms.contains(&Permission::ListenerDelete));
        assert!(perms.contains(&Permission::ModuleExecute));
        assert!(perms.contains(&Permission::ModuleUpload));
        assert!(perms.contains(&Permission::OperatorCreate));
        assert!(perms.contains(&Permission::OperatorModify));
        assert!(perms.contains(&Permission::OperatorDelete));
        assert!(perms.contains(&Permission::SettingsModify));
        assert!(perms.contains(&Permission::AuditView));
        assert!(perms.contains(&Permission::LootDelete));
    }

    #[test]
    fn test_operator_identity_new() {
        let op = OperatorIdentity::new(
            "testuser".to_string(),
            Role::Operator,
            "abc123".to_string(),
        );

        assert_eq!(op.username, "testuser");
        assert_eq!(op.role, Role::Operator);
        assert_eq!(op.cert_fingerprint, "abc123");
        assert!(!op.disabled);
        assert!(op.allowed_sessions.is_none());
        assert!(op.allowed_listeners.is_none());
    }

    #[test]
    fn test_operator_has_permission() {
        let op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());

        assert!(op.has_permission(Permission::SessionView));
        assert!(op.has_permission(Permission::SessionInteract));
        assert!(!op.has_permission(Permission::OperatorCreate));
    }

    #[test]
    fn test_disabled_operator_no_permissions() {
        let mut op = OperatorIdentity::new("op".to_string(), Role::Admin, "cert".to_string());
        op.disabled = true;

        assert!(!op.has_permission(Permission::SessionView));
        assert!(!op.has_permission(Permission::OperatorCreate));
    }

    #[test]
    fn test_session_access_unrestricted() {
        let op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());
        let session_id = uuid::Uuid::new_v4();

        assert!(op.can_access_session(session_id));
    }

    #[test]
    fn test_session_access_restricted() {
        let mut op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());
        let allowed_session = uuid::Uuid::new_v4();
        let other_session = uuid::Uuid::new_v4();

        op.allowed_sessions = Some([allowed_session].into_iter().collect());

        assert!(op.can_access_session(allowed_session));
        assert!(!op.can_access_session(other_session));
    }

    #[test]
    fn test_listener_access_unrestricted() {
        let op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());
        let listener_id = uuid::Uuid::new_v4();

        assert!(op.can_access_listener(listener_id));
    }

    #[test]
    fn test_listener_access_restricted() {
        let mut op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());
        let allowed_listener = uuid::Uuid::new_v4();
        let other_listener = uuid::Uuid::new_v4();

        op.allowed_listeners = Some([allowed_listener].into_iter().collect());

        assert!(op.can_access_listener(allowed_listener));
        assert!(!op.can_access_listener(other_listener));
    }

    #[test]
    fn test_authorize_session_action_success() {
        let op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());
        let session_id = uuid::Uuid::new_v4();

        assert!(op
            .authorize_session_action(Permission::SessionInteract, session_id)
            .is_ok());
    }

    #[test]
    fn test_authorize_session_action_permission_denied() {
        let op = OperatorIdentity::new("op".to_string(), Role::Viewer, "cert".to_string());
        let session_id = uuid::Uuid::new_v4();

        let result = op.authorize_session_action(Permission::SessionInteract, session_id);
        assert!(matches!(result, Err(RbacError::PermissionDenied(_))));
    }

    #[test]
    fn test_authorize_session_action_access_denied() {
        let mut op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());
        let allowed_session = uuid::Uuid::new_v4();
        let other_session = uuid::Uuid::new_v4();
        op.allowed_sessions = Some([allowed_session].into_iter().collect());

        assert!(op
            .authorize_session_action(Permission::SessionInteract, allowed_session)
            .is_ok());

        let result = op.authorize_session_action(Permission::SessionInteract, other_session);
        assert!(matches!(result, Err(RbacError::SessionAccessDenied(_))));
    }

    #[test]
    fn test_authorize_disabled_operator() {
        let mut op = OperatorIdentity::new("op".to_string(), Role::Admin, "cert".to_string());
        op.disabled = true;
        let session_id = uuid::Uuid::new_v4();

        let result = op.authorize_session_action(Permission::SessionView, session_id);
        assert!(matches!(result, Err(RbacError::OperatorDisabled)));
    }

    #[test]
    fn test_operator_touch() {
        let mut op = OperatorIdentity::new("op".to_string(), Role::Operator, "cert".to_string());
        assert!(op.last_seen.is_none());

        op.touch();
        assert!(op.last_seen.is_some());

        let first_seen = op.last_seen.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        op.touch();

        assert!(op.last_seen.unwrap() > first_seen);
    }

    #[test]
    fn test_permission_count() {
        // Ensure we have the expected number of permissions per role
        assert_eq!(role_permissions(Role::Viewer).len(), 6);
        assert_eq!(role_permissions(Role::Operator).len(), 15);
        assert_eq!(role_permissions(Role::Admin).len(), 24);
    }

    #[test]
    fn test_permission_display() {
        assert_eq!(Permission::SessionView.to_string(), "session_view");
        assert_eq!(Permission::OperatorCreate.to_string(), "operator_create");
    }
}
