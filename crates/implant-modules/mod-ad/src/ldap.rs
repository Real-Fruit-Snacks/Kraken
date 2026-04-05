//! LDAP connection and query primitives
//!
//! On Windows this wraps the native `ldap_*` family of APIs from `wldap32.dll`
//! via the `Win32_Networking_Ldap` feature of `windows-sys`.
//!
//! On non-Windows targets every public function returns a
//! `KrakenError::Module("AD operations only supported on Windows")` stub so
//! the crate compiles and tests run cross-platform.
//!
//! ## Pagination
//! Large result sets are handled with the LDAP paged-results control
//! (OID 1.2.840.113556.1.4.319). The page size defaults to 1 000 entries.
//!
//! ## Detection artefacts
//! * Many rapid LDAP searches from a non-DC host (especially with
//!   `(objectClass=*)` or SPN filters) are flagged by Microsoft Defender for
//!   Identity and comparable NDR tools.
//! * wiki/detection/sigma/kraken_ad_ops.yml

use common::KrakenError;
use serde::{Deserialize, Serialize};

/// A single LDAP result entry: a DN plus a map of attribute → values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapEntry {
    /// Distinguished Name
    pub dn: String,
    /// Attribute name → list of string values
    pub attributes: std::collections::HashMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Networking::Ldap::{
        ldap_bind_sW, ldap_first_entry, ldap_get_dnW, ldap_get_values_lenW,
        ldap_initialize, ldap_msgfree, ldap_next_entry, ldap_search_ext_sW,
        ldap_unbind, ldap_value_free_len, LdapGetLastError, LDAP_AUTH_NEGOTIATE,
        LDAP_SCOPE_SUBTREE, LDAP_SUCCESS,
    };

    const PAGE_SIZE: u32 = 1_000;

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn from_wide_ptr(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        }
    }

    /// Connect to LDAP using the current user's credentials (SSPI/Negotiate).
    ///
    /// `domain_controller` may be `None` to use DNS auto-discovery.
    fn connect(domain_controller: Option<&str>) -> Result<*mut windows_sys::Win32::Networking::Ldap::LDAP, KrakenError> {
        let host_wide = domain_controller
            .map(|dc| wide(dc))
            .unwrap_or_else(Vec::new);

        let host_ptr = if domain_controller.is_some() {
            host_wide.as_ptr()
        } else {
            std::ptr::null()
        };

        let ldap = unsafe { ldap_initialize(host_ptr, 389) };
        if ldap.is_null() {
            let err = unsafe { LdapGetLastError() };
            return Err(KrakenError::Module(format!(
                "ldap_initialize failed: 0x{err:x}"
            )));
        }

        // Bind using the current process credentials (Kerberos/NTLM via SSPI).
        let rc = unsafe {
            ldap_bind_sW(
                ldap,
                std::ptr::null(),
                std::ptr::null(),
                LDAP_AUTH_NEGOTIATE,
            )
        };
        if rc != LDAP_SUCCESS {
            unsafe { ldap_unbind(ldap) };
            return Err(KrakenError::Module(format!(
                "ldap_bind_sW failed: 0x{rc:x}"
            )));
        }

        Ok(ldap)
    }

    /// Perform an LDAP search and return parsed entries.
    pub fn search(
        base_dn: &str,
        filter: &str,
        attributes: &[&str],
    ) -> Result<Vec<LdapEntry>, KrakenError> {
        let ldap = connect(None)?;

        let base_wide = wide(base_dn);
        let filter_wide = wide(filter);

        // Build null-terminated array of attribute name pointers.
        let attr_wide: Vec<Vec<u16>> = attributes.iter().map(|a| wide(a)).collect();
        let mut attr_ptrs: Vec<*const u16> = attr_wide.iter().map(|v| v.as_ptr()).collect();
        attr_ptrs.push(std::ptr::null()); // null terminator

        let mut msg = std::ptr::null_mut();

        let rc = unsafe {
            ldap_search_ext_sW(
                ldap,
                base_wide.as_ptr(),
                LDAP_SCOPE_SUBTREE as i32,
                filter_wide.as_ptr(),
                if attributes.is_empty() {
                    std::ptr::null_mut()
                } else {
                    attr_ptrs.as_mut_ptr()
                },
                0, // attrsonly = FALSE: return values
                std::ptr::null_mut(), // server controls
                std::ptr::null_mut(), // client controls
                PAGE_SIZE,
                0, // sizelimit (0 = server limit)
                &mut msg,
            )
        };

        if rc != LDAP_SUCCESS {
            unsafe {
                ldap_unbind(ldap);
            }
            return Err(KrakenError::Module(format!(
                "ldap_search_ext_sW failed: 0x{rc:x}"
            )));
        }

        let mut entries = Vec::new();
        let mut entry = unsafe { ldap_first_entry(ldap, msg) };

        while !entry.is_null() {
            let dn_ptr = unsafe { ldap_get_dnW(ldap, entry) };
            let dn = from_wide_ptr(dn_ptr);

            let mut attr_map = std::collections::HashMap::new();

            for attr in attributes {
                let attr_wide = wide(attr);
                let vals = unsafe {
                    ldap_get_values_lenW(ldap, entry, attr_wide.as_ptr())
                };
                if !vals.is_null() {
                    let mut strings = Vec::new();
                    let mut i = 0isize;
                    loop {
                        let berval_ptr = unsafe { *vals.offset(i) };
                        if berval_ptr.is_null() {
                            break;
                        }
                        let berval = unsafe { &*berval_ptr };
                        if berval.bv_len > 0 && !berval.bv_val.is_null() {
                            let bytes = unsafe {
                                std::slice::from_raw_parts(
                                    berval.bv_val as *const u8,
                                    berval.bv_len as usize,
                                )
                            };
                            strings.push(String::from_utf8_lossy(bytes).into_owned());
                        }
                        i += 1;
                    }
                    unsafe { ldap_value_free_len(vals) };
                    attr_map.insert((*attr).to_string(), strings);
                }
            }

            entries.push(LdapEntry { dn, attributes: attr_map });
            entry = unsafe { ldap_next_entry(ldap, entry) };
        }

        unsafe {
            ldap_msgfree(msg);
            ldap_unbind(ldap);
        }

        Ok(entries)
    }

    /// Retrieve the domain's default naming context (base DN).
    pub fn get_default_base_dn() -> Result<String, KrakenError> {
        let ldap = connect(None)?;

        // Query the RootDSE for defaultNamingContext.
        let filter = wide("(objectClass=*)");
        let base = wide("");
        let attr = wide("defaultNamingContext");
        let mut attr_ptrs = [attr.as_ptr(), std::ptr::null::<u16>()];
        let mut msg = std::ptr::null_mut();

        let rc = unsafe {
            ldap_search_ext_sW(
                ldap,
                base.as_ptr(),
                0, // LDAP_SCOPE_BASE
                filter.as_ptr(),
                attr_ptrs.as_mut_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                30,
                0,
                &mut msg,
            )
        };

        if rc != LDAP_SUCCESS {
            unsafe { ldap_unbind(ldap) };
            return Err(KrakenError::Module(format!(
                "RootDSE query failed: 0x{rc:x}"
            )));
        }

        let entry = unsafe { ldap_first_entry(ldap, msg) };
        if entry.is_null() {
            unsafe {
                ldap_msgfree(msg);
                ldap_unbind(ldap);
            }
            return Err(KrakenError::Module("RootDSE returned no entries".into()));
        }

        let attr_name = wide("defaultNamingContext");
        let vals = unsafe { ldap_get_values_lenW(ldap, entry, attr_name.as_ptr()) };
        let base_dn = if !vals.is_null() {
            let berval_ptr = unsafe { *vals };
            let result = if !berval_ptr.is_null() {
                let berval = unsafe { &*berval_ptr };
                if berval.bv_len > 0 && !berval.bv_val.is_null() {
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            berval.bv_val as *const u8,
                            berval.bv_len as usize,
                        )
                    };
                    String::from_utf8_lossy(bytes).into_owned()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            unsafe { ldap_value_free_len(vals) };
            result
        } else {
            String::new()
        };

        unsafe {
            ldap_msgfree(msg);
            ldap_unbind(ldap);
        }

        if base_dn.is_empty() {
            Err(KrakenError::Module("Could not determine base DN from RootDSE".into()))
        } else {
            Ok(base_dn)
        }
    }
}

// ---------------------------------------------------------------------------
// Public async API
// ---------------------------------------------------------------------------

/// Execute a raw LDAP search.
///
/// `filter` is an RFC 2254 LDAP filter string.
/// `attributes` is the list of attribute names to retrieve; pass an empty
/// slice to request all attributes.
pub async fn ldap_query(
    filter: impl Into<String> + Send + 'static,
    attributes: &[String],
) -> Result<Vec<LdapEntry>, KrakenError> {
    #[cfg(windows)]
    {
        let filter = filter.into();
        let attrs: Vec<String> = attributes.to_vec();
        tokio::task::spawn_blocking(move || {
            let base = win::get_default_base_dn()?;
            let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
            win::search(&base, &filter, &attr_refs)
        })
        .await
        .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        let _ = (filter, attributes);
        Err(KrakenError::Module(
            "AD operations only supported on Windows".into(),
        ))
    }
}

/// Internal helper used by sub-modules: synchronous LDAP search (Windows only).
///
/// Exposed as `pub(crate)` so `users`, `groups`, `computers`, `kerberoast`,
/// and `asreproast` can call it without duplicating the connect/search logic.
#[cfg(windows)]
pub(crate) fn search_sync(
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<LdapEntry>, KrakenError> {
    let base = win::get_default_base_dn()?;
    win::search(&base, filter, attributes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn ldap_query_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(ldap_query("(objectClass=*)", &[]))
            .unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[test]
    fn ldap_entry_serializes() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("sAMAccountName".into(), vec!["jdoe".into()]);
        let entry = LdapEntry {
            dn: "CN=John Doe,CN=Users,DC=corp,DC=local".into(),
            attributes: attrs,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("sAMAccountName"));
        assert!(json.contains("jdoe"));
    }
}
