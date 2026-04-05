//! AD user enumeration
//!
//! Queries Active Directory for user accounts using the LDAP filter:
//! `(&(objectClass=user)(objectCategory=person))`
//!
//! The following attributes are retrieved for each user:
//! * `distinguishedName`
//! * `sAMAccountName`
//! * `displayName`
//! * `memberOf`
//! * `userAccountControl`
//! * `servicePrincipalName`
//!
//! `userAccountControl` flag 0x0002 (`ACCOUNTDISABLE`) is used to populate
//! the `enabled` field.
//!
//! ## Detection artefacts
//! * wiki/detection/sigma/kraken_ad_ops.yml

use common::KrakenError;
use serde::{Deserialize, Serialize};

/// Information about a single AD user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUserInfo {
    /// Distinguished Name, e.g. `CN=John Doe,CN=Users,DC=corp,DC=local`
    pub dn: String,
    /// SAM account name (pre-Windows-2000 logon name)
    pub sam_account_name: String,
    /// Display name (may be empty)
    pub display_name: String,
    /// Account is enabled (`userAccountControl & 0x2 == 0`)
    pub enabled: bool,
    /// Groups the user is a direct member of
    pub groups: Vec<String>,
    /// Service Principal Names (non-empty → potential Kerberoast target)
    pub spns: Vec<String>,
}

#[allow(dead_code)]
const ATTRS: &[&str] = &[
    "distinguishedName",
    "sAMAccountName",
    "displayName",
    "memberOf",
    "userAccountControl",
    "servicePrincipalName",
];

/// Enumerate AD user accounts.
///
/// `extra_filter` is an optional additional LDAP filter clause that is
/// `AND`-combined with the default user filter, e.g.
/// `"(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)"`.
pub async fn get_users(extra_filter: Option<&str>) -> Result<Vec<AdUserInfo>, KrakenError> {
    #[cfg(windows)]
    {
        let filter = build_filter(extra_filter);
        tokio::task::spawn_blocking(move || {
            let entries = crate::ldap::search_sync(&filter, ATTRS)?;
            Ok(entries.into_iter().map(parse_user).collect())
        })
        .await
        .map_err(|e| KrakenError::Internal(e.to_string()))?
    }
    #[cfg(not(windows))]
    {
        let _ = extra_filter;
        Err(KrakenError::Module(
            "AD operations only supported on Windows".into(),
        ))
    }
}

#[allow(dead_code)]
fn build_filter(extra: Option<&str>) -> String {
    let base = "(&(objectClass=user)(objectCategory=person))";
    match extra {
        Some(f) if !f.is_empty() => format!("(&{base}{f})"),
        _ => base.to_string(),
    }
}

#[allow(dead_code)]
fn parse_user(entry: crate::ldap::LdapEntry) -> AdUserInfo {
    let get = |k: &str| -> Vec<String> {
        entry.attributes.get(k).cloned().unwrap_or_default()
    };

    let sam = get("sAMAccountName").into_iter().next().unwrap_or_default();
    let display = get("displayName").into_iter().next().unwrap_or_default();

    // userAccountControl is a decimal integer string; flag 0x2 = ACCOUNTDISABLE.
    let uac: u32 = get("userAccountControl")
        .into_iter()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let enabled = (uac & 0x0002) == 0;

    AdUserInfo {
        dn: entry.dn,
        sam_account_name: sam,
        display_name: display,
        enabled,
        groups: get("memberOf"),
        spns: get("servicePrincipalName"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn get_users_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(get_users(None)).unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[test]
    fn build_filter_no_extra() {
        let f = build_filter(None);
        assert_eq!(f, "(&(objectClass=user)(objectCategory=person))");
    }

    #[test]
    fn build_filter_with_extra() {
        let f = build_filter(Some("(memberOf=CN=DA,DC=corp,DC=local)"));
        assert!(f.starts_with("(&(&"));
        assert!(f.contains("memberOf"));
    }

    #[test]
    fn parse_user_enabled_flag() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("sAMAccountName".into(), vec!["jdoe".into()]);
        attrs.insert("displayName".into(), vec!["John Doe".into()]);
        // uac=512 → normal account, enabled
        attrs.insert("userAccountControl".into(), vec!["512".into()]);
        attrs.insert("memberOf".into(), vec!["CN=Users,DC=corp,DC=local".into()]);
        attrs.insert("servicePrincipalName".into(), vec![]);

        let entry = crate::ldap::LdapEntry {
            dn: "CN=John Doe,CN=Users,DC=corp,DC=local".into(),
            attributes: attrs,
        };
        let user = parse_user(entry);
        assert_eq!(user.sam_account_name, "jdoe");
        assert!(user.enabled);
        assert_eq!(user.groups.len(), 1);
    }

    #[test]
    fn parse_user_disabled_flag() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("sAMAccountName".into(), vec!["disabled_user".into()]);
        // uac=514 → disabled account (512 | 2)
        attrs.insert("userAccountControl".into(), vec!["514".into()]);

        let entry = crate::ldap::LdapEntry {
            dn: "CN=Disabled,CN=Users,DC=corp,DC=local".into(),
            attributes: attrs,
        };
        let user = parse_user(entry);
        assert!(!user.enabled);
    }
}
