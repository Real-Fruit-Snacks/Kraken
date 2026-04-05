//! AD group enumeration
//!
//! Queries Active Directory for group objects using the LDAP filter:
//! `(objectClass=group)`
//!
//! Attributes retrieved per group:
//! * `distinguishedName`
//! * `cn` (common name / group name)
//! * `member`
//!
//! ## Detection artefacts
//! * wiki/detection/sigma/kraken_ad_ops.yml

use common::KrakenError;
use serde::{Deserialize, Serialize};

/// Information about a single AD group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroupInfo {
    /// Distinguished Name
    pub dn: String,
    /// Common name of the group
    pub name: String,
    /// Distinguished names of direct group members
    pub members: Vec<String>,
}

#[allow(dead_code)]
const ATTRS: &[&str] = &["distinguishedName", "cn", "member"];

/// Enumerate AD groups.
///
/// `extra_filter` is optionally `AND`-combined with the default group filter.
pub async fn get_groups(extra_filter: Option<&str>) -> Result<Vec<AdGroupInfo>, KrakenError> {
    #[cfg(windows)]
    {
        let filter = build_filter(extra_filter);
        tokio::task::spawn_blocking(move || {
            let entries = crate::ldap::search_sync(&filter, ATTRS)?;
            Ok(entries.into_iter().map(parse_group).collect())
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
    let base = "(objectClass=group)";
    match extra {
        Some(f) if !f.is_empty() => format!("(&{base}{f})"),
        _ => base.to_string(),
    }
}

#[allow(dead_code)]
fn parse_group(entry: crate::ldap::LdapEntry) -> AdGroupInfo {
    let get = |k: &str| -> Vec<String> {
        entry.attributes.get(k).cloned().unwrap_or_default()
    };
    AdGroupInfo {
        dn: entry.dn,
        name: get("cn").into_iter().next().unwrap_or_default(),
        members: get("member"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn get_groups_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(get_groups(None)).unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[test]
    fn build_filter_no_extra() {
        assert_eq!(build_filter(None), "(objectClass=group)");
    }

    #[test]
    fn build_filter_with_extra() {
        let f = build_filter(Some("(cn=Domain Admins)"));
        assert!(f.starts_with("(&"));
        assert!(f.contains("cn=Domain Admins"));
    }

    #[test]
    fn parse_group_extracts_fields() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("cn".into(), vec!["Domain Admins".into()]);
        attrs.insert(
            "member".into(),
            vec![
                "CN=Administrator,CN=Users,DC=corp,DC=local".into(),
                "CN=jdoe,CN=Users,DC=corp,DC=local".into(),
            ],
        );
        let entry = crate::ldap::LdapEntry {
            dn: "CN=Domain Admins,CN=Users,DC=corp,DC=local".into(),
            attributes: attrs,
        };
        let group = parse_group(entry);
        assert_eq!(group.name, "Domain Admins");
        assert_eq!(group.members.len(), 2);
    }
}
