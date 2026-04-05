//! AD computer enumeration
//!
//! Queries Active Directory for computer accounts using the LDAP filter:
//! `(objectClass=computer)`
//!
//! Attributes retrieved per computer:
//! * `distinguishedName`
//! * `cn`
//! * `operatingSystem`
//! * `userAccountControl`
//!
//! A computer is identified as a Domain Controller when the
//! `userAccountControl` flag `0x2000` (`SERVER_TRUST_ACCOUNT`) is set.
//!
//! ## Detection artefacts
//! * wiki/detection/sigma/kraken_ad_ops.yml

use common::KrakenError;
use serde::{Deserialize, Serialize};

/// Information about a single AD computer account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputerInfo {
    /// Distinguished Name
    pub dn: String,
    /// Computer name (SAM name without trailing `$`)
    pub name: String,
    /// Operating system string (may be empty for older accounts)
    pub os: String,
    /// `true` when `SERVER_TRUST_ACCOUNT (0x2000)` is set in userAccountControl
    pub is_dc: bool,
}

#[allow(dead_code)]
const ATTRS: &[&str] = &[
    "distinguishedName",
    "cn",
    "operatingSystem",
    "userAccountControl",
];

/// Enumerate AD computer accounts.
///
/// `extra_filter` is optionally `AND`-combined with the default computer filter.
pub async fn get_computers(extra_filter: Option<&str>) -> Result<Vec<AdComputerInfo>, KrakenError> {
    #[cfg(windows)]
    {
        let filter = build_filter(extra_filter);
        tokio::task::spawn_blocking(move || {
            let entries = crate::ldap::search_sync(&filter, ATTRS)?;
            Ok(entries.into_iter().map(parse_computer).collect())
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
    let base = "(objectClass=computer)";
    match extra {
        Some(f) if !f.is_empty() => format!("(&{base}{f})"),
        _ => base.to_string(),
    }
}

#[allow(dead_code)]
fn parse_computer(entry: crate::ldap::LdapEntry) -> AdComputerInfo {
    let get = |k: &str| -> Vec<String> {
        entry.attributes.get(k).cloned().unwrap_or_default()
    };

    let name = get("cn").into_iter().next().unwrap_or_default();
    let os = get("operatingSystem").into_iter().next().unwrap_or_default();

    let uac: u32 = get("userAccountControl")
        .into_iter()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // SERVER_TRUST_ACCOUNT = 0x2000
    let is_dc = (uac & 0x2000) != 0;

    AdComputerInfo {
        dn: entry.dn,
        name,
        os,
        is_dc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn get_computers_non_windows_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(get_computers(None)).unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"));
    }

    #[test]
    fn build_filter_no_extra() {
        assert_eq!(build_filter(None), "(objectClass=computer)");
    }

    #[test]
    fn parse_computer_dc_flag() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("cn".into(), vec!["DC01".into()]);
        attrs.insert("operatingSystem".into(), vec!["Windows Server 2022".into()]);
        // uac=8256 = 0x2040 → SERVER_TRUST_ACCOUNT set → is DC
        attrs.insert("userAccountControl".into(), vec!["8256".into()]);

        let entry = crate::ldap::LdapEntry {
            dn: "CN=DC01,OU=Domain Controllers,DC=corp,DC=local".into(),
            attributes: attrs,
        };
        let comp = parse_computer(entry);
        assert_eq!(comp.name, "DC01");
        assert!(comp.is_dc);
        assert_eq!(comp.os, "Windows Server 2022");
    }

    #[test]
    fn parse_computer_workstation_not_dc() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("cn".into(), vec!["WS01".into()]);
        // uac=4096 = 0x1000 → WORKSTATION_TRUST_ACCOUNT, not a DC
        attrs.insert("userAccountControl".into(), vec!["4096".into()]);

        let entry = crate::ldap::LdapEntry {
            dn: "CN=WS01,CN=Computers,DC=corp,DC=local".into(),
            attributes: attrs,
        };
        let comp = parse_computer(entry);
        assert!(!comp.is_dc);
    }
}
