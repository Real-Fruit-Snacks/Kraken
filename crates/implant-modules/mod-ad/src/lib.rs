//! Active Directory enumeration and Kerberos attack module
//!
//! Provides LDAP-based AD enumeration and Kerberos attack primitives for use
//! during authorised red team operations.
//!
//! ## Operations
//! | Function         | Description                                              |
//! |------------------|----------------------------------------------------------|
//! | `get_users`      | Enumerate AD user accounts via LDAP                      |
//! | `get_groups`     | Enumerate AD groups via LDAP                             |
//! | `get_computers`  | Enumerate AD computer accounts via LDAP                  |
//! | `kerberoast`     | Request TGS tickets for SPN accounts (Kerberoasting)     |
//! | `asreproast`     | Request AS-REP for pre-auth disabled accounts            |
//! | `ldap_query`     | Execute a raw LDAP query with custom filter/attributes   |
//! | `list_tickets`   | Enumerate cached Kerberos tickets (klist)                |
//! | `pass_the_ticket`| Inject a .kirbi ticket into the current logon session    |
//! | `purge_tickets`  | Purge all cached Kerberos tickets                        |
//!
//! ## Detection rules
//! wiki/detection/sigma/kraken_ad_ops.yml
//! wiki/detection/yara/kraken_ad.yar

pub mod asreproast;
pub mod computers;
pub mod groups;
pub mod kerberos;
pub mod kerberoast;
pub mod ldap;
pub mod users;

pub use asreproast::{asreproast, AsreproastResult};
pub use computers::{get_computers, AdComputerInfo};
pub use groups::{get_groups, AdGroupInfo};
pub use kerberos::{list_tickets, pass_the_ticket, purge_tickets, TicketInfo};
pub use kerberoast::{kerberoast, KerberoastResult};
pub use ldap::{ldap_query, LdapEntry};
pub use users::{get_users, AdUserInfo};

use common::KrakenError;

/// Execute an AD operation specified by `AdTask`.
///
/// This is the module dispatch entry point called by the implant core.
pub async fn dispatch(task: AdTask) -> Result<AdResult, KrakenError> {
    match task.operation {
        AdOperation::GetUsers(filter) => {
            let users = get_users(filter.as_deref()).await?;
            Ok(AdResult::Users(users))
        }
        AdOperation::GetGroups(filter) => {
            let groups = get_groups(filter.as_deref()).await?;
            Ok(AdResult::Groups(groups))
        }
        AdOperation::GetComputers(filter) => {
            let computers = get_computers(filter.as_deref()).await?;
            Ok(AdResult::Computers(computers))
        }
        AdOperation::Kerberoast(format) => {
            let result = kerberoast(format.as_deref()).await?;
            Ok(AdResult::Kerberoast(result))
        }
        AdOperation::Asreproast(format) => {
            let result = asreproast(format.as_deref()).await?;
            Ok(AdResult::Asreproast(result))
        }
        AdOperation::Query { filter, attributes } => {
            let entries = ldap_query(filter.clone(), &attributes).await?;
            Ok(AdResult::Query(entries))
        }
        AdOperation::ListTickets => {
            let tickets = list_tickets()?;
            Ok(AdResult::Tickets(tickets))
        }
        AdOperation::PassTheTicket(kirbi) => {
            let msg = pass_the_ticket(&kirbi)?;
            Ok(AdResult::Message(msg))
        }
        AdOperation::PurgeTickets => {
            let msg = purge_tickets()?;
            Ok(AdResult::Message(msg))
        }
    }
}

/// Discriminated AD task type
#[derive(Debug, Clone)]
pub struct AdTask {
    pub operation: AdOperation,
}

/// AD operation variants
#[derive(Debug, Clone)]
pub enum AdOperation {
    GetUsers(Option<String>),
    GetGroups(Option<String>),
    GetComputers(Option<String>),
    Kerberoast(Option<String>),
    Asreproast(Option<String>),
    Query {
        filter: String,
        attributes: Vec<String>,
    },
    /// Enumerate cached Kerberos tickets (klist equivalent) — T1558
    ListTickets,
    /// Inject a .kirbi ticket into the current logon session — T1550.003
    PassTheTicket(Vec<u8>),
    /// Purge all cached Kerberos tickets
    PurgeTickets,
}

/// AD operation result
#[derive(Debug, Clone)]
pub enum AdResult {
    Users(Vec<AdUserInfo>),
    Groups(Vec<AdGroupInfo>),
    Computers(Vec<AdComputerInfo>),
    Kerberoast(KerberoastResult),
    Asreproast(AsreproastResult),
    Query(Vec<LdapEntry>),
    /// Kerberos ticket cache enumeration result
    Tickets(Vec<TicketInfo>),
    /// Generic string message (e.g. success confirmation)
    Message(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_compiles_and_variants_accessible() {
        // Verify the public API surface compiles correctly on all platforms.
        let _ = AdOperation::GetUsers(None);
        let _ = AdOperation::GetGroups(Some("CN=Domain Admins".into()));
        let _ = AdOperation::GetComputers(None);
        let _ = AdOperation::Kerberoast(None);
        let _ = AdOperation::Asreproast(None);
        let _ = AdOperation::Query {
            filter: "(&(objectClass=user))".into(),
            attributes: vec!["sAMAccountName".into()],
        };
        let _ = AdOperation::ListTickets;
        let _ = AdOperation::PassTheTicket(vec![0xDE, 0xAD]);
        let _ = AdOperation::PurgeTickets;
    }

    #[cfg(not(windows))]
    #[test]
    fn all_ops_return_platform_error_on_non_windows() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let ops = vec![
            AdOperation::GetUsers(None),
            AdOperation::GetGroups(None),
            AdOperation::GetComputers(None),
            AdOperation::Kerberoast(None),
            AdOperation::Asreproast(None),
            AdOperation::Query {
                filter: "(objectClass=*)".into(),
                attributes: vec![],
            },
            AdOperation::ListTickets,
            AdOperation::PassTheTicket(vec![0xDE, 0xAD]),
            AdOperation::PurgeTickets,
        ];

        for op in ops {
            let task = AdTask { operation: op };
            let err = rt.block_on(dispatch(task)).unwrap_err();
            assert!(
                err.to_string().contains("only supported on Windows"),
                "expected Windows-only error, got: {err}"
            );
        }
    }
}
