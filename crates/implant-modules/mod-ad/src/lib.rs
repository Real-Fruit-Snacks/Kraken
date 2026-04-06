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

// Full Windows LDAP/Kerberos implementation — gated behind the `full-ad`
// feature because it requires a domain-joined Windows host and has additional
// windows-sys bindings that may not be available in all build configurations.
#[cfg(feature = "full-ad")]
pub mod asreproast;
#[cfg(feature = "full-ad")]
pub mod computers;
#[cfg(feature = "full-ad")]
pub mod groups;
#[cfg(feature = "full-ad")]
pub mod kerberos;
#[cfg(feature = "full-ad")]
pub mod kerberoast;
#[cfg(feature = "full-ad")]
pub mod ldap;
#[cfg(feature = "full-ad")]
pub mod users;

#[cfg(feature = "full-ad")]
pub use asreproast::{asreproast, AsreproastResult};
#[cfg(feature = "full-ad")]
pub use computers::{get_computers, AdComputerInfo};
#[cfg(feature = "full-ad")]
pub use groups::{get_groups, AdGroupInfo};
#[cfg(feature = "full-ad")]
pub use kerberos::{list_tickets, pass_the_ticket, purge_tickets, TicketInfo};
#[cfg(feature = "full-ad")]
pub use kerberoast::{kerberoast, KerberoastResult};
#[cfg(feature = "full-ad")]
pub use ldap::{ldap_query, LdapEntry};
#[cfg(feature = "full-ad")]
pub use users::{get_users, AdUserInfo};

use common::{KrakenError, Module, ModuleId, ShellOutput, TaskId, TaskResult};

/// Synchronous Module trait wrapper for the AD module.
///
/// The full AD implementation is async and requires a domain-joined Windows
/// host with LDAP access. This wrapper returns a clean error so that the "ad"
/// task type is recognised by the registry rather than returning "unknown task type".
pub struct AdModule {
    id: ModuleId,
}

impl AdModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("ad"),
        }
    }
}

impl Default for AdModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for AdModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Active Directory"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, _task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        // Full AD operations require a domain-joined Windows host with LDAP
        // access. Return a clean error rather than "unknown task type".
        Ok(TaskResult::Shell(ShellOutput {
            stdout: String::new(),
            stderr: "Active Directory module not yet implemented. \
                     The implant must be running on a domain-joined Windows host \
                     and built with the `full-ad` feature."
                .to_string(),
            exit_code: 1,
            duration_ms: 0,
        }))
    }
}

/// Discriminated AD task type (used by the full implementation)
#[cfg(feature = "full-ad")]
#[derive(Debug, Clone)]
pub struct AdTask {
    pub operation: AdOperation,
}

/// AD operation variants
#[cfg(feature = "full-ad")]
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
#[cfg(feature = "full-ad")]
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

/// Execute an AD operation specified by `AdTask`.
///
/// This is the module dispatch entry point called by the implant core.
#[cfg(feature = "full-ad")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ad_module_id() {
        let m = AdModule::new();
        assert_eq!(m.id().as_str(), "ad");
        assert_eq!(m.name(), "Active Directory");
    }

    #[test]
    fn test_ad_module_handle_returns_clean_error() {
        let m = AdModule::new();
        let result = m.handle(TaskId::new(), &[]);
        assert!(result.is_ok());
        if let Ok(TaskResult::Shell(out)) = result {
            assert_eq!(out.exit_code, 1);
            assert!(!out.stderr.is_empty());
        }
    }

    #[cfg(feature = "full-ad")]
    #[test]
    fn dispatch_compiles_and_variants_accessible() {
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
}
