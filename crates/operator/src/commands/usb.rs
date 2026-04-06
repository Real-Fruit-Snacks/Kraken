//! USB device monitoring commands

use anyhow::Result;
use common::ImplantId;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Start monitoring USB device insertion and removal events on the implant
pub async fn start(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Starting USB device monitor...");
    let task_data = b"start".to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "usb_monitor", task_data).await?;
    print_success(&format!("USB monitor start task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Use 'usb list' to see detected devices");

    Ok(())
}

/// Stop monitoring USB device events on the implant
pub async fn stop(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Stopping USB device monitor...");
    let task_data = b"stop".to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "usb_monitor", task_data).await?;
    print_success(&format!("USB monitor stop task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// List USB devices currently detected on the implant
pub async fn list(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Listing USB devices...");
    let task_data = b"list".to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "usb_monitor", task_data).await?;
    print_success(&format!("USB list task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}
