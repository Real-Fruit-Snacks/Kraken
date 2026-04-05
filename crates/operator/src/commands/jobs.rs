//! Jobs management commands

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_jobs_table, print_success, JobDisplayInfo};

/// List all jobs
pub async fn list(cli: &CliState) -> Result<()> {
    // Get jobs from server - passing empty slice for now
    let jobs = cli.client.list_jobs(&[]).await?;

    // Convert to display format
    let display_jobs: Vec<JobDisplayInfo> = jobs
        .iter()
        .map(|job| {
            let task_id = if job.task_id.len() >= 4 {
                hex::encode(&job.task_id[..4])
            } else if !job.task_id.is_empty() {
                hex::encode(&job.task_id)
            } else {
                "unknown".to_string()
            };

            let status = match job.status {
                0 => "running",
                1 => "completed",
                2 => "failed",
                3 => "cancelled",
                _ => "unknown",
            };

            let created_at = format_timestamp(job.created_at);
            let completed_at = job.completed_at.map(format_timestamp);

            JobDisplayInfo {
                job_id: job.job_id,
                task_id,
                description: job.description.clone(),
                status: status.to_string(),
                progress: job.progress,
                created_at,
                completed_at,
                error_message: None, // Error field not in current JobInfo
                output_preview: String::new(), // Output field not in current JobInfo
            }
        })
        .collect();

    print_jobs_table(&display_jobs);

    Ok(())
}

/// Show detailed job information
pub async fn show(cli: &CliState, job_id: u32) -> Result<()> {
    let jobs = cli.client.list_jobs(&[]).await?;

    if let Some(job) = jobs.iter().find(|j| j.job_id == job_id) {
        println!("\nJob Details:");
        println!("  Job ID:      {}", job.job_id);

        if !job.task_id.is_empty() {
            println!("  Task ID:     {}", hex::encode(&job.task_id));
        }

        println!("  Type:        {}", job.description);
        println!("  Status:      {}", match job.status {
            0 => "running",
            1 => "completed",
            2 => "failed",
            3 => "cancelled",
            _ => "unknown",
        });
        println!("  Progress:    {}%", job.progress);
        println!("  Created:     {}", format_timestamp(job.created_at));

        if let Some(completed) = job.completed_at {
            println!("  Completed:   {}", format_timestamp(completed));
        }

        print_info("Note: Full job output/errors require server-side storage implementation");
    } else {
        print_error(&format!("Job {} not found", job_id));
    }

    Ok(())
}

/// Kill a running job
pub async fn kill(cli: &CliState, job_id: u32) -> Result<()> {
    let success = cli.client.kill_job(&[], job_id).await?;

    if success {
        print_success(&format!("Job {} killed", job_id));
    } else {
        print_error(&format!("Failed to kill job {}", job_id));
    }

    Ok(())
}

/// Show full job output
pub async fn output(cli: &CliState, job_id: u32) -> Result<()> {
    print_info(&format!("Fetching output for job {}...", job_id));

    match cli.client.get_job_output(job_id).await {
        Ok((output_chunks, is_complete, final_status)) => {
            if output_chunks.is_empty() {
                print_info("No output available yet");
                if !is_complete {
                    print_info("Job is still running - check back later");
                }
                return Ok(());
            }

            println!("\n=== Job {} Output ===", job_id);

            // Print all output chunks
            for (i, chunk) in output_chunks.iter().enumerate() {
                // Try to decode as UTF-8, fallback to hex dump
                match String::from_utf8(chunk.clone()) {
                    Ok(text) => print!("{}", text),
                    Err(_) => {
                        println!("\n[Chunk {} - Binary data, {} bytes]", i + 1, chunk.len());
                        // Print hex preview (first 64 bytes)
                        let preview_len = chunk.len().min(64);
                        print!("  ");
                        for byte in &chunk[..preview_len] {
                            print!("{:02x} ", byte);
                        }
                        if chunk.len() > 64 {
                            print!("... ({} more bytes)", chunk.len() - 64);
                        }
                        println!();
                    }
                }
            }

            println!("\n=== End Output ===");

            // Print status
            if is_complete {
                let status_str = match final_status {
                    Some(1) => "completed successfully",
                    Some(2) => "failed",
                    Some(3) => "cancelled",
                    _ => "completed",
                };
                print_success(&format!("Job {}", status_str));
            } else {
                print_info("Job is still running");
            }

            Ok(())
        }
        Err(e) => {
            print_error(&format!("Failed to get job output: {}", e));
            Ok(())
        }
    }
}

/// Clean completed/failed jobs
pub async fn clean(cli: &CliState) -> Result<()> {
    let session = cli.active_session();
    if session.is_none() {
        print_error("No session selected. Use 'use <id>' first.");
        return Ok(());
    }

    print_info("Fetching jobs...");

    let jobs = cli.client.list_jobs(&session.unwrap().full_id).await?;

    // Count completed jobs (status 2 = completed, 3 = failed)
    let completed_count = jobs.iter().filter(|j| j.status == 2 || j.status == 3).count();

    if completed_count == 0 {
        print_info("No completed jobs to clean");
        return Ok(());
    }

    print_info(&format!("Found {} completed/failed jobs", completed_count));
    print_info("Note: Server-side cleanup endpoint not yet available");
    print_info("Jobs will remain in server memory until implant reconnects");
    print_info("Use 'jobs list' to view all jobs");

    Ok(())
}

/// Format a Unix timestamp to HH:MM:SS
fn format_timestamp(ts: i64) -> String {
    if ts == 0 {
        return "N/A".to_string();
    }

    if let Some(dt) = DateTime::<Utc>::from_timestamp(ts, 0) {
        dt.format("%H:%M:%S").to_string()
    } else {
        "invalid".to_string()
    }
}

/// Truncate output to max_len characters
#[allow(dead_code)]
fn truncate_output(output: &str, max_len: usize) -> String {
    if output.len() <= max_len {
        output.to_string()
    } else {
        format!("{}...", &output[..max_len])
    }
}
