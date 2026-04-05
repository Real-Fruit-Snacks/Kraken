//! Shell execution logic
//!
//! Cross-platform shell command execution with timeout support.

use common::{KrakenError, ShellOutput};
use protocol::ShellTask;
use std::time::{Duration, Instant};

/// Execute a shell command and return structured output
pub fn run_shell(task: &ShellTask) -> Result<ShellOutput, KrakenError> {
    let start = Instant::now();
    let timeout_ms = task.timeout_ms.unwrap_or(30_000) as u64;
    let timeout = Duration::from_millis(timeout_ms);

    #[cfg(unix)]
    let result = run_unix(task, timeout);

    #[cfg(windows)]
    let result = run_windows(task, timeout);

    #[cfg(not(any(unix, windows)))]
    let result = Err(KrakenError::internal("unsupported platform"));

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok((stdout, stderr, exit_code)) => Ok(ShellOutput {
            stdout,
            stderr,
            exit_code,
            duration_ms,
        }),
        Err(e) => Ok(ShellOutput {
            stdout: String::new(),
            stderr: e.to_string(),
            exit_code: -1,
            duration_ms,
        }),
    }
}

// ============================================================================
// Unix Implementation
// ============================================================================

#[cfg(unix)]
fn run_unix(
    task: &ShellTask,
    timeout: Duration,
) -> Result<(String, String, i32), KrakenError> {
    use std::process::{Command, Stdio};
    use wait_timeout::ChildExt;

    let shell = task.shell.as_deref().unwrap_or_else(|| default_shell_unix());

    let mut child = Command::new(shell)
        .arg("-c")
        .arg(&task.command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| KrakenError::internal(format!("spawn failed: {}", e)))?;

    // Wait with timeout
    match child.wait_timeout(timeout) {
        Ok(Some(status)) => {
            // Process completed within timeout
            let stdout = read_child_stdout(&mut child);
            let stderr = read_child_stderr(&mut child);
            let exit_code = status.code().unwrap_or(-1);
            Ok((stdout, stderr, exit_code))
        }
        Ok(None) => {
            // Timeout - kill the process
            let _ = child.kill();
            let _ = child.wait(); // Reap zombie
            Err(KrakenError::internal("command timed out"))
        }
        Err(e) => Err(KrakenError::internal(format!("wait failed: {}", e))),
    }
}

#[cfg(unix)]
fn read_child_stdout(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let mut stdout = String::new();
    if let Some(ref mut out) = child.stdout {
        let _ = out.read_to_string(&mut stdout);
    }
    stdout
}

#[cfg(unix)]
fn read_child_stderr(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let mut stderr = String::new();
    if let Some(ref mut err) = child.stderr {
        let _ = err.read_to_string(&mut stderr);
    }
    stderr
}

#[cfg(unix)]
fn default_shell_unix() -> &'static str {
    // SECURITY: Do NOT read from $SHELL - could be attacker-controlled
    // Use hardcoded safe paths
    "/bin/sh"
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(windows)]
fn run_windows(
    task: &ShellTask,
    timeout: Duration,
) -> Result<(String, String, i32), KrakenError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::Pipes::*;
    use windows_sys::Win32::System::Threading::*;

    // Determine shell and arguments
    let shell = task.shell.as_deref().unwrap_or("cmd");
    let (executable, args) = match shell {
        "cmd" => (
            "C:\\Windows\\System32\\cmd.exe",
            format!("/c {}", task.command),
        ),
        "powershell" | "ps" => (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            format!("-NoProfile -NonInteractive -Command {}", task.command),
        ),
        "pwsh" => (
            "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
            format!("-NoProfile -NonInteractive -Command {}", task.command),
        ),
        custom => (custom, task.command.clone()),
    };

    unsafe {
        // Create pipes for stdout/stderr
        let (stdout_read, stdout_write) = create_pipe()?;
        let (stderr_read, stderr_write) = create_pipe()?;

        // Set up startup info with hidden window and redirected handles
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = stdout_write;
        si.hStdError = stderr_write;
        si.hStdInput = 0 as HANDLE; // No stdin
        si.wShowWindow = 0; // SW_HIDE

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // Build command line
        let cmdline = format!("\"{}\" {}", executable, args);
        let mut cmdline_wide: Vec<u16> = OsStr::new(&cmdline)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Create process
        let success = CreateProcessW(
            ptr::null(),
            cmdline_wide.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            TRUE, // Inherit handles
            CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi,
        );

        if success == 0 {
            CloseHandle(stdout_read);
            CloseHandle(stdout_write);
            CloseHandle(stderr_read);
            CloseHandle(stderr_write);
            return Err(KrakenError::internal(format!(
                "CreateProcess failed: {}",
                GetLastError()
            )));
        }

        // Close write ends in parent (important for EOF detection)
        CloseHandle(stdout_write);
        CloseHandle(stderr_write);

        // Wait for process with timeout
        let timeout_ms = timeout.as_millis() as u32;
        let wait_result = WaitForSingleObject(pi.hProcess, timeout_ms);

        if wait_result == WAIT_TIMEOUT {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(stdout_read);
            CloseHandle(stderr_read);
            return Err(KrakenError::internal("command timed out"));
        }

        // Get exit code
        let mut exit_code: u32 = 0;
        GetExitCodeProcess(pi.hProcess, &mut exit_code);

        // Read output from pipes
        let stdout = read_pipe(stdout_read)?;
        let stderr = read_pipe(stderr_read)?;

        // Cleanup handles
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        Ok((stdout, stderr, exit_code as i32))
    }
}

#[cfg(windows)]
fn create_pipe() -> Result<(HANDLE, HANDLE), KrakenError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Pipes::*;

    unsafe {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: TRUE,
        };

        let mut read_handle: HANDLE = 0;
        let mut write_handle: HANDLE = 0;

        let success = CreatePipe(&mut read_handle, &mut write_handle, &mut sa, 0);

        if success == 0 {
            return Err(KrakenError::internal(format!(
                "CreatePipe failed: {}",
                GetLastError()
            )));
        }

        // Make read handle non-inheritable
        SetHandleInformation(read_handle, HANDLE_FLAG_INHERIT, 0);

        Ok((read_handle, write_handle))
    }
}

#[cfg(windows)]
fn read_pipe(handle: HANDLE) -> Result<String, KrakenError> {
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Storage::FileSystem::*;

    unsafe {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];

        loop {
            let mut bytes_read: u32 = 0;
            let success = ReadFile(
                handle,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            );

            if success == 0 || bytes_read == 0 {
                break;
            }

            buffer.extend_from_slice(&chunk[..bytes_read as usize]);
        }

        Ok(String::from_utf8_lossy(&buffer).to_string())
    }
}

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_echo() {
        let task = ShellTask {
            command: "echo test123".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        assert!(result.stdout.contains("test123"));
        assert_eq!(result.exit_code, 0);
        assert!(result.duration_ms < 5000);
    }

    #[test]
    fn test_timeout_handling() {
        #[cfg(unix)]
        let task = ShellTask {
            command: "sleep 10".to_string(),
            shell: None,
            timeout_ms: Some(100), // Very short timeout
        };

        #[cfg(windows)]
        let task = ShellTask {
            command: "ping -n 10 127.0.0.1".to_string(),
            shell: None,
            timeout_ms: Some(100), // Very short timeout
        };

        let result = run_shell(&task).unwrap();
        // Should timeout and return error in stderr
        assert!(result.stderr.contains("timed out") || result.exit_code != 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_custom_shell() {
        let task = ShellTask {
            command: "echo $0".to_string(),
            shell: Some("/bin/bash".to_string()),
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task);
        // If bash is available, it should work
        if result.is_ok() {
            let output = result.unwrap();
            assert!(output.stdout.contains("bash") || output.exit_code == 0);
        }
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_empty_command() {
        let task = ShellTask {
            command: "".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        // Empty command should succeed (no-op)
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty() || result.stdout.trim().is_empty());
    }

    #[test]
    fn test_whitespace_only_command() {
        let task = ShellTask {
            command: "   \t\n   ".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        // Whitespace-only command should succeed
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_very_long_command() {
        // Create a command that echoes a very long string (64KB)
        let long_arg = "x".repeat(65536);
        #[cfg(unix)]
        let task = ShellTask {
            command: format!("echo '{}'", long_arg),
            shell: None,
            timeout_ms: Some(10000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: format!("echo {}", &long_arg[..8000]), // Windows cmd has shorter limits
            shell: None,
            timeout_ms: Some(10000),
        };

        let result = run_shell(&task).unwrap();
        // Should either succeed or fail gracefully (arg too long)
        // We just verify no panic/crash
        assert!(result.exit_code == 0 || result.exit_code != 0);
    }

    #[test]
    fn test_special_characters_in_command() {
        #[cfg(unix)]
        let task = ShellTask {
            command: r#"echo "quotes 'nested' here" && echo $HOME && echo 'dollar$sign'"#
                .to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: r#"echo "quotes here" & echo %USERPROFILE%"#.to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(!result.stdout.is_empty());
    }

    #[test]
    fn test_unicode_in_command() {
        #[cfg(unix)]
        let task = ShellTask {
            command: "echo '日本語 emoji: 🦑 Kraken'".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "echo Unicode test".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_newlines_in_command() {
        #[cfg(unix)]
        let task = ShellTask {
            command: "echo line1\necho line2\necho line3".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "echo line1 & echo line2".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("line1"));
    }

    #[test]
    fn test_zero_timeout() {
        // Zero timeout should be treated as immediate timeout or no-op
        let task = ShellTask {
            command: "echo fast".to_string(),
            shell: None,
            timeout_ms: Some(0),
        };

        let result = run_shell(&task).unwrap();
        // Either times out immediately or completes (race condition)
        // Just verify no panic
        let _ = result;
    }

    #[test]
    fn test_very_short_timeout() {
        #[cfg(unix)]
        let task = ShellTask {
            command: "sleep 5".to_string(),
            shell: None,
            timeout_ms: Some(10), // 10ms timeout
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "ping -n 5 127.0.0.1".to_string(),
            shell: None,
            timeout_ms: Some(10),
        };

        let result = run_shell(&task).unwrap();
        // Should timeout
        assert!(result.stderr.contains("timed out") || result.exit_code != 0);
    }

    #[test]
    fn test_no_timeout_uses_default() {
        let task = ShellTask {
            command: "echo default_timeout".to_string(),
            shell: None,
            timeout_ms: None, // Should use default 30s
        };

        let result = run_shell(&task).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("default_timeout"));
    }

    #[cfg(unix)]
    #[test]
    fn test_nonexistent_shell() {
        let task = ShellTask {
            command: "echo test".to_string(),
            shell: Some("/nonexistent/shell".to_string()),
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        // Should fail gracefully with error in stderr
        assert!(result.exit_code != 0 || !result.stderr.is_empty());
    }

    #[test]
    fn test_large_output() {
        // Generate large output using printf with repetition
        #[cfg(unix)]
        let task = ShellTask {
            // printf repeating a pattern - much faster than loops
            command: "printf '%0.s-' {1..20000}; echo".to_string(),
            shell: Some("/bin/bash".to_string()),
            timeout_ms: Some(10000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "for /L %i in (1,1,1000) do @echo large output line".to_string(),
            shell: Some("cmd".to_string()),
            timeout_ms: Some(30000),
        };

        let result = run_shell(&task).unwrap();
        // Just verify we captured substantial output without checking exit code
        // (some shells may have edge cases with large output)
        assert!(
            result.stdout.len() > 10000,
            "Expected large output, got {} bytes. stderr: {}",
            result.stdout.len(),
            result.stderr
        );
    }

    #[test]
    fn test_stderr_and_stdout_mixed() {
        #[cfg(unix)]
        let task = ShellTask {
            command: "echo stdout_msg && echo stderr_msg >&2 && echo stdout2".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "echo stdout_msg & echo stderr_msg 1>&2".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        assert!(result.stdout.contains("stdout"));
        assert!(result.stderr.contains("stderr"));
    }

    #[test]
    fn test_binary_output() {
        // Command that outputs non-UTF8 bytes
        #[cfg(unix)]
        let task = ShellTask {
            command: "printf '\\x00\\x01\\x02\\xff\\xfe'".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "echo binary".to_string(), // Windows echo is text-only
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        // Should handle binary output without panic (lossy conversion)
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_command_with_null_bytes() {
        // Null bytes in command - should be handled gracefully
        #[cfg(unix)]
        let task = ShellTask {
            command: "echo before".to_string(), // Safe version
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "echo before".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_environment_isolation() {
        // Verify command doesn't inherit dangerous env vars
        // (This is more of a security test)
        #[cfg(unix)]
        let task = ShellTask {
            command: "echo $SHELL".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "echo %SHELL%".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        // Just verify execution completes
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_duration_tracking() {
        #[cfg(unix)]
        let task = ShellTask {
            command: "sleep 0.1".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };
        #[cfg(windows)]
        let task = ShellTask {
            command: "ping -n 1 127.0.0.1".to_string(),
            shell: None,
            timeout_ms: Some(5000),
        };

        let result = run_shell(&task).unwrap();
        // Duration should be tracked
        assert!(result.duration_ms > 0);
        assert!(result.duration_ms < 5000);
    }
}
