//! Shell command execution

use protocol::{ShellResult, ShellTask};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Execute a shell command and return the result
pub async fn execute_shell(task: ShellTask) -> ShellResult {
    let start = std::time::Instant::now();

    let shell = task.shell.unwrap_or_else(default_shell);
    let timeout_ms = task.timeout_ms.unwrap_or(30_000) as u64;

    let result = timeout(
        Duration::from_millis(timeout_ms),
        run_command(&shell, &task.command),
    )
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok((stdout, stderr, exit_code))) => ShellResult {
            stdout,
            stderr,
            exit_code,
            duration_ms,
        },
        Ok(Err(e)) => ShellResult {
            stdout: String::new(),
            stderr: format!("execution error: {}", e),
            exit_code: -1,
            duration_ms,
        },
        Err(_) => ShellResult {
            stdout: String::new(),
            stderr: "command timed out".to_string(),
            exit_code: -2,
            duration_ms,
        },
    }
}

async fn run_command(shell: &str, command: &str) -> Result<(String, String, i32), std::io::Error> {
    #[cfg(unix)]
    let output = Command::new(shell).arg("-c").arg(command).output().await?;

    #[cfg(windows)]
    let output = Command::new(shell).arg("/C").arg(command).output().await?;

    #[cfg(not(any(unix, windows)))]
    let output = Command::new(shell).arg("-c").arg(command).output().await?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    Ok((stdout, stderr, exit_code))
}

/// Returns the hardcoded default shell for the platform.
///
/// SECURITY: Do NOT read from environment variables ($SHELL, $COMSPEC) as these
/// could be attacker-controlled. Use fixed, known-safe paths.
fn default_shell() -> String {
    #[cfg(unix)]
    {
        "/bin/sh".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\Windows\\System32\\cmd.exe".to_string()
    }
    #[cfg(not(any(unix, windows)))]
    {
        "/bin/sh".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::ShellTask;

    fn task(command: &str) -> ShellTask {
        ShellTask {
            command: command.to_string(),
            shell: None,
            timeout_ms: None,
        }
    }

    fn task_with_timeout(command: &str, timeout_ms: u32) -> ShellTask {
        ShellTask {
            command: command.to_string(),
            shell: None,
            timeout_ms: Some(timeout_ms),
        }
    }

    #[tokio::test]
    async fn test_execute_shell_simple_command() {
        let result = execute_shell(task("echo hello")).await;
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "hello");
        assert!(result.stderr.is_empty());
    }

    #[tokio::test]
    async fn test_execute_shell_stderr_capture() {
        // Write to stderr via shell redirection
        let result = execute_shell(task("echo error_output >&2")).await;
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr.trim(), "error_output");
    }

    #[tokio::test]
    async fn test_execute_shell_exit_code() {
        let ok = execute_shell(task("exit 0")).await;
        assert_eq!(ok.exit_code, 0);

        let fail = execute_shell(task("exit 1")).await;
        assert_eq!(fail.exit_code, 1);

        let custom = execute_shell(task("exit 42")).await;
        assert_eq!(custom.exit_code, 42);
    }

    #[tokio::test]
    async fn test_execute_shell_timeout() {
        // 50 ms timeout against a 10-second sleep — must time out
        let result = execute_shell(task_with_timeout("sleep 10", 50)).await;
        assert_eq!(result.exit_code, -2, "expected timeout exit code -2");
        assert_eq!(result.stderr, "command timed out");
    }

    #[tokio::test]
    async fn test_default_shell() {
        #[cfg(unix)]
        {
            let shell = default_shell();
            assert!(!shell.is_empty());
            assert!(
                std::path::Path::new(&shell).exists(),
                "default shell '{}' does not exist",
                shell
            );
        }
        #[cfg(windows)]
        {
            let shell = default_shell();
            assert!(!shell.is_empty());
            assert!(
                std::path::Path::new(&shell).exists(),
                "default shell '{}' does not exist",
                shell
            );
        }
    }
}
