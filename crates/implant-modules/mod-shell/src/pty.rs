//! Interactive PTY shell — T1059
//!
//! Windows: CreatePseudoConsole (ConPTY API, Win10 1809+)
//! Linux: openpty() + fork/exec

use common::KrakenError;

/// PTY session handle
pub struct PtySession {
    // Windows: HPCON pseudo console handle + pipe handles
    // Linux: master/slave fd pair + child pid
    #[cfg(windows)]
    hpc: isize, // HPCON
    #[cfg(windows)]
    input_write: isize, // HANDLE - pipe to write input
    #[cfg(windows)]
    output_read: isize, // HANDLE - pipe to read output
    #[cfg(unix)]
    master_fd: i32,
    #[cfg(unix)]
    child_pid: u32,
}

impl PtySession {
    /// Create a new PTY session with the given shell command.
    ///
    /// On Windows uses the ConPTY API (Win10 1809+).
    /// On Unix uses openpty() + fork/exec.
    #[cfg(windows)]
    pub fn new(shell: &str, cols: u16, rows: u16) -> Result<Self, KrakenError> {
        use std::ffi::OsStr;
        use std::mem;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;
        use windows_sys::Win32::Foundation::*;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Console::*;
        use windows_sys::Win32::System::Pipes::CreatePipe;
        use windows_sys::Win32::System::Threading::*;

        unsafe {
            // ----------------------------------------------------------------
            // 1. Create pipes for PTY I/O
            //    input pipe:  write_in  → PTY reads keystrokes
            //    output pipe: read_out  ← PTY writes terminal data
            // ----------------------------------------------------------------
            let mut sa = SECURITY_ATTRIBUTES {
                nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: ptr::null_mut(),
                bInheritHandle: TRUE,
            };

            // Input pipe (operator writes → shell reads)
            let mut read_in: HANDLE = 0;
            let mut write_in: HANDLE = 0;
            if CreatePipe(&mut read_in, &mut write_in, &mut sa, 0) == 0 {
                return Err(KrakenError::internal(format!(
                    "CreatePipe(input) failed: {}",
                    GetLastError()
                )));
            }

            // Output pipe (shell writes → operator reads)
            let mut read_out: HANDLE = 0;
            let mut write_out: HANDLE = 0;
            if CreatePipe(&mut read_out, &mut write_out, &mut sa, 0) == 0 {
                CloseHandle(read_in);
                CloseHandle(write_in);
                return Err(KrakenError::internal(format!(
                    "CreatePipe(output) failed: {}",
                    GetLastError()
                )));
            }

            // ----------------------------------------------------------------
            // 2. Create pseudo console
            // ----------------------------------------------------------------
            let size = COORD {
                X: cols as i16,
                Y: rows as i16,
            };
            let mut hpc: HPCON = 0;
            let hr = CreatePseudoConsole(size, read_in, write_out, 0, &mut hpc);
            // Close the pipe ends now consumed by the PTY
            CloseHandle(read_in);
            CloseHandle(write_out);

            if hr != 0 {
                CloseHandle(write_in);
                CloseHandle(read_out);
                return Err(KrakenError::internal(format!(
                    "CreatePseudoConsole failed: HRESULT {:#010x}",
                    hr as u32
                )));
            }

            // ----------------------------------------------------------------
            // 3. Build STARTUPINFOEXW with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
            // ----------------------------------------------------------------
            let mut attr_list_size: usize = 0;
            // First call: get required buffer size
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_list_size);

            let mut attr_list_buf = vec![0u8; attr_list_size];
            let attr_list = attr_list_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;

            if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size) == 0 {
                ClosePseudoConsole(hpc);
                CloseHandle(write_in);
                CloseHandle(read_out);
                return Err(KrakenError::internal(format!(
                    "InitializeProcThreadAttributeList failed: {}",
                    GetLastError()
                )));
            }

            if UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                hpc as *mut _,
                mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            ) == 0
            {
                DeleteProcThreadAttributeList(attr_list);
                ClosePseudoConsole(hpc);
                CloseHandle(write_in);
                CloseHandle(read_out);
                return Err(KrakenError::internal(format!(
                    "UpdateProcThreadAttribute failed: {}",
                    GetLastError()
                )));
            }

            // ----------------------------------------------------------------
            // 4. Create the child process
            // ----------------------------------------------------------------
            let mut si_ex: STARTUPINFOEXW = mem::zeroed();
            si_ex.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
            si_ex.lpAttributeList = attr_list;

            let mut cmdline_wide: Vec<u16> = OsStr::new(shell)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut pi: PROCESS_INFORMATION = mem::zeroed();

            let ok = CreateProcessW(
                ptr::null(),
                cmdline_wide.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                FALSE, // Do NOT inherit handles (PTY manages its own)
                EXTENDED_STARTUPINFO_PRESENT,
                ptr::null(),
                ptr::null(),
                &si_ex.StartupInfo,
                &mut pi,
            );

            DeleteProcThreadAttributeList(attr_list);

            if ok == 0 {
                ClosePseudoConsole(hpc);
                CloseHandle(write_in);
                CloseHandle(read_out);
                return Err(KrakenError::internal(format!(
                    "CreateProcessW failed: {}",
                    GetLastError()
                )));
            }

            // We don't need the thread handle
            CloseHandle(pi.hThread);

            Ok(Self {
                hpc: hpc as isize,
                input_write: write_in as isize,
                output_read: read_out as isize,
            })
        }
    }

    #[cfg(unix)]
    pub fn new(shell: &str, cols: u16, rows: u16) -> Result<Self, KrakenError> {
        use std::ffi::CString;
        use libc::{
            close, dup2, execvp, fork, ioctl, openpty, setsid, winsize, TIOCSCTTY,
        };

        let shell_cstr = CString::new(shell)
            .map_err(|_| KrakenError::internal("shell path contains null byte"))?;

        unsafe {
            // ----------------------------------------------------------------
            // 1. openpty — allocate master/slave pair
            // ----------------------------------------------------------------
            let mut master: libc::c_int = -1;
            let mut slave: libc::c_int = -1;
            let ws = winsize {
                ws_col: cols,
                ws_row: rows,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };

            let ret = openpty(
                &mut master,
                &mut slave,
                ptr::null_mut(),
                ptr::null(),
                &ws,
            );
            if ret != 0 {
                return Err(KrakenError::internal(format!(
                    "openpty failed: errno {}",
                    *libc::__errno_location()
                )));
            }

            // ----------------------------------------------------------------
            // 2. fork
            // ----------------------------------------------------------------
            let pid = fork();
            if pid < 0 {
                close(master);
                close(slave);
                return Err(KrakenError::internal(format!(
                    "fork failed: errno {}",
                    *libc::__errno_location()
                )));
            }

            if pid == 0 {
                // ============================================================
                // Child process
                // ============================================================
                close(master);

                // New session so the slave becomes the controlling terminal
                setsid();

                // Make slave the controlling terminal
                ioctl(slave, TIOCSCTTY as _, 0i32);

                // Wire stdin/stdout/stderr to the slave PTY
                dup2(slave, 0);
                dup2(slave, 1);
                dup2(slave, 2);

                if slave > 2 {
                    close(slave);
                }

                // Build argv: [shell, NULL]
                let argv: [*const libc::c_char; 2] =
                    [shell_cstr.as_ptr(), std::ptr::null()];
                execvp(shell_cstr.as_ptr(), argv.as_ptr());

                // execvp only returns on error — exit child immediately
                libc::_exit(127);
            }

            // ================================================================
            // Parent process
            // ================================================================
            close(slave);

            Ok(Self {
                master_fd: master,
                child_pid: pid as u32,
            })
        }
    }

    /// Write input to the PTY (keystrokes from operator).
    pub fn write(&self, data: &[u8]) -> Result<usize, KrakenError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::WriteFile;
            unsafe {
                let mut written: u32 = 0;
                let ok = WriteFile(
                    self.input_write as HANDLE,
                    data.as_ptr(),
                    data.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                );
                if ok == 0 {
                    use windows_sys::Win32::Foundation::GetLastError;
                    return Err(KrakenError::internal(format!(
                        "WriteFile failed: {}",
                        GetLastError()
                    )));
                }
                Ok(written as usize)
            }
        }
        #[cfg(unix)]
        {
            let ret = unsafe {
                libc::write(
                    self.master_fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                )
            };
            if ret < 0 {
                return Err(KrakenError::internal(format!(
                    "write to PTY failed: errno {}",
                    unsafe { *libc::__errno_location() }
                )));
            }
            Ok(ret as usize)
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = data;
            Err(KrakenError::internal("unsupported platform"))
        }
    }

    /// Read output from the PTY (terminal output to operator).
    ///
    /// Non-blocking on Unix (uses O_NONBLOCK semantics via MSG_DONTWAIT-equivalent).
    /// On Windows, peeks first to avoid blocking if no data is available.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, KrakenError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::ReadFile;
            use windows_sys::Win32::System::Pipes::PeekNamedPipe;
            unsafe {
                // Peek to avoid blocking
                let mut bytes_avail: u32 = 0;
                let peek_ok = PeekNamedPipe(
                    self.output_read as HANDLE,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut bytes_avail,
                    std::ptr::null_mut(),
                );
                if peek_ok == 0 || bytes_avail == 0 {
                    return Ok(0);
                }

                let to_read = bytes_avail.min(buf.len() as u32);
                let mut bytes_read: u32 = 0;
                let ok = ReadFile(
                    self.output_read as HANDLE,
                    buf.as_mut_ptr(),
                    to_read,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                );
                if ok == 0 {
                    use windows_sys::Win32::Foundation::GetLastError;
                    return Err(KrakenError::internal(format!(
                        "ReadFile failed: {}",
                        GetLastError()
                    )));
                }
                Ok(bytes_read as usize)
            }
        }
        #[cfg(unix)]
        {
            // Set non-blocking temporarily for this read
            let flags = unsafe { libc::fcntl(self.master_fd, libc::F_GETFL, 0) };
            let _ = unsafe {
                libc::fcntl(self.master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
            };

            let ret = unsafe {
                libc::read(
                    self.master_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };

            // Restore original flags
            let _ = unsafe { libc::fcntl(self.master_fd, libc::F_SETFL, flags) };

            if ret < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    return Ok(0); // No data available right now
                }
                return Err(KrakenError::internal(format!(
                    "read from PTY failed: errno {}",
                    errno
                )));
            }
            Ok(ret as usize)
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = buf;
            Err(KrakenError::internal("unsupported platform"))
        }
    }

    /// Resize the PTY terminal window.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), KrakenError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{
                ClosePseudoConsole as _, ResizePseudoConsole, COORD, HPCON,
            };
            unsafe {
                let size = COORD {
                    X: cols as i16,
                    Y: rows as i16,
                };
                let hr = ResizePseudoConsole(self.hpc as HPCON, size);
                if hr != 0 {
                    return Err(KrakenError::internal(format!(
                        "ResizePseudoConsole failed: HRESULT {:#010x}",
                        hr as u32
                    )));
                }
            }
            Ok(())
        }
        #[cfg(unix)]
        {
            use libc::{ioctl, winsize, TIOCSWINSZ};
            let ws = winsize {
                ws_col: cols,
                ws_row: rows,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let ret = unsafe { ioctl(self.master_fd, TIOCSWINSZ as _, &ws) };
            if ret != 0 {
                return Err(KrakenError::internal(format!(
                    "ioctl(TIOCSWINSZ) failed: errno {}",
                    unsafe { *libc::__errno_location() }
                )));
            }
            Ok(())
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = (cols, rows);
            Err(KrakenError::internal("unsupported platform"))
        }
    }

    /// Check if the child process is still alive.
    pub fn is_alive(&self) -> bool {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{GetLastError, HANDLE, STILL_ACTIVE};
            use windows_sys::Win32::System::Threading::GetExitCodeProcess;
            unsafe {
                // We no longer hold pi.hProcess after construction on Windows.
                // The PTY itself keeps the process alive; a closed output pipe
                // indicates the session has ended. Use a best-effort approach:
                // try peeking the output pipe — if it errors, the process ended.
                use windows_sys::Win32::System::Pipes::PeekNamedPipe;
                let mut bytes_avail: u32 = 0;
                let ok = PeekNamedPipe(
                    self.output_read as HANDLE,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut bytes_avail,
                    std::ptr::null_mut(),
                );
                ok != 0
            }
        }
        #[cfg(unix)]
        {
            // Send signal 0 to check if child is alive (no actual signal delivered)
            let ret = unsafe { libc::kill(self.child_pid as libc::pid_t, 0) };
            ret == 0
        }
        #[cfg(not(any(windows, unix)))]
        {
            false
        }
    }

    /// Close/kill the PTY session and clean up resources.
    pub fn close(&mut self) -> Result<(), KrakenError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Console::{ClosePseudoConsole, HPCON};
            unsafe {
                ClosePseudoConsole(self.hpc as HPCON);
                self.hpc = 0;
                if self.input_write != 0 {
                    CloseHandle(self.input_write as _);
                    self.input_write = 0;
                }
                if self.output_read != 0 {
                    CloseHandle(self.output_read as _);
                    self.output_read = 0;
                }
            }
            Ok(())
        }
        #[cfg(unix)]
        {
            use libc::{close, kill, waitpid, SIGKILL, WNOHANG};
            unsafe {
                if self.child_pid != 0 {
                    // Try graceful termination first, then SIGKILL
                    kill(self.child_pid as libc::pid_t, libc::SIGTERM);
                    // Give it a brief moment; reap with WNOHANG
                    libc::usleep(50_000); // 50ms
                    let mut status: libc::c_int = 0;
                    let reaped =
                        waitpid(self.child_pid as libc::pid_t, &mut status, WNOHANG);
                    if reaped == 0 {
                        // Still running — force kill
                        kill(self.child_pid as libc::pid_t, SIGKILL);
                        waitpid(self.child_pid as libc::pid_t, &mut status, 0);
                    }
                    self.child_pid = 0;
                }
                if self.master_fd >= 0 {
                    close(self.master_fd);
                    self.master_fd = -1;
                }
            }
            Ok(())
        }
        #[cfg(not(any(windows, unix)))]
        {
            Err(KrakenError::internal("unsupported platform"))
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// Bring ptr into scope for unix new()
#[cfg(unix)]
use std::ptr;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Unix tests
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_pty_creation_unix() {
        let session = PtySession::new("/bin/sh", 80, 24);
        assert!(
            session.is_ok(),
            "PTY creation should succeed: {:?}",
            session.err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_is_alive_after_creation() {
        let session = PtySession::new("/bin/sh", 80, 24).expect("PTY creation failed");
        // Give the child a moment to start
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(session.is_alive(), "child process should be alive");
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_write_and_read() {
        let session = PtySession::new("/bin/sh", 80, 24).expect("PTY creation failed");
        // Give shell time to initialize
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Send a command followed by newline
        let cmd = b"echo kraken_pty_test\n";
        let written = session.write(cmd).expect("write should succeed");
        assert_eq!(written, cmd.len());

        // Poll for output
        let mut output = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let mut buf = [0u8; 1024];
            match session.read(&mut buf) {
                Ok(0) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Ok(n) => {
                    output.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&output);
                    if text.contains("kraken_pty_test") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("kraken_pty_test"),
            "expected echo output, got: {:?}",
            text
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_resize() {
        let session = PtySession::new("/bin/sh", 80, 24).expect("PTY creation failed");
        let result = session.resize(132, 50);
        assert!(result.is_ok(), "resize should succeed: {:?}", result.err());
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_close() {
        let mut session = PtySession::new("/bin/sh", 80, 24).expect("PTY creation failed");
        let result = session.close();
        assert!(result.is_ok(), "close should succeed");
        // After close the child should be gone
        assert!(!session.is_alive(), "child should be dead after close");
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_drop_cleans_up() {
        // This test verifies the Drop impl doesn't panic or leak
        {
            let _session =
                PtySession::new("/bin/sh", 80, 24).expect("PTY creation failed");
            // _session dropped here
        }
        // If we reach here without panic, drop worked correctly
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_read_nonblocking_when_empty() {
        let session = PtySession::new("/bin/sh", 80, 24).expect("PTY creation failed");
        // Wait for shell prompt, drain any initial output
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut buf = [0u8; 4096];
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        // Now the read should return 0 immediately (non-blocking)
        let mut buf2 = [0u8; 64];
        let n = session.read(&mut buf2).expect("non-blocking read should not error");
        // Either 0 (no data) or some prompt bytes — just verify it doesn't block forever
        let _ = n;
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_invalid_shell() {
        let result = PtySession::new("/nonexistent/shell", 80, 24);
        // openpty + fork succeed; the child will execvp-fail and _exit(127).
        // The parent gets a valid session object; is_alive() will return false shortly.
        match result {
            Ok(session) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // Child should have exited with 127
                assert!(
                    !session.is_alive(),
                    "child with invalid shell should exit quickly"
                );
            }
            Err(_) => {
                // Also acceptable if openpty itself failed
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_pty_custom_dimensions() {
        let session = PtySession::new("/bin/sh", 200, 50).expect("PTY creation failed");
        // Verify TIOCGWINSZ reports what we set
        use libc::{ioctl, winsize, TIOCGWINSZ};
        let mut ws = winsize {
            ws_col: 0,
            ws_row: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = unsafe { ioctl(session.master_fd, TIOCGWINSZ as _, &mut ws) };
        assert_eq!(ret, 0, "TIOCGWINSZ should succeed");
        assert_eq!(ws.ws_col, 200);
        assert_eq!(ws.ws_row, 50);
    }

    // -----------------------------------------------------------------------
    // Windows tests (compile-checked only on non-Windows; skipped at runtime)
    // -----------------------------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn test_pty_creation_windows() {
        let session = PtySession::new("cmd.exe", 80, 24);
        assert!(
            session.is_ok(),
            "Windows PTY creation should succeed: {:?}",
            session.err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_pty_write_read_windows() {
        let session = PtySession::new("cmd.exe", 80, 24).expect("PTY creation failed");
        std::thread::sleep(std::time::Duration::from_millis(200));

        let cmd = b"echo kraken_pty_windows\r\n";
        session.write(cmd).expect("write should succeed");

        let mut output = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            let mut buf = [0u8; 1024];
            match session.read(&mut buf) {
                Ok(0) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Ok(n) => {
                    output.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&output);
                    if text.contains("kraken_pty_windows") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("kraken_pty_windows"),
            "expected echo output in PTY stream, got: {:?}",
            text
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_pty_resize_windows() {
        let session = PtySession::new("cmd.exe", 80, 24).expect("PTY creation failed");
        let result = session.resize(120, 30);
        assert!(result.is_ok(), "resize should succeed: {:?}", result.err());
    }

    #[cfg(windows)]
    #[test]
    fn test_pty_close_windows() {
        let mut session = PtySession::new("cmd.exe", 80, 24).expect("PTY creation failed");
        let result = session.close();
        assert!(result.is_ok(), "close should succeed");
    }
}
