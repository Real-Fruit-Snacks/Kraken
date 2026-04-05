//! Output capture for .NET assembly execution
//!
//! Redirects Console.Out and Console.Error to capture assembly output.

#![cfg(windows)]

use crate::error::DotNetError;
use crate::Result;

use std::io::Read;
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::Storage::FileSystem::*;

/// Captures stdout and stderr from .NET assembly execution
pub struct OutputCapture {
    stdout_read: HANDLE,
    stdout_write: HANDLE,
    stderr_read: HANDLE,
    stderr_write: HANDLE,
    original_stdout: HANDLE,
    original_stderr: HANDLE,
}

impl OutputCapture {
    /// Create new output capture with anonymous pipes
    pub fn new() -> Result<Self> {
        unsafe {
            let mut security_attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: TRUE,
            };

            // Create stdout pipe
            let mut stdout_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut stdout_write: HANDLE = INVALID_HANDLE_VALUE;

            if CreatePipe(&mut stdout_read, &mut stdout_write, &mut security_attrs, 0) == 0 {
                return Err(DotNetError::OutputCaptureFailed("failed to create stdout pipe".to_string()));
            }

            // Ensure read end is not inherited
            SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

            // Create stderr pipe
            let mut stderr_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut stderr_write: HANDLE = INVALID_HANDLE_VALUE;

            if CreatePipe(&mut stderr_read, &mut stderr_write, &mut security_attrs, 0) == 0 {
                CloseHandle(stdout_read);
                CloseHandle(stdout_write);
                return Err(DotNetError::OutputCaptureFailed("failed to create stderr pipe".to_string()));
            }

            SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);

            // Save original handles
            let original_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
            let original_stderr = GetStdHandle(STD_ERROR_HANDLE);

            // Redirect standard handles
            SetStdHandle(STD_OUTPUT_HANDLE, stdout_write);
            SetStdHandle(STD_ERROR_HANDLE, stderr_write);

            Ok(Self {
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
                original_stdout,
                original_stderr,
            })
        }
    }

    /// Get captured output (stdout, stderr)
    pub fn get_output(&mut self) -> (String, String) {
        unsafe {
            // Restore original handles
            SetStdHandle(STD_OUTPUT_HANDLE, self.original_stdout);
            SetStdHandle(STD_ERROR_HANDLE, self.original_stderr);

            // Close write ends to signal EOF
            if self.stdout_write != INVALID_HANDLE_VALUE {
                CloseHandle(self.stdout_write);
                self.stdout_write = INVALID_HANDLE_VALUE;
            }
            if self.stderr_write != INVALID_HANDLE_VALUE {
                CloseHandle(self.stderr_write);
                self.stderr_write = INVALID_HANDLE_VALUE;
            }

            // Read from pipes
            let stdout = read_pipe(self.stdout_read);
            let stderr = read_pipe(self.stderr_read);

            (stdout, stderr)
        }
    }
}

impl Drop for OutputCapture {
    fn drop(&mut self) {
        unsafe {
            // Restore original handles
            SetStdHandle(STD_OUTPUT_HANDLE, self.original_stdout);
            SetStdHandle(STD_ERROR_HANDLE, self.original_stderr);

            // Close all handles
            if self.stdout_read != INVALID_HANDLE_VALUE {
                CloseHandle(self.stdout_read);
            }
            if self.stdout_write != INVALID_HANDLE_VALUE {
                CloseHandle(self.stdout_write);
            }
            if self.stderr_read != INVALID_HANDLE_VALUE {
                CloseHandle(self.stderr_read);
            }
            if self.stderr_write != INVALID_HANDLE_VALUE {
                CloseHandle(self.stderr_write);
            }
        }
    }
}

/// Read all data from a pipe handle
unsafe fn read_pipe(handle: HANDLE) -> String {
    if handle == INVALID_HANDLE_VALUE {
        return String::new();
    }

    let mut buffer = [0u8; 4096];
    let mut output = Vec::new();

    loop {
        let mut bytes_read: u32 = 0;
        let result = ReadFile(
            handle,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_read,
            std::ptr::null_mut(),
        );

        if result == 0 || bytes_read == 0 {
            break;
        }

        output.extend_from_slice(&buffer[..bytes_read as usize]);
    }

    String::from_utf8_lossy(&output).to_string()
}

/// Thread-safe output buffer for async capture
#[derive(Clone)]
pub struct SharedOutputBuffer {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SharedOutputBuffer {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn append(&self, data: &[u8]) {
        if let Ok(mut buf) = self.buffer.lock() {
            buf.extend_from_slice(data);
        }
    }

    pub fn take(&self) -> String {
        if let Ok(mut buf) = self.buffer.lock() {
            let data = std::mem::take(&mut *buf);
            String::from_utf8_lossy(&data).to_string()
        } else {
            String::new()
        }
    }
}

impl Default for SharedOutputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_buffer() {
        let buf = SharedOutputBuffer::new();
        buf.append(b"hello");
        buf.append(b" world");
        assert_eq!(buf.take(), "hello world");
        assert_eq!(buf.take(), ""); // Should be empty after take
    }

    #[test]
    fn test_shared_buffer_clone() {
        let buf1 = SharedOutputBuffer::new();
        let buf2 = buf1.clone();
        buf1.append(b"test");
        assert_eq!(buf2.take(), "test");
    }
}
