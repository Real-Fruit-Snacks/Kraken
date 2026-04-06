//! Process enumeration implementations for Windows and Linux

use common::{KrakenError, ProcessInfo, ProcessModuleInfo, ProcessModules};

/// Enumerate all running processes
pub fn list_processes() -> Result<Vec<ProcessInfo>, KrakenError> {
    list_processes_impl()
}

/// List modules loaded by a given process
pub fn list_process_modules(pid: u32) -> Result<ProcessModules, KrakenError> {
    list_process_modules_impl(pid)
}

/// Kill a process by PID
pub fn kill_process(pid: u32, force: bool) -> Result<(), KrakenError> {
    kill_process_impl(pid, force)
}

// ============================================================
// Windows implementation
// ============================================================

#[cfg(windows)]
fn list_processes_impl() -> Result<Vec<ProcessInfo>, KrakenError> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(KrakenError::Internal("CreateToolhelp32Snapshot failed".into()));
    }

    let mut processes = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    if ok == 0 {
        unsafe { CloseHandle(snapshot) };
        return Ok(processes);
    }

    loop {
        let name = String::from_utf16_lossy(
            &entry.szExeFile[..entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len())],
        );

        processes.push(ProcessInfo {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name,
            path: None,
            user: None,
            arch: None,
        });

        if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
            break;
        }
    }

    unsafe { CloseHandle(snapshot) };
    Ok(processes)
}

#[cfg(windows)]
fn list_process_modules_impl(pid: u32) -> Result<ProcessModules, KrakenError> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(KrakenError::Internal(format!(
            "CreateToolhelp32Snapshot failed for pid {}",
            pid
        )));
    }

    let mut modules = Vec::new();
    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let ok = unsafe { Module32FirstW(snapshot, &mut entry) };
    if ok == 0 {
        unsafe { CloseHandle(snapshot) };
        return Ok(ProcessModules { pid, modules });
    }

    loop {
        let name = String::from_utf16_lossy(
            &entry.szModule[..entry
                .szModule
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szModule.len())],
        );
        let path = String::from_utf16_lossy(
            &entry.szExePath[..entry
                .szExePath
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExePath.len())],
        );

        modules.push(ProcessModuleInfo {
            name: name.to_string(),
            path: path.to_string(),
            base_address: entry.modBaseAddr as u64,
            size: entry.modBaseSize as u64,
        });

        if unsafe { Module32NextW(snapshot, &mut entry) } == 0 {
            break;
        }
    }

    unsafe { CloseHandle(snapshot) };
    Ok(ProcessModules { pid, modules })
}

#[cfg(windows)]
fn kill_process_impl(pid: u32, force: bool) -> Result<(), KrakenError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle == 0 {
        return Err(KrakenError::Internal(format!(
            "OpenProcess failed for pid {}",
            pid
        )));
    }

    let exit_code = if force { 1u32 } else { 0u32 };
    let ok = unsafe { TerminateProcess(handle, exit_code) };
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        Err(KrakenError::Internal(format!(
            "TerminateProcess failed for pid {}",
            pid
        )))
    } else {
        Ok(())
    }
}

// ============================================================
// Linux / Unix implementation
// ============================================================

#[cfg(unix)]
fn list_processes_impl() -> Result<Vec<ProcessInfo>, KrakenError> {
    use std::fs;

    let mut processes = Vec::new();

    let proc_dir = fs::read_dir("/proc").map_err(|e| KrakenError::Internal(e.to_string()))?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric entries are process directories
        let pid: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let proc_path = format!("/proc/{}", pid);

        // Read /proc/<pid>/status for ppid and name
        let status_path = format!("{}/status", proc_path);
        let status = match fs::read_to_string(&status_path) {
            Ok(s) => s,
            Err(_) => continue, // process may have exited
        };

        let mut proc_name = String::new();
        let mut ppid: u32 = 0;

        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Name:\t") {
                proc_name = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.trim().parse().unwrap_or(0);
            }
        }

        // Read /proc/<pid>/exe for the executable path
        let exe_path = fs::read_link(format!("{}/exe", proc_path))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // Read /proc/<pid>/cmdline for command line
        let _cmdline = fs::read_to_string(format!("{}/cmdline", proc_path))
            .map(|s| s.replace('\0', " ").trim().to_string())
            .unwrap_or_default();

        // Determine user from /proc/<pid>/status (Uid field)
        let user = parse_uid_from_status(&status);

        processes.push(ProcessInfo {
            pid,
            ppid,
            name: proc_name,
            path: exe_path,
            user,
            arch: None,
        });
    }

    processes.sort_by_key(|p| p.pid);
    Ok(processes)
}

#[cfg(unix)]
fn parse_uid_from_status(status: &str) -> Option<String> {
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("Uid:\t") {
            let uid: u32 = val.split_whitespace().next()?.parse().ok()?;
            // Try to resolve uid to username via /etc/passwd
            return resolve_username(uid).or_else(|| Some(uid.to_string()));
        }
    }
    None
}

#[cfg(unix)]
fn resolve_username(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(u) = parts[2].parse::<u32>() {
                if u == uid {
                    return Some(parts[0].to_string());
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn list_process_modules_impl(pid: u32) -> Result<ProcessModules, KrakenError> {
    use std::fs;

    let maps_path = format!("/proc/{}/maps", pid);
    let maps = fs::read_to_string(&maps_path).map_err(|e| {
        KrakenError::Internal(format!("failed to read {}: {}", maps_path, e))
    })?;

    let mut seen = std::collections::HashSet::new();
    let mut modules = Vec::new();

    for line in maps.lines() {
        // Format: address perms offset dev inode pathname
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 6 {
            continue;
        }

        let path = parts[5].trim();
        if path.is_empty() || path.starts_with('[') {
            continue;
        }

        if !seen.insert(path.to_string()) {
            continue;
        }

        // Parse base address from the mapping range (first field: start-end)
        let base_address = parts[0]
            .split('-')
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or(0);

        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());

        modules.push(ProcessModuleInfo {
            name,
            path: path.to_string(),
            base_address,
            size: 0, // size not directly available from maps without parsing all ranges
        });
    }

    Ok(ProcessModules { pid, modules })
}

#[cfg(unix)]
fn kill_process_impl(pid: u32, force: bool) -> Result<(), KrakenError> {
    let sig = if force {
        libc::SIGKILL
    } else {
        libc::SIGTERM
    };

    let ret = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if ret != 0 {
        Err(KrakenError::Internal(format!(
            "kill({}, {}) failed: errno {}",
            pid,
            sig,
            unsafe { *libc::__errno_location() }
        )))
    } else {
        Ok(())
    }
}
