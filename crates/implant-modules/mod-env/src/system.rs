//! System information gathering — OS, hostname, memory, uptime, CPU count, env vars

use common::{EnvVarsOutput, KrakenError, SystemInfoOutput};

pub fn get_system_info() -> Result<SystemInfoOutput, KrakenError> {
    get_system_info_impl()
}

pub fn get_env_vars() -> Result<EnvVarsOutput, KrakenError> {
    let variables = std::env::vars().collect();
    Ok(EnvVarsOutput { variables })
}

// ============================================================
// Windows implementation
// ============================================================

#[cfg(windows)]
fn get_system_info_impl() -> Result<SystemInfoOutput, KrakenError> {
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemInfo, GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
    };

    // CPU count and architecture
    let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut sys_info) };
    let cpu_count = sys_info.dwNumberOfProcessors;

    let arch = match unsafe { sys_info.Anonymous.Anonymous.wProcessorArchitecture } {
        9 => "x86_64",
        12 => "arm64",
        0 => "x86",
        _ => "unknown",
    }
    .to_string();

    // Memory
    let mut mem_status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    unsafe { GlobalMemoryStatusEx(&mut mem_status) };
    let total_memory = mem_status.ullTotalPhys;

    // Uptime
    let uptime_ms = unsafe { GetTickCount64() };
    let uptime_seconds = uptime_ms / 1000;

    // OS version from registry
    let (os_name, os_version) = read_windows_os_version();

    // Hostname
    let computer_name = read_computer_name();

    // Domain
    let domain = read_domain();

    Ok(SystemInfoOutput {
        os_name,
        os_version,
        architecture: arch,
        computer_name,
        domain,
        uptime_seconds,
        total_memory,
        cpu_count,
    })
}

#[cfg(windows)]
fn read_windows_os_version() -> (String, String) {
    // Read from registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_SZ,
    };

    let key_path: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0"
        .encode_utf16()
        .collect();

    let mut hkey = 0isize;
    let ret = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };

    if ret != 0 {
        return ("Windows".to_string(), "Unknown".to_string());
    }

    let product_name = query_reg_string(hkey, "ProductName\0");
    let current_version = query_reg_string(hkey, "CurrentVersion\0");
    let current_build = query_reg_string(hkey, "CurrentBuildNumber\0");

    unsafe { RegCloseKey(hkey) };

    let os_version = if current_build.is_empty() {
        current_version
    } else {
        format!("{}.{}", current_version, current_build)
    };

    (
        product_name
            .is_empty()
            .then(|| "Windows".to_string())
            .unwrap_or(product_name),
        os_version,
    )
}

#[cfg(windows)]
fn query_reg_string(hkey: isize, value_name: &str) -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Registry::{RegQueryValueExW, REG_SZ};

    let name_w: Vec<u16> = value_name.encode_utf16().collect();
    let mut data_type: u32 = 0;
    let mut buf_size: u32 = 0;

    // First call to get size
    let ret = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            std::ptr::null_mut(),
            &mut data_type,
            std::ptr::null_mut(),
            &mut buf_size,
        )
    };
    if ret != 0 || data_type != REG_SZ {
        return String::new();
    }

    let mut buf: Vec<u16> = vec![0u16; (buf_size / 2) as usize + 1];
    let ret = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            std::ptr::null_mut(),
            &mut data_type,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_size,
        )
    };
    if ret != 0 {
        return String::new();
    }

    // Trim null terminator
    while buf.last() == Some(&0) {
        buf.pop();
    }
    OsString::from_wide(&buf)
        .to_string_lossy()
        .into_owned()
}

#[cfg(windows)]
fn read_computer_name() -> String {
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

    let mut buf = [0u16; 256];
    let mut size = buf.len() as u32;
    let ok = unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut size) };
    if ok == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..size as usize])
}

#[cfg(windows)]
fn read_domain() -> String {
    // Try environment variable first
    std::env::var("USERDOMAIN").unwrap_or_default()
}

// ============================================================
// Linux / Unix implementation
// ============================================================

#[cfg(unix)]
fn get_system_info_impl() -> Result<SystemInfoOutput, KrakenError> {
    let os_name = read_os_name();
    let os_version = read_os_version();
    let architecture = read_architecture();
    let computer_name = read_hostname();
    let domain = read_domain_unix();
    let uptime_seconds = read_uptime();
    let total_memory = read_total_memory();
    let cpu_count = read_cpu_count();

    Ok(SystemInfoOutput {
        os_name,
        os_version,
        architecture,
        computer_name,
        domain,
        uptime_seconds,
        total_memory,
        cpu_count,
    })
}

#[cfg(unix)]
fn read_os_name() -> String {
    // Read from /etc/os-release
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("NAME=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    // Fallback to uname
    read_uname_sysname()
}

#[cfg(unix)]
fn read_uname_sysname() -> String {
    let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uname) } == 0 {
        let bytes = uname.sysname.iter()
            .map(|&c| c as u8)
            .take_while(|&c| c != 0)
            .collect::<Vec<u8>>();
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        "Linux".to_string()
    }
}

#[cfg(unix)]
fn read_os_version() -> String {
    // Read from /etc/os-release
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("VERSION_ID=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    // Fallback to uname release
    let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uname) } == 0 {
        let bytes = uname.release.iter()
            .map(|&c| c as u8)
            .take_while(|&c| c != 0)
            .collect::<Vec<u8>>();
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        String::new()
    }
}

#[cfg(unix)]
fn read_architecture() -> String {
    let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uname) } == 0 {
        let bytes = uname.machine.iter()
            .map(|&c| c as u8)
            .take_while(|&c| c != 0)
            .collect::<Vec<u8>>();
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        std::env::consts::ARCH.to_string()
    }
}

#[cfg(unix)]
fn read_hostname() -> String {
    let mut buf = [0u8; 256];
    if unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } == 0 {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        String::new()
    }
}

#[cfg(unix)]
fn read_domain_unix() -> String {
    // Try /etc/resolv.conf for domain
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("domain ") {
                return val.trim().to_string();
            }
            if let Some(val) = line.strip_prefix("search ") {
                // Return first search domain
                if let Some(first) = val.split_whitespace().next() {
                    return first.to_string();
                }
            }
        }
    }
    String::new()
}

#[cfg(unix)]
fn read_uptime() -> u64 {
    // /proc/uptime: seconds.centiseconds idle_seconds
    if let Ok(content) = std::fs::read_to_string("/proc/uptime") {
        if let Some(secs_str) = content.split('.').next() {
            if let Ok(secs) = secs_str.trim().parse::<u64>() {
                return secs;
            }
        }
    }
    // Fallback via sysinfo
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        info.uptime as u64
    } else {
        0
    }
}

#[cfg(unix)]
fn read_total_memory() -> u64 {
    // /proc/meminfo: MemTotal in kB
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("MemTotal:") {
                if let Some(kb_str) = val.trim().split_whitespace().next() {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    // Fallback via sysinfo
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        info.totalram as u64 * info.mem_unit as u64
    } else {
        0
    }
}

#[cfg(unix)]
fn read_cpu_count() -> u32 {
    // Count "processor" lines in /proc/cpuinfo
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        let count = content
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count();
        if count > 0 {
            return count as u32;
        }
    }
    // Fallback: nprocessors_conf
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    if n > 0 { n as u32 } else { 1 }
}
