//! User identity information — username, domain, groups, privilege level

use common::{KrakenError, WhoAmIOutput};

pub fn whoami() -> Result<WhoAmIOutput, KrakenError> {
    whoami_impl()
}

// ============================================================
// Windows implementation
// ============================================================

#[cfg(windows)]
fn whoami_impl() -> Result<WhoAmIOutput, KrakenError> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TokenGroups,
        TokenIntegrityLevel, TokenUser, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = 0;
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(KrakenError::Internal("OpenProcessToken failed".into()));
    }

    let username = get_current_username_windows();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let sid = get_user_sid_string(token);
    let groups = get_group_names(token);
    let (integrity_level, is_elevated) = get_integrity_and_elevation(token);

    unsafe { CloseHandle(token) };

    Ok(WhoAmIOutput {
        username,
        domain,
        sid,
        groups,
        integrity_level,
        is_elevated,
    })
}

#[cfg(windows)]
fn get_current_username_windows() -> String {
    use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;

    let mut buf = [0u16; 256];
    let mut size = buf.len() as u32;
    let ok = unsafe { GetUserNameW(buf.as_mut_ptr(), &mut size) };
    if ok == 0 || size == 0 {
        return std::env::var("USERNAME").unwrap_or_default();
    }
    String::from_utf16_lossy(&buf[..size.saturating_sub(1) as usize])
}

#[cfg(windows)]
fn get_user_sid_string(token: windows_sys::Win32::Foundation::HANDLE) -> String {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, TOKEN_USER,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Foundation::LocalFree;

    let mut size: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
    }
    if size == 0 {
        return String::new();
    }

    let mut buf = vec![0u8; size as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut size,
        )
    };
    if ok == 0 {
        return String::new();
    }

    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;

    let mut sid_str: *mut u16 = std::ptr::null_mut();
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut sid_str) };
    if ok == 0 || sid_str.is_null() {
        return String::new();
    }

    let mut len = 0usize;
    while unsafe { *sid_str.add(len) } != 0 {
        len += 1;
    }
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_str, len) });
    unsafe { LocalFree(sid_str as *mut _) };
    result
}

#[cfg(windows)]
fn get_group_names(token: windows_sys::Win32::Foundation::HANDLE) -> Vec<String> {
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, TokenGroups, TOKEN_GROUPS,
    };
    use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;

    let mut size: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut size);
    }
    if size == 0 {
        return vec![];
    }

    let mut buf = vec![0u8; size as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut size,
        )
    };
    if ok == 0 {
        return vec![];
    }

    let token_groups = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
    let groups_slice = unsafe {
        std::slice::from_raw_parts(
            token_groups.Groups.as_ptr(),
            token_groups.GroupCount as usize,
        )
    };

    let mut names = Vec::new();
    for group in groups_slice {
        if (group.Attributes & SE_GROUP_ENABLED as u32) == 0 {
            continue;
        }

        let mut name_buf = [0u16; 256];
        let mut domain_buf = [0u16; 256];
        let mut name_size = name_buf.len() as u32;
        let mut domain_size = domain_buf.len() as u32;
        let mut sid_name_use = 0i32;

        let ok = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                group.Sid,
                name_buf.as_mut_ptr(),
                &mut name_size,
                domain_buf.as_mut_ptr(),
                &mut domain_size,
                &mut sid_name_use,
            )
        };

        if ok != 0 && name_size > 0 {
            let name = String::from_utf16_lossy(&name_buf[..name_size as usize]);
            let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);
            if domain.is_empty() {
                names.push(name);
            } else {
                names.push(format!("{}\\{}", domain, name));
            }
        }
    }

    names
}

#[cfg(windows)]
fn get_integrity_and_elevation(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> (String, bool) {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TokenIntegrityLevel,
        TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL,
    };

    // Check elevation
    let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    let is_elevated = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        ) != 0
            && elevation.TokenIsElevated != 0
    };

    // Get integrity level
    let mut il_size: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut il_size);
    }

    let integrity_level = if il_size > 0 {
        let mut il_buf = vec![0u8; il_size as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                il_buf.as_mut_ptr() as *mut _,
                il_size,
                &mut il_size,
            )
        };

        if ok != 0 {
            let label = unsafe { &*(il_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
            // Integrity level is encoded in the last sub-authority of the SID
            let sid = label.Label.Sid;
            if !sid.is_null() {
                let sid_typed = sid as *const windows_sys::Win32::Security::SID;
                let sub_count = unsafe { (*sid_typed).SubAuthorityCount } as usize;
                if sub_count > 0 {
                    let sub_authorities = unsafe {
                        std::slice::from_raw_parts(
                            (*sid_typed).SubAuthority.as_ptr(),
                            sub_count,
                        )
                    };
                    let level = sub_authorities[sub_count - 1];
                    match level {
                        0x0000 => "Untrusted".to_string(),
                        0x1000 => "Low".to_string(),
                        0x2000 => "Medium".to_string(),
                        0x2100 => "Medium+".to_string(),
                        0x3000 => "High".to_string(),
                        0x4000 => "System".to_string(),
                        _ => format!("0x{:04X}", level),
                    }
                } else {
                    "Unknown".to_string()
                }
            } else {
                "Unknown".to_string()
            }
        } else {
            "Unknown".to_string()
        }
    } else {
        "Unknown".to_string()
    };

    (integrity_level, is_elevated)
}

// ============================================================
// Linux / Unix implementation
// ============================================================

#[cfg(unix)]
fn whoami_impl() -> Result<WhoAmIOutput, KrakenError> {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };

    let username = resolve_username(uid).unwrap_or_else(|| uid.to_string());
    let domain = read_domain_unix();
    let sid = format!("uid={}", uid);
    let groups = get_groups_unix(uid);
    let is_elevated = euid == 0;
    let integrity_level = if euid == 0 {
        "High".to_string()
    } else {
        "Medium".to_string()
    };

    Ok(WhoAmIOutput {
        username,
        domain,
        sid,
        groups,
        integrity_level,
        is_elevated,
    })
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
fn get_groups_unix(uid: u32) -> Vec<String> {
    let mut group_names = Vec::new();

    // Read primary group from /etc/passwd
    let primary_gid = {
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let mut gid = None;
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                if let Ok(u) = parts[2].parse::<u32>() {
                    if u == uid {
                        gid = parts[3].parse::<u32>().ok();
                        break;
                    }
                }
            }
        }
        gid
    };

    // Read /etc/group and find groups this user belongs to
    if let Ok(group_file) = std::fs::read_to_string("/etc/group") {
        let username = resolve_username(uid).unwrap_or_else(|| uid.to_string());
        for line in group_file.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 4 {
                continue;
            }
            let group_name = parts[0];
            let gid: u32 = parts[2].parse().unwrap_or(u32::MAX);
            let members = parts[3];

            let is_member = members.split(',').any(|m| m.trim() == username);
            let is_primary = primary_gid.map_or(false, |pg| pg == gid);

            if is_member || is_primary {
                group_names.push(group_name.to_string());
            }
        }
    }

    group_names
}

#[cfg(unix)]
fn read_domain_unix() -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("domain ") {
                return val.trim().to_string();
            }
        }
    }
    String::new()
}
