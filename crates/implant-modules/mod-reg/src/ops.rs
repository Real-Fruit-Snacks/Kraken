//! Registry operation implementations (Windows-only)

use common::{KrakenError, RegistryOperationResult, RegistryQueryOutput, RegistryValueOutput};
use protocol::{RegDelete, RegEnumKeys, RegEnumValues, RegQuery, RegSet};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CLASSES_ROOT,
    HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ALL_ACCESS,
    KEY_READ, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_NONE, REG_QWORD, REG_SZ,
};

/// Parse a registry key path into (root_key_handle, subkey_path).
/// Accepts paths like "HKLM\\SOFTWARE\\..." or "HKEY_LOCAL_MACHINE\\SOFTWARE\\..."
#[cfg(windows)]
fn parse_key_path(key_path: &str) -> Result<(HKEY, String), KrakenError> {
    // Handle bare hive names
    match key_path {
        "HKEY_LOCAL_MACHINE" | "HKLM" => return Ok((HKEY_LOCAL_MACHINE, String::new())),
        "HKEY_CURRENT_USER" | "HKCU" => return Ok((HKEY_CURRENT_USER, String::new())),
        "HKEY_CLASSES_ROOT" | "HKCR" => return Ok((HKEY_CLASSES_ROOT, String::new())),
        "HKEY_USERS" | "HKU" => return Ok((HKEY_USERS, String::new())),
        "HKEY_CURRENT_CONFIG" | "HKCC" => return Ok((HKEY_CURRENT_CONFIG, String::new())),
        _ => {}
    }

    let prefixes: &[(&str, HKEY)] = &[
        ("HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE),
        ("HKLM\\", HKEY_LOCAL_MACHINE),
        ("HKEY_CURRENT_USER\\", HKEY_CURRENT_USER),
        ("HKCU\\", HKEY_CURRENT_USER),
        ("HKEY_CLASSES_ROOT\\", HKEY_CLASSES_ROOT),
        ("HKCR\\", HKEY_CLASSES_ROOT),
        ("HKEY_USERS\\", HKEY_USERS),
        ("HKU\\", HKEY_USERS),
        ("HKEY_CURRENT_CONFIG\\", HKEY_CURRENT_CONFIG),
        ("HKCC\\", HKEY_CURRENT_CONFIG),
    ];

    for (prefix, hive) in prefixes {
        if let Some(rest) = key_path.strip_prefix(prefix) {
            return Ok((*hive, rest.to_string()));
        }
    }

    Err(KrakenError::Module(format!(
        "unknown registry hive in path: {}",
        key_path
    )))
}

/// Convert a Rust &str to a null-terminated UTF-16 Vec<u16>
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect()
}

/// Convert a UTF-16 slice (not necessarily null-terminated) to a String
#[cfg(windows)]
fn from_wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    OsString::from_wide(&s[..end])
        .to_string_lossy()
        .into_owned()
}

/// Map a REG_* type constant to a human-readable string
#[cfg(windows)]
fn reg_type_name(reg_type: u32) -> &'static str {
    match reg_type {
        REG_NONE => "REG_NONE",
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_DWORD_BIG_ENDIAN => "REG_DWORD_BIG_ENDIAN",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_QWORD => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

/// Open a registry key; caller must close it with RegCloseKey.
#[cfg(windows)]
fn open_key(root: HKEY, subkey: &str, access: u32) -> Result<HKEY, KrakenError> {
    let subkey_wide = to_wide(subkey);
    let mut hkey: HKEY = 0;
    let status = unsafe { RegOpenKeyExW(root, subkey_wide.as_ptr(), 0, access, &mut hkey) };
    if status != ERROR_SUCCESS {
        return Err(KrakenError::Module(format!(
            "RegOpenKeyExW failed with error {}",
            status
        )));
    }
    Ok(hkey)
}

// ============================================================
// Public API (Windows)
// ============================================================

/// Query a registry value
#[cfg(windows)]
pub fn reg_query(task: &RegQuery) -> Result<RegistryQueryOutput, KrakenError> {
    let (root, subkey) = parse_key_path(&task.key_path)?;
    let hkey = open_key(root, &subkey, KEY_READ)?;
    let result = query_value(hkey, &task.key_path, task.value_name.as_deref());
    unsafe { RegCloseKey(hkey) };
    result
}

#[cfg(windows)]
fn query_value(
    hkey: HKEY,
    key_path: &str,
    value_name: Option<&str>,
) -> Result<RegistryQueryOutput, KrakenError> {
    let value_wide = value_name.map(to_wide).unwrap_or_else(|| vec![0u16]);
    let vname_ptr = value_wide.as_ptr();

    // First call: determine required buffer size
    let mut reg_type: u32 = 0;
    let mut data_len: u32 = 0;
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            vname_ptr,
            std::ptr::null_mut(),
            &mut reg_type,
            std::ptr::null_mut(),
            &mut data_len,
        )
    };

    if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
        return Err(KrakenError::Module(format!(
            "RegQueryValueExW (size query) failed with error {}",
            status
        )));
    }

    // Second call: read the data
    let mut data = vec![0u8; data_len as usize];
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            vname_ptr,
            std::ptr::null_mut(),
            &mut reg_type,
            data.as_mut_ptr(),
            &mut data_len,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(KrakenError::Module(format!(
            "RegQueryValueExW failed with error {}",
            status
        )));
    }
    data.truncate(data_len as usize);

    Ok(RegistryQueryOutput {
        key_path: key_path.to_string(),
        value_name: value_name.unwrap_or("(Default)").to_string(),
        data,
        value_type: reg_type_name(reg_type).to_string(),
    })
}

/// Set a registry value
#[cfg(windows)]
pub fn reg_set(task: &RegSet) -> Result<RegistryOperationResult, KrakenError> {
    let (root, subkey) = parse_key_path(&task.key_path)?;

    let hkey = if task.create_key.unwrap_or(false) {
        let subkey_wide = to_wide(&subkey);
        let mut hkey: HKEY = 0;
        let mut disposition: u32 = 0;
        let status = unsafe {
            RegCreateKeyExW(
                root,
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
        hkey
    } else {
        open_key(root, &subkey, KEY_ALL_ACCESS)?
    };

    let value_wide = to_wide(&task.value_name);
    let status = unsafe {
        RegSetValueExW(
            hkey,
            value_wide.as_ptr(),
            0,
            task.value_type,
            task.data.as_ptr(),
            task.data.len() as u32,
        )
    };
    unsafe { RegCloseKey(hkey) };

    if status != ERROR_SUCCESS {
        return Err(KrakenError::Module(format!(
            "RegSetValueExW failed with error {}",
            status
        )));
    }

    Ok(RegistryOperationResult {
        operation: "set".to_string(),
        key_path: task.key_path.clone(),
        success: true,
        message: Some(format!("value '{}' written", task.value_name)),
    })
}

/// Delete a registry value or key
#[cfg(windows)]
pub fn reg_delete(task: &RegDelete) -> Result<RegistryOperationResult, KrakenError> {
    let (root, subkey) = parse_key_path(&task.key_path)?;

    match task.value_name.as_deref() {
        Some(value_name) => {
            let hkey = open_key(root, &subkey, KEY_ALL_ACCESS)?;
            let value_wide = to_wide(value_name);
            let status = unsafe { RegDeleteValueW(hkey, value_wide.as_ptr()) };
            unsafe { RegCloseKey(hkey) };

            if status != ERROR_SUCCESS {
                return Err(KrakenError::Module(format!(
                    "RegDeleteValueW failed with error {}",
                    status
                )));
            }

            Ok(RegistryOperationResult {
                operation: "delete_value".to_string(),
                key_path: task.key_path.clone(),
                success: true,
                message: Some(format!("value '{}' deleted", value_name)),
            })
        }
        None => {
            let subkey_wide = to_wide(&subkey);
            let status = unsafe { RegDeleteKeyExW(root, subkey_wide.as_ptr(), 0, 0) };

            if status != ERROR_SUCCESS {
                return Err(KrakenError::Module(format!(
                    "RegDeleteKeyExW failed with error {}",
                    status
                )));
            }

            Ok(RegistryOperationResult {
                operation: "delete_key".to_string(),
                key_path: task.key_path.clone(),
                success: true,
                message: None,
            })
        }
    }
}

/// Enumerate subkeys of a registry key
#[cfg(windows)]
pub fn reg_enum_keys(task: &RegEnumKeys) -> Result<Vec<String>, KrakenError> {
    let (root, subkey) = parse_key_path(&task.key_path)?;
    let hkey = open_key(root, &subkey, KEY_READ)?;
    let result = enum_keys_inner(hkey, &task.key_path, task.recursive.unwrap_or(false));
    unsafe { RegCloseKey(hkey) };
    result
}

#[cfg(windows)]
fn enum_keys_inner(hkey: HKEY, prefix: &str, recursive: bool) -> Result<Vec<String>, KrakenError> {
    let mut keys = Vec::new();
    let mut index: u32 = 0;

    loop {
        let mut name_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;

        let status = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            return Err(KrakenError::Module(format!(
                "RegEnumKeyExW failed with error {}",
                status
            )));
        }

        let key_name = from_wide(&name_buf[..name_len as usize]);
        let full_path = format!("{}\\{}", prefix, key_name);
        keys.push(full_path.clone());

        if recursive {
            let subkey_wide = to_wide(&key_name);
            let mut sub_hkey: HKEY = 0;
            let open_status =
                unsafe { RegOpenKeyExW(hkey, subkey_wide.as_ptr(), 0, KEY_READ, &mut sub_hkey) };
            if open_status == ERROR_SUCCESS {
                if let Ok(sub_keys) = enum_keys_inner(sub_hkey, &full_path, true) {
                    keys.extend(sub_keys);
                }
                unsafe { RegCloseKey(sub_hkey) };
            }
        }

        index += 1;
    }

    Ok(keys)
}

/// Enumerate values of a registry key
#[cfg(windows)]
pub fn reg_enum_values(task: &RegEnumValues) -> Result<Vec<RegistryValueOutput>, KrakenError> {
    let (root, subkey) = parse_key_path(&task.key_path)?;
    let hkey = open_key(root, &subkey, KEY_READ)?;

    let mut values = Vec::new();
    let mut index: u32 = 0;

    loop {
        // First pass: get name length and data size
        let mut name_buf = vec![0u16; 16384];
        let mut name_len = name_buf.len() as u32;
        let mut reg_type: u32 = 0;
        let mut data_len: u32 = 0;

        let status = unsafe {
            RegEnumValueW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut reg_type,
                std::ptr::null_mut(),
                &mut data_len,
            )
        };

        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            unsafe { RegCloseKey(hkey) };
            return Err(KrakenError::Module(format!(
                "RegEnumValueW (size) failed with error {}",
                status
            )));
        }

        let value_name = from_wide(&name_buf[..name_len as usize]);

        // Second pass: read data
        let mut name_buf2 = vec![0u16; 16384];
        let mut name_len2 = name_buf2.len() as u32;
        let mut reg_type2: u32 = 0;
        let mut data = vec![0u8; data_len as usize];
        let mut data_len2 = data_len;

        let status2 = unsafe {
            RegEnumValueW(
                hkey,
                index,
                name_buf2.as_mut_ptr(),
                &mut name_len2,
                std::ptr::null_mut(),
                &mut reg_type2,
                data.as_mut_ptr(),
                &mut data_len2,
            )
        };

        if status2 != ERROR_SUCCESS {
            unsafe { RegCloseKey(hkey) };
            return Err(KrakenError::Module(format!(
                "RegEnumValueW (data) failed with error {}",
                status2
            )));
        }
        data.truncate(data_len2 as usize);

        values.push(RegistryValueOutput {
            key_path: task.key_path.clone(),
            value_name,
            data,
            value_type: reg_type_name(reg_type2).to_string(),
        });

        index += 1;
    }

    unsafe { RegCloseKey(hkey) };
    Ok(values)
}

// ============================================================
// Non-Windows stubs
// ============================================================

#[cfg(not(windows))]
pub fn reg_query(_task: &RegQuery) -> Result<RegistryQueryOutput, KrakenError> {
    Err(KrakenError::Module(
        "registry operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn reg_set(_task: &RegSet) -> Result<RegistryOperationResult, KrakenError> {
    Err(KrakenError::Module(
        "registry operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn reg_delete(_task: &RegDelete) -> Result<RegistryOperationResult, KrakenError> {
    Err(KrakenError::Module(
        "registry operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn reg_enum_keys(_task: &RegEnumKeys) -> Result<Vec<String>, KrakenError> {
    Err(KrakenError::Module(
        "registry operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn reg_enum_values(_task: &RegEnumValues) -> Result<Vec<RegistryValueOutput>, KrakenError> {
    Err(KrakenError::Module(
        "registry operations are only supported on Windows".into(),
    ))
}
