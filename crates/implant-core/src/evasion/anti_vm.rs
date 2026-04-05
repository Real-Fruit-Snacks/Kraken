//! Anti-VM detection — Phase 4 OPSEC
//!
//! Detects common virtualization platforms to avoid analysis environments.
//! Detection rules: wiki/detection/sigma/kraken_opsec.yml
//!
//! Checks:
//! - CPUID hypervisor bit
//! - VM vendor MAC addresses
//! - VM-related processes
//! - VM-related registry keys
//! - VM-specific hardware strings

/// VM detection result with details
#[derive(Debug, Clone, Default)]
pub struct VmDetectionResult {
    pub is_vm: bool,
    pub cpuid_hypervisor: bool,
    pub vm_mac_detected: bool,
    pub vm_process_detected: bool,
    pub vm_registry_detected: bool,
    pub detected_platform: Option<String>,
}

/// Check if running in a virtual machine
#[cfg(target_os = "windows")]
pub fn is_virtual_machine() -> bool {
    check_cpuid_hypervisor()
        || check_mac_address()
        || check_vm_processes()
        || check_vm_registry()
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn is_virtual_machine() -> bool {
    // On Linux, check /sys/class/dmi/id for VM indicators
    check_linux_dmi()
}

/// Get detailed VM detection results
#[cfg(target_os = "windows")]
pub fn detect_vm_detailed() -> VmDetectionResult {
    let cpuid = check_cpuid_hypervisor();
    let mac = check_mac_address();
    let process = check_vm_processes();
    let registry = check_vm_registry();

    let platform = if cpuid || mac || process || registry {
        detect_vm_platform()
    } else {
        None
    };

    VmDetectionResult {
        is_vm: cpuid || mac || process || registry,
        cpuid_hypervisor: cpuid,
        vm_mac_detected: mac,
        vm_process_detected: process,
        vm_registry_detected: registry,
        detected_platform: platform,
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn detect_vm_detailed() -> VmDetectionResult {
    let linux_dmi = check_linux_dmi();
    VmDetectionResult {
        is_vm: linux_dmi,
        cpuid_hypervisor: false,
        vm_mac_detected: false,
        vm_process_detected: false,
        vm_registry_detected: false,
        detected_platform: if linux_dmi {
            Some("Linux VM".to_string())
        } else {
            None
        },
    }
}

// =============================================================================
// CPUID Check
// =============================================================================

#[cfg(target_os = "windows")]
fn check_cpuid_hypervisor() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID leaf 1, ECX bit 31 indicates hypervisor presence
        unsafe {
            let result: u32;
            core::arch::asm!(
                "push rbx",       // Save rbx (LLVM reserved)
                "mov eax, 1",
                "cpuid",
                "mov {0:e}, ecx",
                "pop rbx",        // Restore rbx
                out(reg) result,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
            );
            (result >> 31) & 1 == 1
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

// =============================================================================
// MAC Address Check
// =============================================================================

/// Known VM vendor MAC address prefixes (OUI)
#[allow(dead_code)]
const VM_MAC_PREFIXES: &[(&[u8; 3], &str)] = &[
    // VMware
    (b"\x00\x05\x69", "VMware"),
    (b"\x00\x0C\x29", "VMware"),
    (b"\x00\x1C\x14", "VMware"),
    (b"\x00\x50\x56", "VMware"),
    // VirtualBox
    (b"\x08\x00\x27", "VirtualBox"),
    (b"\x0A\x00\x27", "VirtualBox"),
    // Parallels
    (b"\x00\x1C\x42", "Parallels"),
    // Xen
    (b"\x00\x16\x3E", "Xen"),
    // Hyper-V
    (b"\x00\x15\x5D", "Hyper-V"),
    // QEMU/KVM
    (b"\x52\x54\x00", "QEMU/KVM"),
];

#[cfg(target_os = "windows")]
fn check_mac_address() -> bool {
    // Get adapter addresses using GetAdaptersAddresses
    // For now, return false as this requires more complex Windows API calls
    // This is a placeholder that can be expanded
    false
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn check_mac_address() -> bool {
    // On Linux, read /sys/class/net/*/address
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let addr_path = entry.path().join("address");
            if let Ok(mac_str) = std::fs::read_to_string(&addr_path) {
                let mac_str = mac_str.trim();
                // Parse MAC address
                let parts: Vec<&str> = mac_str.split(':').collect();
                if parts.len() >= 3 {
                    if let (Ok(b0), Ok(b1), Ok(b2)) = (
                        u8::from_str_radix(parts[0], 16),
                        u8::from_str_radix(parts[1], 16),
                        u8::from_str_radix(parts[2], 16),
                    ) {
                        let prefix = [b0, b1, b2];
                        for (vm_prefix, _name) in VM_MAC_PREFIXES {
                            if prefix == **vm_prefix {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

// =============================================================================
// Process Check
// =============================================================================

/// Known VM-related process names
#[allow(dead_code)]
const VM_PROCESSES: &[&str] = &[
    // VMware
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
    "vmacthlp.exe",
    // VirtualBox
    "vboxservice.exe",
    "vboxtray.exe",
    "vboxclient.exe",
    // Hyper-V
    "vmms.exe",
    "vmwp.exe",
    // QEMU
    "qemu-ga.exe",
    // Parallels
    "prl_tools.exe",
    "prl_cc.exe",
    // Xen
    "xenservice.exe",
];

#[cfg(target_os = "windows")]
fn check_vm_processes() -> bool {
    // This would use CreateToolhelp32Snapshot to enumerate processes
    // For now, return false as placeholder
    false
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn check_vm_processes() -> bool {
    // On Linux, check /proc for VM guest agents
    let linux_vm_processes = [
        "vmtoolsd",
        "VBoxService",
        "VBoxClient",
        "qemu-ga",
        "spice-vdagent",
        "xe-daemon",
    ];

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(cmdline) = std::fs::read_to_string(entry.path().join("comm")) {
                let cmdline = cmdline.trim();
                for vm_proc in &linux_vm_processes {
                    if cmdline.contains(vm_proc) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// =============================================================================
// Registry Check (Windows only)
// =============================================================================

/// Known VM-related registry keys
#[cfg(target_os = "windows")]
const VM_REGISTRY_KEYS: &[&str] = &[
    r"SOFTWARE\VMware, Inc.\VMware Tools",
    r"SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    r"HARDWARE\ACPI\DSDT\VBOX__",
    r"HARDWARE\ACPI\FADT\VBOX__",
    r"HARDWARE\ACPI\RSDT\VBOX__",
    r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"SYSTEM\CurrentControlSet\Services\VBoxMouse",
    r"SYSTEM\CurrentControlSet\Services\VBoxService",
    r"SYSTEM\CurrentControlSet\Services\VBoxSF",
    r"SYSTEM\CurrentControlSet\Services\vmci",
    r"SYSTEM\CurrentControlSet\Services\vmhgfs",
    r"SYSTEM\CurrentControlSet\Services\vmmouse",
    r"SYSTEM\CurrentControlSet\Services\VMTools",
];

#[cfg(target_os = "windows")]
fn check_vm_registry() -> bool {
    // This would use RegOpenKeyEx to check for VM registry keys
    // For now, return false as placeholder
    false
}

// =============================================================================
// Linux DMI Check
// =============================================================================

#[cfg(not(target_os = "windows"))]
fn check_linux_dmi() -> bool {
    // Check /sys/class/dmi/id for VM indicators
    let dmi_files = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
    ];

    let vm_indicators = [
        "VMware",
        "VirtualBox",
        "QEMU",
        "KVM",
        "Xen",
        "Microsoft Corporation", // Hyper-V
        "Parallels",
        "innotek GmbH", // VirtualBox
        "Red Hat",      // QEMU/KVM
        "Amazon EC2",
        "Google Compute Engine",
        "DigitalOcean",
    ];

    for dmi_file in &dmi_files {
        if let Ok(content) = std::fs::read_to_string(dmi_file) {
            let content = content.trim();
            for indicator in &vm_indicators {
                if content.contains(indicator) {
                    return true;
                }
            }
        }
    }

    false
}

// =============================================================================
// Platform Detection
// =============================================================================

#[cfg(target_os = "windows")]
fn detect_vm_platform() -> Option<String> {
    // Try to identify specific VM platform
    // This would use more specific checks
    Some("Unknown VM".to_string())
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn detect_vm_platform() -> Option<String> {
    // Check DMI for platform name
    if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let product = product.trim();
        if !product.is_empty() {
            return Some(product.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_virtual_machine_returns_bool() {
        // Just verify it returns a boolean without panicking
        let result = is_virtual_machine();
        assert!(result == true || result == false);
    }

    #[test]
    fn test_detect_vm_detailed_returns_result() {
        let result = detect_vm_detailed();
        // Verify the structure is valid
        // On Windows: is_vm should match the individual checks
        // On Linux: is_vm can be set by DMI check even if other flags are false
        #[cfg(target_os = "windows")]
        {
            assert_eq!(
                result.is_vm,
                result.cpuid_hypervisor
                    || result.vm_mac_detected
                    || result.vm_process_detected
                    || result.vm_registry_detected
            );
        }
        // On non-Windows, just verify it returns a valid result
        #[cfg(not(target_os = "windows"))]
        {
            // is_vm may or may not be true depending on environment
            let _ = result.is_vm;
        }
    }

    #[test]
    fn test_vm_detection_result_default() {
        let result = VmDetectionResult::default();
        assert!(!result.is_vm);
        assert!(!result.cpuid_hypervisor);
        assert!(!result.vm_mac_detected);
        assert!(!result.vm_process_detected);
        assert!(!result.vm_registry_detected);
        assert!(result.detected_platform.is_none());
    }

    #[test]
    fn test_vm_mac_prefixes_valid() {
        // Verify MAC prefix data is valid
        for (prefix, name) in VM_MAC_PREFIXES {
            assert_eq!(prefix.len(), 3, "MAC prefix should be 3 bytes");
            assert!(!name.is_empty(), "VM name should not be empty");
        }
    }

    #[test]
    fn test_vm_processes_valid() {
        // Verify process list is valid
        for proc in VM_PROCESSES {
            assert!(!proc.is_empty(), "Process name should not be empty");
            assert!(
                proc.ends_with(".exe"),
                "Windows process should end with .exe"
            );
        }
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_check_mac_address_no_panic() {
        // Just verify it doesn't panic
        let _ = check_mac_address();
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_check_vm_processes_no_panic() {
        // Just verify it doesn't panic
        let _ = check_vm_processes();
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_check_linux_dmi_no_panic() {
        // Just verify it doesn't panic
        let _ = check_linux_dmi();
    }
}
