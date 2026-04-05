//! Known DLL sideloading target database.
//!
//! Catalogues legitimate applications that load DLLs from user-writable
//! directories, making them candidates for DLL search-order hijacking.
//!
//! ## Detection (Blue Team)
//! - Compare loaded DLL hashes against known-good baselines
//! - Monitor DLL loads from `%LOCALAPPDATA%` directories
//! - Sysmon Event 7 with `ImageLoaded` from non-standard paths

/// A known sideload target — a legitimate application that loads a DLL from a
/// user-writable location without signature verification.
#[derive(Debug, Clone)]
pub struct SideloadTarget {
    /// Friendly application name.
    pub application: &'static str,
    /// DLL filename the application loads.
    pub dll_name: &'static str,
    /// Export names the application expects the DLL to provide.
    pub expected_exports: &'static [&'static str],
    /// Typical install path (may contain environment variables).
    pub search_path: &'static str,
    /// Operator notes (privilege, persistence, caveats).
    pub notes: &'static str,
}

/// Built-in catalogue of well-known sideload targets.
pub const KNOWN_TARGETS: &[SideloadTarget] = &[
    SideloadTarget {
        application: "Microsoft OneDrive",
        dll_name: "version.dll",
        expected_exports: &[
            "GetFileVersionInfoA",
            "GetFileVersionInfoW",
            "GetFileVersionInfoSizeA",
            "GetFileVersionInfoSizeW",
            "VerQueryValueA",
            "VerQueryValueW",
        ],
        search_path: r"%LOCALAPPDATA%\Microsoft\OneDrive",
        notes: "Auto-starts with user login via scheduled task / Run key",
    },
    SideloadTarget {
        application: "Microsoft Teams",
        dll_name: "WINMM.dll",
        expected_exports: &["PlaySoundW", "waveOutOpen", "timeGetTime"],
        search_path: r"%LOCALAPPDATA%\Microsoft\Teams",
        notes: "Runs on startup for most corporate users",
    },
    SideloadTarget {
        application: "Slack",
        dll_name: "chrome_elf.dll",
        expected_exports: &["SignalInitializeCrashReporting"],
        search_path: r"%LOCALAPPDATA%\slack",
        notes: "Electron-based app, loads chrome_elf.dll early",
    },
    SideloadTarget {
        application: "Windows Defender (MpCmdRun)",
        dll_name: "MSASN1.dll",
        expected_exports: &["ASN1_CreateModule"],
        search_path: r"C:\ProgramData\Microsoft\Windows Defender\Platform\*",
        notes: "Runs as SYSTEM; requires write access to Defender directory",
    },
    SideloadTarget {
        application: "System (generic)",
        dll_name: "version.dll",
        expected_exports: &[
            "GetFileVersionInfoW",
            "GetFileVersionInfoSizeW",
            "VerQueryValueW",
        ],
        search_path: r"(application directory)",
        notes: "version.dll is commonly sideloaded; many apps import it",
    },
    SideloadTarget {
        application: "System (generic)",
        dll_name: "winmm.dll",
        expected_exports: &["timeGetTime", "waveOutOpen"],
        search_path: r"(application directory)",
        notes: "winmm.dll is loaded by many multimedia applications",
    },
    SideloadTarget {
        application: "System (generic)",
        dll_name: "dbghelp.dll",
        expected_exports: &["MiniDumpWriteDump"],
        search_path: r"(application directory)",
        notes: "Commonly loaded by debuggers and crash reporters",
    },
    SideloadTarget {
        application: "System (generic)",
        dll_name: "cryptbase.dll",
        expected_exports: &["SystemFunction036"],
        search_path: r"(application directory)",
        notes: "Loaded by many apps for RNG; small export surface",
    },
];

/// Look up a sideload target by DLL name (case-insensitive).
pub fn find_target(dll_name: &str) -> Vec<&'static SideloadTarget> {
    KNOWN_TARGETS
        .iter()
        .filter(|t| t.dll_name.eq_ignore_ascii_case(dll_name))
        .collect()
}

/// List all known sideload targets.
pub fn list_targets() -> &'static [SideloadTarget] {
    KNOWN_TARGETS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_target_case_insensitive() {
        let results = find_target("VERSION.DLL");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_find_target_not_found() {
        let results = find_target("nonexistent.dll");
        assert!(results.is_empty());
    }

    #[test]
    fn test_list_targets_non_empty() {
        assert!(!list_targets().is_empty());
    }

    #[test]
    fn test_all_targets_have_exports() {
        for target in list_targets() {
            assert!(
                !target.expected_exports.is_empty(),
                "target {} ({}) has no expected exports",
                target.application,
                target.dll_name
            );
        }
    }

    #[test]
    fn test_all_targets_have_dll_name() {
        for target in list_targets() {
            assert!(
                target.dll_name.ends_with(".dll") || target.dll_name.ends_with(".DLL"),
                "target {} has non-.dll name: {}",
                target.application,
                target.dll_name
            );
        }
    }

    #[test]
    fn test_onedrive_target() {
        let results = find_target("version.dll");
        let onedrive = results
            .iter()
            .find(|t| t.application == "Microsoft OneDrive");
        assert!(onedrive.is_some());
        assert!(onedrive.unwrap().expected_exports.contains(&"GetFileVersionInfoW"));
    }
}
