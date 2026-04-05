//! BOFService gRPC implementation - Beacon Object File catalog and execution

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

use common::{ImplantId, TaskId};
use protocol::{
    bof_service_server::BofService, BofArgType, BofArgument, BofCatalogEntry, BofCategory,
    BofExecution, BofManifest, DeleteBofRequest, DeleteBofResponse, ExecuteBofRequest,
    ExecuteBofResponse, GetBofRequest, ListBofExecutionsRequest, ListBofExecutionsResponse,
    ListBoFsRequest, ListBoFsResponse, Timestamp, UploadBofRequest, UploadBofResponse,
    ValidateBofRequest, ValidateBofResponse,
};

use crate::state::ServerState;

/// Unique ID for a BOF execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionId(uuid::Uuid);

impl ExecutionId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for ExecutionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal BOF catalog entry with binary data
#[derive(Debug, Clone)]
struct CatalogEntry {
    manifest: BofManifest,
    x64_data: Option<Vec<u8>>,
    x86_data: Option<Vec<u8>>,
    added_at: i64,
}

/// Internal execution tracking
#[derive(Debug, Clone)]
struct ExecutionRecord {
    id: ExecutionId,
    implant_id: ImplantId,
    #[allow(dead_code)]
    task_id: TaskId,
    bof_id: String,
    arguments: Vec<String>,
    executed_at: i64,
    output: Option<String>,
    exit_code: Option<i32>,
    error: Option<String>,
    completed: bool,
}

/// BOF catalog and execution manager
pub struct BOFManager {
    catalog: DashMap<String, CatalogEntry>,
    executions: DashMap<ExecutionId, ExecutionRecord>,
    task_to_execution: DashMap<TaskId, ExecutionId>,
}

impl BOFManager {
    pub fn new() -> Self {
        let manager = Self {
            catalog: DashMap::new(),
            executions: DashMap::new(),
            task_to_execution: DashMap::new(),
        };

        // Seed with some common BOFs for demonstration
        manager.seed_default_bofs();
        manager
    }

    fn seed_default_bofs(&self) {
        let now = chrono::Utc::now().timestamp_millis();

        // whoami BOF
        self.catalog.insert(
            "whoami".to_string(),
            CatalogEntry {
                manifest: BofManifest {
                    id: "whoami".to_string(),
                    name: "whoami".to_string(),
                    description: "Display current user and group information".to_string(),
                    author: "trustedsec".to_string(),
                    version: "1.0.0".to_string(),
                    category: BofCategory::Recon as i32,
                    tags: vec!["recon".to_string(), "identity".to_string()],
                    arguments: vec![],
                    entry_point: "go".to_string(),
                    supported_arch: vec!["x64".to_string(), "x86".to_string()],
                    supported_os: vec!["windows".to_string()],
                    opsec_notes: "Low OPSEC risk - uses standard Windows APIs".to_string(),
                    source_url: "https://github.com/trustedsec/CS-Situational-Awareness-BOF".to_string(),
                },
                x64_data: None, // Would contain actual COFF data
                x86_data: None,
                added_at: now,
            },
        );

        // netstat BOF
        self.catalog.insert(
            "netstat".to_string(),
            CatalogEntry {
                manifest: BofManifest {
                    id: "netstat".to_string(),
                    name: "netstat".to_string(),
                    description: "List active network connections and listening ports".to_string(),
                    author: "trustedsec".to_string(),
                    version: "1.0.0".to_string(),
                    category: BofCategory::Recon as i32,
                    tags: vec!["recon".to_string(), "network".to_string()],
                    arguments: vec![],
                    entry_point: "go".to_string(),
                    supported_arch: vec!["x64".to_string(), "x86".to_string()],
                    supported_os: vec!["windows".to_string()],
                    opsec_notes: "Medium OPSEC risk - queries network state".to_string(),
                    source_url: "https://github.com/trustedsec/CS-Situational-Awareness-BOF".to_string(),
                },
                x64_data: None,
                x86_data: None,
                added_at: now,
            },
        );

        // dir BOF
        self.catalog.insert(
            "dir".to_string(),
            CatalogEntry {
                manifest: BofManifest {
                    id: "dir".to_string(),
                    name: "dir".to_string(),
                    description: "List directory contents".to_string(),
                    author: "trustedsec".to_string(),
                    version: "1.0.0".to_string(),
                    category: BofCategory::Recon as i32,
                    tags: vec!["recon".to_string(), "filesystem".to_string()],
                    arguments: vec![BofArgument {
                        name: "path".to_string(),
                        arg_type: BofArgType::BofArgString as i32,
                        description: "Directory path to list".to_string(),
                        required: true,
                        default_value: None,
                    }],
                    entry_point: "go".to_string(),
                    supported_arch: vec!["x64".to_string(), "x86".to_string()],
                    supported_os: vec!["windows".to_string()],
                    opsec_notes: "Low OPSEC risk".to_string(),
                    source_url: "https://github.com/trustedsec/CS-Situational-Awareness-BOF".to_string(),
                },
                x64_data: None,
                x86_data: None,
                added_at: now,
            },
        );

        // reg_query BOF
        self.catalog.insert(
            "reg_query".to_string(),
            CatalogEntry {
                manifest: BofManifest {
                    id: "reg_query".to_string(),
                    name: "reg_query".to_string(),
                    description: "Query registry keys and values".to_string(),
                    author: "trustedsec".to_string(),
                    version: "1.0.0".to_string(),
                    category: BofCategory::Recon as i32,
                    tags: vec!["recon".to_string(), "registry".to_string()],
                    arguments: vec![
                        BofArgument {
                            name: "hive".to_string(),
                            arg_type: BofArgType::BofArgString as i32,
                            description: "Registry hive (HKLM, HKCU, etc.)".to_string(),
                            required: true,
                            default_value: None,
                        },
                        BofArgument {
                            name: "path".to_string(),
                            arg_type: BofArgType::BofArgString as i32,
                            description: "Registry key path".to_string(),
                            required: true,
                            default_value: None,
                        },
                    ],
                    entry_point: "go".to_string(),
                    supported_arch: vec!["x64".to_string(), "x86".to_string()],
                    supported_os: vec!["windows".to_string()],
                    opsec_notes: "Low OPSEC risk - standard registry access".to_string(),
                    source_url: "https://github.com/trustedsec/CS-Situational-Awareness-BOF".to_string(),
                },
                x64_data: None,
                x86_data: None,
                added_at: now,
            },
        );

        // nanodump BOF - credential dumping
        self.catalog.insert(
            "nanodump".to_string(),
            CatalogEntry {
                manifest: BofManifest {
                    id: "nanodump".to_string(),
                    name: "nanodump".to_string(),
                    description: "Dump LSASS process memory for credential extraction".to_string(),
                    author: "fortra".to_string(),
                    version: "1.0.0".to_string(),
                    category: BofCategory::Credentials as i32,
                    tags: vec!["credentials".to_string(), "lsass".to_string(), "dump".to_string()],
                    arguments: vec![
                        BofArgument {
                            name: "pid".to_string(),
                            arg_type: BofArgType::BofArgInt as i32,
                            description: "LSASS process ID (0 = auto-detect)".to_string(),
                            required: false,
                            default_value: Some("0".to_string()),
                        },
                        BofArgument {
                            name: "write_file".to_string(),
                            arg_type: BofArgType::BofArgString as i32,
                            description: "Output file path".to_string(),
                            required: false,
                            default_value: None,
                        },
                    ],
                    entry_point: "go".to_string(),
                    supported_arch: vec!["x64".to_string()],
                    supported_os: vec!["windows".to_string()],
                    opsec_notes: "HIGH OPSEC RISK - Accesses LSASS, may trigger EDR. Uses direct syscalls to evade hooks.".to_string(),
                    source_url: "https://github.com/fortra/nanodump".to_string(),
                },
                x64_data: None,
                x86_data: None,
                added_at: now,
            },
        );

        // schtasks_enum BOF
        self.catalog.insert(
            "schtasks_enum".to_string(),
            CatalogEntry {
                manifest: BofManifest {
                    id: "schtasks_enum".to_string(),
                    name: "schtasks_enum".to_string(),
                    description: "Enumerate scheduled tasks".to_string(),
                    author: "trustedsec".to_string(),
                    version: "1.0.0".to_string(),
                    category: BofCategory::Recon as i32,
                    tags: vec!["recon".to_string(), "persistence".to_string(), "scheduled_tasks".to_string()],
                    arguments: vec![],
                    entry_point: "go".to_string(),
                    supported_arch: vec!["x64".to_string(), "x86".to_string()],
                    supported_os: vec!["windows".to_string()],
                    opsec_notes: "Medium OPSEC risk - COM object instantiation".to_string(),
                    source_url: "https://github.com/trustedsec/CS-Situational-Awareness-BOF".to_string(),
                },
                x64_data: None,
                x86_data: None,
                added_at: now,
            },
        );
    }
}

impl Default for BOFManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BOFServiceImpl {
    state: Arc<ServerState>,
    manager: Arc<RwLock<BOFManager>>,
}

impl BOFServiceImpl {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self {
            state,
            manager: Arc::new(RwLock::new(BOFManager::new())),
        }
    }

    fn parse_implant_id(bytes: &[u8]) -> Result<ImplantId, Status> {
        ImplantId::from_bytes(bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid implant_id: {e}")))
    }

    async fn verify_implant(&self, implant_id: ImplantId) -> Result<db::ImplantRecord, Status> {
        let record = self
            .state
            .db
            .implants()
            .get(implant_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("implant {} not found", implant_id)))?;

        if !record.state.is_taskable() {
            return Err(Status::failed_precondition(format!(
                "implant {} is not in a taskable state (state={})",
                implant_id, record.state
            )));
        }

        Ok(record)
    }

    /// Pack BOF arguments into binary format following the bof_pack convention.
    ///
    /// Format for each argument type:
    /// - String (z): 4-byte length (LE, includes null) + UTF-8 bytes + null terminator
    /// - Wstring (Z): 4-byte length (LE, in bytes, includes null) + UTF-16LE bytes + null terminator (2 bytes)
    /// - Int (i): 4-byte little-endian integer
    /// - Short (s): 2-byte little-endian short
    /// - Binary (b): 4-byte length (LE) + raw bytes
    fn pack_bof_arguments(
        arg_defs: &[BofArgument],
        arg_values: &[String],
    ) -> Result<Vec<u8>, Status> {
        let mut packed = Vec::new();

        for (i, def) in arg_defs.iter().enumerate() {
            // Get the value or default
            let value = if i < arg_values.len() {
                &arg_values[i]
            } else if let Some(ref default) = def.default_value {
                default
            } else if def.required {
                return Err(Status::invalid_argument(format!(
                    "missing required argument '{}'",
                    def.name
                )));
            } else {
                continue; // Optional argument with no value or default - skip
            };

            match BofArgType::try_from(def.arg_type).unwrap_or(BofArgType::BofArgUnspecified) {
                BofArgType::BofArgString => {
                    // z - null-terminated UTF-8 string
                    let bytes = value.as_bytes();
                    let len = (bytes.len() + 1) as u32; // +1 for null terminator
                    packed.extend_from_slice(&len.to_le_bytes());
                    packed.extend_from_slice(bytes);
                    packed.push(0); // null terminator
                }
                BofArgType::BofArgWstring => {
                    // Z - null-terminated UTF-16LE string
                    let utf16: Vec<u16> = value.encode_utf16().collect();
                    let byte_len = ((utf16.len() + 1) * 2) as u32; // +1 for null, *2 for UTF-16
                    packed.extend_from_slice(&byte_len.to_le_bytes());
                    for code_unit in utf16 {
                        packed.extend_from_slice(&code_unit.to_le_bytes());
                    }
                    packed.extend_from_slice(&[0, 0]); // null terminator (2 bytes for UTF-16)
                }
                BofArgType::BofArgInt => {
                    // i - 32-bit integer
                    let int_val: i32 = value.parse().map_err(|_| {
                        Status::invalid_argument(format!(
                            "argument '{}' must be a valid integer, got '{}'",
                            def.name, value
                        ))
                    })?;
                    packed.extend_from_slice(&int_val.to_le_bytes());
                }
                BofArgType::BofArgShort => {
                    // s - 16-bit integer
                    let short_val: i16 = value.parse().map_err(|_| {
                        Status::invalid_argument(format!(
                            "argument '{}' must be a valid short integer, got '{}'",
                            def.name, value
                        ))
                    })?;
                    packed.extend_from_slice(&short_val.to_le_bytes());
                }
                BofArgType::BofArgBinary => {
                    // b - binary data (hex-encoded in the string)
                    let bytes = hex::decode(value).map_err(|_| {
                        Status::invalid_argument(format!(
                            "argument '{}' must be valid hex-encoded binary, got '{}'",
                            def.name, value
                        ))
                    })?;
                    let len = bytes.len() as u32;
                    packed.extend_from_slice(&len.to_le_bytes());
                    packed.extend_from_slice(&bytes);
                }
                BofArgType::BofArgUnspecified => {
                    return Err(Status::invalid_argument(format!(
                        "argument '{}' has unspecified type",
                        def.name
                    )));
                }
            }
        }

        Ok(packed)
    }

    fn catalog_entry_to_proto(entry: &CatalogEntry) -> BofCatalogEntry {
        BofCatalogEntry {
            manifest: Some(entry.manifest.clone()),
            x64_available: entry.x64_data.is_some(),
            x86_available: entry.x86_data.is_some(),
            x64_size: entry.x64_data.as_ref().map(|d| d.len() as u64).unwrap_or(0),
            x86_size: entry.x86_data.as_ref().map(|d| d.len() as u64).unwrap_or(0),
            added_at: Some(Timestamp::from_millis(entry.added_at)),
        }
    }
}

#[tonic::async_trait]
impl BofService for BOFServiceImpl {
    async fn list_bo_fs(
        &self,
        request: Request<ListBoFsRequest>,
    ) -> Result<Response<ListBoFsResponse>, Status> {
        let req = request.into_inner();
        let manager = self.manager.read().await;

        let filter_category = match req.category {
            Some(c) if c != BofCategory::Unspecified as i32 => Some(c),
            _ => None,
        };

        let search_lower = req.search.as_deref().unwrap_or("").to_lowercase();
        let has_search = !search_lower.is_empty();

        let bofs: Vec<BofCatalogEntry> = manager
            .catalog
            .iter()
            .filter(|entry| {
                let cat_entry = entry.value();
                let manifest = &cat_entry.manifest;

                // Filter by category
                if let Some(cat_filter) = filter_category {
                    if manifest.category != cat_filter {
                        return false;
                    }
                }

                // Filter by search
                if has_search {
                    let name_match = manifest.name.to_lowercase().contains(&search_lower);
                    let desc_match = manifest.description.to_lowercase().contains(&search_lower);
                    if !name_match && !desc_match {
                        return false;
                    }
                }

                // Filter by tags
                if !req.tags.is_empty() {
                    let has_all_tags = req.tags.iter().all(|tag| {
                        manifest.tags.iter().any(|t| t.to_lowercase() == tag.to_lowercase())
                    });
                    if !has_all_tags {
                        return false;
                    }
                }

                true
            })
            .map(|entry| Self::catalog_entry_to_proto(entry.value()))
            .collect();

        Ok(Response::new(ListBoFsResponse { bofs }))
    }

    async fn get_bof(
        &self,
        request: Request<GetBofRequest>,
    ) -> Result<Response<BofCatalogEntry>, Status> {
        let req = request.into_inner();
        let manager = self.manager.read().await;

        let entry = manager
            .catalog
            .get(&req.bof_id)
            .ok_or_else(|| Status::not_found(format!("BOF '{}' not found", req.bof_id)))?;

        Ok(Response::new(Self::catalog_entry_to_proto(entry.value())))
    }

    async fn upload_bof(
        &self,
        request: Request<UploadBofRequest>,
    ) -> Result<Response<UploadBofResponse>, Status> {
        let req = request.into_inner();

        let manifest = req
            .manifest
            .ok_or_else(|| Status::invalid_argument("missing manifest"))?;

        if manifest.id.is_empty() {
            return Err(Status::invalid_argument("manifest.id is required"));
        }

        let now = chrono::Utc::now().timestamp_millis();
        let bof_id = manifest.id.clone();

        let manager = self.manager.write().await;
        manager.catalog.insert(
            bof_id.clone(),
            CatalogEntry {
                manifest,
                x64_data: req.x64_data.filter(|d| !d.is_empty()),
                x86_data: req.x86_data.filter(|d| !d.is_empty()),
                added_at: now,
            },
        );

        tracing::info!(bof_id = %bof_id, "BOF uploaded to catalog");

        Ok(Response::new(UploadBofResponse {
            bof_id,
            success: true,
            error: None,
        }))
    }

    async fn delete_bof(
        &self,
        request: Request<DeleteBofRequest>,
    ) -> Result<Response<DeleteBofResponse>, Status> {
        let req = request.into_inner();
        let manager = self.manager.write().await;

        if manager.catalog.remove(&req.bof_id).is_some() {
            tracing::info!(bof_id = %req.bof_id, "BOF deleted from catalog");
            Ok(Response::new(DeleteBofResponse { success: true }))
        } else {
            Err(Status::not_found(format!("BOF '{}' not found", req.bof_id)))
        }
    }

    async fn execute_bof(
        &self,
        request: Request<ExecuteBofRequest>,
    ) -> Result<Response<ExecuteBofResponse>, Status> {
        let req = request.into_inner();

        let implant_id = Self::parse_implant_id(
            &req.implant_id.ok_or_else(|| Status::invalid_argument("missing implant_id"))?.value,
        )?;

        let record = self.verify_implant(implant_id).await?;

        // Determine architecture
        let arch = if let Some(override_arch) = req.arch_override.as_ref() {
            override_arch.clone()
        } else {
            // Infer from implant
            if record.os_arch.as_deref().unwrap_or("").contains("64") {
                "x64".to_string()
            } else {
                "x86".to_string()
            }
        };

        // Get BOF data, entry point, and argument definitions from catalog (scoped to release lock)
        let (bof_data, entry_point, arg_defs) = {
            let manager = self.manager.read().await;
            let entry = manager
                .catalog
                .get(&req.bof_id)
                .ok_or_else(|| Status::not_found(format!("BOF '{}' not found", req.bof_id)))?;

            let data = if arch == "x64" {
                entry.value().x64_data.clone()
            } else {
                entry.value().x86_data.clone()
            };
            let ep = entry.value().manifest.entry_point.clone();
            let args = entry.value().manifest.arguments.clone();
            (data, ep, args)
        };

        // Pack arguments according to manifest definitions
        let packed_args = if !arg_defs.is_empty() || !req.arguments.is_empty() {
            Some(Self::pack_bof_arguments(&arg_defs, &req.arguments)?)
        } else {
            None
        };

        // For now, we'll dispatch even without actual BOF data (catalog is demonstration)
        // In production, this would error if no data available

        let execution_id = ExecutionId::new();
        let task_id = TaskId::new();
        let now = chrono::Utc::now().timestamp_millis();

        // Create BOF task
        use protocol::{BofTask, Task};

        let bof_task = BofTask {
            bof_data: bof_data.unwrap_or_default(),
            entry_point: Some(entry_point),
            arguments: packed_args,
        };

        let task_data = prost::Message::encode_to_vec(&bof_task);

        let proto_task = Task {
            task_id: Some(task_id.into()),
            task_type: "bof".to_string(),
            task_data,
            issued_at: Some(Timestamp::from_millis(now)),
            operator_id: None,
        };

        self.state.enqueue_task(implant_id, proto_task);

        // Track execution
        let manager = self.manager.write().await;
        manager.executions.insert(
            execution_id,
            ExecutionRecord {
                id: execution_id,
                implant_id,
                task_id,
                bof_id: req.bof_id.clone(),
                arguments: req.arguments.clone(),
                executed_at: now,
                output: None,
                exit_code: None,
                error: None,
                completed: false,
            },
        );
        manager.task_to_execution.insert(task_id, execution_id);

        tracing::info!(
            execution_id = %execution_id.0,
            task_id = %task_id,
            implant_id = %implant_id,
            bof_id = %req.bof_id,
            arch = %arch,
            "BOF execution dispatched"
        );

        Ok(Response::new(ExecuteBofResponse {
            execution_id: Some(protocol::Uuid {
                value: execution_id.as_bytes().to_vec(),
            }),
            task_id: Some(task_id.into()),
        }))
    }

    async fn validate_bof(
        &self,
        request: Request<ValidateBofRequest>,
    ) -> Result<Response<ValidateBofResponse>, Status> {
        let req = request.into_inner();

        let implant_id = Self::parse_implant_id(
            &req.implant_id.ok_or_else(|| Status::invalid_argument("missing implant_id"))?.value,
        )?;

        let record = self.verify_implant(implant_id).await?;

        let manager = self.manager.read().await;

        let entry = manager
            .catalog
            .get(&req.bof_id)
            .ok_or_else(|| Status::not_found(format!("BOF '{}' not found", req.bof_id)))?;

        let manifest = &entry.value().manifest;
        let mut warnings = Vec::new();
        let mut compatible = true;

        // Check OS compatibility
        let implant_os = record.os_name.as_deref().unwrap_or("").to_lowercase();
        let os_compatible = manifest.supported_os.iter().any(|os| {
            implant_os.contains(&os.to_lowercase())
        });

        if !os_compatible {
            compatible = false;
            warnings.push(format!(
                "BOF requires {:?} but implant is running {}",
                manifest.supported_os,
                implant_os
            ));
        }

        // Check architecture compatibility
        let implant_arch = record.os_arch.as_deref().unwrap_or("");
        let is_64bit = implant_arch.contains("64");
        let arch_compatible = if is_64bit {
            manifest.supported_arch.contains(&"x64".to_string())
        } else {
            manifest.supported_arch.contains(&"x86".to_string())
        };

        if !arch_compatible {
            compatible = false;
            warnings.push(format!(
                "BOF requires {:?} but implant is {}",
                manifest.supported_arch,
                implant_arch
            ));
        }

        // Add OPSEC warnings
        if !manifest.opsec_notes.is_empty() {
            warnings.push(format!("OPSEC: {}", manifest.opsec_notes));
        }

        let recommended_arch = if is_64bit { "x64" } else { "x86" }.to_string();

        Ok(Response::new(ValidateBofResponse {
            compatible,
            warnings,
            recommended_arch,
        }))
    }

    async fn list_executions(
        &self,
        request: Request<ListBofExecutionsRequest>,
    ) -> Result<Response<ListBofExecutionsResponse>, Status> {
        let req = request.into_inner();
        let manager = self.manager.read().await;

        let filter_implant = req.implant_id.as_ref().and_then(|id| {
            Self::parse_implant_id(&id.value).ok()
        });

        let limit = if req.limit == 0 { 100 } else { req.limit as usize };

        let mut executions: Vec<BofExecution> = manager
            .executions
            .iter()
            .filter(|entry| {
                let exec = entry.value();

                if let Some(implant_id) = filter_implant {
                    if exec.implant_id != implant_id {
                        return false;
                    }
                }

                if let Some(ref filter_bof_id) = req.bof_id {
                    if !filter_bof_id.is_empty() && exec.bof_id != *filter_bof_id {
                        return false;
                    }
                }

                true
            })
            .map(|entry| {
                let e = entry.value();
                BofExecution {
                    id: Some(protocol::Uuid {
                        value: e.id.as_bytes().to_vec(),
                    }),
                    implant_id: Some(protocol::Uuid {
                        value: e.implant_id.as_bytes().to_vec(),
                    }),
                    bof_id: e.bof_id.clone(),
                    arguments: e.arguments.clone(),
                    executed_at: Some(Timestamp::from_millis(e.executed_at)),
                    output: e.output.clone(),
                    exit_code: e.exit_code,
                    error: e.error.clone(),
                    completed: e.completed,
                }
            })
            .collect();

        // Sort by executed_at descending
        executions.sort_by(|a, b| {
            let a_time = a.executed_at.as_ref().map(|t| t.millis).unwrap_or(0);
            let b_time = b.executed_at.as_ref().map(|t| t.millis).unwrap_or(0);
            b_time.cmp(&a_time)
        });

        executions.truncate(limit);

        Ok(Response::new(ListBofExecutionsResponse { executions }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arg(name: &str, arg_type: BofArgType, required: bool, default: Option<&str>) -> BofArgument {
        BofArgument {
            name: name.to_string(),
            arg_type: arg_type as i32,
            description: String::new(),
            required,
            default_value: default.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_pack_bof_string_argument() {
        let defs = vec![make_arg("path", BofArgType::BofArgString, true, None)];
        let values = vec!["C:\\Windows".to_string()];

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();

        // Expected: 4-byte length (11 = 10 chars + null) + "C:\Windows" + null
        assert_eq!(&packed[0..4], &11u32.to_le_bytes());
        assert_eq!(&packed[4..14], b"C:\\Windows");
        assert_eq!(packed[14], 0);
        assert_eq!(packed.len(), 15);
    }

    #[test]
    fn test_pack_bof_wstring_argument() {
        let defs = vec![make_arg("name", BofArgType::BofArgWstring, true, None)];
        let values = vec!["test".to_string()];

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();

        // Expected: 4-byte length (10 = 5 chars * 2 bytes) + UTF-16LE "test" + null (2 bytes)
        assert_eq!(&packed[0..4], &10u32.to_le_bytes());
        // 't' = 0x74, 'e' = 0x65, 's' = 0x73, 't' = 0x74 in UTF-16LE
        assert_eq!(&packed[4..6], &[0x74, 0x00]); // 't'
        assert_eq!(&packed[6..8], &[0x65, 0x00]); // 'e'
        assert_eq!(&packed[8..10], &[0x73, 0x00]); // 's'
        assert_eq!(&packed[10..12], &[0x74, 0x00]); // 't'
        assert_eq!(&packed[12..14], &[0x00, 0x00]); // null terminator
        assert_eq!(packed.len(), 14);
    }

    #[test]
    fn test_pack_bof_int_argument() {
        let defs = vec![make_arg("pid", BofArgType::BofArgInt, true, None)];
        let values = vec!["1234".to_string()];

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();

        assert_eq!(packed, 1234i32.to_le_bytes());
    }

    #[test]
    fn test_pack_bof_short_argument() {
        let defs = vec![make_arg("port", BofArgType::BofArgShort, true, None)];
        let values = vec!["443".to_string()];

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();

        assert_eq!(packed, 443i16.to_le_bytes());
    }

    #[test]
    fn test_pack_bof_binary_argument() {
        let defs = vec![make_arg("data", BofArgType::BofArgBinary, true, None)];
        let values = vec!["deadbeef".to_string()];

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();

        // Expected: 4-byte length (4) + 0xdeadbeef bytes
        assert_eq!(&packed[0..4], &4u32.to_le_bytes());
        assert_eq!(&packed[4..8], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_pack_bof_multiple_arguments() {
        let defs = vec![
            make_arg("pid", BofArgType::BofArgInt, true, None),
            make_arg("path", BofArgType::BofArgString, true, None),
        ];
        let values = vec!["1234".to_string(), "test".to_string()];

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();

        // First: int 1234
        assert_eq!(&packed[0..4], &1234i32.to_le_bytes());
        // Second: string "test" with length prefix
        assert_eq!(&packed[4..8], &5u32.to_le_bytes()); // length including null
        assert_eq!(&packed[8..12], b"test");
        assert_eq!(packed[12], 0);
    }

    #[test]
    fn test_pack_bof_default_value() {
        let defs = vec![make_arg("pid", BofArgType::BofArgInt, false, Some("0"))];
        let values: Vec<String> = vec![]; // No values provided

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();

        assert_eq!(packed, 0i32.to_le_bytes());
    }

    #[test]
    fn test_pack_bof_missing_required_argument() {
        let defs = vec![make_arg("pid", BofArgType::BofArgInt, true, None)];
        let values: Vec<String> = vec![];

        let result = BOFServiceImpl::pack_bof_arguments(&defs, &values);
        assert!(result.is_err());
    }

    #[test]
    fn test_pack_bof_invalid_int() {
        let defs = vec![make_arg("pid", BofArgType::BofArgInt, true, None)];
        let values = vec!["not_a_number".to_string()];

        let result = BOFServiceImpl::pack_bof_arguments(&defs, &values);
        assert!(result.is_err());
    }

    #[test]
    fn test_pack_bof_invalid_hex() {
        let defs = vec![make_arg("data", BofArgType::BofArgBinary, true, None)];
        let values = vec!["not_hex".to_string()];

        let result = BOFServiceImpl::pack_bof_arguments(&defs, &values);
        assert!(result.is_err());
    }

    #[test]
    fn test_pack_bof_empty_arguments() {
        let defs: Vec<BofArgument> = vec![];
        let values: Vec<String> = vec![];

        let packed = BOFServiceImpl::pack_bof_arguments(&defs, &values).unwrap();
        assert!(packed.is_empty());
    }
}
