//! Task result types

use serde::{Deserialize, Serialize};

/// Structured task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskResult {
    Success,
    Error(TaskError),
    Shell(ShellOutput),
    DirectoryListing(DirectoryListing),
    FileContents(FileContents),
    FileOperation(FileOperationResult),
    FileDownloadChunk(FileDownloadChunk),
    ProcessList(ProcessList),
    ProcessTree(ProcessTree),
    ProcessModules(ProcessModules),
    ModuleOperation(ModuleOperationResult),
    BofOutput(BofOutput),
    Screenshot(ScreenshotOutput),
    Clipboard(ClipboardOutput),
    RegistryQuery(RegistryQueryOutput),
    RegistryOperation(RegistryOperationResult),
    RegistryEnumKeys(Vec<String>),
    RegistryEnumValues(Vec<RegistryValueOutput>),
    PersistenceList(PersistenceListOutput),
    PersistenceOperation(PersistenceOpResult),
    ServiceList(ServiceListOutput),
    ServiceInfo(ServiceInfoOutput),
    ServiceOperation(ServiceOpResult),
    Keylog(KeylogOutput),
    EnvSystem(SystemInfoOutput),
    EnvNetwork(NetworkInfoOutput),
    EnvVars(EnvVarsOutput),
    EnvWhoAmI(WhoAmIOutput),
    ScanPort(PortScanOutput),
    ScanPing(PingSweepOutput),
    ScanShare(ShareEnumOutput),
    Lateral(LateralResult),
    AdUsers(AdUsersOutput),
    AdGroups(AdGroupsOutput),
    AdComputers(AdComputersOutput),
    AdKerberoast(AdKerberoastOutput),
    AdAsreproast(AdAsreproastOutput),
    AdQuery(AdQueryOutput),
    Credential(CredentialOutput),
    // Runtime module results
    Inject(InjectOutput),
    Token(TokenOutput),
    Mesh(MeshOutput),
    Socks(SocksOutput),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskError {
    pub code: i32,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryListing {
    pub path: String,
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<i64>,
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContents {
    pub path: String,
    pub data: Vec<u8>,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperationResult {
    pub operation: String,
    pub path: String,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDownloadChunk {
    pub transfer_id: String,
    pub total_size: u64,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub chunk_data: Vec<u8>,
    pub checksum: Vec<u8>,
    pub is_final: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessList {
    pub processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub user: Option<String>,
    pub arch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTree {
    pub nodes: Vec<ProcessTreeNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub children: Vec<ProcessTreeNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessModules {
    pub pid: u32,
    pub modules: Vec<ProcessModuleInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOperationResult {
    pub operation: String,
    pub module_id: String,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BofOutput {
    pub output: String,
    pub exit_code: i32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotOutput {
    /// Encoded image data (BMP or raw BGRA pixels)
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// "bmp" or "raw_bgra"
    pub format: String,
    pub monitor_index: u32,
    /// Unix timestamp in seconds
    pub captured_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardOutput {
    pub entries: Vec<ClipboardEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    pub text: String,
    /// e.g. "CF_UNICODETEXT"
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryQueryOutput {
    pub key_path: String,
    pub value_name: String,
    pub data: Vec<u8>,
    /// e.g. "REG_SZ", "REG_DWORD", "REG_BINARY"
    pub value_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperationResult {
    pub operation: String,
    pub key_path: String,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValueOutput {
    pub key_path: String,
    pub value_name: String,
    pub data: Vec<u8>,
    /// e.g. "REG_SZ", "REG_DWORD", "REG_BINARY"
    pub value_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceOpResult {
    /// "install" or "remove"
    pub operation: String,
    /// e.g. "registry_run", "startup_folder", "scheduled_task"
    pub method: String,
    /// Value/file name used to identify the entry
    pub name: String,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntryInfo {
    pub method: String,
    pub name: String,
    pub location: String,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceListOutput {
    pub entries: Vec<PersistenceEntryInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceListOutput {
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfoOutput {
    pub name: String,
    pub display_name: String,
    pub binary_path: String,
    pub status: String,
    pub start_type: String,
    pub account: String,
    pub pid: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOpResult {
    pub operation: String,
    pub service_name: String,
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeylogOutput {
    pub entries: Vec<KeylogEntry>,
    pub start_time: u64,
    pub end_time: u64,
    pub total_keystrokes: u32,
    /// Informational note, e.g. about stateless mode limitations.
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeylogEntry {
    pub window_title: String,
    pub process_name: String,
    pub keystrokes: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfoOutput {
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub computer_name: String,
    pub domain: String,
    pub uptime_seconds: u64,
    pub total_memory: u64,
    pub cpu_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfoOutput {
    pub interfaces: Vec<NetworkInterfaceInfo>,
    pub dns_servers: Vec<String>,
    pub default_gateway: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac_address: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub is_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarsOutput {
    pub variables: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoAmIOutput {
    pub username: String,
    pub domain: String,
    pub sid: String,
    pub groups: Vec<String>,
    pub integrity_level: String,
    pub is_elevated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanOutput {
    pub target: String,
    pub open_ports: Vec<OpenPortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPortInfo {
    pub port: u32,
    pub service: String,
    pub banner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingSweepOutput {
    pub live_hosts: Vec<String>,
    pub total_scanned: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareEnumOutput {
    pub target: String,
    pub shares: Vec<ShareInfoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfoEntry {
    pub name: String,
    pub share_type: String,
    pub path: String,
    pub remark: String,
}

// --- Lateral Movement Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralResult {
    pub success: bool,
    pub target: String,
    pub method: String,
    pub output: String,
    pub error: String,
}

// --- Active Directory Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUsersOutput {
    pub users: Vec<AdUserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUserInfo {
    pub dn: String,
    pub sam_account_name: String,
    pub display_name: String,
    pub enabled: bool,
    pub groups: Vec<String>,
    pub spn: Option<String>,
    pub last_logon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroupsOutput {
    pub groups: Vec<AdGroupInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroupInfo {
    pub dn: String,
    pub name: String,
    pub description: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputersOutput {
    pub computers: Vec<AdComputerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputerInfo {
    pub dn: String,
    pub name: String,
    pub os: String,
    pub os_version: String,
    pub is_dc: bool,
    pub last_logon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdKerberoastOutput {
    pub hashes: Vec<KerberoastHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastHash {
    pub username: String,
    pub spn: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdAsreproastOutput {
    pub hashes: Vec<String>,
    pub accounts_found: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdQueryOutput {
    pub entries: Vec<AdLdapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdLdapEntry {
    pub dn: String,
    pub attributes: std::collections::HashMap<String, Vec<String>>,
}

// --- Credential Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOutput {
    pub credentials: Vec<CredentialInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub credential_type: String,
    pub domain: String,
    pub username: String,
    pub data: String,
    pub source: String,
}

// --- Process Injection Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectOutput {
    pub success: bool,
    pub thread_id: u32,
    pub technique_used: String,
    pub error: Option<String>,
}

// --- Token Manipulation Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenOutput {
    pub success: bool,
    pub token_id: Option<u32>,
    pub username: Option<String>,
    pub tokens: Vec<StoredTokenInfo>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTokenInfo {
    pub id: u32,
    pub username: String,
    pub source: String,
    pub source_pid: u32,
}

// --- Mesh Networking Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshOutput {
    pub success: bool,
    pub peer_id: Option<Vec<u8>>,
    pub topology: Option<MeshTopology>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshTopology {
    pub peers: Vec<MeshPeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeerInfo {
    pub peer_id: Vec<u8>,
    pub address: String,
    pub transport: String,
    pub state: String,
    pub latency_ms: u32,
}

// --- SOCKS Proxy Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksOutput {
    pub channel_id: u32,
    pub success: bool,
    pub data: Option<Vec<u8>>,
    pub error: Option<String>,
}
