// Static defender data - IOCs, YARA rules, Sigma rules
// Based on wiki/detection/iocs.md and wiki/detection/yara/*.yar, sigma/*.yml

import type {
  NetworkIoc,
  HostIoc,
  MemoryIoc,
  BehavioralIoc,
  YaraRule,
  SigmaRule,
} from './types';

// =============================================================================
// Network IOCs
// =============================================================================

export const NETWORK_IOCS: NetworkIoc[] = [
  // Endpoints
  {
    type: 'uri',
    value: '/c',
    risk: 'high',
    description: 'Primary check-in endpoint (registration + beacon)',
    profile: 'Default HTTP',
  },
  {
    type: 'uri',
    value: '/api/v1/status',
    risk: 'medium',
    description: 'Legacy/alternate check-in URI',
    profile: 'Alternate',
  },
  {
    type: 'uri',
    value: '/api/v1/submit',
    risk: 'medium',
    description: 'Legacy/alternate task submission',
    profile: 'Alternate',
  },
  // Headers
  {
    type: 'user-agent',
    value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    risk: 'medium',
    description: 'Default User-Agent (truncated, missing Chrome version suffix)',
    profile: 'Default HTTP',
  },
  {
    type: 'header',
    value: 'Accept: application/json',
    risk: 'low',
    description: 'Accept header set despite binary payload',
  },
  {
    type: 'header',
    value: 'Content-Type: application/octet-stream',
    risk: 'medium',
    description: 'Binary content type for check-in requests',
  },
  // Absence indicators
  {
    type: 'header',
    value: 'Missing: Cookie, Referer, Origin, Sec-Fetch-*',
    risk: 'high',
    description: 'Absence of standard browser headers differentiates from real browsers',
  },
  // Ports
  {
    type: 'port',
    value: '8080',
    risk: 'low',
    description: 'Default HTTP listener port',
    profile: 'Default HTTP',
  },
  {
    type: 'port',
    value: '443',
    risk: 'low',
    description: 'Production HTTPS listener',
    profile: 'HTTPS',
  },
  {
    type: 'port',
    value: '50051',
    risk: 'medium',
    description: 'Operator-to-server gRPC communication',
  },
];

// =============================================================================
// Host IOCs
// =============================================================================

export const HOST_IOCS: HostIoc[] = [
  // High confidence strings
  {
    type: 'string',
    value: 'AllTransportsFailed',
    risk: 'high',
    description: 'Unique error string in implant',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'kraken-session-v1',
    risk: 'high',
    description: 'HKDF salt for session key derivation',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'implant_core',
    risk: 'high',
    description: 'Module identifier',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'TransportChain',
    risk: 'high',
    description: 'Transport fallback mechanism identifier',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'ImplantCrypto',
    risk: 'high',
    description: 'Crypto module identifier',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'session key not established',
    risk: 'high',
    description: 'Error message during crypto handshake',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'mod_shell',
    risk: 'high',
    description: 'Shell module identifier',
    confidence: 'high',
  },
  // Medium confidence
  {
    type: 'string',
    value: 'MessageEnvelope',
    risk: 'medium',
    description: 'Protobuf message type (may appear in other Rust code)',
    confidence: 'medium',
  },
  {
    type: 'string',
    value: 'CheckInResponse',
    risk: 'medium',
    description: 'Protobuf message type',
    confidence: 'medium',
  },
  // Windows imports
  {
    type: 'import',
    value: 'WinHttpOpen, WinHttpConnect, WinHttpOpenRequest',
    risk: 'medium',
    description: 'WinHTTP API imports (Windows implant uses native WinHTTP)',
    confidence: 'medium',
  },
  // Environment variables
  {
    type: 'env-var',
    value: 'KRAKEN_SERVER',
    risk: 'high',
    description: 'C2 server URL environment variable',
    confidence: 'high',
  },
  {
    type: 'env-var',
    value: 'KRAKEN_SERVER_PUBKEY',
    risk: 'high',
    description: 'Server public key in hex (64 characters)',
    confidence: 'high',
  },
  // OPSEC indicators
  {
    type: 'string',
    value: 'SecureHeap',
    risk: 'high',
    description: 'Heap encryption module (Phase 4 OPSEC)',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'EtwEventWrite',
    risk: 'high',
    description: 'ETW patching target function',
    confidence: 'high',
  },
  {
    type: 'string',
    value: 'AmsiScanBuffer',
    risk: 'high',
    description: 'AMSI bypass target function',
    confidence: 'high',
  },
];

// =============================================================================
// Memory IOCs
// =============================================================================

export const MEMORY_IOCS: MemoryIoc[] = [
  {
    type: 'pattern',
    value: '32-byte aligned buffers',
    risk: 'medium',
    description: 'Session keys, nonces stored in aligned memory',
  },
  {
    type: 'pattern',
    value: 'Incrementing 8-byte counter (little-endian)',
    risk: 'medium',
    description: 'Nonce counter for AES-GCM',
  },
  {
    type: 'pattern',
    value: '16-byte UUID patterns',
    risk: 'low',
    description: 'Implant ID, Task IDs in memory',
  },
  {
    type: 'signature',
    value: '33 C0 C3',
    risk: 'high',
    description: 'ETW patch bytes: xor eax, eax; ret',
  },
  {
    type: 'signature',
    value: 'B8 57 00 07 80 C3',
    risk: 'high',
    description: 'AMSI patch bytes: mov eax, E_INVALIDARG; ret',
  },
  {
    type: 'signature',
    value: '4C 8B D1 B8 ?? ?? 00 00',
    risk: 'high',
    description: 'Indirect syscall setup: mov r10, rcx; mov eax, <num>',
  },
];

// =============================================================================
// Behavioral IOCs
// =============================================================================

export const BEHAVIORAL_IOCS: BehavioralIoc[] = [
  {
    type: 'timing',
    value: '10s base interval (test), 60s (prod), 20% jitter',
    risk: 'medium',
    description: 'Beacon timing pattern with consistent jitter',
  },
  {
    type: 'network-pattern',
    value: 'Periodic HTTP POST to single endpoint (/c)',
    risk: 'high',
    description: 'All traffic to one URI regardless of operation',
  },
  {
    type: 'network-pattern',
    value: '~123 bytes registration, ~77 bytes check-in',
    risk: 'medium',
    description: 'Consistent request sizes for message types',
  },
  {
    type: 'process-behavior',
    value: 'Beaconing continues regardless of user activity',
    risk: 'medium',
    description: 'No user interaction correlation',
  },
  {
    type: 'process-behavior',
    value: 'Binary POST body despite Accept: application/json',
    risk: 'high',
    description: 'Header/content type mismatch',
  },
];

// =============================================================================
// YARA Rules (summaries - full content loaded on demand)
// =============================================================================

export const YARA_RULES: YaraRule[] = [
  // kraken_opsec.yar rules
  {
    name: 'Kraken_Sleep_Mask_Timer_Queue',
    description: 'Detects CreateTimerQueue + VirtualProtect pattern typical of EKKO-style sleep masking',
    author: 'Kraken Research Team',
    date: '2026-03-28',
    severity: 'high',
    category: 'evasion',
    mitreTechniques: ['T1562.008'],
    references: ['EKKO sleep masking technique'],
    content: `rule Kraken_Sleep_Mask_Timer_Queue
{
    meta:
        description = "Detects CreateTimerQueue + VirtualProtect pattern"
        severity = "high"
        mitre_attack = "T1562.008"

    strings:
        $api_create_timer = "CreateTimerQueue" nocase
        $api_virtual_protect = "VirtualProtect" nocase
        $xor_pattern = { 8B [1-2] 33 [1-2] FF C? 3B [1-2] 7? F? }

    condition:
        filesize < 10MB and all of ($api_*)
}`,
  },
  {
    name: 'Kraken_ETW_Patch',
    description: 'Detects ETW patching (xor eax, eax; ret) at ntdll!EtwEventWrite',
    author: 'Kraken Research Team',
    date: '2026-03-28',
    severity: 'critical',
    category: 'evasion',
    mitreTechniques: ['T1562.001', 'T1112'],
    references: ['ETW patching disables Windows logging'],
    content: `rule Kraken_ETW_Patch
{
    meta:
        description = "Detects ETW patching"
        severity = "critical"
        mitre_attack = "T1562.001,T1112"

    strings:
        $etw_patch = { 33 C0 C3 }  // xor eax, eax; ret
        $etw_write = "EtwEventWrite" nocase

    condition:
        filesize < 10MB and $etw_patch and $etw_write
}`,
  },
  {
    name: 'Kraken_AMSI_Bypass',
    description: 'Detects AMSI bypass pattern (mov eax, E_INVALIDARG; ret)',
    author: 'Kraken Research Team',
    date: '2026-03-28',
    severity: 'critical',
    category: 'evasion',
    mitreTechniques: ['T1562.001'],
    references: ['AMSI patching disables content scanning'],
    content: `rule Kraken_AMSI_Bypass
{
    meta:
        description = "Detects AMSI bypass pattern"
        severity = "critical"
        mitre_attack = "T1562.001"

    strings:
        $amsi_patch = { B8 57 00 07 80 C3 }  // mov eax, 0x80070057; ret
        $amsi_scan = "AmsiScanBuffer" nocase

    condition:
        filesize < 10MB and $amsi_patch and $amsi_scan
}`,
  },
  {
    name: 'Kraken_Indirect_Syscall_Stub',
    description: 'Detects indirect syscall stub patterns used to bypass API hooks',
    author: 'Kraken Research Team',
    date: '2026-03-28',
    severity: 'high',
    category: 'evasion',
    mitreTechniques: ['T1562.001'],
    references: ['Indirect syscalls - hook bypass'],
    content: `rule Kraken_Indirect_Syscall_Stub
{
    meta:
        description = "Detects indirect syscall patterns"
        severity = "high"
        mitre_attack = "T1562.001"

    strings:
        $syscall_setup = { 4C 8B D1 B8 ?? ?? 00 00 }  // mov r10, rcx; mov eax
        $syscall_ret = { 0F 05 C3 }  // syscall; ret

    condition:
        filesize < 10MB and $syscall_setup and $syscall_ret
}`,
  },
  {
    name: 'Kraken_Anti_VM_CPUID',
    description: 'Detects CPUID-based hypervisor detection',
    author: 'Kraken Research Team',
    date: '2026-03-28',
    severity: 'medium',
    category: 'evasion',
    mitreTechniques: ['T1497.001'],
    references: ['CPUID leaf 0x40000000 for hypervisor'],
    content: `rule Kraken_Anti_VM_CPUID
{
    meta:
        description = "Detects hypervisor detection via CPUID"
        severity = "medium"
        mitre_attack = "T1497.001"

    strings:
        $cpuid = { 0F A2 }  // cpuid
        $hyper_leaf = { B8 00 00 00 40 }  // mov eax, 0x40000000
        $vmware = "VMware" nocase
        $vbox = "VirtualBox" nocase

    condition:
        filesize < 10MB and $cpuid and ($hyper_leaf or $vmware or $vbox)
}`,
  },
  {
    name: 'Kraken_Implant_Strings',
    description: 'Detects unique Kraken implant error/log strings',
    author: 'Kraken Research Team',
    date: '2026-03-28',
    severity: 'high',
    category: 'implant',
    mitreTechniques: ['T1071.001'],
    references: ['wiki/detection/iocs.md'],
    content: `rule Kraken_Implant_Strings
{
    meta:
        description = "Detects Kraken implant strings"
        severity = "high"

    strings:
        $s1 = "AllTransportsFailed" ascii wide
        $s2 = "kraken-session-v1" ascii wide
        $s3 = "implant_core" ascii wide
        $s4 = "TransportChain" ascii wide

    condition:
        filesize < 10MB and 2 of them
}`,
  },
  {
    name: 'Kraken_OPSEC_Combined',
    description: 'Detects multiple OPSEC evasion techniques used together',
    author: 'Kraken Research Team',
    date: '2026-03-28',
    severity: 'critical',
    category: 'evasion',
    mitreTechniques: ['T1562.001', 'T1562.008', 'T1622', 'T1497.001'],
    references: ['Multiple Phase 4 OPSEC techniques indicate Kraken'],
    content: `rule Kraken_OPSEC_Combined
{
    meta:
        description = "Multiple OPSEC techniques (high confidence)"
        severity = "critical"

    strings:
        $syscall = { 4C 8B D1 B8 ?? ?? 00 00 }
        $etw_patch = { 33 C0 C3 }
        $peb_check = { 65 48 8B ?? 60 00 00 00 }
        $cpuid = { 0F A2 }
        $timer = "CreateTimerQueueTimer" nocase

    condition:
        filesize < 10MB and 3 of them
}`,
  },
];

// =============================================================================
// Sigma Rules (summaries)
// =============================================================================

export const SIGMA_RULES: SigmaRule[] = [
  {
    id: 'kraken-opsec-001',
    title: 'Kraken OPSEC - Memory Protection Manipulation',
    description: 'Detects memory protection state changes consistent with EKKO-style sleep masking',
    author: 'Kraken Security Research Team',
    date: '2026-03-28',
    status: 'experimental',
    level: 'high',
    tags: ['attack.defense_evasion', 'attack.t1562.008'],
    logsource: { category: 'process_access', product: 'windows' },
    content: `title: Kraken OPSEC - Memory Protection Manipulation
id: kraken-opsec-001
status: experimental
level: high
logsource:
  category: process_access
  product: windows
detection:
  selection:
    CallTrace|contains: 'VirtualProtect'
    ProtectionChange|contains:
      - '0x20'  # PAGE_EXECUTE_READ
      - '0x04'  # PAGE_READWRITE
  condition: selection`,
  },
  {
    id: 'kraken-opsec-002',
    title: 'Kraken OPSEC - ETW Tampering Detection',
    description: 'Detects attempts to patch or disable Event Tracing for Windows',
    author: 'Kraken Security Research Team',
    date: '2026-03-28',
    status: 'experimental',
    level: 'critical',
    tags: ['attack.defense_evasion', 'attack.t1562.001', 'attack.t1112'],
    logsource: { category: 'process_access', product: 'windows' },
    content: `title: Kraken OPSEC - ETW Tampering Detection
id: kraken-opsec-002
status: experimental
level: critical
logsource:
  category: process_access
  product: windows
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\\ntdll.dll'
    CallTrace|contains|all:
      - 'WriteProcessMemory'
      - 'EtwEventWrite'
  condition: selection`,
  },
  {
    id: 'kraken-opsec-003',
    title: 'Kraken OPSEC - AMSI Bypass Attempt',
    description: 'Detects AMSI function tampering or disabling',
    author: 'Kraken Security Research Team',
    date: '2026-03-28',
    status: 'experimental',
    level: 'critical',
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
    logsource: { category: 'process_access', product: 'windows' },
    content: `title: Kraken OPSEC - AMSI Bypass Attempt
id: kraken-opsec-003
status: experimental
level: critical
logsource:
  category: process_access
  product: windows
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\\amsi.dll'
    CallTrace|contains|all:
      - 'WriteProcessMemory'
      - 'AmsiScanBuffer'
  condition: selection`,
  },
  {
    id: 'kraken-opsec-004',
    title: 'Kraken OPSEC - Anti-Debug PEB Check',
    description: 'Detects anti-debug techniques including BeingDebugged flag checks',
    author: 'Kraken Security Research Team',
    date: '2026-03-28',
    status: 'experimental',
    level: 'medium',
    tags: ['attack.defense_evasion', 'attack.t1622'],
    logsource: { category: 'process_access', product: 'windows' },
    content: `title: Kraken OPSEC - Anti-Debug PEB Check
id: kraken-opsec-004
status: experimental
level: medium
logsource:
  category: process_access
  product: windows
detection:
  selection:
    CallTrace|contains:
      - 'NtQueryInformationProcess'
      - 'ProcessDebugPort'
  condition: selection`,
  },
  {
    id: 'kraken-opsec-005',
    title: 'Kraken OPSEC - Hypervisor Detection',
    description: 'Detects hypervisor detection techniques (anti-VM checks)',
    author: 'Kraken Security Research Team',
    date: '2026-03-28',
    status: 'experimental',
    level: 'medium',
    tags: ['attack.defense_evasion', 'attack.t1497.001'],
    logsource: { category: 'process_access', product: 'windows' },
    content: `title: Kraken OPSEC - Hypervisor Detection
id: kraken-opsec-005
status: experimental
level: medium
logsource:
  category: process_access
  product: windows
detection:
  selection:
    CallTrace|contains: 'cpuid'
  condition: selection`,
  },
  {
    id: 'kraken-beacon-001',
    title: 'Kraken C2 HTTP Beacon Activity',
    description: 'Detects Kraken beacon traffic patterns in proxy logs',
    author: 'Kraken Security Research Team',
    date: '2026-03-28',
    status: 'experimental',
    level: 'high',
    tags: ['attack.command_and_control', 'attack.t1071.001'],
    logsource: { category: 'proxy', product: 'any' },
    content: `title: Kraken C2 HTTP Beacon Activity
id: kraken-beacon-001
status: experimental
level: high
logsource:
  category: proxy
  product: any
detection:
  selection:
    cs-method: 'POST'
    cs-uri: '/c'
    cs-content-type: 'application/octet-stream'
  filter:
    sc-status:
      - 404
      - 500
  condition: selection and not filter`,
  },
  {
    id: 'kraken-opsec-007',
    title: 'Kraken OPSEC - Multiple Evasion Indicators',
    description: 'Detects use of multiple Phase 4 OPSEC techniques in combination',
    author: 'Kraken Security Research Team',
    date: '2026-03-28',
    status: 'experimental',
    level: 'critical',
    tags: ['attack.defense_evasion', 'attack.t1562.001', 'attack.t1562.008', 'attack.t1622'],
    logsource: { category: 'process_access', product: 'windows' },
    content: `title: Kraken OPSEC - Multiple Evasion Indicators
id: kraken-opsec-007
status: experimental
level: critical
logsource:
  category: process_access
  product: windows
detection:
  etw: CallTrace|contains: 'EtwEventWrite'
  amsi: CallTrace|contains: 'AmsiScanBuffer'
  debug: CallTrace|contains: 'ProcessDebugPort'
  timer: CallTrace|contains: 'CreateTimerQueueTimer'
  condition: 2 of them`,
  },
];

// =============================================================================
// Summary Statistics
// =============================================================================

export function getDefenderStats() {
  return {
    networkIocs: NETWORK_IOCS.length,
    hostIocs: HOST_IOCS.length,
    memoryIocs: MEMORY_IOCS.length,
    behavioralIocs: BEHAVIORAL_IOCS.length,
    yaraRules: YARA_RULES.length,
    sigmaRules: SIGMA_RULES.length,
    criticalRules: [...YARA_RULES, ...SIGMA_RULES].filter(
      r => ('severity' in r ? r.severity : r.level) === 'critical'
    ).length,
    highRiskIocs: [...NETWORK_IOCS, ...HOST_IOCS, ...MEMORY_IOCS, ...BEHAVIORAL_IOCS].filter(
      ioc => ioc.risk === 'high'
    ).length,
  };
}
