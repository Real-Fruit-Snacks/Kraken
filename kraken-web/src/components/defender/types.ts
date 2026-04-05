// Defender Dashboard types - IOCs, YARA, Sigma, OPSEC checks

// =============================================================================
// IOC Types
// =============================================================================

export type IocRisk = 'high' | 'medium' | 'low';
export type IocCategory = 'network' | 'host' | 'memory' | 'behavioral';

export interface NetworkIoc {
  type: 'url' | 'ip' | 'domain' | 'port' | 'header' | 'uri' | 'user-agent' | 'certificate';
  value: string;
  risk: IocRisk;
  description: string;
  profile?: string; // C2 profile name
}

export interface HostIoc {
  type: 'process' | 'file' | 'registry' | 'string' | 'hash' | 'import' | 'env-var';
  value: string;
  risk: IocRisk;
  description: string;
  confidence: 'high' | 'medium';
}

export interface MemoryIoc {
  type: 'pattern' | 'region' | 'signature';
  value: string;
  risk: IocRisk;
  description: string;
}

export interface BehavioralIoc {
  type: 'timing' | 'network-pattern' | 'process-behavior';
  value: string;
  risk: IocRisk;
  description: string;
}

export type Ioc = NetworkIoc | HostIoc | MemoryIoc | BehavioralIoc;

// =============================================================================
// Detection Rule Types
// =============================================================================

export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface YaraRule {
  name: string;
  description: string;
  author: string;
  date: string;
  severity: RuleSeverity;
  category: string;
  mitreTechniques: string[];
  references: string[];
  content: string; // Full rule text
}

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  author: string;
  date: string;
  status: 'experimental' | 'stable' | 'deprecated';
  level: RuleSeverity;
  tags: string[];
  logsource: {
    category: string;
    product: string;
  };
  content: string; // Full rule YAML
}

// =============================================================================
// OPSEC Check Types (for Phase 3 OPSEC Gates)
// =============================================================================

export type OpsecSeverity = 'info' | 'advisory' | 'blocking';

export interface OpsecCheck {
  id: string;
  command: string;
  severity: OpsecSeverity;
  title: string;
  description: string;
  mitreTechnique?: string;
  detectionRisk: string;
  bypassRole?: 'operator' | 'lead' | 'other_operator';
}

export interface OpsecResult {
  check: OpsecCheck;
  blocked: boolean;
  message: string;
  timestamp: Date;
  operatorId?: string;
  approved?: boolean;
  approvedBy?: string;
}

// =============================================================================
// Defender Telemetry (per-implant view like TUI)
// =============================================================================

export interface NetworkConnection {
  remoteIp: string;
  remotePort: number;
  protocol: string;
  state: 'established' | 'listening' | 'closed';
}

export interface MemoryRegion {
  base: string; // hex address
  size: number;
  protection: string;
  module?: string;
}

export interface DefenderTelemetry {
  implantId: string;
  processName: string;
  parentProcess: string;
  commandLine: string;
  integrityLevel: string;
  connections: NetworkConnection[];
  rwxRegions: MemoryRegion[];
  unbackedExecutable: MemoryRegion[];
  etwPatched: boolean;
  amsiPatched: boolean;
  sleepMaskActive: boolean;
}

// =============================================================================
// Color Constants (Catppuccin Mocha)
// =============================================================================

export const RISK_COLORS: Record<IocRisk, { bg: string; text: string; border: string }> = {
  high: { bg: '#f38ba8', text: '#1e1e2e', border: '#f38ba8' },    // Red
  medium: { bg: '#fab387', text: '#1e1e2e', border: '#fab387' },  // Peach/Orange
  low: { bg: '#a6e3a1', text: '#1e1e2e', border: '#a6e3a1' },     // Green
};

export const SEVERITY_COLORS: Record<RuleSeverity, { bg: string; text: string; border: string }> = {
  critical: { bg: '#f38ba8', text: '#1e1e2e', border: '#f38ba8' },      // Red
  high: { bg: '#fab387', text: '#1e1e2e', border: '#fab387' },          // Peach
  medium: { bg: '#f9e2af', text: '#1e1e2e', border: '#f9e2af' },        // Yellow
  low: { bg: '#89b4fa', text: '#1e1e2e', border: '#89b4fa' },           // Blue
  informational: { bg: '#6c7086', text: '#cdd6f4', border: '#6c7086' }, // Overlay0
};

export const OPSEC_COLORS: Record<OpsecSeverity, { bg: string; text: string; border: string; icon: string }> = {
  info: {
    bg: 'rgba(137, 180, 250, 0.1)',   // Blue transparent
    text: '#89b4fa',
    border: '#89b4fa',
    icon: 'info-circle',
  },
  advisory: {
    bg: 'rgba(249, 226, 175, 0.1)',   // Yellow transparent
    text: '#f9e2af',
    border: '#f9e2af',
    icon: 'alert-triangle',
  },
  blocking: {
    bg: 'rgba(243, 139, 168, 0.1)',   // Red transparent
    text: '#f38ba8',
    border: '#f38ba8',
    icon: 'x-octagon',
  },
};

// =============================================================================
// IOC Type Icons
// =============================================================================

export const IOC_TYPE_ICONS: Record<string, string> = {
  // Network
  url: 'link',
  ip: 'server',
  domain: 'globe',
  port: 'hash',
  header: 'file-text',
  uri: 'corner-down-right',
  'user-agent': 'user',
  certificate: 'shield',
  // Host
  process: 'cpu',
  file: 'file',
  registry: 'database',
  string: 'type',
  hash: 'key',
  import: 'download',
  'env-var': 'terminal',
  // Memory
  pattern: 'search',
  region: 'box',
  signature: 'fingerprint',
  // Behavioral
  timing: 'clock',
  'network-pattern': 'activity',
  'process-behavior': 'git-branch',
};
