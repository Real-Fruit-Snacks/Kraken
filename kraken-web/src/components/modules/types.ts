// Module Management Types - Based on Mythic/Sliver/Metasploit research

export type ModuleType = 'extension' | 'bof' | 'post' | 'payload' | 'c2-profile' | 'script';
export type ModuleStatus = 'available' | 'loaded' | 'loading' | 'unloading' | 'error' | 'update-available';
export type ReliabilityRank = 'excellent' | 'great' | 'good' | 'normal' | 'average' | 'low' | 'manual';

export interface ModuleCapability {
  id: string;
  name: string;
  supported: boolean;
}

export interface ModuleCommand {
  name: string;
  help: string;
  longHelp?: string;
  entrypoint: string;
  arguments?: Array<{
    name: string;
    description: string;
    type: string;
    optional: boolean;
  }>;
}

export interface ModuleManifest {
  id: string;
  name: string;
  version: string;
  author: string;
  originalAuthor?: string;
  description: string;
  longDescription?: string;
  type: ModuleType;
  category: string;
  tags: string[];
  platforms: Array<{
    os: 'windows' | 'linux' | 'macos';
    arch: 'x64' | 'x86' | 'arm64';
  }>;
  reliability: ReliabilityRank;
  capabilities: ModuleCapability[];
  commands: ModuleCommand[];
  dependencies: string[];
  conflicts: string[];
  repoUrl?: string;
  size: number;  // bytes
  checksum: string;
}

export interface LoadedModule {
  id: string;
  moduleId: string;
  manifest: ModuleManifest;
  status: ModuleStatus;
  loadedAt: Date;
  memorySize: number;
  errorMessage?: string;
}

export interface ModuleOperation {
  id: string;
  type: 'load' | 'unload' | 'update';
  moduleId: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  steps: OperationStep[];
  currentStep: number;
  startedAt: Date;
  completedAt?: Date;
  error?: string;
}

export interface OperationStep {
  name: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  output?: string;
  duration?: number;
}

// Catppuccin Mocha colors for module UI
export const MODULE_COLORS = {
  // Module type colors
  type: {
    extension: '#89b4fa',   // blue
    bof: '#cba6f7',         // mauve
    post: '#f9e2af',        // yellow
    payload: '#f38ba8',     // red
    'c2-profile': '#a6e3a1', // green
    script: '#94e2d5',      // teal
  },
  // Status colors
  status: {
    available: '#6c7086',      // overlay0
    loaded: '#a6e3a1',         // green
    loading: '#89b4fa',        // blue (animated)
    unloading: '#f9e2af',      // yellow (animated)
    error: '#f38ba8',          // red
    'update-available': '#fab387', // peach
  },
  // Reliability colors (Metasploit-style ranking)
  reliability: {
    excellent: '#a6e3a1',   // green
    great: '#94e2d5',       // teal
    good: '#89b4fa',        // blue
    normal: '#cdd6f4',      // text
    average: '#f9e2af',     // yellow
    low: '#fab387',         // peach
    manual: '#f38ba8',      // red
  },
  // Confirmation severity
  confirmation: {
    none: '#89b4fa',        // blue - simple confirm
    dependencies: '#f9e2af', // yellow - will auto-install deps
    conflicts: '#fab387',   // peach/orange - will unload conflicts
    opsec: '#f38ba8',       // red - OPSEC warning
  },
} as const;

// Module type display configuration
export const MODULE_TYPE_CONFIG: Record<ModuleType, {
  label: string;
  description: string;
  icon: string;
}> = {
  extension: {
    label: 'Extension',
    description: 'Adds new commands and capabilities',
    icon: 'puzzle-piece',
  },
  bof: {
    label: 'BOF',
    description: 'Beacon Object File for in-memory execution',
    icon: 'code-bracket',
  },
  post: {
    label: 'Post-Exploitation',
    description: 'Post-compromise modules',
    icon: 'command-line',
  },
  payload: {
    label: 'Payload',
    description: 'Implant payload type',
    icon: 'cube',
  },
  'c2-profile': {
    label: 'C2 Profile',
    description: 'Communication profile configuration',
    icon: 'signal',
  },
  script: {
    label: 'Script',
    description: 'Automation and helper scripts',
    icon: 'document-text',
  },
};

// Reliability rank configuration
export const RELIABILITY_CONFIG: Record<ReliabilityRank, {
  label: string;
  description: string;
  level: number;  // 1-7 for sorting
}> = {
  excellent: { label: 'Excellent', description: 'Highly reliable, well-tested', level: 7 },
  great: { label: 'Great', description: 'Very reliable', level: 6 },
  good: { label: 'Good', description: 'Reliable in most cases', level: 5 },
  normal: { label: 'Normal', description: 'Standard reliability', level: 4 },
  average: { label: 'Average', description: 'May have edge cases', level: 3 },
  low: { label: 'Low', description: 'Use with caution', level: 2 },
  manual: { label: 'Manual', description: 'Requires manual verification', level: 1 },
};

// Filter state for module search
export interface ModuleFilterState {
  search: string;
  status: ModuleStatus[];
  types: ModuleType[];
  platforms: string[];
  reliability: ReliabilityRank[];
  capabilities: string[];
  showOnlyCompatible: boolean;
}

// Load confirmation severity levels
export type ConfirmationSeverity = 'none' | 'dependencies' | 'conflicts' | 'opsec';

export function getConfirmationSeverity(
  module: ModuleManifest,
  loadedModules: LoadedModule[]
): ConfirmationSeverity {
  // Check for OPSEC warnings
  if (module.type === 'bof' || module.category === 'evasion') {
    return 'opsec';
  }

  // Check for conflicts
  const hasConflicts = module.conflicts.some(
    conflict => loadedModules.some(m => m.moduleId === conflict)
  );
  if (hasConflicts) {
    return 'conflicts';
  }

  // Check for missing dependencies
  const hasMissingDeps = module.dependencies.some(
    dep => !loadedModules.some(m => m.moduleId === dep)
  );
  if (hasMissingDeps) {
    return 'dependencies';
  }

  return 'none';
}
