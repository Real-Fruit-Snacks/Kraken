// BOF Execution Types - Based on CS/Sliver/Havoc research

export type BOFArgType = 'int' | 'short' | 'string' | 'wstring' | 'binary' | 'file';
export type BOFCategory = 'recon' | 'creds' | 'lateral' | 'privesc' | 'evasion' | 'persistence' | 'util';
export type BOFStatus = 'idle' | 'running' | 'success' | 'error' | 'crashed' | 'timeout';

export interface BOFArgument {
  name: string;
  type: BOFArgType;
  description: string;
  optional: boolean;
  defaultValue?: string | number;
}

export interface BOFManifest {
  id: string;
  name: string;
  version: string;
  author: string;
  originalAuthor?: string;
  description: string;
  longDescription?: string;
  category: BOFCategory;
  tags: string[];
  entrypoint: string;
  platforms: Array<{
    os: 'windows' | 'linux';
    arch: 'x64' | 'x86';
    path: string;
  }>;
  arguments: BOFArgument[];
  repoUrl?: string;
  opsecNotes?: string;
}

export interface BOFExecution {
  id: string;
  bofId: string;
  sessionId: string;
  operator: string;
  arguments: Record<string, string | number | Uint8Array>;
  status: BOFStatus;
  startedAt: Date;
  completedAt?: Date;
  output?: string;
  exitCode?: number;
  error?: string;
}

// Catppuccin Mocha color mappings for BOF UI
export const BOF_COLORS = {
  // Category colors (for browser sidebar)
  category: {
    recon: '#89b4fa',       // blue
    creds: '#f9e2af',       // yellow
    lateral: '#cba6f7',     // mauve
    privesc: '#f38ba8',     // red
    evasion: '#a6e3a1',     // green
    persistence: '#fab387', // peach
    util: '#94e2d5',        // teal
  },
  // Status colors
  status: {
    idle: '#6c7086',        // overlay0
    running: '#89b4fa',     // blue (animated)
    success: '#a6e3a1',     // green
    error: '#f38ba8',       // red
    crashed: '#f2cdcd',     // flamingo - session may be lost
    timeout: '#f9e2af',     // yellow
  },
  // Argument type badges
  argType: {
    int: '#89b4fa',         // blue
    short: '#74c7ec',       // sapphire
    string: '#a6e3a1',      // green
    wstring: '#94e2d5',     // teal
    binary: '#cba6f7',      // mauve
    file: '#fab387',        // peach
  },
} as const;

// Category display configuration
export const CATEGORY_CONFIG: Record<BOFCategory, {
  label: string;
  description: string;
  icon: string;
}> = {
  recon: {
    label: 'Reconnaissance',
    description: 'Information gathering and enumeration',
    icon: 'magnifying-glass',
  },
  creds: {
    label: 'Credentials',
    description: 'Credential harvesting and manipulation',
    icon: 'key',
  },
  lateral: {
    label: 'Lateral Movement',
    description: 'Move between systems',
    icon: 'arrows-pointing-out',
  },
  privesc: {
    label: 'Privilege Escalation',
    description: 'Elevate privileges on target',
    icon: 'arrow-trending-up',
  },
  evasion: {
    label: 'Evasion',
    description: 'Defense evasion techniques',
    icon: 'eye-slash',
  },
  persistence: {
    label: 'Persistence',
    description: 'Maintain access',
    icon: 'arrow-path',
  },
  util: {
    label: 'Utilities',
    description: 'General purpose tools',
    icon: 'wrench',
  },
};

// Argument type input configuration
export const ARG_TYPE_CONFIG: Record<BOFArgType, {
  label: string;
  inputType: 'number' | 'text' | 'file';
  validate: (value: unknown) => boolean;
  hint?: string;
}> = {
  int: {
    label: 'int32',
    inputType: 'number',
    validate: (v) => typeof v === 'number' && Number.isInteger(v) && v >= -2147483648 && v <= 2147483647,
  },
  short: {
    label: 'int16',
    inputType: 'number',
    validate: (v) => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 65535,
  },
  string: {
    label: 'cstring',
    inputType: 'text',
    validate: (v) => typeof v === 'string',
  },
  wstring: {
    label: 'wstring',
    inputType: 'text',
    validate: (v) => typeof v === 'string',
    hint: 'Unicode/UTF-16LE',
  },
  binary: {
    label: 'blob',
    inputType: 'file',
    validate: (v) => v instanceof Uint8Array || v instanceof File,
  },
  file: {
    label: 'file',
    inputType: 'file',
    validate: (v) => v instanceof Uint8Array || v instanceof File,
  },
};

// OPSEC risk assessment for BOF execution
export interface BOFOpsecAssessment {
  archMatch: boolean;
  crashRisk: 'low' | 'medium' | 'high';
  detectionVectors: string[];
  recommendations: string[];
}

export function assessBOFOpsec(
  bof: BOFManifest,
  sessionOs: string,
  sessionArch: string
): BOFOpsecAssessment {
  const archMatch = bof.platforms.some(
    p => p.os === sessionOs && p.arch === sessionArch
  );

  const detectionVectors: string[] = [
    'In-memory code execution',
    'Potential API hooking detection',
  ];

  const recommendations: string[] = [];

  if (!archMatch) {
    detectionVectors.push('Architecture mismatch - WILL CRASH');
    recommendations.push('Select correct architecture BOF');
  }

  if (bof.category === 'creds') {
    detectionVectors.push('Credential access monitoring (LSASS)');
    recommendations.push('Consider sleep masking before execution');
  }

  if (bof.category === 'privesc') {
    detectionVectors.push('Privilege escalation detection');
  }

  return {
    archMatch,
    crashRisk: archMatch ? 'medium' : 'high',
    detectionVectors,
    recommendations,
  };
}
