// OPSEC Types and Risk Assessment
// Based on professional C2 OPSEC warning patterns

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface DetectionVector {
  name: string;
  description: string;
  likelihood: 'low' | 'medium' | 'high';
  mitigations?: string[];
}

export interface OpsecAssessment {
  riskLevel: RiskLevel;
  score: number; // 0-100
  summary: string;
  detectionVectors: DetectionVector[];
  recommendations: string[];
  requiresConfirmation: boolean;
}

export interface TaskRiskProfile {
  taskType: string;
  baseRisk: RiskLevel;
  detectionVectors: DetectionVector[];
  description: string;
}

// Risk level colors matching Catppuccin Mocha
export const RISK_COLORS: Record<RiskLevel, {
  text: string;
  bg: string;
  border: string;
  icon: string;
}> = {
  low: {
    text: 'text-green',
    bg: 'bg-green/10',
    border: 'border-green/30',
    icon: 'text-green',
  },
  medium: {
    text: 'text-yellow',
    bg: 'bg-yellow/10',
    border: 'border-yellow/30',
    icon: 'text-yellow',
  },
  high: {
    text: 'text-peach',
    bg: 'bg-peach/10',
    border: 'border-peach/30',
    icon: 'text-peach',
  },
  critical: {
    text: 'text-red',
    bg: 'bg-red/10',
    border: 'border-red/30',
    icon: 'text-red',
  },
};

// Detection likelihood colors
export const LIKELIHOOD_COLORS: Record<string, string> = {
  low: 'text-green',
  medium: 'text-yellow',
  high: 'text-red',
};

// Task type risk profiles - maps task types to their OPSEC characteristics
export const TASK_RISK_PROFILES: Record<string, TaskRiskProfile> = {
  // Low risk operations
  'whoami': {
    taskType: 'whoami',
    baseRisk: 'low',
    description: 'Query current user context',
    detectionVectors: [
      {
        name: 'Process Creation',
        description: 'Creates a new process that may be logged',
        likelihood: 'low',
        mitigations: ['Uses native API calls when possible'],
      },
    ],
  },
  'pwd': {
    taskType: 'pwd',
    baseRisk: 'low',
    description: 'Get current working directory',
    detectionVectors: [],
  },
  'ls': {
    taskType: 'ls',
    baseRisk: 'low',
    description: 'List directory contents',
    detectionVectors: [
      {
        name: 'File System Access',
        description: 'Directory enumeration may trigger file system auditing',
        likelihood: 'low',
      },
    ],
  },

  // Medium risk operations
  'ps': {
    taskType: 'ps',
    baseRisk: 'medium',
    description: 'List running processes',
    detectionVectors: [
      {
        name: 'API Calls',
        description: 'Process enumeration APIs may be monitored by EDR',
        likelihood: 'medium',
        mitigations: ['Uses indirect syscalls', 'Avoids suspicious API patterns'],
      },
    ],
  },
  'netstat': {
    taskType: 'netstat',
    baseRisk: 'medium',
    description: 'List network connections',
    detectionVectors: [
      {
        name: 'Network Enumeration',
        description: 'Network state queries may trigger behavioral detection',
        likelihood: 'medium',
      },
    ],
  },
  'download': {
    taskType: 'download',
    baseRisk: 'medium',
    description: 'Download file from target',
    detectionVectors: [
      {
        name: 'File Access',
        description: 'Reading files may trigger DLP or file monitoring',
        likelihood: 'medium',
      },
      {
        name: 'Network Traffic',
        description: 'Large transfers may trigger network anomaly detection',
        likelihood: 'medium',
        mitigations: ['Chunked transfer', 'Traffic shaping'],
      },
    ],
  },

  // High risk operations
  'upload': {
    taskType: 'upload',
    baseRisk: 'high',
    description: 'Upload file to target',
    detectionVectors: [
      {
        name: 'File Write',
        description: 'Writing files triggers AV/EDR file scanning',
        likelihood: 'high',
        mitigations: ['Write to user-writable locations', 'Avoid temp directories'],
      },
      {
        name: 'Content Inspection',
        description: 'File contents may be scanned for malicious patterns',
        likelihood: 'high',
      },
    ],
  },
  'execute': {
    taskType: 'execute',
    baseRisk: 'high',
    description: 'Execute command or binary',
    detectionVectors: [
      {
        name: 'Process Creation',
        description: 'New process creation is heavily monitored',
        likelihood: 'high',
        mitigations: ['Parent PID spoofing', 'Process hollowing'],
      },
      {
        name: 'Command Line Logging',
        description: 'Command arguments are typically logged',
        likelihood: 'high',
        mitigations: ['Argument obfuscation', 'Indirect execution'],
      },
    ],
  },
  'shell': {
    taskType: 'shell',
    baseRisk: 'high',
    description: 'Execute shell command',
    detectionVectors: [
      {
        name: 'Shell Invocation',
        description: 'Shell spawning (cmd.exe, powershell.exe, /bin/sh) is suspicious',
        likelihood: 'high',
      },
      {
        name: 'Script Block Logging',
        description: 'PowerShell commands are logged by default on modern Windows',
        likelihood: 'high',
      },
    ],
  },
  'inject': {
    taskType: 'inject',
    baseRisk: 'high',
    description: 'Inject code into process',
    detectionVectors: [
      {
        name: 'Memory Allocation',
        description: 'Cross-process memory allocation triggers EDR alerts',
        likelihood: 'high',
      },
      {
        name: 'Thread Creation',
        description: 'Remote thread creation is a known injection indicator',
        likelihood: 'high',
      },
    ],
  },

  // Critical risk operations
  'mimikatz': {
    taskType: 'mimikatz',
    baseRisk: 'critical',
    description: 'Credential dumping',
    detectionVectors: [
      {
        name: 'LSASS Access',
        description: 'LSASS memory access triggers immediate EDR response',
        likelihood: 'high',
      },
      {
        name: 'Signature Detection',
        description: 'Mimikatz signatures are universally detected',
        likelihood: 'high',
      },
      {
        name: 'Behavioral Detection',
        description: 'Credential access patterns are well-known to defenders',
        likelihood: 'high',
      },
    ],
  },
  'hashdump': {
    taskType: 'hashdump',
    baseRisk: 'critical',
    description: 'Dump password hashes',
    detectionVectors: [
      {
        name: 'Registry Access',
        description: 'SAM/SECURITY hive access is monitored',
        likelihood: 'high',
      },
      {
        name: 'Privilege Escalation',
        description: 'Requires SYSTEM privileges, which may trigger alerts',
        likelihood: 'high',
      },
    ],
  },
  'keylogger': {
    taskType: 'keylogger',
    baseRisk: 'critical',
    description: 'Start keystroke logging',
    detectionVectors: [
      {
        name: 'API Hooking',
        description: 'SetWindowsHookEx calls are monitored by EDR',
        likelihood: 'high',
      },
      {
        name: 'Behavioral Analysis',
        description: 'Continuous input monitoring patterns are flagged',
        likelihood: 'high',
      },
    ],
  },
  'screenshot': {
    taskType: 'screenshot',
    baseRisk: 'medium',
    description: 'Capture screen',
    detectionVectors: [
      {
        name: 'GDI API Calls',
        description: 'Screen capture APIs may be monitored',
        likelihood: 'medium',
      },
    ],
  },
  'persist': {
    taskType: 'persist',
    baseRisk: 'critical',
    description: 'Establish persistence',
    detectionVectors: [
      {
        name: 'Registry Modification',
        description: 'Run key modifications trigger immediate alerts',
        likelihood: 'high',
      },
      {
        name: 'Scheduled Task',
        description: 'Task scheduler changes are logged and monitored',
        likelihood: 'high',
      },
      {
        name: 'Service Creation',
        description: 'New service installation is heavily audited',
        likelihood: 'high',
      },
    ],
  },
  'pivot': {
    taskType: 'pivot',
    baseRisk: 'high',
    description: 'Establish pivot/tunnel',
    detectionVectors: [
      {
        name: 'Port Binding',
        description: 'Listening on new ports may trigger firewall alerts',
        likelihood: 'medium',
      },
      {
        name: 'Lateral Traffic',
        description: 'Internal network connections are monitored',
        likelihood: 'high',
      },
    ],
  },
};

// Calculate risk score from 0-100 based on detection vectors
export function calculateRiskScore(profile: TaskRiskProfile): number {
  const baseScores: Record<RiskLevel, number> = {
    low: 15,
    medium: 40,
    high: 70,
    critical: 90,
  };

  let score = baseScores[profile.baseRisk];

  // Add points for each high-likelihood detection vector
  for (const vector of profile.detectionVectors) {
    if (vector.likelihood === 'high') score += 5;
    else if (vector.likelihood === 'medium') score += 2;
  }

  return Math.min(100, score);
}

// Get OPSEC assessment for a task type
export function assessTaskRisk(taskType: string): OpsecAssessment {
  const profile = TASK_RISK_PROFILES[taskType.toLowerCase()];

  if (!profile) {
    // Unknown task - treat as medium risk
    return {
      riskLevel: 'medium',
      score: 50,
      summary: 'Unknown operation - exercise caution',
      detectionVectors: [
        {
          name: 'Unknown Behavior',
          description: 'This operation has no defined risk profile',
          likelihood: 'medium',
        },
      ],
      recommendations: ['Review operation details before executing'],
      requiresConfirmation: true,
    };
  }

  const score = calculateRiskScore(profile);
  const recommendations: string[] = [];

  // Generate recommendations based on risk
  if (profile.baseRisk === 'critical') {
    recommendations.push('Consider if this operation is absolutely necessary');
    recommendations.push('Ensure you have authorization for this action');
    recommendations.push('Be prepared for potential detection and response');
  } else if (profile.baseRisk === 'high') {
    recommendations.push('Execute during low-activity periods if possible');
    recommendations.push('Monitor for defensive response after execution');
  }

  // Add mitigation-based recommendations
  for (const vector of profile.detectionVectors) {
    if (vector.mitigations) {
      recommendations.push(...vector.mitigations.map((m) => `Mitigation: ${m}`));
    }
  }

  return {
    riskLevel: profile.baseRisk,
    score,
    summary: profile.description,
    detectionVectors: profile.detectionVectors,
    recommendations: recommendations.slice(0, 5), // Limit to top 5
    requiresConfirmation: profile.baseRisk === 'high' || profile.baseRisk === 'critical',
  };
}

// Get human-readable risk label
export function getRiskLabel(level: RiskLevel): string {
  const labels: Record<RiskLevel, string> = {
    low: 'Low Risk',
    medium: 'Medium Risk',
    high: 'High Risk',
    critical: 'Critical Risk',
  };
  return labels[level];
}

// ============================================================================
// Injection Technique OPSEC Ratings
// Based on research from Sliver, Cobalt Strike, Havoc, Brute Ratel
// ============================================================================

export type InjectionTechnique = 'auto' | 'win32' | 'ntapi' | 'apc' | 'thread_hijack';

export interface InjectionTechniqueProfile {
  name: string;
  technique: InjectionTechnique;
  riskLevel: RiskLevel;
  opsecScore: number; // 0-100, higher = more OPSEC safe
  description: string;
  detectionVectors: DetectionVector[];
  requirements: string[];
  bestFor: string[];
}

// Injection technique OPSEC profiles - ordered by OPSEC safety
export const INJECTION_TECHNIQUE_PROFILES: Record<InjectionTechnique, InjectionTechniqueProfile> = {
  auto: {
    name: 'Automatic Selection',
    technique: 'auto',
    riskLevel: 'medium',
    opsecScore: 60,
    description: 'Automatically selects the best technique based on target process and environment',
    detectionVectors: [
      {
        name: 'Variable Detection Surface',
        description: 'Detection depends on which technique is selected',
        likelihood: 'medium',
      },
    ],
    requirements: [],
    bestFor: ['General use', 'When unsure of target environment'],
  },

  ntapi: {
    name: 'NT API (Tier 2)',
    technique: 'ntapi',
    riskLevel: 'medium',
    opsecScore: 75,
    description: 'Uses NtCreateThreadEx + NtWriteVirtualMemory to bypass user-mode hooks',
    detectionVectors: [
      {
        name: 'Syscall Monitoring',
        description: 'Kernel-level syscall monitoring can still detect this',
        likelihood: 'medium',
        mitigations: ['Use indirect syscalls', 'Syscall number resolution at runtime'],
      },
      {
        name: 'Memory Allocation',
        description: 'RWX memory allocation is suspicious regardless of API used',
        likelihood: 'medium',
        mitigations: ['Use RW then RX (two-stage)', 'Module stomping'],
      },
    ],
    requirements: ['ntdll.dll access', 'Syscall number resolution'],
    bestFor: ['EDR evasion', 'Bypassing API hooks'],
  },

  win32: {
    name: 'Win32 API (Tier 1)',
    technique: 'win32',
    riskLevel: 'high',
    opsecScore: 40,
    description: 'Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread',
    detectionVectors: [
      {
        name: 'API Hooking',
        description: 'All Win32 APIs are typically hooked by EDR',
        likelihood: 'high',
      },
      {
        name: 'CreateRemoteThread',
        description: 'CreateRemoteThread is a well-known injection indicator',
        likelihood: 'high',
      },
      {
        name: 'Cross-Process Memory',
        description: 'Writing to remote process memory triggers alerts',
        likelihood: 'high',
      },
    ],
    requirements: ['PROCESS_ALL_ACCESS or equivalent'],
    bestFor: ['Compatibility', 'Simple targets', 'Non-EDR environments'],
  },

  apc: {
    name: 'APC Injection (Tier 3)',
    technique: 'apc',
    riskLevel: 'high',
    opsecScore: 55,
    description: 'Queues shellcode via QueueUserAPC to alertable threads',
    detectionVectors: [
      {
        name: 'APC Queue',
        description: 'EDRs monitor APC queuing to remote processes',
        likelihood: 'high',
        mitigations: ['Target processes known to enter alertable state'],
      },
      {
        name: 'Thread State',
        description: 'Requires target thread in alertable wait state',
        likelihood: 'medium',
      },
    ],
    requirements: ['Alertable thread in target', 'THREAD_SET_CONTEXT'],
    bestFor: ['Avoiding CreateRemoteThread', 'Processes with alertable waits'],
  },

  thread_hijack: {
    name: 'Thread Hijack (Tier 4)',
    technique: 'thread_hijack',
    riskLevel: 'critical',
    opsecScore: 30,
    description: 'Suspends thread, modifies context (RIP/EIP), resumes execution',
    detectionVectors: [
      {
        name: 'Thread Suspension',
        description: 'SuspendThread + SetThreadContext is highly suspicious',
        likelihood: 'high',
      },
      {
        name: 'Context Modification',
        description: 'Changing instruction pointer triggers behavioral detection',
        likelihood: 'high',
      },
      {
        name: 'Stability Risk',
        description: 'May crash target if hijacked at wrong point',
        likelihood: 'high',
      },
    ],
    requirements: ['THREAD_SUSPEND_RESUME', 'THREAD_GET_CONTEXT', 'THREAD_SET_CONTEXT'],
    bestFor: ['Last resort', 'When other techniques fail', 'CTF/lab only'],
  },
};

// Get OPSEC assessment for an injection technique
export function assessInjectionTechnique(technique: InjectionTechnique): OpsecAssessment {
  const profile = INJECTION_TECHNIQUE_PROFILES[technique];

  const recommendations: string[] = [];

  if (profile.riskLevel === 'critical') {
    recommendations.push('This technique has very high detection probability');
    recommendations.push('Consider using a less risky technique if possible');
  } else if (profile.riskLevel === 'high') {
    recommendations.push('This technique is commonly detected by EDR');
  }

  recommendations.push(...profile.bestFor.map(b => `Best for: ${b}`));

  return {
    riskLevel: profile.riskLevel,
    score: 100 - profile.opsecScore, // Invert for risk score (higher = more risky)
    summary: profile.description,
    detectionVectors: profile.detectionVectors,
    recommendations: recommendations.slice(0, 5),
    requiresConfirmation: profile.riskLevel === 'high' || profile.riskLevel === 'critical',
  };
}

// Get recommended injection technique based on OPSEC requirements
export function getRecommendedTechnique(preferOpsec: boolean): InjectionTechnique {
  if (preferOpsec) {
    return 'ntapi'; // Best balance of OPSEC and reliability
  }
  return 'auto'; // Let the system choose
}
