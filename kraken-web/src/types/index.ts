// Core types for Kraken Web UI

export interface Session {
  id: string;
  hostname: string;
  username: string;
  externalIp: string;
  internalIp?: string;
  os: string;
  arch: string;
  processId: number;
  processName: string;
  state: SessionState;
  firstSeen: string;
  lastSeen: string;
  sleepInterval: number;
  jitter: number;
}

export type SessionState = 'active' | 'dormant' | 'dead' | 'burned';

export interface Listener {
  id: string;
  name: string;
  protocol: ListenerProtocol;
  bindAddress: string;
  port: number;
  state: ListenerState;
  createdAt: string;
  sessionCount: number;
}

export type ListenerProtocol = 'http' | 'https' | 'dns';
export type ListenerState = 'running' | 'stopped' | 'error';

export interface Task {
  id: string;
  sessionId: string;
  taskType: string;
  status: TaskStatus;
  createdAt: string;
  completedAt?: string;
  output?: string;
  error?: string;
}

export type TaskStatus = 'pending' | 'dispatched' | 'completed' | 'failed';

export interface LootItem {
  id: string;
  sessionId: string;
  lootType: LootType;
  source: string;
  collectedAt: string;
  data: Record<string, unknown>;
}

export type LootType = 'credential' | 'file' | 'screenshot' | 'token';

export interface Operator {
  id: string;
  username: string;
  role: OperatorRole;
  createdAt: string;
  lastLogin?: string;
  isOnline: boolean;
  isDisabled: boolean;
  allowedSessions: string[];
  allowedListeners: string[];
}

export type OperatorRole = 'admin' | 'operator' | 'viewer';

export interface Report {
  id: string;
  title: string;
  reportType: ReportType;
  generatedAt: string;
  generatedBy: string;
  sessionCount: number;
}

export type ReportType = 'engagement' | 'session_timeline' | 'loot_summary' | 'indicators' | 'executive';

export interface CollabEvent {
  type: 'operator_online' | 'operator_offline' | 'session_locked' | 'session_unlocked' | 'chat_message';
  timestamp: string;
  data: Record<string, unknown>;
}

export interface Stats {
  activeSessions: number;
  totalSessions: number;
  activeListeners: number;
  credentialsCollected: number;
  onlineOperators: number;
}

export interface Job {
  job_id: number;
  task_id: Uint8Array;
  description: string;
  status: JobStatus;
  created_at: number;
  completed_at?: number;
  progress: number;
}

export type JobStatus = 'running' | 'completed' | 'failed' | 'cancelled';
