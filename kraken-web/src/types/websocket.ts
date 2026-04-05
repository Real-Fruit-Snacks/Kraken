/**
 * WebSocket event type definitions
 */

export type WebSocketEventType =
  | 'SessionNew'
  | 'SessionCheckin'
  | 'SessionLost'
  | 'SessionRecovered'
  | 'SessionBurned'
  | 'SessionRetired'
  | 'TaskComplete'
  | 'TaskFailed'
  | 'TaskUpdate'
  | 'LootCaptured'
  | 'JobUpdate';

export interface SessionEventData {
  implant_id: string;
}

export interface TaskEventData {
  task_id: string;
  implant_id: string;
  status: number;
  error?: {
    code: number;
    message: string;
  };
}

export interface LootEventData {
  loot_id: string;
  implant_id: string;
  type: string;
  description: string;
}

export interface JobEventData {
  job_id: number;
  task_id: string;
  status: string;
  progress: number;
}
