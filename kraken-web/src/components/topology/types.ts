// Topology visualization types

// Node data types (what goes in node.data)
export interface ImplantNodeData {
  type: 'implant';
  implantId: string;
  hostname: string;
  username: string;
  os: 'windows' | 'linux' | 'macos' | 'unknown';
  state: 'active' | 'dormant' | 'dead' | 'burned';
  isElevated: boolean;
  hasEgress: boolean;
  role: 'leaf' | 'relay' | 'hub';
  [key: string]: unknown; // Index signature for React Flow compatibility
}

export interface C2ServerNodeData {
  type: 'c2-server';
  name: string;
  protocol: 'http' | 'https' | 'dns';
  [key: string]: unknown; // Index signature for React Flow compatibility
}

export type TopologyNodeData = ImplantNodeData | C2ServerNodeData;

// Edge data types
export type EdgeProtocol = 'https' | 'http' | 'smb' | 'tcp' | 'dns' | 'p2p';
export type EdgeState = 'connecting' | 'established' | 'degraded' | 'failed';

export interface TopologyEdgeData {
  protocol: EdgeProtocol;
  state: EdgeState;
  latencyMs?: number;
  animated: boolean;
  [key: string]: unknown; // Index signature for React Flow compatibility
}

// Color mappings based on research (Cobalt Strike protocol colors + accessibility)
export const PROTOCOL_COLORS: Record<EdgeProtocol, { color: string; label: string; lineStyle: 'solid' | 'dashed' | 'dotted' }> = {
  https: { color: '#a6e3a1', label: 'HTTPS', lineStyle: 'solid' },      // Green
  http: { color: '#94e2d5', label: 'HTTP', lineStyle: 'solid' },        // Teal
  smb: { color: '#fab387', label: 'SMB Pivot', lineStyle: 'solid' },    // Orange/Peach
  tcp: { color: '#89b4fa', label: 'TCP Pivot', lineStyle: 'solid' },    // Blue
  dns: { color: '#f9e2af', label: 'DNS', lineStyle: 'dotted' },         // Yellow
  p2p: { color: '#cba6f7', label: 'P2P Mesh', lineStyle: 'solid' },     // Mauve/Purple
};

export const STATE_COLORS: Record<EdgeState, { color: string; opacity: number }> = {
  connecting: { color: '#f9e2af', opacity: 0.6 },   // Yellow, semi-transparent
  established: { color: 'inherit', opacity: 1 },    // Use protocol color
  degraded: { color: '#fab387', opacity: 0.8 },     // Orange
  failed: { color: '#f38ba8', opacity: 1 },         // Red
};

// Node state colors
export const NODE_STATE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  active: { bg: '#313244', border: '#a6e3a1', text: '#cdd6f4' },
  dormant: { bg: '#313244', border: '#f9e2af', text: '#a6adc8' },
  dead: { bg: '#45475a', border: '#f38ba8', text: '#6c7086' },
  burned: { bg: '#45475a', border: '#f38ba8', text: '#6c7086' },
};

// OS icons (using emoji for now, can be replaced with SVG)
export const OS_ICONS: Record<string, string> = {
  windows: '🪟',
  linux: '🐧',
  macos: '🍎',
  unknown: '💻',
};

// Node and Edge type aliases for external use
import type { Node, Edge } from '@xyflow/react';
export type TopologyNode = Node<TopologyNodeData>;
export type TopologyEdge = Edge<TopologyEdgeData>;

// Layout options
export type LayoutDirection = 'TB' | 'LR' | 'BT' | 'RL';

export interface LayoutOptions {
  direction: LayoutDirection;
  nodeSpacing: number;
  levelSpacing: number;
}

export const DEFAULT_LAYOUT_OPTIONS: LayoutOptions = {
  direction: 'LR',  // Left-to-right for pivot chains
  nodeSpacing: 50,
  levelSpacing: 150,
};
