// Mesh Control Panel Types - Based on CS/Mythic/Sliver research

export type MeshTransport = 'tcp' | 'smb' | 'pipe';
export type MeshRole = 'egress' | 'router' | 'leaf';
export type ConnectionStatus = 'active' | 'waiting' | 'broken' | 'disconnected';

export interface MeshNode {
  id: string;
  implantId: string;
  hostname: string;
  username: string;
  os: 'windows' | 'linux' | 'macos';
  arch: 'x64' | 'x86' | 'arm64';
  role: MeshRole;
  isElevated: boolean;
  lastSeen: Date;
  pid: number;
}

export interface MeshConnection {
  id: string;
  sourceId: string;
  targetId: string;
  transport: MeshTransport;
  status: ConnectionStatus;
  address?: string;
  port?: number;
  pipeName?: string;
  establishedAt?: Date;
  bytesIn: number;
  bytesOut: number;
}

export interface PeerConnectionRequest {
  targetId?: string;
  transport: MeshTransport;
  address: string;
  port?: number;
  pipeName?: string;
  role: MeshRole;
}

// Catppuccin Mocha color mappings for mesh (adapted from CS arrow colors)
export const MESH_COLORS = {
  // Transport colors
  transport: {
    tcp: '#89b4fa',      // blue - TCP connections
    smb: '#fab387',      // peach - SMB/named pipe
    pipe: '#fab387',     // peach - named pipe
    http: '#a6e3a1',     // green - HTTP egress (dashed)
    dns: '#f9e2af',      // yellow - DNS egress (dashed)
  },
  // Status colors
  status: {
    active: '#a6e3a1',       // green - live connection
    waiting: '#fab387',      // peach - unlinked, awaiting reconnect
    broken: '#f38ba8',       // red - link failed
    disconnected: '#6c7086', // overlay0 - session ended
  },
  // Role colors
  role: {
    egress: '#a6e3a1',   // green - direct C2 connection
    router: '#89b4fa',   // blue - relay node
    leaf: '#cba6f7',     // mauve - endpoint agent
  },
} as const;

// Role configuration for UI display
export const ROLE_CONFIG: Record<MeshRole, {
  label: string;
  description: string;
  color: string;
  icon: string;
}> = {
  egress: {
    label: 'Egress Node',
    description: 'Direct C2 server connection. Routes traffic for downstream peers.',
    color: MESH_COLORS.role.egress,
    icon: 'globe',
  },
  router: {
    label: 'Router',
    description: 'No direct egress. Relays traffic between leaves and egress nodes.',
    color: MESH_COLORS.role.router,
    icon: 'arrows-right-left',
  },
  leaf: {
    label: 'Leaf Node',
    description: 'Endpoint agent. Connects to parent router or egress only.',
    color: MESH_COLORS.role.leaf,
    icon: 'computer-desktop',
  },
};

// Transport configuration
export const TRANSPORT_CONFIG: Record<MeshTransport, {
  label: string;
  description: string;
  fields: ('address' | 'port' | 'pipeName')[];
  defaultPort?: number;
}> = {
  tcp: {
    label: 'TCP',
    description: 'Direct TCP connection. Fast, reliable, but more detectable.',
    fields: ['address', 'port'],
    defaultPort: 4444,
  },
  smb: {
    label: 'SMB',
    description: 'SMB named pipe. Blends with Windows traffic, slower.',
    fields: ['address', 'pipeName'],
  },
  pipe: {
    label: 'Named Pipe',
    description: 'Local named pipe. Same-host communication only.',
    fields: ['pipeName'],
  },
};
