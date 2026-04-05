// SOCKS Proxy Management Types - Based on CS/Sliver/Metasploit research

export type ProxyVersion = 'socks4' | 'socks5';
export type ProxyStatus = 'starting' | 'running' | 'stopping' | 'stopped' | 'error';
export type ForwardDirection = 'local' | 'remote';

export interface SocksProxy {
  id: string;
  sessionId: string;
  sessionName: string;
  version: ProxyVersion;
  bindHost: string;
  bindPort: number;
  status: ProxyStatus;
  username?: string;
  password?: string;
  createdAt: Date;
  connections: number;
  bytesIn: number;
  bytesOut: number;
}

export interface PortForward {
  id: string;
  sessionId: string;
  sessionName: string;
  direction: ForwardDirection;
  localHost: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  status: ProxyStatus;
  createdAt: Date;
  bytesIn: number;
  bytesOut: number;
}

export interface PivotListener {
  id: string;
  sessionId: string;
  sessionName: string;
  transport: 'tcp' | 'udp' | 'pipe';
  bindAddress: string;
  port?: number;
  pipeName?: string;
  status: ProxyStatus;
  activePivots: number;
  createdAt: Date;
}

export interface CreateProxyRequest {
  sessionId: string;
  version: ProxyVersion;
  bindHost?: string;  // defaults to 127.0.0.1
  bindPort: number;
  enableAuth?: boolean;
}

export interface CreatePortForwardRequest {
  sessionId: string;
  direction: ForwardDirection;
  localHost: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
}

// Catppuccin Mocha colors for proxy UI
export const PROXY_COLORS = {
  // Status colors
  status: {
    starting: '#f9e2af',   // yellow (pulsing)
    running: '#a6e3a1',    // green (pulsing)
    stopping: '#f9e2af',   // yellow (pulsing)
    stopped: '#6c7086',    // overlay0
    error: '#f38ba8',      // red
  },
  // Version badges
  version: {
    socks4: '#f5e0dc',     // rosewater
    socks5: '#cba6f7',     // mauve
  },
  // Traffic indicators
  traffic: {
    bytesIn: '#a6e3a1',    // green
    bytesOut: '#89b4fa',   // blue
  },
  // Addresses
  address: {
    bind: '#74c7ec',       // sapphire
    remote: '#fab387',     // peach
  },
  // Actions
  action: {
    create: '#89b4fa',     // blue
    stop: '#f38ba8',       // red
  },
  // Direction
  direction: {
    local: '#a6e3a1',      // green - local to remote
    remote: '#fab387',     // peach - remote to local
  },
} as const;

// OPSEC warnings for proxy operations (from Sliver source)
export const PROXY_OPSEC_WARNINGS: Record<string, string> = {
  credentialExposure: 'Credentials are tunneled to the implant and recoverable from memory',
  dnsSlowTunnel: 'DNS C2 connections may be slow for proxy operations',
  rdpPort: 'Port 3389 (RDP) may have compatibility issues with some SOCKS implementations',
  wireGuard: 'For WireGuard tunneling, consider using wg-portfwd instead',
  highTraffic: 'High-bandwidth proxy usage increases detection risk',
};

// Generate proxychains.conf snippet
export function generateProxychainsConfig(proxy: SocksProxy): string {
  const version = proxy.version === 'socks5' ? 'socks5' : 'socks4';

  if (proxy.username && proxy.password) {
    return `${version} ${proxy.bindHost} ${proxy.bindPort} ${proxy.username} ${proxy.password}`;
  }

  return `${version} ${proxy.bindHost} ${proxy.bindPort}`;
}

// Format bytes for display
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

// Common port presets for quick selection
export const PORT_PRESETS = [
  { port: 1080, label: 'SOCKS default' },
  { port: 8080, label: 'HTTP proxy' },
  { port: 9050, label: 'Tor default' },
  { port: 3128, label: 'Squid default' },
] as const;

// Common remote port presets for port forwarding
export const REMOTE_PORT_PRESETS = [
  { port: 22, label: 'SSH' },
  { port: 80, label: 'HTTP' },
  { port: 443, label: 'HTTPS' },
  { port: 3389, label: 'RDP' },
  { port: 5432, label: 'PostgreSQL' },
  { port: 3306, label: 'MySQL' },
  { port: 6379, label: 'Redis' },
  { port: 27017, label: 'MongoDB' },
] as const;
