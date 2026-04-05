// SOCKS Proxy Manager - Professional proxy and pivoting UI
// Based on research: CS/Sliver patterns, port-only minimum, proxychains integration

import { useState } from 'react';
import {
  SocksProxy,
  PortForward,
  ProxyVersion,
  CreateProxyRequest,
  CreatePortForwardRequest,
  PROXY_COLORS,
  PROXY_OPSEC_WARNINGS,
  PORT_PRESETS,
  REMOTE_PORT_PRESETS,
  generateProxychainsConfig,
  formatBytes,
} from './types';

interface SocksProxyManagerProps {
  sessionId: string;
  sessionName: string;
  proxies: SocksProxy[];
  portForwards: PortForward[];
  onCreateProxy: (request: CreateProxyRequest) => Promise<void>;
  onStopProxy: (proxyId: string) => Promise<void>;
  onCreatePortForward: (request: CreatePortForwardRequest) => Promise<void>;
  onStopPortForward: (forwardId: string) => Promise<void>;
}

export function SocksProxyManager({
  sessionId,
  sessionName,
  proxies,
  portForwards,
  onCreateProxy,
  onStopProxy,
  onCreatePortForward,
  onStopPortForward,
}: SocksProxyManagerProps) {
  const [activeTab, setActiveTab] = useState<'socks' | 'portfwd'>('socks');
  const [showCreateProxy, setShowCreateProxy] = useState(false);
  const [showCreateForward, setShowCreateForward] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Proxy form state
  const [proxyPort, setProxyPort] = useState(1080);
  const [proxyVersion, setProxyVersion] = useState<ProxyVersion>('socks5');
  const [proxyBindHost, setProxyBindHost] = useState('127.0.0.1');
  const [enableAuth, setEnableAuth] = useState(false);

  // Port forward form state
  const [fwdLocalHost, setFwdLocalHost] = useState('127.0.0.1');
  const [fwdLocalPort, setFwdLocalPort] = useState(8080);
  const [fwdRemoteHost, setFwdRemoteHost] = useState('');
  const [fwdRemotePort, setFwdRemotePort] = useState(80);
  const [fwdDirection, setFwdDirection] = useState<'local' | 'remote'>('local');

  const handleCreateProxy = async () => {
    setIsCreating(true);
    try {
      await onCreateProxy({
        sessionId,
        version: proxyVersion,
        bindHost: proxyBindHost,
        bindPort: proxyPort,
        enableAuth,
      });
      setShowCreateProxy(false);
      setProxyPort(1080);
    } finally {
      setIsCreating(false);
    }
  };

  const handleCreateForward = async () => {
    setIsCreating(true);
    try {
      await onCreatePortForward({
        sessionId,
        direction: fwdDirection,
        localHost: fwdLocalHost,
        localPort: fwdLocalPort,
        remoteHost: fwdRemoteHost,
        remotePort: fwdRemotePort,
      });
      setShowCreateForward(false);
    } finally {
      setIsCreating(false);
    }
  };

  const copyProxychains = (proxy: SocksProxy) => {
    const config = generateProxychainsConfig(proxy);
    navigator.clipboard.writeText(config);
    setCopiedId(proxy.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-ctp-surface0 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-ctp-surface0 flex items-center justify-center">
            <svg className="w-4 h-4 text-ctp-mauve" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-medium text-ctp-text">Pivoting</h3>
            <p className="text-xs text-ctp-subtext0">{sessionName}</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-ctp-surface0">
        <button
          onClick={() => setActiveTab('socks')}
          className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'socks'
              ? 'text-ctp-text border-b-2 border-ctp-mauve'
              : 'text-ctp-subtext0 hover:text-ctp-text'
          }`}
        >
          SOCKS Proxy
          {proxies.length > 0 && (
            <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-ctp-green/20 text-ctp-green">
              {proxies.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('portfwd')}
          className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'portfwd'
              ? 'text-ctp-text border-b-2 border-ctp-mauve'
              : 'text-ctp-subtext0 hover:text-ctp-text'
          }`}
        >
          Port Forward
          {portForwards.length > 0 && (
            <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-ctp-green/20 text-ctp-green">
              {portForwards.length}
            </span>
          )}
        </button>
      </div>

      {/* SOCKS Tab */}
      {activeTab === 'socks' && (
        <div className="p-4">
          {/* Create Button */}
          <button
            onClick={() => setShowCreateProxy(true)}
            className="w-full py-2 rounded-lg bg-ctp-blue text-ctp-crust text-sm font-medium hover:bg-ctp-blue/90 transition-colors flex items-center justify-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Start SOCKS Proxy
          </button>

          {/* Active Proxies */}
          <div className="mt-4 space-y-2">
            {proxies.length === 0 ? (
              <p className="text-sm text-ctp-subtext0 text-center py-4">No active proxies</p>
            ) : (
              proxies.map((proxy) => (
                <div
                  key={proxy.id}
                  className="p-3 rounded-lg bg-ctp-surface0 border border-ctp-surface1"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          proxy.status === 'running' ? 'animate-pulse' : ''
                        }`}
                        style={{ backgroundColor: PROXY_COLORS.status[proxy.status] }}
                      />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-mono text-ctp-text">
                            {proxy.bindHost}:{proxy.bindPort}
                          </span>
                          <span
                            className="px-1.5 py-0.5 text-xs rounded"
                            style={{
                              backgroundColor: PROXY_COLORS.version[proxy.version] + '20',
                              color: PROXY_COLORS.version[proxy.version],
                            }}
                          >
                            {proxy.version.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-ctp-subtext0">
                          <span>{proxy.connections} connections</span>
                          <span>
                            <span style={{ color: PROXY_COLORS.traffic.bytesIn }}>↓</span> {formatBytes(proxy.bytesIn)}
                          </span>
                          <span>
                            <span style={{ color: PROXY_COLORS.traffic.bytesOut }}>↑</span> {formatBytes(proxy.bytesOut)}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => copyProxychains(proxy)}
                        className="p-1.5 rounded hover:bg-ctp-surface1 transition-colors"
                        title="Copy proxychains config"
                      >
                        {copiedId === proxy.id ? (
                          <svg className="w-4 h-4 text-ctp-green" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                        ) : (
                          <svg className="w-4 h-4 text-ctp-subtext0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        )}
                      </button>
                      <button
                        onClick={() => onStopProxy(proxy.id)}
                        className="p-1.5 rounded hover:bg-ctp-red/20 text-ctp-red transition-colors"
                        title="Stop proxy"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  {/* Proxychains config snippet */}
                  <div className="mt-2 p-2 rounded bg-ctp-mantle font-mono text-xs text-ctp-subtext0">
                    # proxychains.conf<br />
                    {generateProxychainsConfig(proxy)}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Port Forward Tab */}
      {activeTab === 'portfwd' && (
        <div className="p-4">
          <button
            onClick={() => setShowCreateForward(true)}
            className="w-full py-2 rounded-lg bg-ctp-blue text-ctp-crust text-sm font-medium hover:bg-ctp-blue/90 transition-colors flex items-center justify-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add Port Forward
          </button>

          <div className="mt-4 space-y-2">
            {portForwards.length === 0 ? (
              <p className="text-sm text-ctp-subtext0 text-center py-4">No active forwards</p>
            ) : (
              portForwards.map((fwd) => (
                <div
                  key={fwd.id}
                  className="p-3 rounded-lg bg-ctp-surface0 border border-ctp-surface1"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          fwd.status === 'running' ? 'animate-pulse' : ''
                        }`}
                        style={{ backgroundColor: PROXY_COLORS.status[fwd.status] }}
                      />
                      <div>
                        <div className="flex items-center gap-2 text-sm font-mono">
                          <span style={{ color: PROXY_COLORS.address.bind }}>
                            {fwd.localHost}:{fwd.localPort}
                          </span>
                          <span className="text-ctp-subtext0">
                            {fwd.direction === 'local' ? '→' : '←'}
                          </span>
                          <span style={{ color: PROXY_COLORS.address.remote }}>
                            {fwd.remoteHost}:{fwd.remotePort}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-ctp-subtext0">
                          <span
                            className="px-1.5 py-0.5 rounded"
                            style={{
                              backgroundColor: PROXY_COLORS.direction[fwd.direction] + '20',
                              color: PROXY_COLORS.direction[fwd.direction],
                            }}
                          >
                            {fwd.direction === 'local' ? 'Local' : 'Remote'}
                          </span>
                          <span>↓ {formatBytes(fwd.bytesIn)}</span>
                          <span>↑ {formatBytes(fwd.bytesOut)}</span>
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={() => onStopPortForward(fwd.id)}
                      className="p-1.5 rounded hover:bg-ctp-red/20 text-ctp-red transition-colors"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Create Proxy Modal */}
      {showCreateProxy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-ctp-crust/80 backdrop-blur-sm" onClick={() => setShowCreateProxy(false)} />
          <div className="relative w-full max-w-md mx-4 bg-ctp-base rounded-xl border border-ctp-surface0 shadow-xl">
            <div className="p-6">
              <h3 className="text-lg font-semibold text-ctp-text">Start SOCKS Proxy</h3>
              <p className="text-sm text-ctp-subtext0 mt-1">Create a SOCKS proxy through this session</p>

              <div className="mt-4 space-y-4">
                {/* Port */}
                <div>
                  <label className="block text-xs font-medium text-ctp-subtext0 mb-1">
                    Bind Port
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="number"
                      value={proxyPort}
                      onChange={(e) => setProxyPort(parseInt(e.target.value) || 0)}
                      className="flex-1 px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve font-mono"
                    />
                    <div className="flex gap-1">
                      {PORT_PRESETS.slice(0, 2).map((preset) => (
                        <button
                          key={preset.port}
                          onClick={() => setProxyPort(preset.port)}
                          className="px-2 py-1 text-xs rounded bg-ctp-surface0 text-ctp-subtext0 hover:bg-ctp-surface1 transition-colors"
                          title={preset.label}
                        >
                          {preset.port}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Version */}
                <div>
                  <label className="block text-xs font-medium text-ctp-subtext0 mb-1">
                    SOCKS Version
                  </label>
                  <div className="flex gap-2">
                    {(['socks5', 'socks4'] as ProxyVersion[]).map((ver) => (
                      <button
                        key={ver}
                        onClick={() => setProxyVersion(ver)}
                        className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${
                          proxyVersion === ver
                            ? 'bg-ctp-mauve text-ctp-crust'
                            : 'bg-ctp-surface0 text-ctp-subtext1 hover:bg-ctp-surface1'
                        }`}
                      >
                        {ver.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Bind Host */}
                <div>
                  <label className="block text-xs font-medium text-ctp-subtext0 mb-1">
                    Bind Host
                  </label>
                  <input
                    type="text"
                    value={proxyBindHost}
                    onChange={(e) => setProxyBindHost(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve font-mono"
                  />
                  <p className="text-xs text-ctp-overlay0 mt-1">
                    Use 0.0.0.0 to bind all interfaces
                  </p>
                </div>

                {/* Auth Toggle */}
                {proxyVersion === 'socks5' && (
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={enableAuth}
                      onChange={(e) => setEnableAuth(e.target.checked)}
                      className="rounded border-ctp-surface1 bg-ctp-surface0 text-ctp-mauve focus:ring-ctp-mauve"
                    />
                    <span className="text-sm text-ctp-subtext1">Enable authentication</span>
                  </label>
                )}

                {/* OPSEC Warning */}
                {enableAuth && (
                  <div className="p-3 rounded-lg bg-ctp-yellow/10 border border-ctp-yellow/30">
                    <p className="text-xs text-ctp-yellow">{PROXY_OPSEC_WARNINGS.credentialExposure}</p>
                  </div>
                )}
              </div>

              <div className="mt-6 flex gap-3">
                <button
                  onClick={() => setShowCreateProxy(false)}
                  className="flex-1 py-2 rounded-lg bg-ctp-surface0 text-ctp-text hover:bg-ctp-surface1 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateProxy}
                  disabled={isCreating || proxyPort < 1 || proxyPort > 65535}
                  className="flex-1 py-2 rounded-lg bg-ctp-green text-ctp-crust font-medium hover:bg-ctp-green/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isCreating && (
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  Start Proxy
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create Port Forward Modal */}
      {showCreateForward && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-ctp-crust/80 backdrop-blur-sm" onClick={() => setShowCreateForward(false)} />
          <div className="relative w-full max-w-md mx-4 bg-ctp-base rounded-xl border border-ctp-surface0 shadow-xl">
            <div className="p-6">
              <h3 className="text-lg font-semibold text-ctp-text">Add Port Forward</h3>

              <div className="mt-4 space-y-4">
                {/* Direction */}
                <div>
                  <label className="block text-xs font-medium text-ctp-subtext0 mb-1">Direction</label>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setFwdDirection('local')}
                      className={`flex-1 py-2 rounded-lg text-sm transition-colors ${
                        fwdDirection === 'local'
                          ? 'bg-ctp-green text-ctp-crust'
                          : 'bg-ctp-surface0 text-ctp-subtext1'
                      }`}
                    >
                      Local → Remote
                    </button>
                    <button
                      onClick={() => setFwdDirection('remote')}
                      className={`flex-1 py-2 rounded-lg text-sm transition-colors ${
                        fwdDirection === 'remote'
                          ? 'bg-ctp-peach text-ctp-crust'
                          : 'bg-ctp-surface0 text-ctp-subtext1'
                      }`}
                    >
                      Remote → Local
                    </button>
                  </div>
                </div>

                {/* Local */}
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-xs font-medium text-ctp-subtext0 mb-1">Local Host</label>
                    <input
                      type="text"
                      value={fwdLocalHost}
                      onChange={(e) => setFwdLocalHost(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve font-mono text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-ctp-subtext0 mb-1">Local Port</label>
                    <input
                      type="number"
                      value={fwdLocalPort}
                      onChange={(e) => setFwdLocalPort(parseInt(e.target.value) || 0)}
                      className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve font-mono text-sm"
                    />
                  </div>
                </div>

                {/* Remote */}
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-xs font-medium text-ctp-subtext0 mb-1">Remote Host</label>
                    <input
                      type="text"
                      value={fwdRemoteHost}
                      onChange={(e) => setFwdRemoteHost(e.target.value)}
                      placeholder="192.168.1.100"
                      className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve font-mono text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-ctp-subtext0 mb-1">Remote Port</label>
                    <div className="flex gap-1">
                      <input
                        type="number"
                        value={fwdRemotePort}
                        onChange={(e) => setFwdRemotePort(parseInt(e.target.value) || 0)}
                        className="flex-1 px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve font-mono text-sm"
                      />
                    </div>
                  </div>
                </div>

                {/* Port presets */}
                <div className="flex flex-wrap gap-1">
                  {REMOTE_PORT_PRESETS.map((preset) => (
                    <button
                      key={preset.port}
                      onClick={() => setFwdRemotePort(preset.port)}
                      className="px-2 py-1 text-xs rounded bg-ctp-surface0 text-ctp-subtext0 hover:bg-ctp-surface1 transition-colors"
                    >
                      {preset.label} ({preset.port})
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-6 flex gap-3">
                <button
                  onClick={() => setShowCreateForward(false)}
                  className="flex-1 py-2 rounded-lg bg-ctp-surface0 text-ctp-text hover:bg-ctp-surface1 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateForward}
                  disabled={isCreating || !fwdRemoteHost}
                  className="flex-1 py-2 rounded-lg bg-ctp-green text-ctp-crust font-medium hover:bg-ctp-green/90 transition-colors disabled:opacity-50"
                >
                  Create Forward
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default SocksProxyManager;
