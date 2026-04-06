import { useState, useEffect } from 'react';
import { proxyClient } from '../../api';
import { ProxyState, PortForward } from '../../gen/kraken_pb.js';

interface Props {
  sessionId: string;
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function uuidToHex(value: Uint8Array | undefined): string {
  if (!value) return '';
  return Array.from(value).map(b => b.toString(16).padStart(2, '0')).join('');
}

function stateLabel(state: ProxyState): { label: string; className: string } {
  switch (state) {
    case ProxyState.ACTIVE:
      return { label: 'Active', className: 'bg-ctp-green/20 text-ctp-green' };
    case ProxyState.STOPPED:
      return { label: 'Stopped', className: 'bg-ctp-surface2 text-ctp-subtext0' };
    case ProxyState.ERROR:
      return { label: 'Error', className: 'bg-ctp-red/20 text-ctp-red' };
    default:
      return { label: 'Unknown', className: 'bg-ctp-surface2 text-ctp-subtext0' };
  }
}

export function PortForwardPanel({ sessionId }: Props) {
  const [bindPort, setBindPort] = useState('');
  const [forwardHost, setForwardHost] = useState('');
  const [forwardPort, setForwardPort] = useState('');
  const [reverse, setReverse] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tunnels, setTunnels] = useState<PortForward[]>([]);
  const [listLoading, setListLoading] = useState(false);
  const [stoppingId, setStoppingId] = useState<string | null>(null);

  const loadTunnels = async () => {
    setListLoading(true);
    try {
      const response = await proxyClient.listProxies({
        implantId: { value: hexToUint8Array(sessionId) },
      });
      setTunnels(response.portForwards ?? []);
    } catch {
      // non-fatal — list may be empty or unavailable
    } finally {
      setListLoading(false);
    }
  };

  useEffect(() => {
    loadTunnels();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const validate = (): string | null => {
    const bp = parseInt(bindPort, 10);
    if (!bindPort || isNaN(bp) || bp < 1 || bp > 65535) return 'Bind port must be 1–65535.';
    if (!forwardHost.trim()) return 'Forward host is required.';
    const fp = parseInt(forwardPort, 10);
    if (!forwardPort || isNaN(fp) || fp < 1 || fp > 65535) return 'Forward port must be 1–65535.';
    return null;
  };

  const handleStart = async () => {
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      await proxyClient.startPortForward({
        implantId: { value: hexToUint8Array(sessionId) },
        localHost: '0.0.0.0',
        localPort: parseInt(bindPort, 10),
        remoteHost: forwardHost.trim(),
        remotePort: parseInt(forwardPort, 10),
        reverse,
      });
      setBindPort('');
      setForwardHost('');
      setForwardPort('');
      setReverse(false);
      await loadTunnels();
    } catch (err: any) {
      setError(err.message || 'Failed to start port forward');
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async (tunnel: PortForward) => {
    const id = uuidToHex(tunnel.id?.value);
    setStoppingId(id);
    try {
      await proxyClient.stopPortForward({
        forwardId: tunnel.id,
      });
      await loadTunnels();
    } catch (err: any) {
      setError(err.message || 'Failed to stop port forward');
    } finally {
      setStoppingId(null);
    }
  };

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Port Forwarding</h3>
        <button
          onClick={loadTunnels}
          disabled={listLoading}
          className="p-1.5 rounded hover:bg-ctp-surface0 disabled:opacity-40 transition-colors"
          title="Refresh"
        >
          <svg className={`w-4 h-4 text-ctp-subtext0 ${listLoading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>

      {/* Add tunnel form */}
      <div className="rounded border border-ctp-surface2 bg-ctp-surface0 p-3 space-y-3">
        <p className="text-xs text-ctp-subtext0 uppercase tracking-wide">Add Tunnel</p>

        <div className="grid grid-cols-3 gap-2">
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Bind Port</label>
            <input
              type="number"
              min="1"
              max="65535"
              value={bindPort}
              onChange={e => setBindPort(e.target.value)}
              placeholder="8080"
              disabled={loading}
              className="w-full bg-ctp-mantle border border-ctp-surface2 rounded px-2 py-1.5 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
            />
          </div>
          <div className="col-span-2">
            <label className="block text-xs text-ctp-subtext0 mb-1">Forward Address (host:port)</label>
            <div className="flex gap-1">
              <input
                type="text"
                value={forwardHost}
                onChange={e => setForwardHost(e.target.value)}
                placeholder="192.168.1.100"
                disabled={loading}
                className="flex-1 bg-ctp-mantle border border-ctp-surface2 rounded px-2 py-1.5 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
              />
              <input
                type="number"
                min="1"
                max="65535"
                value={forwardPort}
                onChange={e => setForwardPort(e.target.value)}
                placeholder="3389"
                disabled={loading}
                className="w-20 bg-ctp-mantle border border-ctp-surface2 rounded px-2 py-1.5 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <div
              onClick={() => setReverse(r => !r)}
              className={`relative w-9 h-5 rounded-full transition-colors ${reverse ? 'bg-ctp-blue' : 'bg-ctp-surface2'}`}
            >
              <span
                className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-ctp-base transition-transform ${reverse ? 'translate-x-4' : ''}`}
              />
            </div>
            <span className="text-xs text-ctp-subtext0">
              {reverse ? 'Reverse (remote → local)' : 'Forward (local → remote)'}
            </span>
          </label>

          <button
            onClick={handleStart}
            disabled={loading}
            className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Starting...' : 'Start'}
          </button>
        </div>
      </div>

      {error && (
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
          {error}
        </div>
      )}

      {/* Active tunnels table */}
      <div className="rounded border border-ctp-surface2 bg-ctp-surface0 overflow-hidden">
        <div className="px-3 py-2 border-b border-ctp-surface2">
          <p className="text-xs text-ctp-subtext0 uppercase tracking-wide">
            Active Tunnels {tunnels.length > 0 && `(${tunnels.length})`}
          </p>
        </div>
        {listLoading && tunnels.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-ctp-subtext0">Loading...</div>
        ) : tunnels.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-ctp-subtext0">
            No active tunnels.
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-ctp-crust">
              <tr className="text-left text-ctp-subtext0">
                <th className="px-3 py-1.5 font-medium w-16">Port</th>
                <th className="px-3 py-1.5 font-medium">Forward Address</th>
                <th className="px-3 py-1.5 font-medium w-20">Direction</th>
                <th className="px-3 py-1.5 font-medium w-16">Status</th>
                <th className="px-3 py-1.5 font-medium w-14"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface1">
              {tunnels.map((tunnel) => {
                const id = uuidToHex(tunnel.id?.value);
                const { label, className } = stateLabel(tunnel.state);
                return (
                  <tr key={id} className="hover:bg-ctp-surface1/50">
                    <td className="px-3 py-1.5 font-mono text-ctp-text">{tunnel.localPort}</td>
                    <td className="px-3 py-1.5 font-mono text-ctp-text">
                      {tunnel.remoteHost}:{tunnel.remotePort}
                    </td>
                    <td className="px-3 py-1.5">
                      <span className={`px-1.5 py-0.5 rounded font-medium ${tunnel.reverse ? 'bg-ctp-mauve/20 text-ctp-mauve' : 'bg-ctp-sapphire/20 text-ctp-sapphire'}`}>
                        {tunnel.reverse ? 'Reverse' : 'Forward'}
                      </span>
                    </td>
                    <td className="px-3 py-1.5">
                      <span className={`px-1.5 py-0.5 rounded font-medium ${className}`}>
                        {label}
                      </span>
                    </td>
                    <td className="px-3 py-1.5">
                      <button
                        onClick={() => handleStop(tunnel)}
                        disabled={stoppingId === id}
                        className="px-2 py-0.5 rounded text-xs bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {stoppingId === id ? '...' : 'Stop'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
