import { useState } from 'react';
import { taskClient } from '../../api';

interface Props {
  sessionId: string;
}

type Protocol = 'SMB' | 'HTTP' | 'LDAP';

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function NTLMRelayPanel({ sessionId }: Props) {
  const [listenerHost, setListenerHost] = useState('');
  const [listenerPort, setListenerPort] = useState('445');
  const [targetHost, setTargetHost] = useState('');
  const [targetPort, setTargetPort] = useState('445');
  const [protocol, setProtocol] = useState<Protocol>('SMB');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [isRelayActive, setIsRelayActive] = useState(false);

  const validate = (): string | null => {
    if (!listenerHost.trim()) return 'Listener host is required.';
    if (!listenerPort.trim() || isNaN(Number(listenerPort))) return 'Valid listener port is required.';
    if (!targetHost.trim()) return 'Target host is required.';
    if (!targetPort.trim() || isNaN(Number(targetPort))) return 'Valid target port is required.';
    return null;
  };

  const handleStartRelay = async () => {
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      // Encode as null-separated args: listener_host\0listener_port\0target_host\0target_port\0protocol
      const args = [
        listenerHost.trim(),
        listenerPort.trim(),
        targetHost.trim(),
        targetPort.trim(),
        protocol,
      ];
      const encoded = args.join('\0');
      const taskData = new TextEncoder().encode(encoded) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'ntlm_relay',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskId(id);
      setIsRelayActive(true);
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch task');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">NTLM Relay</h3>
        <span
          className={`inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-full font-medium ${
            isRelayActive
              ? 'bg-ctp-peach/20 text-ctp-peach'
              : 'bg-ctp-surface1 text-ctp-subtext0'
          }`}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${isRelayActive ? 'bg-ctp-peach animate-pulse' : 'bg-ctp-subtext0'}`}
          />
          {isRelayActive ? 'Relay Active' : 'Idle'}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">Listener Host</label>
          <input
            type="text"
            value={listenerHost}
            onChange={e => setListenerHost(e.target.value)}
            placeholder="0.0.0.0"
            disabled={loading}
            className="w-full bg-ctp-surface0 border border-ctp-surface2 rounded px-3 py-2 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
          />
        </div>
        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">Listener Port</label>
          <input
            type="number"
            min="1"
            max="65535"
            value={listenerPort}
            onChange={e => setListenerPort(e.target.value)}
            disabled={loading}
            className="w-full bg-ctp-surface0 border border-ctp-surface2 rounded px-3 py-2 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
          />
        </div>
        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">Target Host</label>
          <input
            type="text"
            value={targetHost}
            onChange={e => setTargetHost(e.target.value)}
            placeholder="192.168.1.100"
            disabled={loading}
            className="w-full bg-ctp-surface0 border border-ctp-surface2 rounded px-3 py-2 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
          />
        </div>
        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">Target Port</label>
          <input
            type="number"
            min="1"
            max="65535"
            value={targetPort}
            onChange={e => setTargetPort(e.target.value)}
            disabled={loading}
            className="w-full bg-ctp-surface0 border border-ctp-surface2 rounded px-3 py-2 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
          />
        </div>
        <div className="col-span-2">
          <label className="block text-xs text-ctp-subtext0 mb-1">Protocol</label>
          <select
            value={protocol}
            onChange={e => setProtocol(e.target.value as Protocol)}
            disabled={loading}
            className="w-full bg-ctp-surface0 border border-ctp-surface2 rounded px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-blue disabled:opacity-50"
          >
            <option value="SMB">SMB</option>
            <option value="HTTP">HTTP</option>
            <option value="LDAP">LDAP</option>
          </select>
        </div>
      </div>

      <button
        onClick={handleStartRelay}
        disabled={loading}
        className="px-4 py-2 rounded text-sm font-medium bg-ctp-mauve text-ctp-base hover:bg-ctp-mauve/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Dispatching...' : 'Start Relay'}
      </button>

      {error && (
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
          {error}
        </div>
      )}

      {taskId && (
        <div className="rounded border border-ctp-surface2 bg-ctp-surface0 p-3 space-y-1">
          <p className="text-xs text-ctp-subtext0 uppercase tracking-wide">Active Relay</p>
          <div className="text-xs font-mono text-ctp-subtext0">
            Task ID: <span className="text-ctp-blue">{taskId}</span>
          </div>
          <div className="text-xs text-ctp-subtext0">
            <span className="text-ctp-text">{listenerHost}:{listenerPort}</span>
            <span className="mx-2 text-ctp-overlay0">→</span>
            <span className="text-ctp-text">{targetHost}:{targetPort}</span>
            <span className="ml-2 px-1.5 py-0.5 rounded bg-ctp-mauve/20 text-ctp-mauve font-medium">{protocol}</span>
          </div>
        </div>
      )}
    </div>
  );
}
