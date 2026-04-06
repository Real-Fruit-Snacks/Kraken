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

type LateralMethod = 'psexec' | 'wmi' | 'dcom' | 'winrm' | 'schtask';

interface MethodConfig {
  label: string;
  risk: 'HIGH' | 'MEDIUM' | 'LOW';
  riskColor: string;
  taskNameField: boolean;
}

const METHODS: Record<LateralMethod, MethodConfig> = {
  psexec:  { label: 'PSExec',  risk: 'HIGH',   riskColor: 'bg-ctp-red/20 text-ctp-red border-ctp-red/30',     taskNameField: false },
  wmi:     { label: 'WMI',     risk: 'MEDIUM',  riskColor: 'bg-ctp-yellow/20 text-ctp-yellow border-ctp-yellow/30', taskNameField: false },
  dcom:    { label: 'DCOM',    risk: 'MEDIUM',  riskColor: 'bg-ctp-yellow/20 text-ctp-yellow border-ctp-yellow/30', taskNameField: false },
  winrm:   { label: 'WinRM',   risk: 'LOW',     riskColor: 'bg-ctp-green/20 text-ctp-green border-ctp-green/30',   taskNameField: false },
  schtask: { label: 'SchTask', risk: 'MEDIUM',  riskColor: 'bg-ctp-yellow/20 text-ctp-yellow border-ctp-yellow/30', taskNameField: true  },
};

export function LateralPanel({ sessionId }: Props) {
  const [method, setMethod] = useState<LateralMethod>('wmi');
  const [target, setTarget] = useState('');
  const [command, setCommand] = useState('');
  const [taskName, setTaskName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);

  const cfg = METHODS[method];

  const handleExecute = async () => {
    if (!target.trim() || !command.trim()) {
      setError('Target host and command are required.');
      return;
    }
    setLoading(true);
    setError(null);
    setTaskId(null);
    try {
      const encoder = new TextEncoder();
      const parts = cfg.taskNameField && taskName.trim()
        ? [method, target.trim(), taskName.trim(), command.trim()]
        : [method, target.trim(), command.trim()];
      const taskData = encoder.encode(parts.join('\0')) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'lateral',
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

  return (
    <div className="p-4 space-y-4">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Lateral Movement</h3>

      {/* Method selector */}
      <div className="space-y-2">
        <label className="text-xs text-ctp-subtext0 uppercase tracking-wide">Method</label>
        <div className="flex flex-wrap gap-2">
          {(Object.keys(METHODS) as LateralMethod[]).map((m) => (
            <button
              key={m}
              onClick={() => setMethod(m)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors border ${
                method === m
                  ? 'bg-ctp-mauve text-ctp-base border-ctp-mauve'
                  : 'bg-ctp-surface0 text-ctp-text border-ctp-surface2 hover:bg-ctp-surface1'
              }`}
            >
              {METHODS[m].label}
            </button>
          ))}
        </div>
      </div>

      {/* OPSEC risk badge */}
      <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${cfg.riskColor}`}>
        OPSEC Risk: {cfg.risk}
      </div>

      {/* Fields */}
      <div className="space-y-3">
        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">Target Host</label>
          <input
            type="text"
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="192.168.1.10 or HOSTNAME"
            className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve"
          />
        </div>

        {cfg.taskNameField && (
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Task Name</label>
            <input
              type="text"
              value={taskName}
              onChange={e => setTaskName(e.target.value)}
              placeholder="e.g. WindowsUpdate"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve"
            />
          </div>
        )}

        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">Command</label>
          <input
            type="text"
            value={command}
            onChange={e => setCommand(e.target.value)}
            placeholder="cmd.exe /c whoami"
            className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve"
          />
        </div>
      </div>

      <button
        onClick={handleExecute}
        disabled={loading}
        className="px-4 py-2 rounded text-sm font-medium bg-ctp-mauve text-ctp-base hover:bg-ctp-mauve/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Dispatching...' : 'Execute'}
      </button>

      {error && (
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
          {error}
        </div>
      )}

      {taskId && (
        <div className="text-xs text-ctp-subtext0">
          Task ID: <span className="font-mono text-ctp-blue">{taskId}</span>
        </div>
      )}
    </div>
  );
}
