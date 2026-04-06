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

type RegType = 'REG_SZ' | 'REG_DWORD' | 'REG_BINARY' | 'REG_EXPAND_SZ' | 'REG_MULTI_SZ';
const REG_TYPES: RegType[] = ['REG_SZ', 'REG_DWORD', 'REG_BINARY', 'REG_EXPAND_SZ', 'REG_MULTI_SZ'];

interface RegEntry {
  name: string;
  type: string;
  data: string;
}

export function RegistryBrowser({ sessionId }: Props) {
  // Browse / query
  const [browsePath, setBrowsePath] = useState('HKLM\\SOFTWARE');
  const [queryPath, setQueryPath] = useState('');

  // Set form
  const [setPath, setSetPath] = useState('');
  const [setName, setSetName] = useState('');
  const [setType, setSetType] = useState<RegType>('REG_SZ');
  const [setData, setSetData] = useState('');

  // Delete
  const [deletePath, setDeletePath] = useState('');
  const [deleteName, setDeleteName] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [entries, setEntries] = useState<RegEntry[]>([]);
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
        taskType: 'reg',
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

  const handleEnumKeys = async () => {
    if (!browsePath.trim()) { setError('Path is required'); return; }
    const id = await dispatchTask(`enum\0${browsePath.trim()}`);
    if (id) {
      setEntries([{ name: '(pending)', type: '—', data: 'Results will appear in the task stream.' }]);
      setStatusMsg(null);
    }
  };

  const handleQuery = async () => {
    const path = queryPath.trim() || browsePath.trim();
    if (!path) { setError('Path is required'); return; }
    const id = await dispatchTask(`query\0${path}`);
    if (id) {
      setEntries([{ name: '(pending)', type: '—', data: 'Results will appear in the task stream.' }]);
      setStatusMsg(null);
    }
  };

  const handleSet = async () => {
    if (!setPath.trim()) { setError('Path is required'); return; }
    if (!setName.trim()) { setError('Value name is required'); return; }
    if (!setData.trim()) { setError('Data is required'); return; }
    const parts = ['set', setPath.trim(), setName.trim(), setType, setData.trim()];
    const id = await dispatchTask(parts.join('\0'));
    if (id) {
      setStatusMsg(`Set "${setName}" dispatched.`);
      setSetName('');
      setSetData('');
    }
  };

  const handleDelete = async () => {
    if (!deletePath.trim()) { setError('Path is required'); return; }
    const parts = ['delete', deletePath.trim(), deleteName.trim()];
    const id = await dispatchTask(parts.join('\0'));
    if (id) {
      setStatusMsg(`Delete dispatched for ${deleteName.trim() ? `"${deleteName}"` : `key "${deletePath}"`}.`);
      setDeleteName('');
    }
  };

  return (
    <div className="p-4 space-y-5">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Registry Browser</h3>

      {/* Enumerate Keys */}
      <div className="space-y-2 p-3 rounded border border-ctp-surface2 bg-ctp-surface0/40">
        <p className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Enumerate Keys</p>
        <div className="flex gap-2">
          <input
            type="text"
            value={browsePath}
            onChange={e => setBrowsePath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleEnumKeys()}
            placeholder="HKLM\SOFTWARE"
            className="flex-1 px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm font-mono placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
          />
          <button
            onClick={handleEnumKeys}
            disabled={loading}
            className="px-4 py-2 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Enumerate
          </button>
        </div>
      </div>

      {/* Query */}
      <div className="space-y-2 p-3 rounded border border-ctp-surface2 bg-ctp-surface0/40">
        <p className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Query Value</p>
        <div className="flex gap-2">
          <input
            type="text"
            value={queryPath}
            onChange={e => setQueryPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleQuery()}
            placeholder="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
            className="flex-1 px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm font-mono placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
          />
          <button
            onClick={handleQuery}
            disabled={loading}
            className="px-4 py-2 rounded text-sm font-medium bg-ctp-mauve text-ctp-base hover:bg-ctp-mauve/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Query
          </button>
        </div>
      </div>

      {/* Set Value */}
      <div className="space-y-2 p-3 rounded border border-ctp-surface2 bg-ctp-surface0/40">
        <p className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Set Value</p>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Path</label>
            <input
              type="text"
              value={setPath}
              onChange={e => setSetPath(e.target.value)}
              placeholder="HKCU\SOFTWARE\MyApp"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm font-mono placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Value Name</label>
            <input
              type="text"
              value={setName}
              onChange={e => setSetName(e.target.value)}
              placeholder="MyValue"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Type</label>
            <select
              value={setType}
              onChange={e => setSetType(e.target.value as RegType)}
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-blue"
            >
              {REG_TYPES.map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Data</label>
            <input
              type="text"
              value={setData}
              onChange={e => setSetData(e.target.value)}
              placeholder="value data"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
        </div>
        <button
          onClick={handleSet}
          disabled={loading}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-green text-ctp-base hover:bg-ctp-green/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Dispatching...' : 'Set Value'}
        </button>
      </div>

      {/* Delete */}
      <div className="space-y-2 p-3 rounded border border-ctp-surface2 bg-ctp-surface0/40">
        <p className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Delete</p>
        <div className="flex gap-2">
          <input
            type="text"
            value={deletePath}
            onChange={e => setDeletePath(e.target.value)}
            placeholder="HKCU\SOFTWARE\MyApp"
            className="flex-1 px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm font-mono placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
          />
          <input
            type="text"
            value={deleteName}
            onChange={e => setDeleteName(e.target.value)}
            placeholder="ValueName (blank = key)"
            className="flex-1 px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
          />
          <button
            onClick={handleDelete}
            disabled={loading || !deletePath.trim()}
            className="px-4 py-2 rounded text-sm font-medium bg-ctp-red text-ctp-base hover:bg-ctp-red/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Delete
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

      {/* Key/Value list */}
      {entries.length > 0 && (
        <div className="rounded border border-ctp-surface2 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-ctp-surface0">
              <tr className="text-left text-ctp-subtext0">
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium w-32">Type</th>
                <th className="px-3 py-2 font-medium">Data</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {entries.map((entry, i) => (
                <tr key={i} className="hover:bg-ctp-surface0/50">
                  <td className="px-3 py-2 text-ctp-text text-xs font-mono">{entry.name}</td>
                  <td className="px-3 py-2 text-xs">
                    <span className="bg-ctp-surface1 text-ctp-subtext0 px-1.5 py-0.5 rounded text-xs font-mono">
                      {entry.type}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-ctp-subtext0 text-xs font-mono truncate max-w-xs">{entry.data}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
