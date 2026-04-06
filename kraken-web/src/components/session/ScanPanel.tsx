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

type ScanMode = 'portscan' | 'pingsweep' | 'shareenum';

interface ScanResult {
  host: string;
  port?: string;
  status: string;
  info?: string;
}

export function ScanPanel({ sessionId }: Props) {
  const [mode, setMode] = useState<ScanMode>('portscan');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [sortCol, setSortCol] = useState<keyof ScanResult>('host');
  const [sortAsc, setSortAsc] = useState(true);

  // Port scan fields
  const [psTarget, setPsTarget] = useState('');
  const [psPorts, setPsPorts] = useState('1-1024');
  const [psThreads, setPsThreads] = useState('');
  const [psTimeout, setPsTimeout] = useState('');

  // Ping sweep fields
  const [pingSubnet, setPingSubnet] = useState('');
  const [pingTimeout, setPingTimeout] = useState('');

  // Share enum fields
  const [shareTarget, setShareTarget] = useState('');

  const dispatchTask = async (payload: string) => {
    setLoading(true);
    setError(null);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(payload) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'scan',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskId(id);
      setResults([{ host: 'Task dispatched', status: 'Pending', info: 'Results will appear in the task stream.' }]);
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch task');
    } finally {
      setLoading(false);
    }
  };

  const handleScan = () => {
    if (mode === 'portscan') {
      if (!psTarget.trim()) { setError('Target is required'); return; }
      const parts = ['ports', psTarget.trim(), psPorts.trim(), psThreads.trim(), psTimeout.trim()];
      dispatchTask(parts.join('\0'));
    } else if (mode === 'pingsweep') {
      if (!pingSubnet.trim()) { setError('Subnet is required'); return; }
      const parts = ['ping', pingSubnet.trim(), pingTimeout.trim()];
      dispatchTask(parts.join('\0'));
    } else {
      if (!shareTarget.trim()) { setError('Target is required'); return; }
      const parts = ['shares', shareTarget.trim()];
      dispatchTask(parts.join('\0'));
    }
  };

  const handleSort = (col: keyof ScanResult) => {
    if (sortCol === col) {
      setSortAsc(!sortAsc);
    } else {
      setSortCol(col);
      setSortAsc(true);
    }
  };

  const sortedResults = [...results].sort((a, b) => {
    const av = a[sortCol] ?? '';
    const bv = b[sortCol] ?? '';
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  });

  const SortIcon = ({ col }: { col: keyof ScanResult }) => (
    <span className="ml-1 text-ctp-overlay0">
      {sortCol === col ? (sortAsc ? '▲' : '▼') : '⇅'}
    </span>
  );

  return (
    <div className="p-4 space-y-4">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Network Scan</h3>

      {/* Mode selector */}
      <div className="flex gap-1 p-1 bg-ctp-surface0 rounded">
        {(['portscan', 'pingsweep', 'shareenum'] as ScanMode[]).map(m => (
          <button
            key={m}
            onClick={() => { setMode(m); setError(null); }}
            className={`flex-1 py-1.5 text-xs font-medium rounded transition-colors ${
              mode === m
                ? 'bg-ctp-blue text-ctp-base'
                : 'text-ctp-subtext0 hover:text-ctp-text'
            }`}
          >
            {m === 'portscan' ? 'Port Scan' : m === 'pingsweep' ? 'Ping Sweep' : 'Share Enum'}
          </button>
        ))}
      </div>

      {/* Port scan form */}
      {mode === 'portscan' && (
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-xs text-ctp-subtext0 mb-1">Target</label>
              <input
                type="text"
                value={psTarget}
                onChange={e => setPsTarget(e.target.value)}
                placeholder="192.168.1.1"
                className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
              />
            </div>
            <div>
              <label className="block text-xs text-ctp-subtext0 mb-1">Ports</label>
              <input
                type="text"
                value={psPorts}
                onChange={e => setPsPorts(e.target.value)}
                placeholder="1-1024"
                className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
              />
            </div>
            <div>
              <label className="block text-xs text-ctp-subtext0 mb-1">Threads (optional)</label>
              <input
                type="number"
                value={psThreads}
                onChange={e => setPsThreads(e.target.value)}
                placeholder="10"
                className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
              />
            </div>
            <div>
              <label className="block text-xs text-ctp-subtext0 mb-1">Timeout ms (optional)</label>
              <input
                type="number"
                value={psTimeout}
                onChange={e => setPsTimeout(e.target.value)}
                placeholder="1000"
                className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
              />
            </div>
          </div>
        </div>
      )}

      {/* Ping sweep form */}
      {mode === 'pingsweep' && (
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Subnet</label>
            <input
              type="text"
              value={pingSubnet}
              onChange={e => setPingSubnet(e.target.value)}
              placeholder="192.168.1.0/24"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
          <div>
            <label className="block text-xs text-ctp-subtext0 mb-1">Timeout ms (optional)</label>
            <input
              type="number"
              value={pingTimeout}
              onChange={e => setPingTimeout(e.target.value)}
              placeholder="1000"
              className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
            />
          </div>
        </div>
      )}

      {/* Share enum form */}
      {mode === 'shareenum' && (
        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">Target</label>
          <input
            type="text"
            value={shareTarget}
            onChange={e => setShareTarget(e.target.value)}
            placeholder="192.168.1.10"
            className="w-full px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
          />
        </div>
      )}

      <button
        onClick={handleScan}
        disabled={loading}
        className="px-4 py-2 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Dispatching...' : 'Scan'}
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

      {results.length > 0 && (
        <div className="rounded border border-ctp-surface2 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-ctp-surface0">
              <tr className="text-left text-ctp-subtext0">
                <th
                  className="px-3 py-2 font-medium cursor-pointer hover:text-ctp-text select-none"
                  onClick={() => handleSort('host')}
                >
                  Host <SortIcon col="host" />
                </th>
                {mode === 'portscan' && (
                  <th
                    className="px-3 py-2 font-medium cursor-pointer hover:text-ctp-text select-none"
                    onClick={() => handleSort('port')}
                  >
                    Port <SortIcon col="port" />
                  </th>
                )}
                <th
                  className="px-3 py-2 font-medium cursor-pointer hover:text-ctp-text select-none"
                  onClick={() => handleSort('status')}
                >
                  Status <SortIcon col="status" />
                </th>
                <th
                  className="px-3 py-2 font-medium cursor-pointer hover:text-ctp-text select-none"
                  onClick={() => handleSort('info')}
                >
                  Info <SortIcon col="info" />
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {sortedResults.map((r, i) => (
                <tr key={i} className="hover:bg-ctp-surface0/50">
                  <td className="px-3 py-2 font-mono text-ctp-text text-xs">{r.host}</td>
                  {mode === 'portscan' && (
                    <td className="px-3 py-2 font-mono text-ctp-text text-xs">{r.port ?? '-'}</td>
                  )}
                  <td className="px-3 py-2 text-xs">
                    <span
                      className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                        r.status === 'open' || r.status === 'up'
                          ? 'bg-ctp-green/20 text-ctp-green'
                          : r.status === 'Pending'
                          ? 'bg-ctp-yellow/20 text-ctp-yellow'
                          : 'bg-ctp-surface1 text-ctp-subtext0'
                      }`}
                    >
                      {r.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-ctp-subtext0 text-xs">{r.info ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
