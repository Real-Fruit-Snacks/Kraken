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

type InfoTab = 'sysinfo' | 'netinfo' | 'envvars' | 'whoami';

const TABS: { id: InfoTab; label: string; subcommand: string }[] = [
  { id: 'sysinfo', label: 'System Info', subcommand: 'sysinfo' },
  { id: 'netinfo', label: 'Network Info', subcommand: 'netinfo' },
  { id: 'envvars', label: 'Env Vars', subcommand: 'envvars' },
  { id: 'whoami', label: 'Whoami', subcommand: 'whoami' },
];

export function EnvironmentPanel({ sessionId }: Props) {
  const [activeTab, setActiveTab] = useState<InfoTab>('sysinfo');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskIds, setTaskIds] = useState<Partial<Record<InfoTab, string>>>({});
  const [results, setResults] = useState<Partial<Record<InfoTab, string>>>({});

  const dispatchTask = async (tab: InfoTab, subcommand: string) => {
    setLoading(true);
    setError(null);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(subcommand) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'env',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskIds(prev => ({ ...prev, [tab]: id }));
      setResults(prev => ({ ...prev, [tab]: 'Task dispatched — results will appear in the task stream.' }));
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch task');
    } finally {
      setLoading(false);
    }
  };

  const handleFetch = () => {
    const tab = TABS.find(t => t.id === activeTab)!;
    dispatchTask(tab.id, tab.subcommand);
  };

  const currentTaskId = taskIds[activeTab];
  const currentResult = results[activeTab];

  return (
    <div className="p-4 space-y-4">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Environment</h3>

      {/* Tab selector */}
      <div className="flex gap-1 border-b border-ctp-surface2 pb-0">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-2 text-sm font-medium rounded-t transition-colors -mb-px ${
              activeTab === tab.id
                ? 'bg-ctp-surface0 text-ctp-text border border-b-ctp-surface0 border-ctp-surface2'
                : 'text-ctp-subtext0 hover:text-ctp-text hover:bg-ctp-surface0/50'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Fetch button */}
      <button
        onClick={handleFetch}
        disabled={loading}
        className="px-4 py-2 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Dispatching...' : `Fetch ${TABS.find(t => t.id === activeTab)?.label}`}
      </button>

      {error && (
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
          {error}
        </div>
      )}

      {currentTaskId && (
        <div className="text-xs text-ctp-subtext0">
          Task ID: <span className="font-mono text-ctp-blue">{currentTaskId}</span>
        </div>
      )}

      {currentResult && (
        <div className="rounded border border-ctp-surface2 bg-ctp-surface0 p-3">
          <p className="text-xs text-ctp-subtext0 mb-1 uppercase tracking-wide">
            {TABS.find(t => t.id === activeTab)?.label}
          </p>
          <pre className="text-sm text-ctp-text font-mono whitespace-pre-wrap">{currentResult}</pre>
        </div>
      )}
    </div>
  );
}
