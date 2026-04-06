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

export function ClipboardPanel({ sessionId }: Props) {
  const [setText, setSetText] = useState('');
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  const dispatchTask = async (payload: string) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(payload) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'clipboard',
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

  const handleGet = async () => {
    const id = await dispatchTask('get');
    if (id) setResult('Get dispatched — results will appear in the task stream.');
  };

  const handleSet = async () => {
    if (!setText.trim()) return;
    const id = await dispatchTask(`set\0${setText}`);
    if (id) setResult(`Set clipboard to: "${setText}"`);
  };

  const handleMonitorToggle = async () => {
    const subcommand = isMonitoring ? 'monitor_stop' : 'monitor_start';
    const id = await dispatchTask(subcommand);
    if (id) setIsMonitoring(!isMonitoring);
  };

  const handleDump = async () => {
    const id = await dispatchTask('dump');
    if (id) setResult('Dump dispatched — results will appear in the task stream.');
  };

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Clipboard</h3>
        <span
          className={`inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-full font-medium ${
            isMonitoring
              ? 'bg-ctp-green/20 text-ctp-green'
              : 'bg-ctp-surface1 text-ctp-subtext0'
          }`}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${isMonitoring ? 'bg-ctp-green animate-pulse' : 'bg-ctp-subtext0'}`}
          />
          {isMonitoring ? 'Monitoring' : 'Idle'}
        </span>
      </div>

      {/* Get / Dump / Monitor row */}
      <div className="flex gap-2 flex-wrap">
        <button
          onClick={handleGet}
          disabled={loading}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Get
        </button>
        <button
          onClick={handleDump}
          disabled={loading}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Dump
        </button>
        <button
          onClick={handleMonitorToggle}
          disabled={loading}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
            isMonitoring
              ? 'bg-ctp-red text-ctp-base hover:bg-ctp-red/80'
              : 'bg-ctp-green text-ctp-base hover:bg-ctp-green/80'
          }`}
        >
          {isMonitoring ? 'Stop Monitor' : 'Start Monitor'}
        </button>
      </div>

      {/* Set clipboard */}
      <div className="flex gap-2">
        <input
          type="text"
          value={setText}
          onChange={e => setSetText(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSet()}
          placeholder="Text to set on clipboard..."
          className="flex-1 px-3 py-2 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue"
        />
        <button
          onClick={handleSet}
          disabled={loading || !setText.trim()}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-mauve text-ctp-base hover:bg-ctp-mauve/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Set
        </button>
      </div>

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
        <div className="rounded border border-ctp-surface2 bg-ctp-surface0 p-3">
          <p className="text-xs text-ctp-subtext0 mb-1 uppercase tracking-wide">Result</p>
          <pre className="text-sm text-ctp-text font-mono whitespace-pre-wrap">{result}</pre>
        </div>
      )}
    </div>
  );
}
