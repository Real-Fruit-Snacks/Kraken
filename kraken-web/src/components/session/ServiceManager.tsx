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

interface ServiceEntry {
  name: string;
  status: string;
  startType: string;
}

export function ServiceManager({ sessionId }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [services] = useState<ServiceEntry[]>([]);

  // Create service form
  const [createName, setCreateName] = useState('');
  const [createBinPath, setCreateBinPath] = useState('');
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Modify dialog
  const [modifyTarget, setModifyTarget] = useState('');
  const [modifyField, setModifyField] = useState('');
  const [modifyValue, setModifyValue] = useState('');
  const [showModifyForm, setShowModifyForm] = useState(false);

  const dispatch = async (subcommand: string, label: string) => {
    setLoading(true);
    setError(null);
    setTaskId(null);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(subcommand) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'svc',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskId(id);
      return id;
    } catch (err: any) {
      setError(err.message || `Failed to dispatch ${label}`);
      return null;
    } finally {
      setLoading(false);
    }
  };

  const handleList = () => dispatch('list', 'list services');

  const handleStart = (name: string) => dispatch(`start\0${name}`, `start ${name}`);
  const handleStop  = (name: string) => dispatch(`stop\0${name}`,  `stop ${name}`);
  const handleDelete = (name: string) => dispatch(`delete\0${name}`, `delete ${name}`);

  const handleCreate = async () => {
    if (!createName.trim() || !createBinPath.trim()) {
      setError('Service name and binary path are required.');
      return;
    }
    const id = await dispatch(`create\0${createName.trim()}\0${createBinPath.trim()}`, 'create service');
    if (id) {
      setCreateName('');
      setCreateBinPath('');
      setShowCreateForm(false);
    }
  };

  const handleModify = async () => {
    if (!modifyTarget.trim() || !modifyField.trim() || !modifyValue.trim()) {
      setError('Service name, field, and value are required.');
      return;
    }
    const id = await dispatch(
      `modify\0${modifyTarget.trim()}\0${modifyField.trim()}\0${modifyValue.trim()}`,
      'modify service'
    );
    if (id) {
      setModifyTarget('');
      setModifyField('');
      setModifyValue('');
      setShowModifyForm(false);
    }
  };

  const statusColor = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'running') return 'text-ctp-green';
    if (s === 'stopped') return 'text-ctp-red';
    return 'text-ctp-yellow';
  };

  return (
    <div className="p-4 space-y-4">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Service Manager</h3>

      {/* Toolbar */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={handleList}
          disabled={loading}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Loading...' : 'List Services'}
        </button>
        <button
          onClick={() => { setShowCreateForm(!showCreateForm); setShowModifyForm(false); }}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors border border-ctp-surface2"
        >
          Create Service
        </button>
        <button
          onClick={() => { setShowModifyForm(!showModifyForm); setShowCreateForm(false); }}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors border border-ctp-surface2"
        >
          Modify Service
        </button>
      </div>

      {/* Create form */}
      {showCreateForm && (
        <div className="space-y-2 p-3 rounded bg-ctp-surface0 border border-ctp-surface2">
          <p className="text-xs text-ctp-subtext0 uppercase tracking-wide font-medium">Create Service</p>
          <input
            type="text"
            value={createName}
            onChange={e => setCreateName(e.target.value)}
            placeholder="Service name"
            className="w-full px-3 py-1.5 rounded bg-ctp-base border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-green"
          />
          <input
            type="text"
            value={createBinPath}
            onChange={e => setCreateBinPath(e.target.value)}
            placeholder="Binary path (e.g. C:\Windows\evil.exe)"
            className="w-full px-3 py-1.5 rounded bg-ctp-base border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-green"
          />
          <div className="flex gap-2">
            <button
              onClick={handleCreate}
              disabled={loading}
              className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-green text-ctp-base hover:bg-ctp-green/80 transition-colors disabled:opacity-50"
            >
              Create
            </button>
            <button
              onClick={() => setShowCreateForm(false)}
              className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Modify form */}
      {showModifyForm && (
        <div className="space-y-2 p-3 rounded bg-ctp-surface0 border border-ctp-surface2">
          <p className="text-xs text-ctp-subtext0 uppercase tracking-wide font-medium">Modify Service</p>
          <input
            type="text"
            value={modifyTarget}
            onChange={e => setModifyTarget(e.target.value)}
            placeholder="Service name"
            className="w-full px-3 py-1.5 rounded bg-ctp-base border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-yellow"
          />
          <input
            type="text"
            value={modifyField}
            onChange={e => setModifyField(e.target.value)}
            placeholder="Field (e.g. binpath, start_type)"
            className="w-full px-3 py-1.5 rounded bg-ctp-base border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-yellow"
          />
          <input
            type="text"
            value={modifyValue}
            onChange={e => setModifyValue(e.target.value)}
            placeholder="New value"
            className="w-full px-3 py-1.5 rounded bg-ctp-base border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-yellow"
          />
          <div className="flex gap-2">
            <button
              onClick={handleModify}
              disabled={loading}
              className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-yellow text-ctp-base hover:bg-ctp-yellow/80 transition-colors disabled:opacity-50"
            >
              Modify
            </button>
            <button
              onClick={() => setShowModifyForm(false)}
              className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

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

      {/* Service table */}
      {services.length > 0 ? (
        <div className="rounded border border-ctp-surface2 overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-ctp-crust sticky top-0">
              <tr className="text-left text-ctp-subtext0">
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium w-28">Status</th>
                <th className="px-3 py-2 font-medium w-32">Start Type</th>
                <th className="px-3 py-2 font-medium w-36">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {services.map((svc) => (
                <tr key={svc.name} className="hover:bg-ctp-surface0/50">
                  <td className="px-3 py-2 text-ctp-text font-mono text-xs">{svc.name}</td>
                  <td className={`px-3 py-2 text-xs font-medium ${statusColor(svc.status)}`}>
                    {svc.status}
                  </td>
                  <td className="px-3 py-2 text-xs text-ctp-subtext0">{svc.startType}</td>
                  <td className="px-3 py-2">
                    <div className="flex gap-1">
                      <button
                        onClick={() => handleStart(svc.name)}
                        disabled={loading}
                        title="Start"
                        className="px-2 py-0.5 rounded text-xs bg-ctp-green/20 text-ctp-green hover:bg-ctp-green/30 transition-colors disabled:opacity-50"
                      >
                        Start
                      </button>
                      <button
                        onClick={() => handleStop(svc.name)}
                        disabled={loading}
                        title="Stop"
                        className="px-2 py-0.5 rounded text-xs bg-ctp-yellow/20 text-ctp-yellow hover:bg-ctp-yellow/30 transition-colors disabled:opacity-50"
                      >
                        Stop
                      </button>
                      <button
                        onClick={() => handleDelete(svc.name)}
                        disabled={loading}
                        title="Delete"
                        className="px-2 py-0.5 rounded text-xs bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/30 transition-colors disabled:opacity-50"
                      >
                        Del
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex items-center justify-center h-20 rounded border border-ctp-surface2 text-ctp-subtext0 text-sm">
          Click "List Services" to populate the table.
        </div>
      )}
    </div>
  );
}
