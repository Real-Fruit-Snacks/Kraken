import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { moduleClient, implantClient, taskClient } from '../api/index.js';
import type { ModuleInfo as ProtoModuleInfo, PlatformVersion, Implant } from '../gen/kraken_pb.js';
import { ShellTask, ImplantState } from '../gen/kraken_pb.js';
import { Modal } from '../components/Modal';

interface ModuleItem {
  id: string;
  name: string;
  description: string;
  platforms: PlatformInfo[];
}

interface PlatformInfo {
  platform: string;
  version: string;
  size: number;
  compiledAt: string;
}

function protoModuleToUI(m: ProtoModuleInfo): ModuleItem {
  return {
    id: m.id,
    name: m.name,
    description: m.description ?? '',
    platforms: m.platforms.map((p: PlatformVersion) => ({
      platform: p.platform,
      version: p.version,
      size: Number(p.size),
      compiledAt: p.compiledAt ? new Date(Number(p.compiledAt)).toLocaleString() : '',
    })),
  };
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  } else if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${bytes} B`;
}

// ---------------------------------------------------------------------------
// Module Detail Modal
// ---------------------------------------------------------------------------

function ModuleDetailModal({ module, onClose }: { module: ModuleItem; onClose: () => void }) {
  return (
    <Modal
      isOpen={true}
      onClose={onClose}
      title={module.name}
      size="lg"
      footer={
        <button
          onClick={onClose}
          className="px-4 py-2 text-sm text-ctp-subtext1 hover:text-ctp-text transition-colors"
        >
          Close
        </button>
      }
    >
      <div className="space-y-4">
        <div className="space-y-2">
          <div className="flex flex-col gap-0.5">
            <span className="text-xs text-ctp-subtext0 uppercase tracking-wide">Module ID</span>
            <span className="text-sm text-ctp-text font-mono">{module.id}</span>
          </div>
          {module.description && (
            <div className="flex flex-col gap-0.5">
              <span className="text-xs text-ctp-subtext0 uppercase tracking-wide">Description</span>
              <span className="text-sm text-ctp-text">{module.description}</span>
            </div>
          )}
        </div>

        {/* Platform versions */}
        <div className="border-t border-ctp-surface0 pt-3">
          <span className="text-xs text-ctp-subtext0 uppercase tracking-wide">Available Platforms</span>
          {module.platforms.length === 0 ? (
            <p className="text-sm text-ctp-subtext1 mt-2">No compiled versions available</p>
          ) : (
            <div className="mt-2 space-y-2">
              {module.platforms.map((p, idx) => (
                <div key={idx} className="bg-ctp-surface0 rounded-lg p-3 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="font-mono text-ctp-teal">{p.platform}</span>
                    <span className="text-ctp-subtext1">v{p.version}</span>
                  </div>
                  <div className="flex justify-between text-ctp-subtext0 text-xs mt-1">
                    <span>{formatSize(p.size)}</span>
                    {p.compiledAt && <span>Compiled: {p.compiledAt}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Usage hint */}
        <div className="border-t border-ctp-surface0 pt-3">
          <span className="text-xs text-ctp-subtext0 uppercase tracking-wide">Usage</span>
          <div className="mt-2 bg-ctp-crust rounded-lg p-3 font-mono text-sm text-ctp-text">
            <p className="text-ctp-subtext1"># Load module to an implant</p>
            <p className="text-ctp-green">module load {module.id}</p>
            <p className="text-ctp-subtext1 mt-2"># Unload module</p>
            <p className="text-ctp-red">module unload {module.id}</p>
          </div>
        </div>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Load to Session Modal
// ---------------------------------------------------------------------------

function hexFromUint8Array(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function getImplantDisplayName(implant: Implant): string {
  const info = implant.systemInfo;
  const hostname = info?.hostname || 'unknown';
  const username = info?.username || '';
  return username ? `${hostname} (${username})` : hostname;
}

function LoadToSessionModal({
  module,
  onClose,
}: {
  module: ModuleItem;
  onClose: () => void;
}) {
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const { data: implants, isLoading: sessionsLoading } = useQuery({
    queryKey: ['implants-for-module-load'],
    queryFn: async () => {
      const res = await implantClient.listImplants({});
      return (res.implants ?? []).filter(
        (imp) => imp.state === ImplantState.ACTIVE,
      );
    },
  });

  const loadMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      const shellTask = new ShellTask({ command: `module load ${module.id}` });
      const taskData = new Uint8Array(shellTask.toBinary()) as Uint8Array<ArrayBuffer>;
      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'shell',
        taskData,
      });
    },
    onSuccess: () => {
      setFeedback({ type: 'success', message: `Module "${module.name}" load command dispatched successfully.` });
    },
    onError: (err: Error) => {
      setFeedback({ type: 'error', message: `Failed to dispatch: ${err.message}` });
    },
  });

  const handleConfirm = () => {
    if (!selectedSessionId) return;
    setFeedback(null);
    loadMutation.mutate(selectedSessionId);
  };

  return (
    <Modal
      isOpen={true}
      onClose={onClose}
      title={`Load "${module.name}" to Session`}
      size="md"
      footer={
        <div className="flex gap-2 justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-ctp-subtext1 hover:text-ctp-text transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!selectedSessionId || loadMutation.isPending}
            className="px-4 py-2 text-sm bg-ctp-mauve text-ctp-base rounded-lg hover:bg-ctp-mauve/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loadMutation.isPending ? 'Dispatching...' : 'Load Module'}
          </button>
        </div>
      }
    >
      <div className="space-y-4">
        {feedback && (
          <div
            className={`p-3 rounded-lg text-sm ${
              feedback.type === 'success'
                ? 'bg-ctp-green/20 border border-ctp-green/40 text-ctp-green'
                : 'bg-ctp-red/20 border border-ctp-red/40 text-ctp-red'
            }`}
          >
            {feedback.message}
          </div>
        )}

        <p className="text-sm text-ctp-subtext1">
          Select an active session to load module{' '}
          <span className="font-mono text-ctp-teal">{module.id}</span> into.
        </p>

        {sessionsLoading ? (
          <p className="text-sm text-ctp-subtext0 py-4 text-center">Loading sessions...</p>
        ) : !implants || implants.length === 0 ? (
          <p className="text-sm text-ctp-subtext0 py-4 text-center">No active sessions available.</p>
        ) : (
          <div className="space-y-1 max-h-60 overflow-y-auto">
            {implants.map((implant) => {
              const idHex = implant.id?.value ? hexFromUint8Array(implant.id.value) : '';
              const displayName = getImplantDisplayName(implant);
              const isSelected = selectedSessionId === idHex;
              return (
                <button
                  key={idHex}
                  onClick={() => setSelectedSessionId(idHex)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                    isSelected
                      ? 'bg-ctp-mauve/20 border border-ctp-mauve/40 text-ctp-mauve'
                      : 'bg-ctp-surface0 hover:bg-ctp-surface1 text-ctp-text border border-transparent'
                  }`}
                >
                  <div className="font-medium">{displayName}</div>
                  <div className="font-mono text-xs text-ctp-subtext0 truncate">{idHex}</div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function Modules() {
  const [selectedModule, setSelectedModule] = useState<ModuleItem | null>(null);
  const [loadTargetModule, setLoadTargetModule] = useState<ModuleItem | null>(null);

  const { data: modules, isLoading, error, refetch } = useQuery({
    queryKey: ['modules'],
    queryFn: async () => {
      const res = await moduleClient.listModules({});
      return res.modules.map(protoModuleToUI);
    },
  });

  return (
    <div>
      {selectedModule && (
        <ModuleDetailModal module={selectedModule} onClose={() => setSelectedModule(null)} />
      )}
      {loadTargetModule && (
        <LoadToSessionModal module={loadTargetModule} onClose={() => setLoadTargetModule(null)} />
      )}

      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Modules</h1>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium transition-colors border border-ctp-surface1"
        >
          Refresh
        </button>
      </div>

      {/* Info banner */}
      <div className="mb-4 p-3 bg-ctp-surface0/50 border border-ctp-surface1 rounded-lg text-sm text-ctp-subtext1">
        <p>
          Dynamic modules extend implant capabilities at runtime. Load modules to active implants
          from the session detail page or via TUI commands.
        </p>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          Failed to load modules: {(error as Error).message}
        </div>
      )}

      <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
        <table className="w-full">
          <thead className="bg-ctp-crust">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">ID</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Name</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Description</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Platforms</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ctp-subtext0">
                  Loading modules...
                </td>
              </tr>
            ) : !modules || modules.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ctp-subtext0">
                  No modules registered. Use <code className="bg-ctp-surface0 px-1 rounded">just module-register</code> to add modules.
                </td>
              </tr>
            ) : (
              modules.map((module) => (
                <tr key={module.id} className="hover:bg-ctp-surface0/30">
                  <td className="px-4 py-3 font-mono text-sm text-ctp-subtext1">{module.id}</td>
                  <td className="px-4 py-3">
                    <span className="font-medium text-ctp-teal">{module.name}</span>
                  </td>
                  <td className="px-4 py-3 text-ctp-subtext1 text-sm max-w-xs truncate">
                    {module.description || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {module.platforms.length === 0 ? (
                        <span className="text-ctp-subtext0 text-sm">-</span>
                      ) : (
                        module.platforms.map((p, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 bg-ctp-surface1 rounded text-xs font-mono text-ctp-sapphire"
                            title={`${formatSize(p.size)} - v${p.version}`}
                          >
                            {p.platform.split('-')[0]}
                          </span>
                        ))
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => setSelectedModule(module)}
                        className="text-ctp-mauve hover:underline text-sm"
                      >
                        View
                      </button>
                      <button
                        onClick={() => setLoadTargetModule(module)}
                        className="text-ctp-green hover:underline text-sm"
                      >
                        Load
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
