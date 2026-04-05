import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { listenerClient } from '../api/index.js';
import type { StartListenerRequest } from '../api/index.js';
import { Listener as ListenerType } from '../types';
import type { Listener as ProtoListener } from '../gen/kraken_pb.js';
import { Modal } from '../components/Modal';

function uuidToHex(uuid: { value: Uint8Array } | undefined): string {
  if (!uuid?.value) return '';
  return Array.from(uuid.value).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function protoListenerToUI(l: ProtoListener): ListenerType {
  return {
    id: uuidToHex(l.id),
    name: `${l.listenerType.toUpperCase()} :${l.bindPort}`,
    protocol: (l.listenerType as ListenerType['protocol']) || 'http',
    bindAddress: l.bindHost,
    port: l.bindPort,
    state: l.isRunning ? 'running' : 'stopped',
    createdAt: l.startedAt ? new Date(Number(l.startedAt.millis)).toISOString() : '',
    sessionCount: Number(l.connectionsTotal),
  };
}

interface CreateListenerFormData {
  name: string;
  protocol: 'http' | 'https' | 'dns';
  bindAddress: string;
  port: string;
  baseDomain: string;
}

function EditListenerModal({
  listener,
  onClose,
}: {
  listener: ListenerType;
  onClose: () => void;
}) {
  const footer = (
    <button
      onClick={onClose}
      className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium text-ctp-text transition-colors"
    >
      Close
    </button>
  );

  return (
    <Modal isOpen={true} onClose={onClose} title="Edit Listener" size="md" footer={footer}>
      <div className="space-y-4">
        <div className="p-3 bg-ctp-surface0 rounded-lg text-sm text-ctp-subtext1 border border-ctp-surface1">
          <p className="font-medium text-ctp-text mb-1">Listener settings cannot be changed while active.</p>
          <p>To update settings, stop this listener and create a new one with the desired configuration.</p>
        </div>

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-ctp-subtext0">Protocol</span>
            <span className="text-ctp-text font-mono">{listener.protocol.toUpperCase()}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-ctp-subtext0">Bind Address</span>
            <span className="text-ctp-text font-mono">{listener.bindAddress}:{listener.port}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-ctp-subtext0">Status</span>
            <span className={`font-medium ${listener.state === 'running' ? 'text-ctp-green' : 'text-ctp-overlay1'}`}>
              {listener.state}
            </span>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function CreateListenerModal({
  isOpen,
  onClose,
  onSubmit,
  isPending,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: StartListenerRequest) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState<CreateListenerFormData>({
    name: '',
    protocol: 'http',
    bindAddress: '0.0.0.0',
    port: '8080',
    baseDomain: '',
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const portNum = parseInt(form.port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) return;
    if (form.protocol === 'dns' && !form.baseDomain.trim()) return;
    const defaultProfileId = form.protocol === 'dns'
      ? `dns-${form.baseDomain.trim()}-${portNum}`
      : `${form.protocol}-${portNum}`;
    onSubmit({
      listenerType: form.protocol,
      bindHost: form.bindAddress,
      bindPort: portNum,
      profileId: form.name || defaultProfileId,
    } as unknown as StartListenerRequest);
  }

  const footer = (
    <>
      <button
        type="button"
        onClick={onClose}
        className="px-4 py-2 text-sm text-ctp-subtext1 hover:text-ctp-text transition-colors"
      >
        Cancel
      </button>
      <button
        type="submit"
        form="create-listener-form"
        disabled={isPending}
        className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 disabled:opacity-50 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
      >
        {isPending ? 'Starting...' : 'Start Listener'}
      </button>
    </>
  );

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Listener" size="md" footer={footer}>
      <form id="create-listener-form" onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="listener-name">
            Name
          </label>
          <input
            id="listener-name"
            type="text"
            placeholder="my-listener"
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="listener-protocol">
            Protocol
          </label>
          <select
            id="listener-protocol"
            value={form.protocol}
            onChange={e => setForm(f => ({ ...f, protocol: e.target.value as 'http' | 'https' | 'dns' }))}
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
          >
            <option value="http">HTTP</option>
            <option value="https">HTTPS</option>
            <option value="dns">DNS</option>
          </select>
        </div>

        {form.protocol === 'dns' && (
          <div>
            <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="listener-base-domain">
              Base Domain <span className="text-ctp-red">*</span>
            </label>
            <input
              id="listener-base-domain"
              type="text"
              placeholder="c2.example.com"
              value={form.baseDomain}
              onChange={e => setForm(f => ({ ...f, baseDomain: e.target.value }))}
              className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
              required
            />
            <p className="text-xs text-ctp-subtext0 mt-1">
              DNS implants will tunnel traffic via subdomains of this domain.
            </p>
          </div>
        )}

        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="listener-bind">
            Bind Address
          </label>
          <input
            id="listener-bind"
            type="text"
            value={form.bindAddress}
            onChange={e => setForm(f => ({ ...f, bindAddress: e.target.value }))}
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="listener-port">
            Port
          </label>
          <input
            id="listener-port"
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={e => setForm(f => ({ ...f, port: e.target.value }))}
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
          />
        </div>
      </form>
    </Modal>
  );
}

export function Listeners() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editListener, setEditListener] = useState<ListenerType | null>(null);

  const { data: listeners, isLoading, error } = useQuery({
    queryKey: ['listeners'],
    queryFn: async () => {
      const res = await listenerClient.listListeners({});
      return res.listeners.map(protoListenerToUI);
    },
  });

  const stopMutation = useMutation({
    mutationFn: (id: string) =>
      listenerClient.stopListener({ listenerId: { value: hexToUint8Array(id) } }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['listeners'] }),
  });

  const startMutation = useMutation({
    mutationFn: (data: StartListenerRequest) => listenerClient.startListener(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['listeners'] });
      setShowCreateModal(false);
    },
  });

  return (
    <div>
      <CreateListenerModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSubmit={data => startMutation.mutate(data)}
        isPending={startMutation.isPending}
      />

      {editListener && (
        <EditListenerModal
          listener={editListener}
          onClose={() => setEditListener(null)}
        />
      )}

      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Listeners</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium transition-colors text-ctp-crust"
        >
          Create Listener
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          Failed to load listeners: {(error as Error).message}
        </div>
      )}

      {startMutation.error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          Failed to start listener: {(startMutation.error as Error).message}
        </div>
      )}

      {stopMutation.error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          Failed to stop listener: {(stopMutation.error as Error).message}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          <div className="text-ctp-subtext0">Loading listeners...</div>
        ) : listeners?.length === 0 ? (
          <div className="col-span-full bg-ctp-mantle rounded-lg p-8 text-center border border-ctp-surface0">
            <p className="text-ctp-subtext0 mb-4">No listeners configured.</p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium transition-colors text-ctp-crust"
            >
              Create Your First Listener
            </button>
          </div>
        ) : (
          listeners?.map((listener) => (
            <ListenerCard
              key={listener.id}
              listener={listener}
              onStop={() => stopMutation.mutate(listener.id)}
              onStart={() => setShowCreateModal(true)}
              onEdit={() => setEditListener(listener)}
              isStopPending={stopMutation.isPending}
            />
          ))
        )}
      </div>
    </div>
  );
}

function ListenerCard({
  listener,
  onStop,
  onStart,
  onEdit,
  isStopPending,
}: {
  listener: ListenerType;
  onStop: () => void;
  onStart: () => void;
  onEdit: () => void;
  isStopPending: boolean;
}) {
  const stateColors: Record<ListenerType['state'], string> = {
    running: 'text-ctp-green',
    stopped: 'text-ctp-overlay1',
    error: 'text-ctp-red',
  };

  return (
    <div className="bg-ctp-mantle rounded-lg p-4 border border-ctp-surface0">
      <div className="flex justify-between items-start mb-3">
        <div>
          <h3 className="font-medium">{listener.name}</h3>
          <p className="text-sm text-ctp-subtext0">{listener.protocol.toUpperCase()}</p>
        </div>
        <span className={`text-sm font-medium ${stateColors[listener.state]}`}>
          {listener.state}
        </span>
      </div>
      <div className="text-sm text-ctp-subtext1 mb-3">
        {listener.bindAddress}:{listener.port}
      </div>
      <div className="flex justify-between items-center text-sm">
        <span className="text-ctp-subtext0">{listener.sessionCount} sessions</span>
        <div className="space-x-2">
          <button className="text-ctp-mauve hover:underline" onClick={onEdit} disabled={isStopPending}>
            Edit
          </button>
          {listener.state === 'running' ? (
            <button
              className="text-ctp-subtext0 hover:text-ctp-text disabled:opacity-50"
              disabled={isStopPending}
              onClick={onStop}
            >
              Stop
            </button>
          ) : (
            <button
              className="text-ctp-green hover:text-ctp-green/80 disabled:opacity-50"
              disabled={isStopPending}
              onClick={onStart}
            >
              Start
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
