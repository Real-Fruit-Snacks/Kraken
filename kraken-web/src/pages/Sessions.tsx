import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Session, SessionState } from '../types';
import { SessionEventData } from '../types/websocket';
import { implantClient } from '../api';
import { Implant, ImplantState } from '../gen/kraken_pb.js';
import { ConfirmModal, ConfirmModalWithInput, ErrorBanner } from '../components/ConfirmModal';
import { useRealtime } from '../hooks/useRealtime';

function uuidToHex(uuid: { value: Uint8Array } | undefined): string {
  if (!uuid?.value) return '';
  return Array.from(uuid.value).map(b => b.toString(16).padStart(2, '0')).join('');
}

function mapImplantState(state: ImplantState): SessionState {
  switch (state) {
    case ImplantState.ACTIVE:
      return 'active';
    case ImplantState.LOST:
      return 'dormant';
    case ImplantState.BURNED:
      return 'burned';
    case ImplantState.RETIRED:
    case ImplantState.STAGING:
    case ImplantState.UNSPECIFIED:
    default:
      return 'dead';
  }
}

function implantToSession(implant: Implant): Session {
  const info = implant.systemInfo;
  const lastSeenTs = implant.lastSeen;
  const firstSeenTs = implant.registeredAt;

  return {
    id: uuidToHex(implant.id),
    hostname: info?.hostname ?? '',
    username: info?.username ?? '',
    externalIp: info?.localIps?.[0] ?? '',
    internalIp: info?.localIps?.[1],
    os: info ? `${info.osName} ${info.osVersion}`.trim() : '',
    arch: info?.osArch ?? '',
    processId: info?.processId ?? 0,
    processName: info?.processName ?? '',
    state: mapImplantState(implant.state),
    firstSeen: firstSeenTs ? new Date(Number(firstSeenTs.millis)).toISOString() : '',
    lastSeen: lastSeenTs ? new Date(Number(lastSeenTs.millis)).toISOString() : '',
    sleepInterval: implant.checkinInterval,
    jitter: implant.jitterPercent,
  };
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buf) as Uint8Array<ArrayBuffer>;
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Modal state types
type ModalType = 'retire' | 'burn' | 'delete' | null;

interface ModalState {
  type: ModalType;
  session: Session | null;
}

export function Sessions() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  // Modal state
  const [modal, setModal] = useState<ModalState>({ type: null, session: null });
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const closeModal = () => setModal({ type: null, session: null });
  const dismissError = () => setErrorMessage(null);

  const retireMutation = useMutation({
    mutationFn: (sessionId: string) =>
      implantClient.retireImplant({ implantId: { value: hexToUint8Array(sessionId) } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      closeModal();
    },
    onError: (err) => {
      console.error('Failed to retire implant:', err);
      setErrorMessage(`Failed to retire implant: ${err instanceof Error ? err.message : 'Unknown error'}`);
      closeModal();
    },
  });

  const burnMutation = useMutation({
    mutationFn: ({ sessionId, reason }: { sessionId: string; reason: string }) =>
      implantClient.burnImplant({
        implantId: { value: hexToUint8Array(sessionId) },
        reason,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      closeModal();
    },
    onError: (err) => {
      console.error('Failed to burn implant:', err);
      setErrorMessage(`Failed to burn implant: ${err instanceof Error ? err.message : 'Unknown error'}`);
      closeModal();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (sessionId: string) =>
      implantClient.deleteImplant({ implantId: { value: hexToUint8Array(sessionId) } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      closeModal();
    },
    onError: (err) => {
      console.error('Failed to delete implant:', err);
      setErrorMessage(`Failed to delete implant: ${err instanceof Error ? err.message : 'Unknown error'}`);
      closeModal();
    },
  });

  const { data: sessions, isLoading, isError, error } = useQuery({
    queryKey: ['sessions'],
    queryFn: async () => {
      const response = await implantClient.listImplants({});
      return (response.implants ?? []).map(implantToSession);
    },
  });

  useEffect(() => {
    const abortController = new AbortController();

    async function subscribe() {
      try {
        const stream = implantClient.streamImplantEvents({}, { signal: abortController.signal });
        for await (const _event of stream) {
          if (abortController.signal.aborted) break;
          queryClient.invalidateQueries({ queryKey: ['sessions'] });
        }
      } catch (err) {
        // Ignore abort errors (expected on navigation/unmount)
        if (abortController.signal.aborted) return;
        console.error('ImplantEvent stream error:', err);
      }
    }

    subscribe();

    return () => {
      abortController.abort();
    };
  }, [queryClient]);

  // WebSocket real-time updates - optimistic UI updates without full refetch
  useRealtime<SessionEventData>('SessionNew', (data) => {
    queryClient.setQueryData<Session[]>(['sessions'], (old) => {
      if (!old) return old;
      // Check if session already exists (avoid duplicates)
      if (old.some(s => s.id === data.implant_id)) return old;
      // Note: SessionNew doesn't include full session data, will be fetched on next poll
      // For now, trigger a refetch to get full session details
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      return old;
    });
  });

  useRealtime<SessionEventData>('SessionCheckin', (data) => {
    queryClient.setQueryData<Session[]>(['sessions'], (old) => {
      if (!old) return old;
      return old.map(session =>
        session.id === data.implant_id
          ? { ...session, lastSeen: new Date().toISOString() }
          : session
      );
    });
  });

  useRealtime<SessionEventData>('SessionLost', (data) => {
    queryClient.setQueryData<Session[]>(['sessions'], (old) => {
      if (!old) return old;
      return old.map(session =>
        session.id === data.implant_id
          ? { ...session, state: 'dormant' as SessionState }
          : session
      );
    });
  });

  useRealtime<SessionEventData>('SessionRecovered', (data) => {
    queryClient.setQueryData<Session[]>(['sessions'], (old) => {
      if (!old) return old;
      return old.map(session =>
        session.id === data.implant_id
          ? { ...session, state: 'active' as SessionState }
          : session
      );
    });
  });

  useRealtime<SessionEventData>('SessionBurned', (data) => {
    queryClient.setQueryData<Session[]>(['sessions'], (old) => {
      if (!old) return old;
      return old.map(session =>
        session.id === data.implant_id
          ? { ...session, state: 'burned' as SessionState }
          : session
      );
    });
  });

  useRealtime<SessionEventData>('SessionRetired', (data) => {
    queryClient.setQueryData<Session[]>(['sessions'], (old) => {
      if (!old) return old;
      return old.map(session =>
        session.id === data.implant_id
          ? { ...session, state: 'dead' as SessionState }
          : session
      );
    });
  });

  // Modal handlers
  const handleRetireConfirm = () => {
    if (modal.session) {
      retireMutation.mutate(modal.session.id);
    }
  };

  const handleBurnConfirm = (reason: string) => {
    if (modal.session) {
      burnMutation.mutate({ sessionId: modal.session.id, reason });
    }
  };

  const handleDeleteConfirm = () => {
    if (modal.session) {
      deleteMutation.mutate(modal.session.id);
    }
  };

  return (
    <div>
      {/* Retire Confirmation Modal */}
      <ConfirmModal
        isOpen={modal.type === 'retire'}
        title="Retire Implant"
        message={`Retire implant ${modal.session?.hostname}?\n\nThis gracefully marks it as retired and stops tasking. The implant is not destroyed.`}
        confirmText="Retire"
        variant="warning"
        onConfirm={handleRetireConfirm}
        onCancel={closeModal}
      />

      {/* Burn Confirmation Modal (with reason input) */}
      <ConfirmModalWithInput
        isOpen={modal.type === 'burn'}
        title="Burn Implant"
        message={`Burn implant ${modal.session?.hostname}?\n\nThis marks it as compromised and stops all tasking.`}
        inputLabel="Reason (for audit log)"
        inputDefault="Suspected compromise"
        confirmText="Burn"
        variant="danger"
        onConfirm={handleBurnConfirm}
        onCancel={closeModal}
      />

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={modal.type === 'delete'}
        title="Delete Implant"
        message={`Delete implant ${modal.session?.hostname}?\n\nThis permanently removes all records. Cannot be undone.`}
        confirmText="Delete"
        variant="danger"
        onConfirm={handleDeleteConfirm}
        onCancel={closeModal}
      />

      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Sessions</h1>
        <div className="text-sm text-ctp-subtext0">
          {sessions?.length ?? 0} sessions
        </div>
      </div>

      {/* Error Banner */}
      {errorMessage && (
        <ErrorBanner message={errorMessage} onDismiss={dismissError} />
      )}

      <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
        <table className="w-full">
          <thead className="bg-ctp-crust">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Hostname</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">User</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">External IP</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">OS</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Process</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">State</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Last Seen</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-ctp-subtext0">
                  Loading sessions...
                </td>
              </tr>
            ) : isError ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-ctp-red">
                  Failed to load sessions: {error instanceof Error ? error.message : 'Unknown error'}
                </td>
              </tr>
            ) : sessions?.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-ctp-subtext0">
                  No active sessions. Deploy an implant to get started.
                </td>
              </tr>
            ) : (
              sessions?.map((session) => (
                <tr
                  key={session.id}
                  className="hover:bg-ctp-surface0/30 cursor-pointer"
                  onClick={() => navigate(`/sessions/${session.id}`)}
                >
                  <td className="px-4 py-3 font-medium">{session.hostname}</td>
                  <td className="px-4 py-3 text-ctp-subtext1">{session.username}</td>
                  <td className="px-4 py-3 text-ctp-subtext1">{session.externalIp}</td>
                  <td className="px-4 py-3 text-ctp-subtext1">{session.os}</td>
                  <td className="px-4 py-3 text-ctp-subtext0 text-sm">
                    {session.processName} ({session.processId})
                  </td>
                  <td className="px-4 py-3">
                    <SessionStateBadge state={session.state} />
                  </td>
                  <td className="px-4 py-3 text-ctp-subtext0 text-sm">
                    {session.lastSeen ? new Date(session.lastSeen).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3 flex gap-2" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={() => navigate(`/sessions/${session.id}`)}
                      className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-mauve text-ctp-crust hover:bg-ctp-mauve/80"
                    >
                      Interact
                    </button>
                    {session.state !== 'burned' && (
                      <button
                        onClick={() => setModal({ type: 'burn', session })}
                        disabled={burnMutation.isPending}
                        className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-peach/20 text-ctp-peach hover:bg-ctp-peach/40 disabled:opacity-50"
                      >
                        Burn
                      </button>
                    )}
                    {session.state !== 'dead' && (
                      <button
                        onClick={() => setModal({ type: 'retire', session })}
                        disabled={retireMutation.isPending}
                        className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-teal/20 text-ctp-teal hover:bg-ctp-teal/40 disabled:opacity-50"
                      >
                        Retire
                      </button>
                    )}
                    <button
                      onClick={() => setModal({ type: 'delete', session })}
                      disabled={deleteMutation.isPending}
                      className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/40 disabled:opacity-50"
                    >
                      Delete
                    </button>
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

function SessionStateBadge({ state }: { state: Session['state'] }) {
  const colors = {
    active: 'bg-ctp-green/20 text-ctp-green',
    dormant: 'bg-ctp-yellow/20 text-ctp-yellow',
    dead: 'bg-ctp-overlay0/20 text-ctp-overlay1',
    burned: 'bg-ctp-red/20 text-ctp-red',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[state]}`}>
      {state}
    </span>
  );
}
