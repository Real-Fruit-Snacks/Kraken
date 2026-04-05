import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Implant } from '../../gen/kraken_pb.js';
import { ImplantState, ExitCommand, SleepTask } from '../../gen/kraken_pb.js';
import { taskClient, implantClient } from '../../api';
import { ConfirmModal } from '../ConfirmModal';

interface SessionInfoSidebarProps {
  implant: Implant;
  sessionId: string;
  onAction?: () => void;
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

type ModalType = 'kill' | 'retire' | null;

export function SessionInfoSidebar({ implant, sessionId, onAction }: SessionInfoSidebarProps) {
  const queryClient = useQueryClient();
  const [showSleepModal, setShowSleepModal] = useState(false);
  const [sleepInterval, setSleepInterval] = useState(implant.checkinInterval?.toString() ?? '60');
  const [sleepJitter, setSleepJitter] = useState(implant.jitterPercent?.toString() ?? '10');
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [confirmModal, setConfirmModal] = useState<ModalType>(null);

  const info = implant.systemInfo;
  const lastSeen = implant.lastSeen
    ? new Date(Number(implant.lastSeen.millis))
    : null;
  const firstSeen = implant.registeredAt
    ? new Date(Number(implant.registeredAt.millis))
    : null;

  const timeSinceLastSeen = lastSeen
    ? formatTimeSince(lastSeen)
    : 'Unknown';

  const sleepMutation = useMutation({
    mutationFn: async ({ interval, jitter }: { interval: number; jitter: number }) => {
      const sleepTask = new SleepTask({ interval, jitter });
      const taskData = new Uint8Array(sleepTask.toBinary()) as Uint8Array<ArrayBuffer>;
      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'sleep',
        taskData,
      });
    },
    onSuccess: () => {
      setFeedback({ type: 'success', message: 'Sleep task dispatched' });
      setShowSleepModal(false);
      onAction?.();
      setTimeout(() => setFeedback(null), 3000);
    },
    onError: (err) => {
      setFeedback({ type: 'error', message: err instanceof Error ? err.message : 'Failed to dispatch sleep task' });
    },
  });

  const killMutation = useMutation({
    mutationFn: async () => {
      const exitCmd = new ExitCommand({ clean: true });
      const taskData = new Uint8Array(exitCmd.toBinary()) as Uint8Array<ArrayBuffer>;
      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'exit',
        taskData,
      });
    },
    onSuccess: () => {
      setFeedback({ type: 'success', message: 'Kill command sent' });
      queryClient.invalidateQueries({ queryKey: ['implant', sessionId] });
      setConfirmModal(null);
      onAction?.();
    },
    onError: (err) => {
      setFeedback({ type: 'error', message: err instanceof Error ? err.message : 'Failed to kill' });
      setConfirmModal(null);
    },
  });

  const handleSleepSubmit = () => {
    const interval = parseInt(sleepInterval, 10);
    const jitter = parseInt(sleepJitter, 10);
    if (isNaN(interval) || interval < 1) {
      setFeedback({ type: 'error', message: 'Invalid sleep interval' });
      return;
    }
    if (isNaN(jitter) || jitter < 0 || jitter > 100) {
      setFeedback({ type: 'error', message: 'Jitter must be 0-100%' });
      return;
    }
    sleepMutation.mutate({ interval, jitter });
  };

  const retireMutation = useMutation({
    mutationFn: async () => {
      await implantClient.retireImplant({
        implantId: { value: hexToUint8Array(sessionId) },
      });
    },
    onSuccess: () => {
      setFeedback({ type: 'success', message: 'Implant retired' });
      queryClient.invalidateQueries({ queryKey: ['implant', sessionId] });
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      setConfirmModal(null);
      onAction?.();
    },
    onError: (err) => {
      setFeedback({ type: 'error', message: err instanceof Error ? err.message : 'Failed to retire' });
      setConfirmModal(null);
    },
  });

  return (
    <div className="w-64 flex-shrink-0 bg-ctp-mantle rounded-lg border border-ctp-surface0 p-4 overflow-y-auto">
      {/* Kill Confirmation Modal */}
      <ConfirmModal
        isOpen={confirmModal === 'kill'}
        title="Kill Implant"
        message="This will terminate the implant process. Continue?"
        confirmText="Kill"
        variant="danger"
        onConfirm={() => killMutation.mutate()}
        onCancel={() => setConfirmModal(null)}
      />

      {/* Retire Confirmation Modal */}
      <ConfirmModal
        isOpen={confirmModal === 'retire'}
        title="Retire Implant"
        message="Retire this implant?\n\nThis gracefully marks it as retired and stops tasking. The implant is not destroyed."
        confirmText="Retire"
        variant="warning"
        onConfirm={() => retireMutation.mutate()}
        onCancel={() => setConfirmModal(null)}
      />

      {/* Header */}
      <div className="mb-4 pb-4 border-b border-ctp-surface0">
        <h2 className="font-semibold text-lg text-ctp-text truncate">
          {info?.hostname ?? 'Unknown Host'}
        </h2>
        <div className="flex items-center gap-2 mt-1">
          <StateBadge state={implant.state} />
          <span className="text-xs text-ctp-subtext0">{timeSinceLastSeen}</span>
        </div>
      </div>

      {/* Info sections */}
      <div className="space-y-4">
        <InfoSection title="Target">
          <InfoRow label="User" value={info?.username ?? '—'} />
          <InfoRow label="Hostname" value={info?.hostname ?? '—'} />
          <InfoRow label="Domain" value={info?.domain || '—'} />
        </InfoSection>

        <InfoSection title="System">
          <InfoRow label="OS" value={info?.osName ?? '—'} />
          <InfoRow label="Version" value={info?.osVersion ?? '—'} />
          <InfoRow label="Arch" value={info?.osArch ?? '—'} />
        </InfoSection>

        <InfoSection title="Process">
          <InfoRow label="Name" value={info?.processName ?? '—'} />
          <InfoRow label="PID" value={info?.processId?.toString() ?? '—'} />
          <InfoRow label="Integrity" value={info?.integrityLevel ?? '—'} />
        </InfoSection>

        <InfoSection title="Network">
          {(info?.localIps ?? []).length > 0 ? (
            info!.localIps.map((ip, i) => (
              <InfoRow key={i} label={i === 0 ? 'IPs' : ''} value={ip} mono />
            ))
          ) : (
            <InfoRow label="IPs" value="—" />
          )}
        </InfoSection>

        <InfoSection title="Beacon">
          <InfoRow
            label="Sleep"
            value={`${implant.checkinInterval}s ± ${implant.jitterPercent}%`}
          />
          <InfoRow
            label="First Seen"
            value={firstSeen ? firstSeen.toLocaleString() : '—'}
          />
          <InfoRow
            label="Last Seen"
            value={lastSeen ? lastSeen.toLocaleString() : '—'}
          />
        </InfoSection>
      </div>

      {/* Feedback */}
      {feedback && (
        <div className={`mt-4 p-2 rounded text-xs ${
          feedback.type === 'success'
            ? 'bg-ctp-green/20 text-ctp-green'
            : 'bg-ctp-red/20 text-ctp-red'
        }`}>
          {feedback.message}
        </div>
      )}

      {/* Actions */}
      <div className="mt-6 pt-4 border-t border-ctp-surface0 space-y-2">
        <ActionButton
          variant="warning"
          onClick={() => setShowSleepModal(true)}
          disabled={sleepMutation.isPending}
        >
          {sleepMutation.isPending ? 'Updating...' : 'Sleep'}
        </ActionButton>
        {implant.state !== ImplantState.RETIRED && (
          <ActionButton
            variant="teal"
            onClick={() => setConfirmModal('retire')}
            disabled={retireMutation.isPending}
          >
            {retireMutation.isPending ? 'Retiring...' : 'Retire'}
          </ActionButton>
        )}
        <ActionButton
          variant="danger"
          onClick={() => setConfirmModal('kill')}
          disabled={killMutation.isPending}
        >
          {killMutation.isPending ? 'Sending...' : 'Kill'}
        </ActionButton>
      </div>

      {/* Sleep Modal */}
      {showSleepModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowSleepModal(false)}>
          <div className="bg-ctp-base border border-ctp-surface0 rounded-xl p-6 w-80 shadow-2xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-ctp-text mb-4">Update Sleep Settings</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-ctp-subtext0 mb-1">
                  Check-in Interval (seconds)
                </label>
                <input
                  type="number"
                  min="1"
                  value={sleepInterval}
                  onChange={(e) => setSleepInterval(e.target.value)}
                  className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve"
                />
              </div>
              <div>
                <label className="block text-sm text-ctp-subtext0 mb-1">
                  Jitter (%)
                </label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={sleepJitter}
                  onChange={(e) => setSleepJitter(e.target.value)}
                  className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve"
                />
              </div>
            </div>
            <div className="flex gap-2 mt-6">
              <button
                onClick={() => setShowSleepModal(false)}
                className="flex-1 px-3 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm text-ctp-text transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSleepSubmit}
                disabled={sleepMutation.isPending}
                className="flex-1 px-3 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm text-ctp-crust font-medium transition-colors disabled:opacity-50"
              >
                {sleepMutation.isPending ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function InfoSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide mb-2">
        {title}
      </h3>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between text-sm">
      <span className="text-ctp-subtext0">{label}</span>
      <span className={`text-ctp-text truncate ml-2 ${mono ? 'font-mono text-xs' : ''}`}>
        {value}
      </span>
    </div>
  );
}

function StateBadge({ state }: { state: ImplantState }) {
  const config: Record<ImplantState, { label: string; cls: string }> = {
    [ImplantState.ACTIVE]: { label: 'Active', cls: 'bg-ctp-green/20 text-ctp-green' },
    [ImplantState.STAGING]: { label: 'Staging', cls: 'bg-ctp-yellow/20 text-ctp-yellow' },
    [ImplantState.LOST]: { label: 'Lost', cls: 'bg-ctp-peach/20 text-ctp-peach' },
    [ImplantState.BURNED]: { label: 'Burned', cls: 'bg-ctp-red/20 text-ctp-red' },
    [ImplantState.RETIRED]: { label: 'Retired', cls: 'bg-ctp-overlay0/20 text-ctp-overlay1' },
    [ImplantState.UNSPECIFIED]: { label: 'Unknown', cls: 'bg-ctp-overlay0/20 text-ctp-overlay1' },
  };

  const { label, cls } = config[state] ?? config[ImplantState.UNSPECIFIED];

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {label}
    </span>
  );
}

function ActionButton({
  variant,
  children,
  onClick,
  disabled,
}: {
  variant: 'primary' | 'warning' | 'danger' | 'teal';
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  const styles = {
    primary: 'bg-ctp-mauve hover:bg-ctp-mauve/80 text-ctp-crust',
    warning: 'bg-ctp-yellow/20 hover:bg-ctp-yellow/30 text-ctp-yellow border border-ctp-yellow/30',
    danger: 'bg-ctp-red/20 hover:bg-ctp-red/30 text-ctp-red border border-ctp-red/30',
    teal: 'bg-ctp-teal/20 hover:bg-ctp-teal/30 text-ctp-teal border border-ctp-teal/30',
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`w-full px-3 py-1.5 rounded text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${styles[variant]}`}
    >
      {children}
    </button>
  );
}

function formatTimeSince(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
