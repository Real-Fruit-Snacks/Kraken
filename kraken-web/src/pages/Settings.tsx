import { useState } from 'react';
import { useAuthStore } from '../stores/authStore';
import { useToast } from '../contexts/ToastContext';
import { Modal } from '../components/Modal';

// ─── Section wrapper ────────────────────────────────────────────────────────

function Section({
  title,
  description,
  children,
  danger,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
  danger?: boolean;
}) {
  return (
    <div
      className={`rounded-lg border p-6 ${
        danger
          ? 'bg-ctp-mantle border-ctp-red/40'
          : 'bg-ctp-mantle border-ctp-surface0'
      }`}
    >
      <div className="mb-4">
        <h2 className={`text-lg font-semibold ${danger ? 'text-ctp-red' : 'text-ctp-text'}`}>
          {title}
        </h2>
        {description && (
          <p className="text-sm text-ctp-subtext0 mt-1">{description}</p>
        )}
      </div>
      {children}
    </div>
  );
}

// ─── Field components ───────────────────────────────────────────────────────

function FieldRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
      <div className="sm:w-64 flex-shrink-0">
        <span className="text-sm text-ctp-text font-medium">{label}</span>
        {hint && <p className="text-xs text-ctp-subtext0 mt-0.5">{hint}</p>}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  );
}

function TextInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
    />
  );
}

function NumberInput({
  value,
  onChange,
  min,
  max,
  unit,
}: {
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  unit?: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <input
        type="number"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        min={min}
        max={max}
        className="w-32 bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
      />
      {unit && <span className="text-sm text-ctp-subtext0">{unit}</span>}
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className="flex items-center gap-3 group"
    >
      <div
        className={`relative w-10 h-5 rounded-full transition-colors ${
          checked ? 'bg-ctp-mauve' : 'bg-ctp-surface2'
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-ctp-base transition-transform ${
            checked ? 'translate-x-5' : 'translate-x-0'
          }`}
        />
      </div>
      <span className="text-sm text-ctp-text">{label}</span>
    </button>
  );
}

// ─── Danger confirm dialog ───────────────────────────────────────────────────

function DangerConfirmModal({
  title,
  message,
  confirmLabel,
  onClose,
  onConfirm,
}: {
  title: string;
  message: string;
  confirmLabel: string;
  onClose: () => void;
  onConfirm: () => void;
}) {
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
        type="button"
        onClick={() => { onConfirm(); onClose(); }}
        className="px-4 py-2 bg-ctp-red hover:bg-ctp-red/80 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
      >
        {confirmLabel}
      </button>
    </>
  );

  return (
    <Modal isOpen={true} onClose={onClose} title={title} size="sm" footer={footer}>
      <p className="text-sm text-ctp-subtext1">{message}</p>
    </Modal>
  );
}

// ─── Main Settings page ──────────────────────────────────────────────────────

type DangerAction = 'reset-sessions' | 'clear-audit' | null;

export function Settings() {
  const operator = useAuthStore((s) => s.operator);
  const { showToast } = useToast();

  // Server Configuration
  const [serverName, setServerName] = useState('Kraken C2');
  const [defaultSleep, setDefaultSleep] = useState(60);
  const [jitterPercent, setJitterPercent] = useState(20);

  // Team Settings
  const [teamName, setTeamName] = useState('Red Team');
  const [notifyNewSession, setNotifyNewSession] = useState(true);
  const [notifyTaskComplete, setNotifyTaskComplete] = useState(true);
  const [notifyErrors, setNotifyErrors] = useState(false);

  // Security Settings
  const [sessionTimeout, setSessionTimeout] = useState(30);
  const [require2FA, setRequire2FA] = useState(false);

  // Danger zone confirm
  const [dangerAction, setDangerAction] = useState<DangerAction>(null);

  const isAdmin = operator?.role === 'admin';

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-ctp-surface0 flex items-center justify-center">
            <svg className="w-6 h-6 text-ctp-red" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m0 0v2m0-2h2m-2 0H10m2-5a7 7 0 100-14 7 7 0 000 14z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-ctp-text mb-2">Access Denied</h2>
          <p className="text-ctp-subtext0">Settings are only accessible to administrators.</p>
        </div>
      </div>
    );
  }

  function saveServerConfig() {
    // In production this would call an API
    showToast('Server configuration saved.', 'success');
  }

  function saveTeamSettings() {
    showToast('Team settings saved.', 'success');
  }

  function saveSecuritySettings() {
    showToast('Security settings saved.', 'success');
  }

  function handleResetSessions() {
    showToast('All active sessions have been reset.', 'warning');
  }

  function handleClearAuditLog() {
    showToast('Audit log cleared.', 'warning');
  }

  return (
    <>
      {dangerAction === 'reset-sessions' && (
        <DangerConfirmModal
          title="Reset All Sessions"
          message="This will terminate all active operator sessions immediately. Everyone currently logged in will be signed out. This action cannot be undone."
          confirmLabel="Reset Sessions"
          onClose={() => setDangerAction(null)}
          onConfirm={handleResetSessions}
        />
      )}
      {dangerAction === 'clear-audit' && (
        <DangerConfirmModal
          title="Clear Audit Log"
          message="This will permanently delete the entire audit log history. This action cannot be undone and may affect compliance requirements."
          confirmLabel="Clear Audit Log"
          onClose={() => setDangerAction(null)}
          onConfirm={handleClearAuditLog}
        />
      )}

      <div className="p-6 max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-ctp-text">Settings</h1>
          <p className="text-ctp-subtext0 mt-1">Configure server and team settings</p>
        </div>

        {/* Server Configuration */}
        <Section
          title="Server Configuration"
          description="Global C2 server parameters applied to new implants by default."
        >
          <div className="space-y-5">
            <FieldRow label="Server Name" hint="Display name shown in the UI and reports.">
              <TextInput
                value={serverName}
                onChange={setServerName}
                placeholder="Kraken C2"
              />
            </FieldRow>
            <FieldRow label="Default Sleep Interval" hint="How long implants sleep between callbacks.">
              <NumberInput
                value={defaultSleep}
                onChange={setDefaultSleep}
                min={1}
                max={86400}
                unit="seconds"
              />
            </FieldRow>
            <FieldRow label="Jitter Percentage" hint="Random variance added to sleep interval (0–100%).">
              <NumberInput
                value={jitterPercent}
                onChange={setJitterPercent}
                min={0}
                max={100}
                unit="%"
              />
            </FieldRow>
          </div>
          <div className="mt-6 flex justify-end">
            <button
              type="button"
              onClick={saveServerConfig}
              className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
            >
              Save Server Config
            </button>
          </div>
        </Section>

        {/* Team Settings */}
        <Section
          title="Team Settings"
          description="Configure team identity and notification preferences."
        >
          <div className="space-y-5">
            <FieldRow label="Team Name" hint="Shown in reports and exported artifacts.">
              <TextInput
                value={teamName}
                onChange={setTeamName}
                placeholder="Red Team"
              />
            </FieldRow>
            <div>
              <p className="text-sm text-ctp-subtext1 font-medium mb-3">Notifications</p>
              <div className="space-y-3 pl-1">
                <Toggle
                  checked={notifyNewSession}
                  onChange={setNotifyNewSession}
                  label="Notify on new session check-in"
                />
                <Toggle
                  checked={notifyTaskComplete}
                  onChange={setNotifyTaskComplete}
                  label="Notify on task completion"
                />
                <Toggle
                  checked={notifyErrors}
                  onChange={setNotifyErrors}
                  label="Notify on implant errors"
                />
              </div>
            </div>
          </div>
          <div className="mt-6 flex justify-end">
            <button
              type="button"
              onClick={saveTeamSettings}
              className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
            >
              Save Team Settings
            </button>
          </div>
        </Section>

        {/* Security Settings */}
        <Section
          title="Security Settings"
          description="Operator authentication and session security controls."
        >
          <div className="space-y-5">
            <FieldRow label="Session Timeout" hint="Operator sessions expire after this period of inactivity.">
              <NumberInput
                value={sessionTimeout}
                onChange={setSessionTimeout}
                min={5}
                max={1440}
                unit="minutes"
              />
            </FieldRow>
            <FieldRow label="Require 2FA" hint="Enforce two-factor authentication for all operators.">
              <Toggle
                checked={require2FA}
                onChange={setRequire2FA}
                label={require2FA ? 'Enabled' : 'Disabled'}
              />
            </FieldRow>
          </div>
          <div className="mt-6 flex justify-end">
            <button
              type="button"
              onClick={saveSecuritySettings}
              className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
            >
              Save Security Settings
            </button>
          </div>
        </Section>

        {/* Danger Zone */}
        <Section
          title="Danger Zone"
          description="Irreversible actions. Proceed with caution."
          danger
        >
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-lg bg-ctp-surface0/40 border border-ctp-surface1">
              <div>
                <p className="text-sm font-medium text-ctp-text">Reset All Sessions</p>
                <p className="text-xs text-ctp-subtext0 mt-0.5">
                  Terminate all active operator sessions and force re-authentication.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setDangerAction('reset-sessions')}
                className="flex-shrink-0 px-4 py-2 bg-ctp-red/20 hover:bg-ctp-red/30 border border-ctp-red/40 rounded-lg text-sm font-medium text-ctp-red transition-colors"
              >
                Reset Sessions
              </button>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-lg bg-ctp-surface0/40 border border-ctp-surface1">
              <div>
                <p className="text-sm font-medium text-ctp-text">Clear Audit Log</p>
                <p className="text-xs text-ctp-subtext0 mt-0.5">
                  Permanently delete all audit log entries. This cannot be recovered.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setDangerAction('clear-audit')}
                className="flex-shrink-0 px-4 py-2 bg-ctp-red/20 hover:bg-ctp-red/30 border border-ctp-red/40 rounded-lg text-sm font-medium text-ctp-red transition-colors"
              >
                Clear Audit Log
              </button>
            </div>
          </div>
        </Section>
      </div>
    </>
  );
}
