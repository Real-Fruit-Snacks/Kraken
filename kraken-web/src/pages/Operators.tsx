import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { operatorClient } from '../api/index.js';
import type { Operator as ProtoOperator } from '../gen/kraken_pb.js';
import { Operator } from '../types';
import { Modal } from '../components/Modal';

function uuidToHex(uuid: { value: Uint8Array } | undefined): string {
  if (!uuid?.value) return '';
  return Array.from(uuid.value).map(b => b.toString(16).padStart(2, '0')).join('');
}

// TODO: RBAC - These helpers will be needed when session/listener restrictions are implemented
// function bytesToHex(bytes: Uint8Array): string {
//   return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
// }
// function parseIds(raw: string): string[] {
//   return raw.split(',').map(s => s.trim()).filter(s => s.length > 0);
// }

function protoOperatorToUI(op: ProtoOperator): Operator {
  const role = (op.role === 'admin' || op.role === 'operator' || op.role === 'viewer')
    ? op.role as Operator['role']
    : 'viewer';

  return {
    id: uuidToHex(op.id),
    username: op.username,
    role,
    createdAt: op.createdAt
      ? new Date(Number(op.createdAt.millis)).toISOString()
      : '',
    lastLogin: op.lastSeen
      ? new Date(Number(op.lastSeen.millis)).toISOString()
      : undefined,
    isOnline: op.isActive,
    isDisabled: !op.isActive,
    allowedSessions: [], // TODO: RBAC - not yet in proto
    allowedListeners: [], // TODO: RBAC - not yet in proto
  };
}

// ---------------------------------------------------------------------------
// Add Operator Modal
// ---------------------------------------------------------------------------

interface AddOperatorFormData {
  username: string;
  role: Operator['role'];
  password: string;
  // TODO: RBAC - allowedSessions and allowedListeners not yet in proto
}

function AddOperatorModal({
  onClose,
  onSubmit,
  isPending,
  error,
}: {
  onClose: () => void;
  onSubmit: (data: AddOperatorFormData) => void;
  isPending: boolean;
  error: Error | null;
}) {
  const [form, setForm] = useState<AddOperatorFormData>({
    username: '',
    role: 'operator',
    password: '',
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.username.trim() || !form.password.trim()) return;
    onSubmit(form);
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
        form="add-operator-form"
        disabled={isPending || !form.username.trim() || !form.password.trim()}
        className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 disabled:opacity-50 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
      >
        {isPending ? 'Adding...' : 'Add Operator'}
      </button>
    </>
  );

  return (
    <Modal isOpen={true} onClose={onClose} title="Add Operator" size="md" footer={footer}>
      {error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          {error.message}
        </div>
      )}

      <form id="add-operator-form" onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="add-op-username">
            Username
          </label>
          <input
            id="add-op-username"
            type="text"
            placeholder="operator-name"
            value={form.username}
            onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
            required
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="add-op-password">
            Password
          </label>
          <input
            id="add-op-password"
            type="password"
            placeholder="••••••••"
            value={form.password}
            onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
            required
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="add-op-role">
            Role
          </label>
          <select
            id="add-op-role"
            value={form.role}
            onChange={e => setForm(f => ({ ...f, role: e.target.value as Operator['role'] }))}
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
          >
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
        </div>

        <div className="border-t border-ctp-surface1 pt-4">
          <p className="text-xs text-ctp-overlay0 mb-3">
            Access Restrictions — leave empty for full access. Add specific IDs to restrict access.
          </p>

          <div className="space-y-3">
            {/* TODO: RBAC - Session and Listener restrictions not yet implemented in proto */}
          </div>
        </div>
      </form>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Edit Operator Modal
// ---------------------------------------------------------------------------

interface EditOperatorFormData {
  role: Operator['role'];
  // TODO: RBAC - allowedSessions and allowedListeners not yet in proto
}

function EditOperatorModal({
  operator,
  onClose,
  onSubmit,
  isPending,
  error,
}: {
  operator: Operator;
  onClose: () => void;
  onSubmit: (id: string, data: EditOperatorFormData) => void;
  isPending: boolean;
  error: Error | null;
}) {
  const [form, setForm] = useState<EditOperatorFormData>({
    role: operator.role,
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSubmit(operator.id, form);
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
        form="edit-operator-form"
        disabled={isPending}
        className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 disabled:opacity-50 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
      >
        {isPending ? 'Saving...' : 'Save Changes'}
      </button>
    </>
  );

  return (
    <Modal isOpen={true} onClose={onClose} title="Edit Operator" size="md" footer={footer}>
      {error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          {error.message}
        </div>
      )}

      <form id="edit-operator-form" onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1">
            Username
          </label>
          <div className="w-full bg-ctp-surface0/50 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-subtext1">
            {operator.username}
          </div>
        </div>

        <div>
          <label className="block text-sm text-ctp-subtext1 mb-1" htmlFor="edit-op-role">
            Role
          </label>
          <select
            id="edit-op-role"
            value={form.role}
            onChange={e => setForm(f => ({ ...f, role: e.target.value as Operator['role'] }))}
            className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
          >
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
        </div>

        <div className="border-t border-ctp-surface1 pt-4">
          <p className="text-xs text-ctp-overlay0 mb-3">
            Access Restrictions — leave empty for full access. Add specific IDs to restrict access.
          </p>

          <div className="space-y-3">
            {/* TODO: RBAC - Session and Listener restrictions not yet implemented in proto */}
          </div>
        </div>
      </form>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Revoke Confirmation Dialog
// ---------------------------------------------------------------------------

function RevokeOperatorDialog({
  operator,
  onClose,
  onConfirm,
  isPending,
  error,
}: {
  operator: Operator;
  onClose: () => void;
  onConfirm: (id: string) => void;
  isPending: boolean;
  error: Error | null;
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
        disabled={isPending}
        onClick={() => onConfirm(operator.id)}
        className="px-4 py-2 bg-ctp-red hover:bg-ctp-red/80 disabled:opacity-50 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
      >
        {isPending ? 'Revoking...' : 'Revoke Access'}
      </button>
    </>
  );

  return (
    <Modal isOpen={true} onClose={onClose} title="Revoke Operator" size="sm" footer={footer}>
      {error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          {error.message}
        </div>
      )}

      <p className="text-sm text-ctp-subtext1 mb-2">
        Are you sure you want to revoke access for{' '}
        <span className="font-semibold text-ctp-text">{operator.username}</span>?
      </p>
      <p className="text-sm text-ctp-red/80">
        This will disable the operator's account. They will be unable to authenticate.
      </p>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// TODO: RBAC - isScoped will be used when session/listener restrictions are implemented
// function isScoped(op: Operator): boolean {
//   return op.allowedSessions.length > 0 || op.allowedListeners.length > 0;
// }

// ---------------------------------------------------------------------------
// Main Operators Page
// ---------------------------------------------------------------------------

type ModalState =
  | { type: 'none' }
  | { type: 'add' }
  | { type: 'edit'; operator: Operator }
  | { type: 'revoke'; operator: Operator };

export function Operators() {
  const queryClient = useQueryClient();
  const [modal, setModal] = useState<ModalState>({ type: 'none' });
  const [showDisabled, setShowDisabled] = useState(false);

  const { data: operators, isLoading, error } = useQuery({
    queryKey: ['operators'],
    queryFn: async () => {
      const res = await operatorClient.listOperators({});
      return res.operators.map(protoOperatorToUI);
    },
  });

  const addMutation = useMutation({
    mutationFn: async (data: AddOperatorFormData) => {
      await operatorClient.createOperator({
        username: data.username,
        password: data.password,
        role: data.role,
        // TODO: RBAC - allowedSessions and allowedListeners not yet in proto
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['operators'] });
      setModal({ type: 'none' });
    },
  });

  const editMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: EditOperatorFormData }) => {
      await operatorClient.updateOperator({
        operatorId: hexToBytes(id),
        role: data.role,
        // TODO: RBAC - allowedSessions and allowedListeners not yet in proto
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['operators'] });
      setModal({ type: 'none' });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: async (id: string) => {
      await operatorClient.deleteOperator({
        operatorId: hexToBytes(id),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['operators'] });
      setModal({ type: 'none' });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, disabled }: { id: string; disabled: boolean }) => {
      await operatorClient.updateOperator({
        operatorId: hexToBytes(id),
        disabled,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['operators'] });
    },
  });

  function handleCloseModal() {
    setModal({ type: 'none' });
    addMutation.reset();
    editMutation.reset();
    revokeMutation.reset();
  }

  return (
    <div>
      {/* Modals */}
      {modal.type === 'add' && (
        <AddOperatorModal
          onClose={handleCloseModal}
          onSubmit={data => addMutation.mutate(data)}
          isPending={addMutation.isPending}
          error={addMutation.error}
        />
      )}
      {modal.type === 'edit' && (
        <EditOperatorModal
          operator={modal.operator}
          onClose={handleCloseModal}
          onSubmit={(id, data) => editMutation.mutate({ id, data })}
          isPending={editMutation.isPending}
          error={editMutation.error}
        />
      )}
      {modal.type === 'revoke' && (
        <RevokeOperatorDialog
          operator={modal.operator}
          onClose={handleCloseModal}
          onConfirm={id => revokeMutation.mutate(id)}
          isPending={revokeMutation.isPending}
          error={revokeMutation.error}
        />
      )}

      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Operators</h1>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-ctp-subtext1 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showDisabled}
              onChange={e => setShowDisabled(e.target.checked)}
              className="w-4 h-4 rounded border-ctp-surface1 bg-ctp-surface0 accent-ctp-mauve cursor-pointer"
            />
            Show disabled operators
          </label>
          <button
            onClick={() => setModal({ type: 'add' })}
            className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium transition-colors text-ctp-crust"
          >
            Add Operator
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          Failed to load operators: {(error as Error).message}
        </div>
      )}

      <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
        <table className="w-full">
          <thead className="bg-ctp-crust">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Username</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Role</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Status</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Last Login</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ctp-subtext0">
                  Loading operators...
                </td>
              </tr>
            ) : operators?.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ctp-subtext0">
                  No operators configured.
                </td>
              </tr>
            ) : (
              operators
                ?.filter(op => showDisabled || !op.isDisabled)
                .map((op) => (
                <tr key={op.id} className={`hover:bg-ctp-surface0/30 ${op.isDisabled ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-3 font-medium">
                    <span className="flex items-center gap-2 flex-wrap">
                      <span className={op.isDisabled ? 'line-through text-ctp-subtext0' : ''}>{op.username}</span>
                      {op.isDisabled && (
                        <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-ctp-surface1 text-ctp-overlay1 uppercase tracking-wide">
                          Disabled
                        </span>
                      )}
                      {/* TODO: RBAC - Scoped access badge when session/listener restrictions implemented */}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <RoleBadge role={op.role} />
                  </td>
                  <td className="px-4 py-3">
                    <span className={`flex items-center gap-2 text-sm ${op.isOnline ? 'text-ctp-green' : 'text-ctp-overlay1'}`}>
                      <span className={`w-2 h-2 rounded-full ${op.isOnline ? 'bg-ctp-green' : 'bg-ctp-overlay0'}`} />
                      {op.isOnline ? 'Online' : 'Offline'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-ctp-subtext0 text-sm">
                    {op.lastLogin ? new Date(op.lastLogin).toLocaleString() : 'Never'}
                  </td>
                  <td className="px-4 py-3 space-x-2">
                    <button
                      onClick={() => setModal({ type: 'edit', operator: op })}
                      className="text-ctp-mauve hover:underline text-sm"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => toggleMutation.mutate({ id: op.id, disabled: !op.isDisabled })}
                      disabled={toggleMutation.isPending}
                      className={`text-sm hover:underline disabled:opacity-50 ${op.isDisabled ? 'text-ctp-green' : 'text-ctp-yellow'}`}
                    >
                      {op.isDisabled ? 'Enable' : 'Disable'}
                    </button>
                    <button
                      onClick={() => setModal({ type: 'revoke', operator: op })}
                      className="text-ctp-red hover:underline text-sm"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Permissions Reference */}
      <div className="mt-8">
        <h2 className="text-lg font-semibold mb-4">Role Permissions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <PermissionCard
            role="Admin"
            permissions={[
              'Full access to all features',
              'Manage operators',
              'Configure listeners',
              'View audit logs',
            ]}
          />
          <PermissionCard
            role="Operator"
            permissions={[
              'Interact with sessions',
              'Execute modules',
              'View and export loot',
              'Generate reports',
            ]}
          />
          <PermissionCard
            role="Viewer"
            permissions={[
              'View sessions (read-only)',
              'View loot (read-only)',
              'View reports',
              'No interaction allowed',
            ]}
          />
        </div>
      </div>
    </div>
  );
}

function RoleBadge({ role }: { role: Operator['role'] }) {
  const colors: Record<Operator['role'], string> = {
    admin: 'bg-ctp-mauve/20 text-ctp-mauve',
    operator: 'bg-ctp-blue/20 text-ctp-blue',
    viewer: 'bg-ctp-overlay0/20 text-ctp-overlay1',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium uppercase ${colors[role]}`}>
      {role}
    </span>
  );
}

function PermissionCard({ role, permissions }: { role: string; permissions: string[] }) {
  return (
    <div className="bg-ctp-mantle rounded-lg p-4 border border-ctp-surface0">
      <h3 className="font-medium mb-3">{role}</h3>
      <ul className="space-y-2">
        {permissions.map((perm, i) => (
          <li key={i} className="flex items-center gap-2 text-sm text-ctp-subtext1">
            <svg className="w-4 h-4 text-ctp-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            {perm}
          </li>
        ))}
      </ul>
    </div>
  );
}
