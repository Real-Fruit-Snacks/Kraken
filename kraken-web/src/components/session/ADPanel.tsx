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

interface ADResult {
  columns: string[];
  rows: string[][];
}

type ActiveOp = 'users' | 'groups' | 'computers' | 'kerberoast' | 'asreproast' | 'query' | null;

export function ADPanel({ sessionId }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [activeOp, setActiveOp] = useState<ActiveOp>(null);
  const [result, setResult] = useState<ADResult | null>(null);

  // filter inputs for enumerate buttons
  const [userFilter, setUserFilter] = useState('');
  const [groupFilter, setGroupFilter] = useState('');
  const [computerFilter, setComputerFilter] = useState('');

  // LDAP query inputs
  const [ldapFilter, setLdapFilter] = useState('');
  const [ldapAttrs, setLdapAttrs] = useState('');

  const dispatch = async (op: ActiveOp, parts: string[]) => {
    setLoading(true);
    setError(null);
    setTaskId(null);
    setResult(null);
    setActiveOp(op);
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(parts.join('\0')) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'ad',
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setTaskId(id);
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch task');
    } finally {
      setLoading(false);
    }
  };

  const handleEnumUsers = () =>
    dispatch('users', userFilter.trim() ? ['get_users', userFilter.trim()] : ['get_users']);

  const handleEnumGroups = () =>
    dispatch('groups', groupFilter.trim() ? ['get_groups', groupFilter.trim()] : ['get_groups']);

  const handleEnumComputers = () =>
    dispatch('computers', computerFilter.trim() ? ['get_computers', computerFilter.trim()] : ['get_computers']);

  const handleKerberoast = () => dispatch('kerberoast', ['kerberoast']);

  const handleAsreproast = () => dispatch('asreproast', ['asreproast']);

  const handleLdapQuery = () => {
    if (!ldapFilter.trim()) {
      setError('LDAP filter is required.');
      return;
    }
    const attrs = ldapAttrs.trim()
      ? ldapAttrs.split(',').map(a => a.trim()).filter(Boolean)
      : [];
    dispatch('query', ['query', ldapFilter.trim(), ...attrs]);
  };

  const opLabel: Record<NonNullable<ActiveOp>, string> = {
    users: 'Enumerate Users',
    groups: 'Enumerate Groups',
    computers: 'Enumerate Computers',
    kerberoast: 'Kerberoast',
    asreproast: 'ASREPRoast',
    query: 'LDAP Query',
  };

  return (
    <div className="p-4 space-y-5">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Active Directory</h3>

      {/* Enumerate section */}
      <div className="space-y-3">
        <p className="text-xs text-ctp-subtext0 uppercase tracking-wide">Enumerate</p>

        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={userFilter}
              onChange={e => setUserFilter(e.target.value)}
              placeholder="Filter (optional)"
              className="flex-1 px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
            />
            <button
              onClick={handleEnumUsers}
              disabled={loading}
              className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            >
              Users
            </button>
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={groupFilter}
              onChange={e => setGroupFilter(e.target.value)}
              placeholder="Filter (optional)"
              className="flex-1 px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
            />
            <button
              onClick={handleEnumGroups}
              disabled={loading}
              className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            >
              Groups
            </button>
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={computerFilter}
              onChange={e => setComputerFilter(e.target.value)}
              placeholder="Filter (optional)"
              className="flex-1 px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
            />
            <button
              onClick={handleEnumComputers}
              disabled={loading}
              className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            >
              Computers
            </button>
          </div>
        </div>
      </div>

      {/* Attacks */}
      <div className="space-y-2">
        <p className="text-xs text-ctp-subtext0 uppercase tracking-wide">Attacks</p>
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={handleKerberoast}
            disabled={loading}
            className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-mauve text-ctp-base hover:bg-ctp-mauve/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Kerberoast
          </button>
          <button
            onClick={handleAsreproast}
            disabled={loading}
            className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-mauve text-ctp-base hover:bg-ctp-mauve/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            ASREPRoast
          </button>
        </div>
        <p className="text-xs text-ctp-subtext0 italic">Hashes will be automatically stored in loot.</p>
      </div>

      {/* LDAP Query */}
      <div className="space-y-2">
        <p className="text-xs text-ctp-subtext0 uppercase tracking-wide">LDAP Query</p>
        <input
          type="text"
          value={ldapFilter}
          onChange={e => setLdapFilter(e.target.value)}
          placeholder="(objectClass=user)"
          className="w-full px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
        />
        <input
          type="text"
          value={ldapAttrs}
          onChange={e => setLdapAttrs(e.target.value)}
          placeholder="Attributes (comma-separated, e.g. cn,mail,memberOf)"
          className="w-full px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm placeholder-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
        />
        <button
          onClick={handleLdapQuery}
          disabled={loading}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-surface1 text-ctp-text hover:bg-ctp-surface2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Dispatching...' : 'Run Query'}
        </button>
      </div>

      {error && (
        <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
          {error}
        </div>
      )}

      {taskId && (
        <div className="space-y-1">
          <div className="text-xs text-ctp-subtext0">
            Operation: <span className="text-ctp-text">{activeOp ? opLabel[activeOp] : ''}</span>
          </div>
          <div className="text-xs text-ctp-subtext0">
            Task ID: <span className="font-mono text-ctp-blue">{taskId}</span>
          </div>
        </div>
      )}

      {result && (
        <div className="rounded border border-ctp-surface2 overflow-auto">
          <table className="w-full text-xs">
            <thead className="bg-ctp-crust">
              <tr>
                {result.columns.map(col => (
                  <th key={col} className="px-3 py-2 text-left text-ctp-subtext0 font-medium">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {result.rows.map((row, i) => (
                <tr key={i} className="hover:bg-ctp-surface0/50">
                  {row.map((cell, j) => (
                    <td key={j} className="px-3 py-1.5 text-ctp-text font-mono">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
