import { useState, useMemo } from 'react';
import { useAuthStore } from '../stores/authStore';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AuditEvent {
  id: string;
  timestamp: number;
  operator: string;
  action: string;
  target: string | null;
  details: string;
}

// ---------------------------------------------------------------------------
// Mock data (replace with real AuditService API call later)
// ---------------------------------------------------------------------------

const MOCK_AUDIT_EVENTS: AuditEvent[] = [
  { id: '1',  timestamp: Date.now() - 3_600_000,   operator: 'admin',     action: 'session.interact',  target: 'DESKTOP-ABC123',   details: 'Executed: whoami' },
  { id: '2',  timestamp: Date.now() - 7_200_000,   operator: 'operator1', action: 'task.dispatch',     target: 'WORKSTATION-01',   details: 'Shell command' },
  { id: '3',  timestamp: Date.now() - 10_800_000,  operator: 'admin',     action: 'listener.create',   target: null,               details: 'HTTPS listener on :443' },
  { id: '4',  timestamp: Date.now() - 14_400_000,  operator: 'operator2', action: 'loot.export',       target: 'FILESERVER-02',    details: 'Exported credentials.json' },
  { id: '5',  timestamp: Date.now() - 18_000_000,  operator: 'admin',     action: 'operator.create',   target: null,               details: 'Created operator: operator2' },
  { id: '6',  timestamp: Date.now() - 21_600_000,  operator: 'operator1', action: 'session.interact',  target: 'LAPTOP-HR-07',     details: 'Executed: ipconfig /all' },
  { id: '7',  timestamp: Date.now() - 25_200_000,  operator: 'admin',     action: 'operator.delete',   target: null,               details: 'Revoked operator: tempuser' },
  { id: '8',  timestamp: Date.now() - 28_800_000,  operator: 'operator2', action: 'module.run',        target: 'DESKTOP-ABC123',   details: 'mod-inject: process hollowing' },
  { id: '9',  timestamp: Date.now() - 32_400_000,  operator: 'admin',     action: 'listener.delete',   target: null,               details: 'Deleted HTTP listener on :80' },
  { id: '10', timestamp: Date.now() - 36_000_000,  operator: 'operator1', action: 'session.interact',  target: 'FILESERVER-02',    details: 'Executed: net user /domain' },
  { id: '11', timestamp: Date.now() - 39_600_000,  operator: 'admin',     action: 'report.generate',   target: null,               details: 'Generated engagement report' },
  { id: '12', timestamp: Date.now() - 43_200_000,  operator: 'operator2', action: 'loot.view',         target: 'WORKSTATION-01',   details: 'Viewed credential dump' },
  { id: '13', timestamp: Date.now() - 46_800_000,  operator: 'admin',     action: 'session.kill',      target: 'LAPTOP-HR-07',     details: 'Terminated session' },
  { id: '14', timestamp: Date.now() - 50_400_000,  operator: 'operator1', action: 'task.dispatch',     target: 'FILESERVER-02',    details: 'File upload: beacon.exe' },
  { id: '15', timestamp: Date.now() - 54_000_000,  operator: 'admin',     action: 'operator.update',   target: null,               details: 'Updated role: operator1 -> admin' },
  { id: '16', timestamp: Date.now() - 57_600_000,  operator: 'operator1', action: 'session.interact',  target: 'DC-01',            details: 'Executed: nltest /domain_trusts' },
  { id: '17', timestamp: Date.now() - 61_200_000,  operator: 'admin',     action: 'listener.create',   target: null,               details: 'DNS listener on :53' },
  { id: '18', timestamp: Date.now() - 64_800_000,  operator: 'operator2', action: 'module.run',        target: 'DC-01',            details: 'mod-token: impersonation' },
  { id: '19', timestamp: Date.now() - 68_400_000,  operator: 'admin',     action: 'session.interact',  target: 'DC-01',            details: 'Executed: mimikatz' },
  { id: '20', timestamp: Date.now() - 72_000_000,  operator: 'operator1', action: 'loot.export',       target: 'DC-01',            details: 'Exported loot bundle' },
];

// ---------------------------------------------------------------------------
// Action badge helpers
// ---------------------------------------------------------------------------

type ActionCategory = 'read' | 'write' | 'delete';

function categorizeAction(action: string): ActionCategory {
  const verb = action.split('.')[1] ?? action;
  if (['delete', 'kill', 'revoke'].includes(verb)) return 'delete';
  if (['view', 'export', 'interact'].includes(verb)) return 'read';
  return 'write';
}

const CATEGORY_COLORS: Record<ActionCategory, string> = {
  read:   'bg-ctp-green/20 text-ctp-green',
  write:  'bg-ctp-yellow/20 text-ctp-yellow',
  delete: 'bg-ctp-red/20 text-ctp-red',
};

function ActionBadge({ action }: { action: string }) {
  const category = categorizeAction(action);
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${CATEGORY_COLORS[category]}`}>
      {action}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------

function exportJSON(events: AuditEvent[]) {
  const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit-log-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCSV(events: AuditEvent[]) {
  const header = 'id,timestamp,operator,action,target,details';
  const rows = events.map(e =>
    [
      e.id,
      new Date(e.timestamp).toISOString(),
      e.operator,
      e.action,
      e.target ?? '',
      `"${e.details.replace(/"/g, '""')}"`,
    ].join(',')
  );
  const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PAGE_SIZE = 10;

const ALL_OPERATORS = Array.from(new Set(MOCK_AUDIT_EVENTS.map(e => e.operator))).sort();
const ALL_ACTIONS   = Array.from(new Set(MOCK_AUDIT_EVENTS.map(e => e.action))).sort();

// ---------------------------------------------------------------------------
// Main Audit Page
// ---------------------------------------------------------------------------

export function Audit() {
  const operator = useAuthStore(s => s.operator);
  const isAdmin  = operator?.role === 'admin';

  // Filters
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo,   setDateTo]   = useState('');
  const [filterOperator, setFilterOperator] = useState('');
  const [filterAction,   setFilterAction]   = useState('');

  // Pagination
  const [page, setPage] = useState(1);

  const filtered = useMemo(() => {
    return MOCK_AUDIT_EVENTS.filter(e => {
      if (filterOperator && e.operator !== filterOperator) return false;
      if (filterAction   && e.action   !== filterAction)   return false;
      if (dateFrom) {
        const from = new Date(dateFrom).getTime();
        if (e.timestamp < from) return false;
      }
      if (dateTo) {
        // include the entire end day
        const to = new Date(dateTo).getTime() + 86_400_000;
        if (e.timestamp > to) return false;
      }
      return true;
    }).sort((a, b) => b.timestamp - a.timestamp);
  }, [filterOperator, filterAction, dateFrom, dateTo]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageEvents = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  function resetFilters() {
    setDateFrom('');
    setDateTo('');
    setFilterOperator('');
    setFilterAction('');
    setPage(1);
  }

  // Admin gate
  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <svg className="w-12 h-12 text-ctp-overlay0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        <p className="text-ctp-subtext0 text-sm">Admin access required to view audit logs.</p>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">Audit Log</h1>
          <p className="text-sm text-ctp-subtext0 mt-0.5">
            {filtered.length} event{filtered.length !== 1 ? 's' : ''} matching current filters
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => exportCSV(filtered)}
            className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium transition-colors text-ctp-text border border-ctp-surface1"
          >
            Export CSV
          </button>
          <button
            onClick={() => exportJSON(filtered)}
            className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium transition-colors text-ctp-crust"
          >
            Export JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-ctp-mantle rounded-lg border border-ctp-surface0 p-4 mb-4">
        <div className="flex flex-wrap gap-3 items-end">
          {/* Date From */}
          <div className="flex flex-col gap-1 min-w-[140px]">
            <label className="text-xs text-ctp-subtext0">From</label>
            <input
              type="date"
              value={dateFrom}
              onChange={e => { setDateFrom(e.target.value); setPage(1); }}
              className="bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-1.5 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
            />
          </div>

          {/* Date To */}
          <div className="flex flex-col gap-1 min-w-[140px]">
            <label className="text-xs text-ctp-subtext0">To</label>
            <input
              type="date"
              value={dateTo}
              onChange={e => { setDateTo(e.target.value); setPage(1); }}
              className="bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-1.5 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
            />
          </div>

          {/* Operator filter */}
          <div className="flex flex-col gap-1 min-w-[160px]">
            <label className="text-xs text-ctp-subtext0">Operator</label>
            <select
              value={filterOperator}
              onChange={e => { setFilterOperator(e.target.value); setPage(1); }}
              className="bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-1.5 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
            >
              <option value="">All operators</option>
              {ALL_OPERATORS.map(op => (
                <option key={op} value={op}>{op}</option>
              ))}
            </select>
          </div>

          {/* Action filter */}
          <div className="flex flex-col gap-1 min-w-[200px]">
            <label className="text-xs text-ctp-subtext0">Action type</label>
            <select
              value={filterAction}
              onChange={e => { setFilterAction(e.target.value); setPage(1); }}
              className="bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-1.5 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
            >
              <option value="">All actions</option>
              {ALL_ACTIONS.map(a => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
          </div>

          {/* Reset */}
          {(dateFrom || dateTo || filterOperator || filterAction) && (
            <button
              onClick={resetFilters}
              className="px-3 py-1.5 text-sm text-ctp-subtext1 hover:text-ctp-text transition-colors self-end"
            >
              Reset filters
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
        <table className="w-full">
          <thead className="bg-ctp-crust">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0 whitespace-nowrap">Timestamp</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Operator</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Action</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Target</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {pageEvents.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ctp-subtext0 text-sm">
                  No audit events match the current filters.
                </td>
              </tr>
            ) : (
              pageEvents.map(event => (
                <tr key={event.id} className="hover:bg-ctp-surface0/30">
                  <td className="px-4 py-3 text-xs text-ctp-subtext0 whitespace-nowrap font-mono">
                    {new Date(event.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-sm font-medium text-ctp-text">
                    {event.operator}
                  </td>
                  <td className="px-4 py-3">
                    <ActionBadge action={event.action} />
                  </td>
                  <td className="px-4 py-3 text-sm text-ctp-subtext1 font-mono">
                    {event.target ?? <span className="text-ctp-overlay0 italic">—</span>}
                  </td>
                  <td className="px-4 py-3 text-sm text-ctp-subtext1 max-w-xs truncate" title={event.details}>
                    {event.details}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between mt-4">
        <p className="text-sm text-ctp-subtext0">
          Page {safePage} of {totalPages} &mdash; {filtered.length} total events
        </p>
        <div className="flex gap-2">
          <button
            onClick={() => setPage(1)}
            disabled={safePage === 1}
            className="px-3 py-1.5 bg-ctp-surface0 hover:bg-ctp-surface1 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm transition-colors"
            aria-label="First page"
          >
            «
          </button>
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={safePage === 1}
            className="px-3 py-1.5 bg-ctp-surface0 hover:bg-ctp-surface1 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm transition-colors"
            aria-label="Previous page"
          >
            ‹
          </button>

          {/* Page number pills */}
          {Array.from({ length: totalPages }, (_, i) => i + 1)
            .filter(p => p === 1 || p === totalPages || Math.abs(p - safePage) <= 1)
            .reduce<(number | '…')[]>((acc, p, idx, arr) => {
              if (idx > 0 && (p as number) - (arr[idx - 1] as number) > 1) acc.push('…');
              acc.push(p);
              return acc;
            }, [])
            .map((p, idx) =>
              p === '…' ? (
                <span key={`ellipsis-${idx}`} className="px-2 py-1.5 text-sm text-ctp-subtext0">…</span>
              ) : (
                <button
                  key={p}
                  onClick={() => setPage(p as number)}
                  className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                    safePage === p
                      ? 'bg-ctp-mauve text-ctp-crust font-medium'
                      : 'bg-ctp-surface0 hover:bg-ctp-surface1 text-ctp-text'
                  }`}
                >
                  {p}
                </button>
              )
            )}

          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={safePage === totalPages}
            className="px-3 py-1.5 bg-ctp-surface0 hover:bg-ctp-surface1 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm transition-colors"
            aria-label="Next page"
          >
            ›
          </button>
          <button
            onClick={() => setPage(totalPages)}
            disabled={safePage === totalPages}
            className="px-3 py-1.5 bg-ctp-surface0 hover:bg-ctp-surface1 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm transition-colors"
            aria-label="Last page"
          >
            »
          </button>
        </div>
      </div>
    </div>
  );
}
