import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { implantClient, collabClient, lootClient, listenerClient } from '@/api';
import { ImplantState, LootType } from '@/api';
import type { CollabEvent, Implant } from '@/api';
import { useCollab } from '../contexts/CollabContext';

// Helper: convert Uuid bytes to hex string
function uuidHex(id: { value: Uint8Array } | undefined): string {
  if (!id) return '';
  return Array.from(id.value)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Helper: format a Timestamp proto to a short time string
function formatTimestamp(ts: { millis: bigint } | undefined): string {
  if (!ts) return '';
  const d = new Date(Number(ts.millis));
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// Helper: format a CollabEvent into a human-readable string
function formatEvent(event: CollabEvent): string {
  const ev = event.event;
  switch (ev.case) {
    case 'operatorOnline':
      return `Operator ${ev.value.username} came online`;
    case 'operatorOffline':
      return `Operator ${ev.value.username} went offline`;
    case 'sessionLocked': {
      const sid = uuidHex(ev.value.sessionId).slice(0, 8);
      return `Session ${sid} locked by ${ev.value.username}`;
    }
    case 'sessionUnlocked': {
      const sid = uuidHex(ev.value.sessionId).slice(0, 8);
      return `Session ${sid} unlocked by ${ev.value.username}`;
    }
    case 'taskDispatched': {
      const sid = uuidHex(ev.value.sessionId).slice(0, 8);
      return `Task dispatched on session ${sid}`;
    }
    case 'taskCompleted': {
      const sid = uuidHex(ev.value.sessionId).slice(0, 8);
      const status = ev.value.success ? 'completed' : 'failed';
      return `Task ${status} on session ${sid}`;
    }
    case 'chatMessage':
      return `${ev.value.fromUsername}: ${ev.value.message}`;
    default:
      return 'Unknown event';
  }
}

// Helper: pick an accent color per event type
function eventColor(event: CollabEvent): string {
  switch (event.event.case) {
    case 'operatorOnline':   return 'text-ctp-green';
    case 'operatorOffline':  return 'text-ctp-red';
    case 'sessionLocked':    return 'text-ctp-yellow';
    case 'sessionUnlocked':  return 'text-ctp-teal';
    case 'taskDispatched':   return 'text-ctp-blue';
    case 'taskCompleted':    return 'text-ctp-sapphire';
    case 'chatMessage':      return 'text-ctp-mauve';
    default:                 return 'text-ctp-subtext0';
  }
}

// ─── Chart: Session Activity (line chart) ───────────────────────────────────

interface DayPoint {
  label: string;
  value: number;
}

function SessionActivityChart({ implants }: { implants: Implant[] }) {
  // Build last-7-days buckets from implant lastSeen timestamps
  const now = Date.now();
  const MS_PER_DAY = 86_400_000;

  const days: DayPoint[] = Array.from({ length: 7 }, (_, i) => {
    const dayStart = now - (6 - i) * MS_PER_DAY;
    const dayEnd = dayStart + MS_PER_DAY;
    const d = new Date(dayStart);
    const label = d.toLocaleDateString([], { weekday: 'short' });

    const count = implants.filter((imp) => {
      const t = imp.lastSeen ? Number(imp.lastSeen.millis) : 0;
      return t >= dayStart && t < dayEnd;
    }).length;

    return { label, value: count };
  });

  const maxVal = Math.max(...days.map((d) => d.value), 1);

  const W = 300;
  const H = 100;
  const padL = 24;
  const padR = 8;
  const padT = 8;
  const padB = 20;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  const pts = days.map((d, i) => {
    const x = padL + (i / (days.length - 1)) * chartW;
    const y = padT + chartH - (d.value / maxVal) * chartH;
    return { x, y, ...d };
  });

  const linePath = pts
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(' ');

  const areaPath =
    `M ${pts[0].x.toFixed(1)} ${(padT + chartH).toFixed(1)} ` +
    pts.map((p) => `L ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ') +
    ` L ${pts[pts.length - 1].x.toFixed(1)} ${(padT + chartH).toFixed(1)} Z`;

  return (
    <div className="bg-ctp-mantle rounded-lg p-6 border border-ctp-surface0">
      <h2 className="text-lg font-semibold mb-4">Session Activity (7 days)</h2>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ height: 120 }}
        aria-label="Session activity over last 7 days"
      >
        <defs>
          <linearGradient id="actGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#a6e3a1" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#a6e3a1" stopOpacity="0.02" />
          </linearGradient>
        </defs>

        {/* Y-axis gridlines */}
        {[0, 0.25, 0.5, 0.75, 1].map((frac) => {
          const y = padT + frac * chartH;
          const val = Math.round(maxVal * (1 - frac));
          return (
            <g key={frac}>
              <line
                x1={padL} y1={y} x2={W - padR} y2={y}
                stroke="#313244" strokeWidth="1"
              />
              <text x={padL - 4} y={y + 3} textAnchor="end" fontSize="7" fill="#6c7086">
                {val}
              </text>
            </g>
          );
        })}

        {/* Area fill */}
        <path d={areaPath} fill="url(#actGrad)" />

        {/* Line */}
        <path d={linePath} fill="none" stroke="#a6e3a1" strokeWidth="1.5" strokeLinejoin="round" />

        {/* Dots */}
        {pts.map((p) => (
          <circle key={p.label} cx={p.x} cy={p.y} r="2.5" fill="#a6e3a1" />
        ))}

        {/* X-axis labels */}
        {pts.map((p) => (
          <text key={p.label} x={p.x} y={H - 4} textAnchor="middle" fontSize="7" fill="#6c7086">
            {p.label}
          </text>
        ))}
      </svg>
    </div>
  );
}

// ─── Chart: Task Statistics (donut) ─────────────────────────────────────────

interface TaskStats {
  completed: number;
  failed: number;
  pending: number;
}

function TaskDonutChart({ events }: { events: CollabEvent[] }) {
  // Tally task outcomes from collab events
  let completed = 0;
  let failed = 0;
  let pending = 0;

  for (const ev of events) {
    if (ev.event.case === 'taskDispatched') pending++;
    if (ev.event.case === 'taskCompleted') {
      if (ev.event.value.success) completed++;
      else failed++;
    }
  }

  const stats: TaskStats = { completed, failed, pending };
  const total = stats.completed + stats.failed + stats.pending;

  // Build donut arcs
  const cx = 60;
  const cy = 60;
  const R = 44;
  const r = 28;

  type Segment = { value: number; color: string; label: string };
  const segments: Segment[] = [
    { value: stats.completed, color: '#a6e3a1', label: 'Completed' },
    { value: stats.failed,    color: '#f38ba8', label: 'Failed' },
    { value: stats.pending,   color: '#f9e2af', label: 'Pending' },
  ];

  function polarToCartesian(angle: number, radius: number) {
    const rad = ((angle - 90) * Math.PI) / 180;
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
  }

  function arcPath(startAngle: number, endAngle: number): string {
    const large = endAngle - startAngle > 180 ? 1 : 0;
    const o1 = polarToCartesian(startAngle, R);
    const o2 = polarToCartesian(endAngle, R);
    const i1 = polarToCartesian(endAngle, r);
    const i2 = polarToCartesian(startAngle, r);
    return [
      `M ${o1.x.toFixed(2)} ${o1.y.toFixed(2)}`,
      `A ${R} ${R} 0 ${large} 1 ${o2.x.toFixed(2)} ${o2.y.toFixed(2)}`,
      `L ${i1.x.toFixed(2)} ${i1.y.toFixed(2)}`,
      `A ${r} ${r} 0 ${large} 0 ${i2.x.toFixed(2)} ${i2.y.toFixed(2)}`,
      'Z',
    ].join(' ');
  }

  let cursor = 0;
  const arcs = segments.map((seg) => {
    const sweep = (seg.value / total) * 360;
    const path = arcPath(cursor, cursor + sweep - 0.5);
    cursor += sweep;
    return { ...seg, path };
  });

  return (
    <div className="bg-ctp-mantle rounded-lg p-6 border border-ctp-surface0">
      <h2 className="text-lg font-semibold mb-4">Task Statistics</h2>
      {total === 0 ? (
        <div className="text-ctp-subtext0 text-sm text-center py-8">
          No task data yet. Tasks will appear here as operators dispatch work.
        </div>
      ) : (
        <div className="flex items-center gap-6">
          <svg viewBox="0 0 120 120" style={{ width: 120, height: 120, flexShrink: 0 }} aria-label="Task statistics donut chart">
            {arcs.map((arc) => (
              <path key={arc.label} d={arc.path} fill={arc.color} opacity="0.9" />
            ))}
            <text x={cx} y={cy - 5} textAnchor="middle" fontSize="14" fontWeight="bold" fill="#cdd6f4">
              {total}
            </text>
            <text x={cx} y={cy + 9} textAnchor="middle" fontSize="7" fill="#6c7086">
              tasks
            </text>
          </svg>
          <div className="space-y-2 text-sm">
            {segments.map((seg) => (
              <div key={seg.label} className="flex items-center gap-2">
                <span
                  className="inline-block w-3 h-3 rounded-sm shrink-0"
                  style={{ backgroundColor: seg.color }}
                />
                <span className="text-ctp-subtext1">{seg.label}</span>
                <span className="ml-auto font-mono text-ctp-text pl-4">
                  {seg.value}
                  <span className="text-ctp-subtext0 text-xs ml-1">
                    ({Math.round((seg.value / total) * 100)}%)
                  </span>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Chart: OS Distribution (horizontal bar) ────────────────────────────────

function OsDistributionChart({ implants }: { implants: Implant[] }) {
  // Tally OS names from real implant data
  const counts: Record<string, number> = {};

  for (const imp of implants) {
    const raw = imp.systemInfo?.osName ?? '';
    let os = 'Unknown';
    if (/windows/i.test(raw)) os = 'Windows';
    else if (/linux/i.test(raw)) os = 'Linux';
    else if (/darwin|mac/i.test(raw)) os = 'macOS';
    else if (raw.trim()) os = raw.trim();
    counts[os] = (counts[os] ?? 0) + 1;
  }

  const entries: { os: string; count: number; color: string }[] =
    Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([os, count], i) => {
        const palette = ['#89b4fa', '#a6e3a1', '#cba6f7', '#fab387', '#f9e2af'];
        return { os, count, color: palette[i % palette.length] };
      });

  const maxCount = Math.max(...entries.map((e) => e.count), 1);

  return (
    <div className="bg-ctp-mantle rounded-lg p-6 border border-ctp-surface0">
      <h2 className="text-lg font-semibold mb-4">OS Distribution</h2>
      <div className="space-y-3">
        {entries.map((entry) => {
          const pct = (entry.count / maxCount) * 100;
          return (
            <div key={entry.os}>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-ctp-subtext1">{entry.os}</span>
                <span className="font-mono text-ctp-text">{entry.count}</span>
              </div>
              <div className="w-full bg-ctp-surface0 rounded-full h-2 overflow-hidden">
                <div
                  className="h-2 rounded-full transition-all duration-500"
                  style={{ width: `${pct}%`, backgroundColor: entry.color }}
                />
              </div>
            </div>
          );
        })}
        {entries.length === 0 && (
          <p className="text-ctp-subtext0 text-sm">No implant data available.</p>
        )}
      </div>
    </div>
  );
}

// ─── Main Dashboard ──────────────────────────────────────────────────────────

export function Dashboard() {
  const { state: collabState } = useCollab();
  const recentEvents = collabState.recentEvents.slice(0, 10);

  const { data: implantsData, isLoading: implantsLoading, isError: implantsError, error: implantsErr } = useQuery({
    queryKey: ['implants'],
    queryFn: () => implantClient.listImplants({}),
    refetchInterval: 5000,
    retry: 1,
  });

  const { data: collabStats } = useQuery({
    queryKey: ['collabStats'],
    queryFn: () => collabClient.getStats({}),
    refetchInterval: 5000,
    retry: 0,  // Don't retry - auth may not be configured
  });

  const { data: lootData, isLoading: lootLoading, isError: lootError, error: lootErr } = useQuery({
    queryKey: ['loot', 'all'],
    queryFn: () => lootClient.listLoot({ limit: 1 }),
    refetchInterval: 30000,
    retry: 1,
  });

  const { data: credData } = useQuery({
    queryKey: ['loot', 'credentials'],
    queryFn: () => lootClient.listLoot({ limit: 1, typeFilter: LootType.CREDENTIAL }),
    refetchInterval: 30000,
    retry: 1,
  });

  const { data: listenersData, isLoading: listenersLoading, isError: listenersError, error: listenersErr } = useQuery({
    queryKey: ['listeners'],
    queryFn: () => listenerClient.listListeners({}),
    refetchInterval: 5000,
    retry: 1,
  });

  const isLoading = implantsLoading || lootLoading || listenersLoading;
  // CollabService may fail auth in dev mode - don't block dashboard
  const isError = implantsError || lootError || listenersError;

  const implants = implantsData?.implants ?? [];
  const activeSessions = implants.filter(i => i.state === ImplantState.ACTIVE).length;
  const totalSessions = implants.length;
  const activeListeners = (listenersData?.listeners ?? []).filter(l => l.isRunning).length;
  const totalLoot = lootData?.totalCount ?? 0;
  const totalCredentials = credData?.totalCount ?? 0;
  const onlineOperators = collabStats?.onlineOperators ?? 0;

  // Sort implants by lastSeen descending for recent sessions
  const recentSessions = [...implants]
    .sort((a, b) => {
      const aTime = a.lastSeen?.millis ?? BigInt(0);
      const bTime = b.lastSeen?.millis ?? BigInt(0);
      return aTime > bTime ? -1 : aTime < bTime ? 1 : 0;
    })
    .slice(0, 10);

  if (isLoading) {
    return <div className="text-gray-400">Loading...</div>;
  }

  if (isError) {
    const errors = [
      implantsErr && `Implants: ${implantsErr}`,
      lootErr && `Loot: ${lootErr}`,
      listenersErr && `Listeners: ${listenersErr}`,
    ].filter(Boolean);

    console.error('Dashboard errors:', { implantsErr, lootErr, listenersErr });

    return (
      <div className="bg-ctp-mantle rounded-lg p-6 border border-ctp-red/50">
        <p className="text-ctp-red font-semibold mb-2">Failed to load dashboard data</p>
        <ul className="text-xs text-ctp-subtext0 space-y-1 font-mono">
          {errors.map((e, i) => <li key={i}>{e}</li>)}
        </ul>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <StatCard
          label="Active Sessions"
          value={activeSessions}
          color="text-ctp-green"
        />
        <StatCard
          label="Total Sessions"
          value={totalSessions}
          color="text-ctp-text"
        />
        <StatCard
          label="Listeners"
          value={activeListeners}
          color="text-ctp-blue"
        />
        <StatCard
          label="Loot"
          value={totalLoot}
          subValue={totalCredentials > 0 ? `${totalCredentials} creds` : undefined}
          color="text-ctp-yellow"
        />
        <StatCard
          label="Operators Online"
          value={onlineOperators}
          color="text-ctp-mauve"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-1">
          <SessionActivityChart implants={implants} />
        </div>
        <div className="lg:col-span-1">
          <TaskDonutChart events={collabState.recentEvents} />
        </div>
        <div className="lg:col-span-1">
          <OsDistributionChart implants={implants} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Sessions */}
        <div className="lg:col-span-2 bg-ctp-mantle rounded-lg p-6 border border-ctp-surface0">
          <h2 className="text-lg font-semibold mb-4">Recent Sessions</h2>
          {recentSessions.length === 0 ? (
            <div className="text-ctp-subtext0 text-sm">
              No sessions yet. Sessions will appear here once implants check in.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-ctp-subtext0 text-left border-b border-ctp-surface0">
                  <th className="pb-2 pr-4">Name</th>
                  <th className="pb-2 pr-4">Hostname</th>
                  <th className="pb-2 pr-4">User</th>
                  <th className="pb-2 pr-4">OS</th>
                  <th className="pb-2">State</th>
                </tr>
              </thead>
              <tbody>
                {recentSessions.map((implant, idx) => (
                  <SessionRow
                    key={uuidHex(implant.id) || idx}
                    implant={implant}
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Activity Feed */}
        <div className="bg-ctp-mantle rounded-lg p-6 border border-ctp-surface0">
          <h2 className="text-lg font-semibold mb-4">Activity</h2>
          {recentEvents.length === 0 ? (
            <div className="text-ctp-subtext0 text-sm">
              No recent activity. Events will appear here as operators connect and tasks run.
            </div>
          ) : (
            <ol className="space-y-3">
              {recentEvents.map((event, idx) => (
                <li key={idx} className="flex gap-3 text-sm">
                  <div className="flex flex-col items-center">
                    <div className={`w-2 h-2 rounded-full mt-1 shrink-0 ${eventColor(event).replace('text-', 'bg-')}`} />
                    {idx < recentEvents.length - 1 && (
                      <div className="w-px flex-1 bg-ctp-surface0 mt-1" />
                    )}
                  </div>
                  <div className="pb-3 min-w-0">
                    <p className={`font-medium leading-tight truncate ${eventColor(event)}`}>
                      {formatEvent(event)}
                    </p>
                    <p className="text-ctp-subtext0 text-xs mt-0.5">
                      {formatTimestamp(event.timestamp)}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color, subValue }: { label: string; value: number; color: string; subValue?: string }) {
  return (
    <div className="bg-ctp-mantle rounded-lg p-4 border border-ctp-surface0">
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
      <div className="text-ctp-subtext0 text-sm">{label}</div>
      {subValue && (
        <div className="text-ctp-subtext0 text-xs mt-0.5 font-mono">{subValue}</div>
      )}
    </div>
  );
}

function SessionRow({ implant }: { implant: Implant }) {
  const navigate = useNavigate();

  const stateLabel: Record<number, string> = {
    [ImplantState.ACTIVE]: 'Active',
    [ImplantState.STAGING]: 'Staging',
    [ImplantState.LOST]: 'Lost',
    [ImplantState.UNSPECIFIED]: 'Unknown',
  };

  const stateColor: Record<number, string> = {
    [ImplantState.ACTIVE]: 'text-ctp-green',
    [ImplantState.STAGING]: 'text-ctp-yellow',
    [ImplantState.LOST]: 'text-ctp-red',
    [ImplantState.UNSPECIFIED]: 'text-ctp-subtext0',
  };

  const label = stateLabel[implant.state] ?? 'Unknown';
  const color = stateColor[implant.state] ?? 'text-ctp-subtext0';
  const sessionId = uuidHex(implant.id);

  const handleClick = sessionId ? () => navigate(`/sessions/${sessionId}`) : undefined;

  return (
    <tr
      className={`border-b border-ctp-surface0 last:border-0 transition-colors ${sessionId ? 'hover:bg-ctp-surface0/50 cursor-pointer' : ''}`}
      onClick={handleClick}
    >
      <td className="py-2 pr-4 font-mono text-ctp-text">{implant.name || '—'}</td>
      <td className="py-2 pr-4 text-ctp-subtext1">{implant.systemInfo?.hostname || '—'}</td>
      <td className="py-2 pr-4 text-ctp-subtext1">{implant.systemInfo?.username || '—'}</td>
      <td className="py-2 pr-4 text-ctp-subtext1">{implant.systemInfo?.osName || '—'}</td>
      <td className={`py-2 font-semibold ${color}`}>{label}</td>
    </tr>
  );
}
