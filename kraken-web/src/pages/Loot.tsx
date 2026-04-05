import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { lootClient } from '../api/index.js';
import { LootType } from '../gen/kraken_pb.js';
import type { LootEntry as ProtoLootEntry } from '../gen/kraken_pb.js';
import { LootItem } from '../types';
import { LootEventData } from '../types/websocket';
import { Modal } from '../components/Modal';
import { useRealtime } from '../hooks/useRealtime';

function uuidToHex(uuid: { value: Uint8Array } | undefined): string {
  if (!uuid?.value) return '';
  return Array.from(uuid.value).map(b => b.toString(16).padStart(2, '0')).join('');
}

function protoLootTypeToUI(t: LootType): LootItem['lootType'] {
  switch (t) {
    case LootType.CREDENTIAL: return 'credential';
    case LootType.TOKEN: return 'token';
    case LootType.FILE: return 'file';
    case LootType.HASH: return 'credential'; // map hash to credential bucket
    default: return 'credential';
  }
}

function protoLootToUI(entry: ProtoLootEntry): LootItem {
  let data: Record<string, unknown> = {};

  if (entry.data.case === 'credential') {
    const c = entry.data.value;
    data = { username: c.username, domain: c.domain, credentialType: 'password', secret: c.password };
  } else if (entry.data.case === 'hash') {
    const h = entry.data.value;
    data = { username: h.username, credentialType: h.hashType, secret: h.hash };
  } else if (entry.data.case === 'token') {
    const t = entry.data.value;
    data = {
      tokenType: t.tokenType,
      token: t.tokenValue,
      service: t.service,
      expiresAt: t.expiresAt ? new Date(Number(t.expiresAt.millis)).toLocaleString() : undefined,
    };
  } else if (entry.data.case === 'file') {
    const f = entry.data.value;
    data = {
      path: f.originalPath,
      size: String(f.size),
      filename: f.filename,
      description: f.description,
      content: f.content.length > 0 ? f.content : undefined,
    };
  }

  return {
    id: uuidToHex(entry.id),
    sessionId: uuidToHex(entry.implantId),
    lootType: protoLootTypeToUI(entry.lootType),
    // keep the raw case so the modal can distinguish credential vs hash
    _protoCase: entry.data.case,
    source: entry.source,
    collectedAt: entry.collectedAt
      ? new Date(Number(entry.collectedAt.millis)).toISOString()
      : new Date().toISOString(),
    data,
  } as LootItem & { _protoCase: string | undefined };
}

const FILTERS = ['All', 'Credentials', 'Files', 'Tokens'] as const;
type Filter = typeof FILTERS[number];

function matchesFilter(item: LootItem, filter: Filter): boolean {
  if (filter === 'All') return true;
  if (filter === 'Credentials') return item.lootType === 'credential';
  if (filter === 'Files') return item.lootType === 'file';
  if (filter === 'Tokens') return item.lootType === 'token';
  return true;
}

// ---------------------------------------------------------------------------
// Deduplication logic
// ---------------------------------------------------------------------------

interface DeduplicatedCredential {
  key: string; // username@domain or equivalent
  username: string;
  domain?: string;
  credentialType: string;
  secret: string;
  sources: string[];
  sourceCount: number;
  collectedAt: string;
  items: ExtendedLootItem[]; // Original items for bulk operations
}

function deduplicateCredentials(items: ExtendedLootItem[]): DeduplicatedCredential[] {
  const credMap = new Map<string, DeduplicatedCredential>();

  items.forEach(item => {
    if (item.lootType !== 'credential') return;

    const data = item.data as Record<string, string>;
    const protoCase = item._protoCase;

    let username = '';
    let domain = '';
    let credentialType = '';
    let secret = '';

    if (protoCase === 'credential') {
      username = data.username || '';
      domain = data.domain || '';
      credentialType = 'password';
      secret = data.secret || '';
    } else if (protoCase === 'hash') {
      username = data.username || '';
      domain = '';
      credentialType = data.credentialType || 'hash';
      secret = data.secret || '';
    }

    const key = domain ? `${username}@${domain}` : username;

    if (!credMap.has(key)) {
      credMap.set(key, {
        key,
        username,
        domain,
        credentialType,
        secret,
        sources: [item.source],
        sourceCount: 1,
        collectedAt: item.collectedAt,
        items: [item],
      });
    } else {
      const existing = credMap.get(key)!;
      if (!existing.sources.includes(item.source)) {
        existing.sources.push(item.source);
        existing.sourceCount++;
      }
      existing.items.push(item);
      // Keep the earliest collection time
      if (new Date(item.collectedAt) < new Date(existing.collectedAt)) {
        existing.collectedAt = item.collectedAt;
      }
    }
  });

  return Array.from(credMap.values()).sort((a, b) =>
    new Date(b.collectedAt).getTime() - new Date(a.collectedAt).getTime()
  );
}

// ---------------------------------------------------------------------------
// Export functions
// ---------------------------------------------------------------------------

function exportToCSV(items: LootItem[]) {
  const headers = ['Type', 'Username', 'Domain', 'Secret', 'Source', 'Collected At'];
  const rows = items.map(item => {
    const data = item.data as Record<string, string>;
    const protoCase = (item as ExtendedLootItem)._protoCase;

    let username = '';
    let domain = '';
    let secret = '';

    if (protoCase === 'credential') {
      username = data.username || '';
      domain = data.domain || '';
      secret = data.secret || '';
    } else if (protoCase === 'hash') {
      username = data.username || '';
      domain = '';
      secret = data.secret || '';
    } else if (item.lootType === 'token') {
      username = data.service || '';
      domain = '';
      secret = data.token || '';
    }

    return [
      item.lootType,
      username,
      domain,
      secret,
      item.source,
      new Date(item.collectedAt).toLocaleString(),
    ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(',');
  });

  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `loot-export-${new Date().toISOString().split('T')[0]}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportToJSON(items: LootItem[]) {
  const json = JSON.stringify(items, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `loot-export-${new Date().toISOString().split('T')[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Copy button
// ---------------------------------------------------------------------------

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <button
      onClick={handleCopy}
      className="ml-2 px-2 py-0.5 text-xs rounded bg-ctp-surface1 hover:bg-ctp-surface2 text-ctp-subtext1 hover:text-ctp-text transition-colors"
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Detail row helper
// ---------------------------------------------------------------------------

function DetailRow({
  label,
  value,
  sensitive = false,
  mono = false,
}: {
  label: string;
  value: string | undefined;
  sensitive?: boolean;
  mono?: boolean;
}) {
  const [revealed, setRevealed] = useState(false);

  if (!value) return null;

  const displayValue = sensitive && !revealed ? '••••••••••••' : value;

  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-ctp-subtext0 uppercase tracking-wide">{label}</span>
      <div className="flex items-center gap-1 flex-wrap">
        <span className={`text-sm text-ctp-text break-all ${mono ? 'font-mono' : ''}`}>
          {displayValue}
        </span>
        {sensitive && (
          <button
            onClick={() => setRevealed(r => !r)}
            className="px-2 py-0.5 text-xs rounded bg-ctp-surface1 hover:bg-ctp-surface2 text-ctp-subtext1 hover:text-ctp-text transition-colors"
          >
            {revealed ? 'Hide' : 'Show'}
          </button>
        )}
        {sensitive && revealed && <CopyButton value={value} />}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Expanded row inline preview
// ---------------------------------------------------------------------------

type ExtendedLootItem = LootItem & { _protoCase?: string };

function ExpandedRowContent({ item }: { item: ExtendedLootItem }) {
  const data = item.data as Record<string, string>;
  const protoCase = item._protoCase;

  return (
    <tr className="bg-ctp-surface0/50">
      {/* offset for checkbox + expand columns */}
      <td colSpan={7} className="px-6 py-4">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          {/* Credential (password) */}
          {protoCase === 'credential' && (
            <>
              <DetailRow label="Username" value={data.username} mono />
              <DetailRow label="Domain" value={data.domain} mono />
              <DetailRow label="Password" value={data.secret} sensitive mono />
            </>
          )}

          {/* Credential (hash) */}
          {protoCase === 'hash' && (
            <>
              <DetailRow label="Username" value={data.username} mono />
              <DetailRow label="Hash Type" value={data.credentialType} />
              <DetailRow label="Hash" value={data.secret} sensitive mono />
            </>
          )}

          {/* Token */}
          {item.lootType === 'token' && (
            <>
              <DetailRow label="Token Type" value={data.tokenType} />
              <DetailRow label="Service" value={data.service} mono />
              <DetailRow label="Token" value={data.token} sensitive mono />
              <DetailRow label="Expires At" value={data.expiresAt} />
            </>
          )}

          {/* File */}
          {item.lootType === 'file' && (
            <>
              <DetailRow label="Filename" value={data.filename} mono />
              <DetailRow label="Path" value={data.path} mono />
              <DetailRow label="Size" value={data.size ? `${data.size} bytes` : undefined} />
              <DetailRow label="Description" value={data.description} />
              {data.content && (
                <div className="col-span-full pt-1">
                  <button
                    onClick={() => {
                      const bytes = data.content as unknown as Uint8Array;
                      const copy = new Uint8Array(bytes.length);
                      copy.set(bytes);
                      const blob = new Blob([copy], { type: 'application/octet-stream' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = data.filename || 'loot-file';
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      URL.revokeObjectURL(url);
                    }}
                    className="inline-block px-3 py-1.5 bg-ctp-blue/20 hover:bg-ctp-blue/30 text-ctp-blue rounded-lg text-sm font-medium transition-colors"
                  >
                    Download File
                  </button>
                </div>
              )}
            </>
          )}

          {/* Screenshot */}
          {item.lootType === 'screenshot' && (
            <>
              <DetailRow label="Dimensions" value={data.width && data.height ? `${data.width}x${data.height}` : undefined} />
              {data.content && (
                <div className="col-span-full">
                  <img
                    src={`data:image/png;base64,${data.content}`}
                    alt="Screenshot"
                    className="max-w-full rounded-lg border border-ctp-surface1 mt-2"
                  />
                </div>
              )}
            </>
          )}

          {/* Common fields */}
          <div className="col-span-full border-t border-ctp-surface1 pt-3 mt-1 grid grid-cols-2 md:grid-cols-3 gap-4">
            <DetailRow label="Source" value={item.source} />
            <DetailRow label="Session ID" value={item.sessionId} mono />
            <DetailRow label="Collected At" value={new Date(item.collectedAt).toLocaleString()} />
          </div>
        </div>
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// View Detail Modal
// ---------------------------------------------------------------------------

function LootDetailModal({ item, onClose }: { item: ExtendedLootItem; onClose: () => void }) {
  const data = item.data as Record<string, string>;
  const protoCase = item._protoCase;

  const title = (
    <span className="flex items-center gap-3">
      <LootTypeBadge type={item.lootType} />
      Loot Detail
    </span>
  ) as unknown as string;

  const footer = (
    <button
      onClick={onClose}
      className="px-4 py-2 text-sm text-ctp-subtext1 hover:text-ctp-text transition-colors"
    >
      Close
    </button>
  );

  return (
    <Modal isOpen={true} onClose={onClose} title={title} size="lg" footer={footer}>
      <div className="space-y-4">
        {/* Credential (password) */}
        {protoCase === 'credential' && (
          <>
            <DetailRow label="Username" value={data.username} mono />
            <DetailRow label="Domain" value={data.domain} mono />
            <DetailRow label="Password" value={data.secret} sensitive mono />
          </>
        )}

        {/* Credential (hash) */}
        {protoCase === 'hash' && (
          <>
            <DetailRow label="Username" value={data.username} mono />
            <DetailRow label="Hash Type" value={data.credentialType} />
            <DetailRow label="Hash" value={data.secret} sensitive mono />
          </>
        )}

        {/* Token */}
        {item.lootType === 'token' && (
          <>
            <DetailRow label="Token Type" value={data.tokenType} />
            <DetailRow label="Service" value={data.service} mono />
            <DetailRow label="Token" value={data.token} sensitive mono />
            <DetailRow label="Expires At" value={data.expiresAt} />
          </>
        )}

        {/* File */}
        {item.lootType === 'file' && (
          <>
            <DetailRow label="Filename" value={data.filename} mono />
            <DetailRow label="Path" value={data.path} mono />
            <DetailRow label="Size" value={data.size ? `${data.size} bytes` : undefined} />
            <DetailRow label="Description" value={data.description} />
            {data.content && (
              <div className="pt-1">
                <button
                  onClick={() => {
                    const bytes = data.content as unknown as Uint8Array;
                    const copy = new Uint8Array(bytes.length);
                    copy.set(bytes);
                    const blob = new Blob([copy], { type: 'application/octet-stream' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = data.filename || 'loot-file';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                  }}
                  className="inline-block px-3 py-1.5 bg-ctp-blue/20 hover:bg-ctp-blue/30 text-ctp-blue rounded-lg text-sm font-medium transition-colors"
                >
                  Download File
                </button>
              </div>
            )}
          </>
        )}

        {/* Screenshot */}
        {item.lootType === 'screenshot' && (
          <>
            <DetailRow label="Dimensions" value={data.width && data.height ? `${data.width}x${data.height}` : undefined} />
            {data.content && (
              <img
                src={`data:image/png;base64,${data.content}`}
                alt="Screenshot"
                className="w-full rounded-lg border border-ctp-surface1 mt-2"
              />
            )}
          </>
        )}

        {/* Common fields */}
        <div className="border-t border-ctp-surface0 pt-3 mt-2 space-y-3">
          <DetailRow label="Source" value={item.source} />
          <DetailRow label="Session ID" value={item.sessionId} mono />
          <DetailRow label="Collected At" value={new Date(item.collectedAt).toLocaleString()} />
        </div>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Bulk delete confirmation modal
// ---------------------------------------------------------------------------

function DeleteConfirmModal({
  count,
  onConfirm,
  onCancel,
}: {
  count: number;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const footer = (
    <>
      <button
        onClick={onCancel}
        className="px-4 py-2 text-sm text-ctp-subtext1 hover:text-ctp-text transition-colors"
      >
        Cancel
      </button>
      <button
        onClick={onConfirm}
        className="px-4 py-2 text-sm bg-ctp-red/20 hover:bg-ctp-red/30 text-ctp-red rounded-lg font-medium transition-colors border border-ctp-red/30"
      >
        Delete {count} {count === 1 ? 'item' : 'items'}
      </button>
    </>
  );

  return (
    <Modal isOpen={true} onClose={onCancel} title="Delete Selected Loot" size="sm" footer={footer}>
      <p className="text-sm text-ctp-subtext1">
        Are you sure you want to delete <span className="text-ctp-red font-medium">{count}</span> loot{' '}
        {count === 1 ? 'item' : 'items'}? This action cannot be undone.
      </p>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Deduplicated credentials table
// ---------------------------------------------------------------------------

function DeduplicatedCredentialsTable({
  credentials,
  onViewDetails,
}: {
  credentials: DeduplicatedCredential[];
  onViewDetails: (item: ExtendedLootItem) => void;
}) {
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());

  function toggleExpand(key: string) {
    setExpandedKeys(prev => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }

  return (
    <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
      <table className="w-full">
        <thead className="bg-ctp-crust">
          <tr>
            <th className="px-2 py-3 w-8" />
            <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Username</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Domain</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Type</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Sources</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">First Seen</th>
            <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-ctp-surface0">
          {credentials.length === 0 ? (
            <tr>
              <td colSpan={7} className="px-4 py-8 text-center text-ctp-subtext0">
                No credentials found.
              </td>
            </tr>
          ) : (
            credentials.map((cred) => {
              const isExpanded = expandedKeys.has(cred.key);
              return (
                <>
                  <tr key={cred.key} className="hover:bg-ctp-surface0/30">
                    {/* Expand toggle */}
                    <td className="px-2 py-3">
                      <button
                        onClick={() => toggleExpand(cred.key)}
                        className="text-ctp-subtext0 hover:text-ctp-text transition-colors text-xs leading-none"
                        aria-label={isExpanded ? 'Collapse row' : 'Expand row'}
                      >
                        {isExpanded ? '▼' : '▶'}
                      </button>
                    </td>
                    <td className="px-4 py-3 font-mono text-sm">{cred.username}</td>
                    <td className="px-4 py-3 font-mono text-sm text-ctp-subtext1">
                      {cred.domain || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className="px-2 py-0.5 rounded bg-ctp-surface1 text-ctp-text text-xs">
                        {cred.credentialType}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className="px-2 py-0.5 rounded bg-ctp-blue/20 text-ctp-blue text-xs font-medium">
                        {cred.sourceCount} {cred.sourceCount === 1 ? 'source' : 'sources'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-ctp-subtext0 text-sm">
                      {new Date(cred.collectedAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <CopyButton value={cred.secret} />
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="bg-ctp-surface0/50">
                      <td colSpan={7} className="px-6 py-4">
                        <div className="space-y-3">
                          <div>
                            <span className="text-xs text-ctp-subtext0 uppercase tracking-wide block mb-2">
                              Sources ({cred.sources.length})
                            </span>
                            <div className="flex flex-wrap gap-2">
                              {cred.sources.map((source, idx) => (
                                <span
                                  key={idx}
                                  className="px-2 py-1 rounded bg-ctp-surface1 text-ctp-text text-xs"
                                >
                                  {source}
                                </span>
                              ))}
                            </div>
                          </div>
                          <div>
                            <span className="text-xs text-ctp-subtext0 uppercase tracking-wide block mb-2">
                              Individual Entries ({cred.items.length})
                            </span>
                            <div className="space-y-1">
                              {cred.items.map((item, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-center justify-between px-3 py-2 bg-ctp-mantle rounded text-sm"
                                >
                                  <span className="text-ctp-subtext1">
                                    {item.source} - {new Date(item.collectedAt).toLocaleString()}
                                  </span>
                                  <button
                                    onClick={() => onViewDetails(item)}
                                    className="text-ctp-mauve hover:underline text-xs"
                                  >
                                    View Details
                                  </button>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function Loot() {
  const queryClient = useQueryClient();
  const [activeFilter, setActiveFilter] = useState<Filter>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedItem, setSelectedItem] = useState<ExtendedLootItem | null>(null);

  // Multi-select state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  // Expanded rows state
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  // Bulk delete confirmation
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  // View mode: 'all' or 'deduplicated'
  const [viewMode, setViewMode] = useState<'all' | 'deduplicated'>('all');
  // Source filter
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  const { data: loot, isLoading, error, refetch } = useQuery({
    queryKey: ['loot', searchQuery],
    queryFn: async () => {
      if (searchQuery.trim()) {
        const res = await lootClient.searchLoot({ query: searchQuery.trim() });
        return res.entries.map(protoLootToUI);
      }
      const res = await lootClient.listLoot({ limit: 100 });
      return res.entries.map(protoLootToUI);
    },
  });

  // WebSocket real-time updates for new loot
  // Note: LootCaptured events are ready to receive but require server-side
  // loot event publishing to be implemented in the Rust server
  useRealtime<LootEventData>('LootCaptured', (data) => {
    // Refetch loot list to get the new item with full details
    // In the future, this could be optimized to add the item directly if
    // the WebSocket event contains all necessary data
    queryClient.invalidateQueries({ queryKey: ['loot', searchQuery] });

    // Show toast notification (optional - requires toast system)
    console.log('New loot captured:', data);
  });


  const filtered = loot?.filter(item => matchesFilter(item as LootItem, activeFilter)) ?? [];

  // Apply source filter
  const sourceFiltered = sourceFilter === 'all'
    ? filtered
    : filtered.filter(item => item.source === sourceFilter);

  // Get unique sources for filter dropdown
  const uniqueSources = Array.from(new Set(filtered.map(item => item.source))).sort();

  // Deduplication view for credentials only
  const deduplicatedCredentials = viewMode === 'deduplicated' && activeFilter === 'Credentials'
    ? deduplicateCredentials(sourceFiltered as ExtendedLootItem[])
    : [];

  // Select all / deselect all helpers
  const allFilteredIds = sourceFiltered.map(i => i.id);
  const allSelected = allFilteredIds.length > 0 && allFilteredIds.every(id => selectedIds.has(id));
  const someSelected = allFilteredIds.some(id => selectedIds.has(id));

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(prev => {
        const next = new Set(prev);
        allFilteredIds.forEach(id => next.delete(id));
        return next;
      });
    } else {
      setSelectedIds(prev => {
        const next = new Set(prev);
        allFilteredIds.forEach(id => next.add(id));
        return next;
      });
    }
  }

  function toggleSelect(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function toggleExpand(id: string) {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  // Export selected items
  function handleExportSelected(format: 'json' | 'csv') {
    const items = sourceFiltered.filter(i => selectedIds.has(i.id));
    if (format === 'json') {
      exportToJSON(items);
    } else {
      exportToCSV(items);
    }
  }

  // Export all filtered items
  function handleExportAll(format: 'json' | 'csv') {
    if (format === 'json') {
      exportToJSON(sourceFiltered);
    } else {
      exportToCSV(sourceFiltered);
    }
  }

  // Convert hex string back to Uint8Array for Uuid proto message
  function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
    const buf = new ArrayBuffer(hex.length / 2);
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // Bulk delete — calls deleteLoot for each selected id, then refetches
  async function handleBulkDelete() {
    setShowDeleteConfirm(false);
    const ids = Array.from(selectedIds);
    await Promise.allSettled(
      ids.map(id => lootClient.deleteLoot({ lootId: { value: hexToUint8Array(id) } }))
    );
    setSelectedIds(new Set());
    refetch();
  }

  const selectedCount = Array.from(selectedIds).filter(id => allFilteredIds.includes(id)).length;

  return (
    <div>
      {selectedItem && (
        <LootDetailModal item={selectedItem} onClose={() => setSelectedItem(null)} />
      )}
      {showDeleteConfirm && (
        <DeleteConfirmModal
          count={selectedCount}
          onConfirm={handleBulkDelete}
          onCancel={() => setShowDeleteConfirm(false)}
        />
      )}

      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Loot</h1>
        <div className="flex gap-2">
          <button
            onClick={() => handleExportAll('csv')}
            className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium transition-colors border border-ctp-surface1"
          >
            Export CSV
          </button>
          <button
            onClick={() => handleExportAll('json')}
            className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium transition-colors border border-ctp-surface1"
          >
            Export JSON
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search loot..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          className="w-full md:w-64 px-3 py-1.5 rounded-lg bg-ctp-surface0 border border-ctp-surface1 text-sm focus:outline-none focus:border-ctp-mauve"
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 mb-4">
        {/* Type filters */}
        <div className="flex gap-2">
          {FILTERS.map((filter) => (
            <button
              key={filter}
              onClick={() => {
                setActiveFilter(filter);
                // Reset to 'all' view when switching away from credentials
                if (filter !== 'Credentials') {
                  setViewMode('all');
                }
              }}
              className={`px-3 py-1 rounded-full text-sm transition-colors ${
                activeFilter === filter
                  ? 'bg-ctp-mauve text-ctp-crust'
                  : 'bg-ctp-surface0 hover:bg-ctp-surface1'
              }`}
            >
              {filter}
            </button>
          ))}
        </div>

        {/* Source filter */}
        {uniqueSources.length > 1 && (
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="px-3 py-1 rounded-lg bg-ctp-surface0 border border-ctp-surface1 text-sm focus:outline-none focus:border-ctp-mauve"
          >
            <option value="all">All Sources</option>
            {uniqueSources.map((source) => (
              <option key={source} value={source}>
                {source}
              </option>
            ))}
          </select>
        )}

        {/* Deduplication toggle (only for credentials) */}
        {activeFilter === 'Credentials' && (
          <button
            onClick={() => setViewMode(viewMode === 'all' ? 'deduplicated' : 'all')}
            className={`px-3 py-1 rounded-lg text-sm transition-colors border ${
              viewMode === 'deduplicated'
                ? 'bg-ctp-green/20 text-ctp-green border-ctp-green/30'
                : 'bg-ctp-surface0 hover:bg-ctp-surface1 border-ctp-surface1'
            }`}
          >
            {viewMode === 'deduplicated' ? 'Deduplicated' : 'Show All'}
          </button>
        )}
      </div>

      {/* Bulk action toolbar — only visible when items are selected */}
      {selectedCount > 0 && (
        <div className="mb-4 flex items-center gap-3 px-4 py-2.5 bg-ctp-surface0 border border-ctp-surface1 rounded-lg">
          <span className="text-sm text-ctp-subtext1 flex-1">
            {selectedCount} {selectedCount === 1 ? 'item' : 'items'} selected
          </span>
          <button
            onClick={() => handleExportSelected('csv')}
            className="px-3 py-1.5 text-sm bg-ctp-blue/20 hover:bg-ctp-blue/30 text-ctp-blue rounded-lg font-medium transition-colors border border-ctp-blue/30"
          >
            Export CSV
          </button>
          <button
            onClick={() => handleExportSelected('json')}
            className="px-3 py-1.5 text-sm bg-ctp-blue/20 hover:bg-ctp-blue/30 text-ctp-blue rounded-lg font-medium transition-colors border border-ctp-blue/30"
          >
            Export JSON
          </button>
          <button
            onClick={() => setShowDeleteConfirm(true)}
            className="px-3 py-1.5 text-sm bg-ctp-red/20 hover:bg-ctp-red/30 text-ctp-red rounded-lg font-medium transition-colors border border-ctp-red/30"
          >
            Delete Selected
          </button>
        </div>
      )}

      {error && (
        <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg text-ctp-red text-sm">
          Failed to load loot: {(error as Error).message}
        </div>
      )}

      {/* Show deduplicated view for credentials or regular table for everything else */}
      {viewMode === 'deduplicated' && activeFilter === 'Credentials' ? (
        <DeduplicatedCredentialsTable
          credentials={deduplicatedCredentials}
          onViewDetails={setSelectedItem}
        />
      ) : (
        <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
          <table className="w-full">
            <thead className="bg-ctp-crust">
              <tr>
                {/* Checkbox column */}
                <th className="px-3 py-3 w-10">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    ref={el => { if (el) el.indeterminate = someSelected && !allSelected; }}
                    onChange={toggleSelectAll}
                    className="w-4 h-4 rounded accent-ctp-mauve cursor-pointer"
                    aria-label="Select all"
                  />
                </th>
                {/* Expand column */}
                <th className="px-2 py-3 w-8" />
                <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Type</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Details</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Source</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Collected</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-ctp-subtext0">
                    Loading loot...
                  </td>
                </tr>
              ) : sourceFiltered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-ctp-subtext0">
                    No loot collected yet.
                  </td>
                </tr>
              ) : (
                sourceFiltered.map((item) => {
                  const isSelected = selectedIds.has(item.id);
                  const isExpanded = expandedIds.has(item.id);
                  return (
                    <>
                      <tr
                        key={item.id}
                        className={`hover:bg-ctp-surface0/30 ${isSelected ? 'bg-ctp-mauve/5' : ''}`}
                      >
                        {/* Checkbox */}
                        <td className="px-3 py-3">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggleSelect(item.id)}
                            onClick={e => e.stopPropagation()}
                            className="w-4 h-4 rounded accent-ctp-mauve cursor-pointer"
                            aria-label={`Select item ${item.id}`}
                          />
                        </td>
                        {/* Expand toggle */}
                        <td className="px-2 py-3">
                          <button
                            onClick={() => toggleExpand(item.id)}
                            className="text-ctp-subtext0 hover:text-ctp-text transition-colors text-xs leading-none"
                            aria-label={isExpanded ? 'Collapse row' : 'Expand row'}
                          >
                            {isExpanded ? '▼' : '▶'}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <LootTypeBadge type={item.lootType} />
                        </td>
                        <td className="px-4 py-3 font-mono text-sm">
                          {formatLootDetails(item)}
                        </td>
                        <td className="px-4 py-3 text-ctp-subtext1 text-sm">{item.source}</td>
                        <td className="px-4 py-3 text-ctp-subtext0 text-sm">
                          {new Date(item.collectedAt).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => setSelectedItem(item as ExtendedLootItem)}
                            className="text-ctp-mauve hover:underline text-sm"
                          >
                            View
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <ExpandedRowContent key={`${item.id}-expanded`} item={item as ExtendedLootItem} />
                      )}
                    </>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function LootTypeBadge({ type }: { type: LootItem['lootType'] }) {
  const colors: Record<LootItem['lootType'], string> = {
    credential: 'bg-ctp-yellow/20 text-ctp-yellow',
    file: 'bg-ctp-blue/20 text-ctp-blue',
    screenshot: 'bg-ctp-pink/20 text-ctp-pink',
    token: 'bg-ctp-green/20 text-ctp-green',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[type]}`}>
      {type}
    </span>
  );
}

function formatLootDetails(item: LootItem): string {
  const data = item.data as Record<string, string>;
  switch (item.lootType) {
    case 'credential':
      return `${data.username || 'unknown'} (${data.credentialType || 'unknown'})`;
    case 'file':
      return data.path || 'unknown file';
    case 'screenshot':
      return `${data.width}x${data.height}`;
    case 'token':
      return data.tokenType || 'unknown token';
    default:
      return JSON.stringify(data);
  }
}
