import { useEffect, useRef, useState, useCallback } from 'react';
import type { ReactNode } from 'react';
import Anser from 'anser';
import { TaskStatus, ShellResult } from '../../gen/kraken_pb.js';
import type { TaskInfo } from '../../gen/kraken_pb.js';
import { useCollab } from '../../contexts/CollabContext.js';
import { useAuthStore } from '../../stores/authStore.js';
import type { OperatorPresence } from '../../api/index.js';

interface TerminalProps {
  tasks: TaskInfo[];
  isLoading: boolean;
}

function uuidToHex(uuid: { value: Uint8Array } | undefined): string {
  if (!uuid?.value) return '';
  return Array.from(uuid.value).map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseShellResult(data: Uint8Array): ShellResult | null {
  if (!data || data.length === 0) return null;
  try {
    return ShellResult.fromBinary(data);
  } catch {
    return null;
  }
}

/** Resolve an operatorId UUID to a display username.
 *  Checks online operators first, then the current auth operator,
 *  falling back to the first 8 chars of the hex UUID. */
function resolveOperatorName(
  operatorId: { value: Uint8Array } | undefined,
  onlineOperators: OperatorPresence[],
  currentOperatorIdHex: string | null,
  currentOperatorUsername: string | null,
): string | null {
  if (!operatorId) return null;
  const hex = uuidToHex(operatorId);
  if (!hex) return null;
  for (const op of onlineOperators) {
    if (uuidToHex(op.operatorId) === hex) return op.username;
  }
  if (currentOperatorIdHex && hex === currentOperatorIdHex && currentOperatorUsername) {
    return currentOperatorUsername;
  }
  return hex.slice(0, 8);
}

/** Returns plain-text content for a task (command + stdout + stderr) used for search matching */
function getTaskSearchText(task: TaskInfo): string {
  const parts: string[] = [task.taskType];
  if (task.status === TaskStatus.COMPLETED) {
    const result = parseShellResult(task.resultData);
    if (result) {
      if (result.stdout) parts.push(result.stdout);
      if (result.stderr) parts.push(result.stderr);
    }
  }
  if (task.error?.message) parts.push(task.error.message);
  return parts.join('\n');
}

/** Wrap occurrences of `query` in a yellow highlight span */
function highlightText(text: string, query: string): ReactNode {
  if (!query.trim()) return text;
  const lower = text.toLowerCase();
  const lowerQuery = query.toLowerCase();
  const nodes: ReactNode[] = [];
  let pos = 0;
  let idx: number;
  while ((idx = lower.indexOf(lowerQuery, pos)) !== -1) {
    if (idx > pos) nodes.push(text.slice(pos, idx));
    nodes.push(
      <mark key={idx} className="bg-ctp-yellow text-ctp-crust rounded-sm">
        {text.slice(idx, idx + query.length)}
      </mark>
    );
    pos = idx + query.length;
  }
  if (pos < text.length) nodes.push(text.slice(pos));
  return <>{nodes}</>;
}

export function Terminal({ tasks, isLoading }: TerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Operator attribution
  const { state: collabState } = useCollab();
  const currentOperator = useAuthStore(s => s.operator);
  const currentOperatorIdHex = currentOperator?.id ? uuidToHex(currentOperator.id) : null;
  const currentOperatorUsername = currentOperator?.username ?? null;

  // Search state
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [matchIndices, setMatchIndices] = useState<number[]>([]);
  const [currentMatchIndex, setCurrentMatchIndex] = useState(0);

  // Recompute matches whenever query or tasks change
  useEffect(() => {
    if (!searchQuery.trim()) {
      setMatchIndices([]);
      setCurrentMatchIndex(0);
      return;
    }
    const lower = searchQuery.toLowerCase();
    const indices: number[] = [];
    tasks.forEach((task, i) => {
      if (getTaskSearchText(task).toLowerCase().includes(lower)) {
        indices.push(i);
      }
    });
    setMatchIndices(indices);
    setCurrentMatchIndex(0);
  }, [searchQuery, tasks]);

  // Scroll the active match into view
  useEffect(() => {
    if (matchIndices.length === 0) return;
    const activeTaskIndex = matchIndices[currentMatchIndex];
    if (activeTaskIndex === undefined) return;
    containerRef.current
      ?.querySelector(`[data-task-index="${activeTaskIndex}"]`)
      ?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [currentMatchIndex, matchIndices]);

  // Global Ctrl+Shift+F to open search
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key === 'F') {
        e.preventDefault();
        setSearchOpen(true);
        setTimeout(() => searchInputRef.current?.focus(), 0);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const closeSearch = useCallback(() => {
    setSearchOpen(false);
    setSearchQuery('');
    setMatchIndices([]);
    setCurrentMatchIndex(0);
  }, []);

  const goToNextMatch = useCallback(() => {
    if (matchIndices.length === 0) return;
    setCurrentMatchIndex(i => (i + 1) % matchIndices.length);
  }, [matchIndices.length]);

  const goToPrevMatch = useCallback(() => {
    if (matchIndices.length === 0) return;
    setCurrentMatchIndex(i => (i - 1 + matchIndices.length) % matchIndices.length);
  }, [matchIndices.length]);

  const handleSearchKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      closeSearch();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) goToPrevMatch();
      else goToNextMatch();
    }
  };

  // Auto-scroll to bottom when new tasks arrive
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [tasks, autoScroll]);

  // Track if user has scrolled up (disable auto-scroll)
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
    setAutoScroll(isAtBottom);
  };

  if (isLoading && tasks.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-ctp-subtext0">
        Loading tasks...
      </div>
    );
  }

  return (
    <div className="flex-1 relative overflow-hidden flex flex-col">
      {/* Search bar */}
      {searchOpen && (
        <div className="flex items-center gap-2 px-3 py-2 bg-ctp-surface0 border-b border-ctp-surface1 shrink-0 z-10">
          <input
            ref={searchInputRef}
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={handleSearchKeyDown}
            placeholder="Search output..."
            className="flex-1 bg-ctp-surface1 text-ctp-text placeholder-ctp-overlay0 text-sm px-3 py-1 rounded outline-none focus:ring-1 focus:ring-ctp-yellow font-mono"
          />
          <span className="text-xs font-mono text-ctp-subtext0 shrink-0 min-w-[7rem] text-right">
            {searchQuery.trim()
              ? matchIndices.length > 0
                ? `${currentMatchIndex + 1} of ${matchIndices.length} matches`
                : 'no matches'
              : ''}
          </span>
          <button
            onClick={goToPrevMatch}
            disabled={matchIndices.length === 0}
            title="Previous match (Shift+Enter)"
            className="p-1 rounded text-ctp-subtext0 hover:text-ctp-text hover:bg-ctp-surface1 disabled:opacity-30 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
            </svg>
          </button>
          <button
            onClick={goToNextMatch}
            disabled={matchIndices.length === 0}
            title="Next match (Enter)"
            className="p-1 rounded text-ctp-subtext0 hover:text-ctp-text hover:bg-ctp-surface1 disabled:opacity-30 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          <button
            onClick={closeSearch}
            title="Close search (Escape)"
            className="p-1 rounded text-ctp-subtext0 hover:text-ctp-red hover:bg-ctp-surface1 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto bg-ctp-crust font-mono text-sm p-4 space-y-4"
      >
        {tasks.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full min-h-48 py-16 select-none">
            <pre className="font-mono text-ctp-surface1 text-xs leading-tight mb-6 text-center">{
`┌───────────────────┐
│   ██╗  ██╗██████╗ │
│   ██║ ██╔╝██╔══██╗│
│   █████╔╝ ██████╔╝│
│   ██╔═██╗ ██╔══██╗│
│   ██║  ██╗██║  ██║│
│   ╚═╝  ╚═╝╚═╝  ╚═╝│
└───────────────────┘`
            }</pre>
            <div className="flex items-center gap-2 text-ctp-overlay1 font-mono text-sm mb-5">
              <span className="text-ctp-green">$</span>
              <span className="text-ctp-subtext0">no commands executed yet</span>
              <span className="inline-block w-2 h-[1em] bg-ctp-green animate-cursor-blink align-middle" />
            </div>
            <div className="flex flex-col items-center gap-2 text-xs font-mono">
              <span className="text-ctp-subtext0">Type a command below to get started</span>
              <span className="text-ctp-overlay0">
                Press{' '}
                <kbd className="px-1 py-0.5 bg-ctp-surface0 rounded text-ctp-subtext0 border border-ctp-surface1">?</kbd>
                {' '}for keyboard shortcuts
              </span>
            </div>
          </div>
        ) : (
          tasks.map((task, index) => {
            const matchPos = matchIndices.indexOf(index);
            const isActive = matchPos !== -1 && matchPos === currentMatchIndex;
            return (
              <div
                key={uuidToHex(task.taskId)}
                data-task-index={index}
                className={isActive ? 'rounded ring-1 ring-ctp-yellow/50' : ''}
              >
                <TaskEntry
                  task={task}
                  searchQuery={searchQuery}
                  onlineOperators={collabState.onlineOperators}
                  currentOperatorIdHex={currentOperatorIdHex}
                  currentOperatorUsername={currentOperatorUsername}
                />
              </div>
            );
          })
        )}
      </div>

      {/* Scroll lock toggle */}
      <button
        onClick={() => {
          setAutoScroll(prev => {
            if (!prev && containerRef.current) {
              // Scroll to bottom when enabling
              containerRef.current.scrollTop = containerRef.current.scrollHeight;
            }
            return !prev;
          });
        }}
        className={`absolute bottom-4 right-4 p-2 rounded-lg transition-all ${
          autoScroll
            ? 'bg-ctp-surface0 text-ctp-green'
            : 'bg-ctp-yellow/20 text-ctp-yellow border border-ctp-yellow/30'
        }`}
        title={autoScroll ? 'Auto-scroll enabled (click to lock)' : 'Scroll locked (click to unlock)'}
      >
        {autoScroll ? (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
          </svg>
        ) : (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15V3m0 12l-4-4m4 4l4-4M2 17l.621 2.485A2 2 0 004.561 21h14.878a2 2 0 001.94-1.515L22 17" />
          </svg>
        )}
      </button>

      {/* Scroll locked indicator */}
      {!autoScroll && (
        <div className="absolute top-2 right-2 px-2 py-1 bg-ctp-yellow/20 text-ctp-yellow border border-ctp-yellow/30 rounded text-xs font-mono">
          scroll locked
        </div>
      )}
    </div>
  );
}

function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diffMs = now - timestamp;
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);

  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return new Date(timestamp).toLocaleDateString();
}

interface TaskEntryProps {
  task: TaskInfo;
  searchQuery: string;
  onlineOperators: OperatorPresence[];
  currentOperatorIdHex: string | null;
  currentOperatorUsername: string | null;
}

function TaskEntry({ task, searchQuery, onlineOperators, currentOperatorIdHex, currentOperatorUsername }: TaskEntryProps) {
  const taskId = uuidToHex(task.taskId).slice(0, 8);
  const timestampMs = task.issuedAt ? Number(task.issuedAt.millis) : null;
  const relativeTime = timestampMs ? formatRelativeTime(timestampMs) : '';
  const absoluteTime = timestampMs ? new Date(timestampMs).toLocaleString() : '';

  // Resolve operator name from operatorId UUID
  const operatorName = resolveOperatorName(
    task.operatorId,
    onlineOperators,
    currentOperatorIdHex,
    currentOperatorUsername,
  );

  // For shell tasks, try to extract command from result if available
  // Note: TaskInfo doesn't store the original command, only resultData
  const command = task.taskType;

  // Parse result (for completed shell tasks)
  const result = task.status === TaskStatus.COMPLETED
    ? parseShellResult(task.resultData)
    : null;

  const statusIndicator = getStatusIndicator(task.status);

  return (
    <div className="group">
      {/* Command line */}
      <div className="flex items-start gap-2">
        <span className={`font-bold ${statusIndicator.color}`}>
          {statusIndicator.prefix}
        </span>
        <span className="text-ctp-subtext0 text-xs" title={absoluteTime}>[{relativeTime}]</span>
        {operatorName && (
          <span className="text-ctp-mauve text-xs">{operatorName}@kraken</span>
        )}
        <span className="text-ctp-green">$</span>
        <span className="text-ctp-text flex-1">{highlightText(command, searchQuery)}</span>
        <span className="text-ctp-overlay0 text-xs opacity-0 group-hover:opacity-100 transition-opacity">
          {taskId}
        </span>
      </div>

      {/* Output */}
      {task.status === TaskStatus.QUEUED && (
        <div className="ml-6 text-ctp-yellow animate-pulse">
          Queued...
        </div>
      )}

      {task.status === TaskStatus.DISPATCHED && (
        <div className="ml-6 text-ctp-blue animate-pulse">
          Dispatched...
        </div>
      )}

      {task.status === TaskStatus.EXPIRED && (
        <div className="ml-6 text-ctp-overlay0">
          Expired (implant lost)
        </div>
      )}

      {task.error && (
        <div className="ml-6 text-ctp-red">
          Error: {highlightText(task.error.message, searchQuery)}
        </div>
      )}

      {result && (
        <OutputWithCopy result={result} searchQuery={searchQuery} />
      )}

      {task.status === TaskStatus.COMPLETED && !result && !task.error && (
        <div className="ml-6 text-ctp-overlay0 italic">
          (no output)
        </div>
      )}
    </div>
  );
}

function OutputWithCopy({ result, searchQuery }: { result: ShellResult; searchQuery: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const text = [result.stdout, result.stderr].filter(Boolean).join('\n');
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="ml-6 mt-1 group/output relative">
      {result.stdout && (
        <AnsiOutput text={result.stdout} searchQuery={searchQuery} />
      )}
      {result.stderr && (
        <AnsiOutput text={result.stderr} className="text-ctp-red" searchQuery={searchQuery} />
      )}
      <div className="flex gap-4 text-xs text-ctp-overlay0 mt-1">
        <span>
          exit:{' '}
          <span className={result.exitCode === 0 ? 'text-ctp-green' : 'text-ctp-red'}>
            {result.exitCode}
          </span>
        </span>
        <span>duration: {Number(result.durationMs)}ms</span>
        <button
          onClick={handleCopy}
          className="opacity-0 group-hover/output:opacity-100 transition-opacity text-ctp-subtext0 hover:text-ctp-mauve"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

function AnsiOutput({ text, className = '', searchQuery }: { text: string; className?: string; searchQuery: string }) {
  if (searchQuery.trim()) {
    // Strip ANSI escape codes and render plain text with highlights
    const plain = text.replace(/\x1b\[[0-9;]*m/g, '');
    return (
      <pre className={`whitespace-pre-wrap break-all ${className}`}>
        {highlightText(plain, searchQuery)}
      </pre>
    );
  }

  // Normal rendering: parse ANSI codes and convert to HTML
  const html = Anser.ansiToHtml(text, {
    use_classes: false,
  });

  return (
    <pre
      className={`whitespace-pre-wrap break-all ${className}`}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

function getStatusIndicator(status: TaskStatus): { prefix: string; color: string } {
  switch (status) {
    case TaskStatus.QUEUED:
      return { prefix: '◌', color: 'text-ctp-yellow' };
    case TaskStatus.DISPATCHED:
      return { prefix: '→', color: 'text-ctp-blue' };
    case TaskStatus.COMPLETED:
      return { prefix: '✓', color: 'text-ctp-green' };
    case TaskStatus.FAILED:
      return { prefix: '✗', color: 'text-ctp-red' };
    case TaskStatus.CANCELLED:
      return { prefix: '○', color: 'text-ctp-overlay0' };
    case TaskStatus.EXPIRED:
      return { prefix: '⊘', color: 'text-ctp-overlay0' };
    default:
      return { prefix: '?', color: 'text-ctp-overlay0' };
  }
}
