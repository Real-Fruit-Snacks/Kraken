// Command Palette - Cmd+K quick actions interface
// Based on research: No C2 has this - major UX differentiator

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { KeyboardShortcutsModal } from './KeyboardShortcutsModal';

interface CommandAction {
  id: string;
  label: string;
  description?: string;
  category: 'navigation' | 'session' | 'action' | 'settings';
  shortcut?: string;
  icon?: React.ReactNode;
  action: () => void;
  keywords?: string[];
}

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  sessionId?: string;
  sessionName?: string;
}

export function CommandPalette({ isOpen, onClose, sessionId, sessionName }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  // Define all available commands
  const commands = useMemo<CommandAction[]>(() => {
    const baseCommands: CommandAction[] = [
      // Navigation
      {
        id: 'nav-dashboard',
        label: 'Go to Dashboard',
        category: 'navigation',
        shortcut: 'G D',
        icon: <HomeIcon />,
        action: () => navigate('/dashboard'),
        keywords: ['home', 'main', 'overview'],
      },
      {
        id: 'nav-sessions',
        label: 'Go to Sessions',
        category: 'navigation',
        shortcut: 'G S',
        icon: <TerminalIcon />,
        action: () => navigate('/sessions'),
        keywords: ['implants', 'agents', 'beacons'],
      },
      {
        id: 'nav-listeners',
        label: 'Go to Listeners',
        category: 'navigation',
        shortcut: 'G L',
        icon: <SignalIcon />,
        action: () => navigate('/listeners'),
        keywords: ['ports', 'c2', 'handlers'],
      },
      {
        id: 'nav-topology',
        label: 'Go to Topology',
        category: 'navigation',
        shortcut: 'G T',
        icon: <NetworkIcon />,
        action: () => navigate('/topology'),
        keywords: ['mesh', 'graph', 'network', 'map'],
      },
      {
        id: 'nav-defender',
        label: 'Go to Defender View',
        category: 'navigation',
        shortcut: 'G F',
        icon: <ShieldIcon />,
        action: () => navigate('/defender'),
        keywords: ['iocs', 'yara', 'sigma', 'detection', 'blue team'],
      },
      {
        id: 'nav-loot',
        label: 'Go to Loot',
        category: 'navigation',
        shortcut: 'G O',
        icon: <ArchiveIcon />,
        action: () => navigate('/loot'),
        keywords: ['credentials', 'files', 'data', 'exfil'],
      },
      {
        id: 'nav-modules',
        label: 'Go to Modules',
        category: 'navigation',
        shortcut: 'G M',
        icon: <PuzzleIcon />,
        action: () => navigate('/modules'),
        keywords: ['plugins', 'extensions', 'bof'],
      },
      {
        id: 'nav-operators',
        label: 'Go to Operators',
        category: 'navigation',
        shortcut: 'G P',
        icon: <UsersIcon />,
        action: () => navigate('/operators'),
        keywords: ['users', 'team', 'admin'],
      },
      {
        id: 'nav-reports',
        label: 'Go to Reports',
        category: 'navigation',
        shortcut: 'G R',
        icon: <DocumentIcon />,
        action: () => navigate('/reports'),
        keywords: ['export', 'pdf', 'summary'],
      },

      // Actions
      {
        id: 'action-new-listener',
        label: 'Create New Listener',
        category: 'action',
        shortcut: 'Ctrl+Shift+L',
        icon: <PlusIcon />,
        action: () => navigate('/listeners?new=true'),
        keywords: ['add', 'start', 'handler'],
      },
      {
        id: 'action-generate-payload',
        label: 'Generate Payload',
        category: 'action',
        shortcut: 'Ctrl+Shift+P',
        icon: <CodeIcon />,
        action: () => navigate('/payloads?new=true'),
        keywords: ['implant', 'agent', 'beacon', 'shellcode'],
      },

      // Settings
      {
        id: 'settings-shortcuts',
        label: 'Keyboard Shortcuts',
        category: 'settings',
        shortcut: '?',
        icon: <KeyboardIcon />,
        action: () => setShortcutsOpen(true),
        keywords: ['keys', 'hotkeys', 'bindings'],
      },
    ];

    // Add session-specific commands if a session is active
    if (sessionId) {
      baseCommands.push(
        {
          id: 'session-shell',
          label: `Execute Shell on ${sessionName || 'Session'}`,
          category: 'session',
          shortcut: 'Enter',
          icon: <TerminalIcon />,
          action: () => navigate(`/sessions/${sessionId}`),
          keywords: ['command', 'cmd', 'bash', 'powershell'],
        },
        {
          id: 'session-upload',
          label: 'Upload File',
          category: 'session',
          shortcut: 'U',
          icon: <UploadIcon />,
          action: () => navigate(`/sessions/${sessionId}?tab=files&action=upload`),
          keywords: ['transfer', 'put'],
        },
        {
          id: 'session-download',
          label: 'Download File',
          category: 'session',
          shortcut: 'D',
          icon: <DownloadIcon />,
          action: () => navigate(`/sessions/${sessionId}?tab=files&action=download`),
          keywords: ['transfer', 'get', 'exfil'],
        },
        {
          id: 'session-socks',
          label: 'Start SOCKS Proxy',
          category: 'session',
          icon: <GlobeIcon />,
          action: () => navigate(`/sessions/${sessionId}?tab=pivot&action=socks`),
          keywords: ['proxy', 'tunnel', 'pivot'],
        },
        {
          id: 'session-portfwd',
          label: 'Add Port Forward',
          category: 'session',
          icon: <ArrowsIcon />,
          action: () => navigate(`/sessions/${sessionId}?tab=pivot&action=portfwd`),
          keywords: ['tunnel', 'redirect'],
        }
      );
    }

    return baseCommands;
  }, [navigate, sessionId, sessionName]);

  // Filter commands based on query
  const filteredCommands = useMemo(() => {
    if (!query) return commands;

    const lowerQuery = query.toLowerCase();
    return commands.filter((cmd) => {
      return (
        cmd.label.toLowerCase().includes(lowerQuery) ||
        cmd.description?.toLowerCase().includes(lowerQuery) ||
        cmd.keywords?.some((k) => k.toLowerCase().includes(lowerQuery))
      );
    });
  }, [commands, query]);

  // Group commands by category
  const groupedCommands = useMemo(() => {
    const groups: Record<string, CommandAction[]> = {};
    filteredCommands.forEach((cmd) => {
      if (!groups[cmd.category]) groups[cmd.category] = [];
      groups[cmd.category].push(cmd);
    });
    return groups;
  }, [filteredCommands]);

  // Flatten for keyboard navigation
  const flatCommands = useMemo(() => filteredCommands, [filteredCommands]);

  // Handle keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, flatCommands.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (flatCommands[selectedIndex]) {
          flatCommands[selectedIndex].action();
          onClose();
        }
        break;
      case 'Escape':
        e.preventDefault();
        onClose();
        break;
    }
  }, [flatCommands, selectedIndex, onClose]);

  // Reset state when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [isOpen]);

  // Global keyboard shortcut for ? to show shortcuts
  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      // "?" key (Shift+/) to show shortcuts when palette is not focused
      if (e.key === '?' && !isOpen && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        e.preventDefault();
        setShortcutsOpen(true);
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, [isOpen]);

  const categoryLabels: Record<string, string> = {
    navigation: 'Navigation',
    session: 'Session Actions',
    action: 'Actions',
    settings: 'Settings',
  };

  return (
    <>
      {/* Keyboard Shortcuts Modal */}
      <KeyboardShortcutsModal
        isOpen={shortcutsOpen}
        onClose={() => setShortcutsOpen(false)}
      />

      {/* Command Palette */}
      {isOpen && (
        <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-ctp-crust/80 backdrop-blur-sm"
            onClick={onClose}
          />

      {/* Palette */}
      <div className="relative w-full max-w-xl mx-4 bg-ctp-base rounded-xl border border-ctp-surface0 shadow-2xl overflow-hidden">
        {/* Search Input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-ctp-surface0">
          <svg className="w-5 h-5 text-ctp-overlay0 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Type a command or search..."
            className="flex-1 bg-transparent text-ctp-text placeholder:text-ctp-overlay0 focus:outline-none"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="hidden sm:inline-flex px-2 py-1 text-xs font-mono rounded bg-ctp-surface0 text-ctp-subtext0">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-[50vh] overflow-y-auto">
          {flatCommands.length === 0 ? (
            <div className="px-4 py-8 text-center text-ctp-subtext0">
              No commands found
            </div>
          ) : (
            Object.entries(groupedCommands).map(([category, cmds]) => (
              <div key={category}>
                <div className="px-4 py-2 text-xs font-medium text-ctp-subtext0 uppercase tracking-wide bg-ctp-mantle">
                  {categoryLabels[category] || category}
                </div>
                {cmds.map((cmd) => {
                  const globalIndex = flatCommands.findIndex((c) => c.id === cmd.id);
                  const isSelected = globalIndex === selectedIndex;
                  return (
                    <button
                      key={cmd.id}
                      onClick={() => {
                        cmd.action();
                        onClose();
                      }}
                      onMouseEnter={() => setSelectedIndex(globalIndex)}
                      className={`w-full px-4 py-3 flex items-center gap-3 text-left transition-colors ${
                        isSelected ? 'bg-ctp-surface0' : 'hover:bg-ctp-surface0/50'
                      }`}
                    >
                      <div className="w-8 h-8 rounded-lg bg-ctp-surface0 flex items-center justify-center text-ctp-subtext0">
                        {cmd.icon}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-ctp-text truncate">
                          {cmd.label}
                        </div>
                        {cmd.description && (
                          <div className="text-xs text-ctp-subtext0 truncate">
                            {cmd.description}
                          </div>
                        )}
                      </div>
                      {cmd.shortcut && (
                        <kbd className="px-2 py-1 text-xs font-mono rounded bg-ctp-surface0 text-ctp-overlay0">
                          {cmd.shortcut}
                        </kbd>
                      )}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer hint */}
        <div className="px-4 py-2 border-t border-ctp-surface0 flex items-center gap-4 text-xs text-ctp-overlay0">
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 rounded bg-ctp-surface0">↑↓</kbd> navigate
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 rounded bg-ctp-surface0">↵</kbd> select
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 rounded bg-ctp-surface0">esc</kbd> close
          </span>
        </div>
      </div>
    </div>
      )}
    </>
  );
}

// Inline SVG icons (consistent with existing codebase pattern)
const HomeIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
  </svg>
);

const TerminalIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
  </svg>
);

const SignalIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z" />
  </svg>
);

const NetworkIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
  </svg>
);

const ShieldIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const ArchiveIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
  </svg>
);

const PuzzleIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" />
  </svg>
);

const UsersIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
  </svg>
);

const DocumentIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
);

const PlusIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
  </svg>
);

const CodeIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
  </svg>
);

const KeyboardIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
  </svg>
);

const UploadIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
  </svg>
);

const DownloadIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
  </svg>
);

const GlobeIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const ArrowsIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
  </svg>
);

export default CommandPalette;
