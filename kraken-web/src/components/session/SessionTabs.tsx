import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSessionStore } from '../../stores/sessionStore';

const MAX_VISIBLE_TABS = 5;

function getOsColor(os: string | undefined): string {
  const osLower = os?.toLowerCase() || '';
  if (osLower.includes('windows')) return 'bg-ctp-blue';
  if (osLower.includes('linux')) return 'bg-ctp-green';
  if (osLower.includes('darwin') || osLower.includes('macos')) return 'bg-ctp-mauve';
  return 'bg-ctp-overlay0';
}

interface SessionTabsProps {
  currentSessionId: string;
}

export function SessionTabs({ currentSessionId }: SessionTabsProps) {
  const navigate = useNavigate();
  const { openTabs, closeSession, setActiveTab } = useSessionStore();
  const [showOverflow, setShowOverflow] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const visibleTabs = openTabs.slice(0, MAX_VISIBLE_TABS);
  const overflowTabs = openTabs.slice(MAX_VISIBLE_TABS);

  const handleTabClick = (sessionId: string) => {
    setActiveTab(sessionId);
    navigate(`/sessions/${sessionId}`);
  };

  const handleClose = (e: React.MouseEvent, sessionId: string) => {
    e.stopPropagation();
    closeSession(sessionId);

    if (sessionId === currentSessionId) {
      const remaining = openTabs.filter(t => t.id !== sessionId);
      if (remaining.length > 0) {
        navigate(`/sessions/${remaining[remaining.length - 1].id}`);
      } else {
        navigate('/sessions');
      }
    }
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    if (!showOverflow) return;

    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowOverflow(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showOverflow]);

  if (openTabs.length === 0) return null;

  return (
    <div className="flex items-center gap-1 px-2 py-1 bg-ctp-crust border-b border-ctp-surface0">
      {visibleTabs.map((tab) => {
        const isActive = tab.id === currentSessionId;
        const stateColors: Record<string, string> = {
          active: 'ring-ctp-green',
          dormant: 'ring-ctp-yellow',
          dead: 'ring-ctp-overlay0',
          burned: 'ring-ctp-red',
        };

        return (
          <div
            key={tab.id}
            onClick={() => handleTabClick(tab.id)}
            onAuxClick={(e) => { if (e.button === 1) handleClose(e, tab.id); }}
            className={`
              flex items-center gap-2 px-3 py-1.5 rounded-t cursor-pointer
              transition-colors group min-w-0
              ${isActive
                ? 'bg-ctp-mantle border-t border-x border-ctp-surface0 -mb-px'
                : 'bg-ctp-surface0/30 hover:bg-ctp-surface0/50'
              }
            `}
          >
            {/* OS indicator dot with state ring */}
            <div
              className={`w-2 h-2 rounded-full flex-shrink-0 ${getOsColor(tab.os)} ring-1 ${stateColors[tab.state]}`}
            />

            {/* Hostname */}
            <span className={`text-sm truncate max-w-[120px] ${isActive ? 'text-ctp-text' : 'text-ctp-subtext0'}`}>
              {tab.hostname}
            </span>

            {/* Username (if space) */}
            {tab.username && (
              <span className="text-xs text-ctp-overlay0 truncate hidden sm:inline">
                ({tab.username})
              </span>
            )}

            {/* Close button */}
            <button
              onClick={(e) => handleClose(e, tab.id)}
              className={`
                ml-1 w-4 h-4 flex items-center justify-center rounded
                transition-colors text-xs
                ${isActive
                  ? 'text-ctp-overlay0 hover:text-ctp-red hover:bg-ctp-red/20'
                  : 'text-ctp-overlay0 opacity-0 group-hover:opacity-100 hover:text-ctp-red hover:bg-ctp-red/20'
                }
              `}
              aria-label={`Close ${tab.hostname}`}
            >
              ×
            </button>
          </div>
        );
      })}

      {/* Overflow dropdown */}
      {overflowTabs.length > 0 && (
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setShowOverflow(!showOverflow)}
            className="px-2 py-1 text-xs bg-ctp-surface0 hover:bg-ctp-surface1 rounded text-ctp-subtext0"
          >
            +{overflowTabs.length} more
          </button>
          {showOverflow && (
            <div className="absolute top-full left-0 mt-1 bg-ctp-mantle border border-ctp-surface0 rounded-lg shadow-xl z-50 min-w-[200px]">
              {overflowTabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => { handleTabClick(tab.id); setShowOverflow(false); }}
                  className="w-full px-3 py-2 flex items-center gap-2 hover:bg-ctp-surface0 text-left"
                >
                  <div className={`w-2 h-2 rounded-full ${getOsColor(tab.os)}`} />
                  <span className="text-sm truncate">{tab.hostname}</span>
                  <span className="text-xs text-ctp-overlay0">({tab.username})</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Sessions list link */}
      <button
        onClick={() => navigate('/sessions')}
        className="ml-2 px-2 py-1 text-xs text-ctp-overlay0 hover:text-ctp-text transition-colors"
        title="View all sessions"
      >
        +
      </button>
    </div>
  );
}
