import { useState } from 'react';
import { useCollab } from '../contexts/CollabContext.js';

export function CollabStatus() {
  const { state } = useCollab();
  const { onlineOperators } = state;
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="relative">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-ctp-surface0 hover:bg-ctp-surface1 transition-colors"
        title="Online operators"
      >
        {/* Green pulse dot */}
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-ctp-green opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-ctp-green" />
        </span>
        <span className="text-sm text-ctp-text">
          {onlineOperators.length}
        </span>
        <span className="text-xs text-ctp-subtext0 hidden sm:inline">
          {onlineOperators.length === 1 ? 'operator' : 'operators'}
        </span>
      </button>

      {expanded && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => setExpanded(false)}
          />

          {/* Dropdown panel */}
          <div className="absolute right-0 mt-2 w-56 z-20 rounded-xl bg-ctp-mantle border border-ctp-surface1 shadow-lg overflow-hidden">
            <div className="px-3 py-2 border-b border-ctp-surface0">
              <p className="text-xs font-semibold text-ctp-subtext0 uppercase tracking-wide">
                Online Operators
              </p>
            </div>

            {onlineOperators.length === 0 ? (
              <div className="px-3 py-3 text-sm text-ctp-subtext0">
                No operators online
              </div>
            ) : (
              <ul className="py-1 max-h-64 overflow-y-auto">
                {onlineOperators.map((op) => (
                  <li
                    key={op.username}
                    className="flex items-center gap-3 px-3 py-2 hover:bg-ctp-surface0/50"
                  >
                    {/* Avatar */}
                    <div className="flex-shrink-0 w-7 h-7 rounded-full bg-ctp-mauve/20 flex items-center justify-center">
                      <span className="text-xs font-bold text-ctp-mauve uppercase">
                        {op.username.charAt(0) || '?'}
                      </span>
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm text-ctp-text truncate">
                        {op.username}
                      </p>
                      {op.activeSession && (
                        <p className="text-xs text-ctp-subtext0 truncate">
                          Session active
                        </p>
                      )}
                    </div>
                    {/* Online indicator */}
                    <span className="ml-auto flex-shrink-0 w-2 h-2 rounded-full bg-ctp-green" />
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </div>
  );
}
