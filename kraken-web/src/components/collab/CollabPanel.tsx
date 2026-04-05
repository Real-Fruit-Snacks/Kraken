// CollabPanel - Unified collaboration sidebar
// Combines EventFeed, ChatPanel, and online operators display

import { useState } from 'react';
import { useCollab } from '../../contexts/CollabContext';
import { EventFeed } from './EventFeed';
import { ChatPanel } from './ChatPanel';

type Tab = 'events' | 'chat' | 'operators';

// Online indicator dot
function OnlineDot() {
  return (
    <span className="relative flex h-2 w-2">
      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-ctp-green opacity-75" />
      <span className="relative inline-flex rounded-full h-2 w-2 bg-ctp-green" />
    </span>
  );
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  badge?: number;
}

function TabButton({ active, onClick, icon, label, badge }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`
        flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg transition-colors
        ${active
          ? 'bg-ctp-mauve text-ctp-crust'
          : 'text-ctp-subtext0 hover:text-ctp-text hover:bg-ctp-surface0'
        }
      `}
    >
      {icon}
      {label}
      {badge !== undefined && badge > 0 && (
        <span
          className={`
            ml-1 px-1.5 py-0.5 text-xs rounded-full
            ${active ? 'bg-ctp-crust/20 text-ctp-crust' : 'bg-ctp-surface1 text-ctp-subtext0'}
          `}
        >
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </button>
  );
}

interface OperatorItemProps {
  username: string;
  status?: string;
}

function OperatorItem({ username, status }: OperatorItemProps) {
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-ctp-surface0 transition-colors">
      <OnlineDot />
      <div className="flex-1 min-w-0">
        <div className="font-medium text-ctp-text truncate">{username}</div>
        {status && (
          <div className="text-xs text-ctp-subtext0 truncate">{status}</div>
        )}
      </div>
    </div>
  );
}

function OperatorList() {
  const { state } = useCollab();
  const { onlineOperators, sessionLocks } = state;

  // Build a map of operator -> locked session
  const operatorLocks = new Map<string, string>();
  for (const lock of sessionLocks) {
    operatorLocks.set(lock.username, 'Working on session');
  }

  if (onlineOperators.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-ctp-subtext0 text-sm p-4">
        <svg className="w-8 h-8 mb-2 text-ctp-surface1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
        </svg>
        No operators online
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-none px-4 py-3 border-b border-ctp-surface0">
        <h3 className="font-semibold text-ctp-text">Online Operators</h3>
        <p className="text-xs text-ctp-subtext0 mt-1">
          {onlineOperators.length} operator{onlineOperators.length !== 1 ? 's' : ''} connected
        </p>
      </div>
      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        {onlineOperators.map((op) => (
          <OperatorItem
            key={op.username}
            username={op.username}
            status={operatorLocks.get(op.username)}
          />
        ))}
      </div>
    </div>
  );
}

// Icons
const EventsIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
  </svg>
);

const ChatIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
  </svg>
);

const OperatorsIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
  </svg>
);

interface CollabPanelProps {
  currentOperatorId?: string;
  sessionContext?: string;
  defaultTab?: Tab;
}

export function CollabPanel({
  currentOperatorId,
  sessionContext,
  defaultTab = 'events',
}: CollabPanelProps) {
  const [activeTab, setActiveTab] = useState<Tab>(defaultTab);
  const { state, collabAvailable } = useCollab();

  if (!collabAvailable) {
    return (
      <div className="flex flex-col h-full bg-ctp-base border-l border-ctp-surface0">
        <div className="flex items-center justify-center h-full text-ctp-subtext0 text-sm p-4">
          <div className="text-center">
            <svg className="w-12 h-12 mx-auto mb-3 text-ctp-surface1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 5.636a9 9 0 010 12.728m0 0l-2.829-2.829m2.829 2.829L21 21M15.536 8.464a5 5 0 010 7.072m0 0l-2.829-2.829m-4.243 2.829a4.978 4.978 0 01-1.414-2.83m-1.414 5.658a9 9 0 01-2.167-9.238m7.824 2.167a1 1 0 111.414 1.414m-1.414-1.414L3 3m8.293 8.293l1.414 1.414" />
            </svg>
            <p className="font-medium text-ctp-text mb-1">Collaboration Unavailable</p>
            <p className="text-xs">Authentication required</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-ctp-base border-l border-ctp-surface0">
      {/* Tab bar */}
      <div className="flex-none flex gap-1 p-2 border-b border-ctp-surface0">
        <TabButton
          active={activeTab === 'events'}
          onClick={() => setActiveTab('events')}
          icon={<EventsIcon />}
          label="Events"
          badge={state.recentEvents.length}
        />
        <TabButton
          active={activeTab === 'chat'}
          onClick={() => setActiveTab('chat')}
          icon={<ChatIcon />}
          label="Chat"
          badge={state.chatMessages.length}
        />
        <TabButton
          active={activeTab === 'operators'}
          onClick={() => setActiveTab('operators')}
          icon={<OperatorsIcon />}
          label="Team"
          badge={state.onlineOperators.length}
        />
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'events' && <EventFeed />}
        {activeTab === 'chat' && (
          <ChatPanel
            currentOperatorId={currentOperatorId}
            sessionContext={sessionContext}
          />
        )}
        {activeTab === 'operators' && <OperatorList />}
      </div>
    </div>
  );
}
