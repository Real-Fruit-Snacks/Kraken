// EventFeed - Real-time operational event log
// Based on Mythic's color-coded event feed pattern

import { useState, useRef, useEffect } from 'react';
import { useCollab } from '../../contexts/CollabContext';
import type { CollabEvent } from '../../api/index';

type EventType = 'all' | 'operator' | 'session' | 'task' | 'chat';

// Event type configuration
const EVENT_CONFIG: Record<string, {
  color: string;
  bgColor: string;
  icon: string;
  label: string;
  category: EventType;
}> = {
  operatorOnline: {
    color: 'text-green',
    bgColor: 'bg-green/10',
    icon: '👤',
    label: 'Joined',
    category: 'operator',
  },
  operatorOffline: {
    color: 'text-subtext0',
    bgColor: 'bg-surface0',
    icon: '👤',
    label: 'Left',
    category: 'operator',
  },
  sessionLocked: {
    color: 'text-yellow',
    bgColor: 'bg-yellow/10',
    icon: '🔒',
    label: 'Session Locked',
    category: 'session',
  },
  sessionUnlocked: {
    color: 'text-blue',
    bgColor: 'bg-blue/10',
    icon: '🔓',
    label: 'Session Unlocked',
    category: 'session',
  },
  sessionActivity: {
    color: 'text-lavender',
    bgColor: 'bg-lavender/10',
    icon: '📍',
    label: 'Activity',
    category: 'session',
  },
  chatMessage: {
    color: 'text-mauve',
    bgColor: 'bg-mauve/10',
    icon: '💬',
    label: 'Chat',
    category: 'chat',
  },
  taskDispatched: {
    color: 'text-peach',
    bgColor: 'bg-peach/10',
    icon: '📤',
    label: 'Task Dispatched',
    category: 'task',
  },
  taskCompleted: {
    color: 'text-green',
    bgColor: 'bg-green/10',
    icon: '✅',
    label: 'Task Completed',
    category: 'task',
  },
};

function formatTimestamp(millis: bigint | undefined): string {
  if (!millis) return '';
  const date = new Date(Number(millis));
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function getEventDetails(event: CollabEvent): { username: string; detail: string } {
  const ev = event.event;
  switch (ev.case) {
    case 'operatorOnline':
      return { username: ev.value.username, detail: 'came online' };
    case 'operatorOffline':
      return { username: ev.value.username, detail: 'went offline' };
    case 'sessionLocked':
      return { username: ev.value.username, detail: 'locked a session' };
    case 'sessionUnlocked':
      return { username: ev.value.username, detail: 'unlocked a session' };
    case 'sessionActivity':
      return { username: '', detail: ev.value.activity };
    case 'chatMessage':
      return { username: ev.value.fromUsername, detail: ev.value.message };
    case 'taskDispatched':
      return { username: '', detail: `Task ${ev.value.taskType} dispatched` };
    case 'taskCompleted':
      return { username: '', detail: `Task ${ev.value.success ? 'succeeded' : 'failed'}` };
    default:
      return { username: '', detail: 'Unknown event' };
  }
}

interface EventRowProps {
  event: CollabEvent;
}

function EventRow({ event }: EventRowProps) {
  const config = EVENT_CONFIG[event.event.case || ''] || {
    color: 'text-subtext0',
    bgColor: 'bg-surface0',
    icon: '❓',
    label: 'Unknown',
    category: 'all' as EventType,
  };
  const { username, detail } = getEventDetails(event);
  const timestamp = formatTimestamp(event.timestamp?.millis);

  return (
    <div className={`flex items-start gap-3 px-3 py-2 ${config.bgColor} rounded-lg`}>
      <span className="text-base flex-shrink-0">{config.icon}</span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          {username && (
            <span className={`font-medium ${config.color}`}>{username}</span>
          )}
          <span className="text-subtext0 text-sm">{detail}</span>
        </div>
      </div>
      <span className="text-xs text-subtext0 flex-shrink-0 tabular-nums">
        {timestamp}
      </span>
    </div>
  );
}

interface FilterButtonProps {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
}

function FilterButton({ active, onClick, label, count }: FilterButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`
        px-2 py-1 rounded text-xs transition-colors
        ${active
          ? 'bg-mauve text-crust'
          : 'bg-surface0 text-subtext0 hover:bg-surface1'
        }
      `}
    >
      {label} ({count})
    </button>
  );
}

export function EventFeed() {
  const { state } = useCollab();
  const { recentEvents } = state;
  const [filter, setFilter] = useState<EventType>('all');
  const [autoScroll, setAutoScroll] = useState(true);
  const containerRef = useRef<HTMLDivElement>(null);

  // Filter events by category
  const filteredEvents = recentEvents.filter((event) => {
    if (filter === 'all') return true;
    const config = EVENT_CONFIG[event.event.case || ''];
    return config?.category === filter;
  });

  // Count events by category
  const counts = {
    all: recentEvents.length,
    operator: recentEvents.filter(e => EVENT_CONFIG[e.event.case || '']?.category === 'operator').length,
    session: recentEvents.filter(e => EVENT_CONFIG[e.event.case || '']?.category === 'session').length,
    task: recentEvents.filter(e => EVENT_CONFIG[e.event.case || '']?.category === 'task').length,
    chat: recentEvents.filter(e => EVENT_CONFIG[e.event.case || '']?.category === 'chat').length,
  };

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [recentEvents.length, autoScroll]);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex-none px-4 py-3 border-b border-surface0">
        <div className="flex items-center justify-between mb-2">
          <h3 className="font-semibold text-text">Event Feed</h3>
          <label className="flex items-center gap-2 text-xs text-subtext0">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded border-surface1 bg-surface0 text-mauve focus:ring-mauve"
            />
            Auto-scroll
          </label>
        </div>

        {/* Filters */}
        <div className="flex gap-2 flex-wrap">
          <FilterButton
            active={filter === 'all'}
            onClick={() => setFilter('all')}
            label="All"
            count={counts.all}
          />
          <FilterButton
            active={filter === 'operator'}
            onClick={() => setFilter('operator')}
            label="Operators"
            count={counts.operator}
          />
          <FilterButton
            active={filter === 'session'}
            onClick={() => setFilter('session')}
            label="Sessions"
            count={counts.session}
          />
          <FilterButton
            active={filter === 'task'}
            onClick={() => setFilter('task')}
            label="Tasks"
            count={counts.task}
          />
          <FilterButton
            active={filter === 'chat'}
            onClick={() => setFilter('chat')}
            label="Chat"
            count={counts.chat}
          />
        </div>
      </div>

      {/* Event list */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-2 space-y-1"
      >
        {filteredEvents.length === 0 ? (
          <div className="flex items-center justify-center h-full text-subtext0 text-sm">
            {recentEvents.length === 0
              ? 'Waiting for events...'
              : 'No events match the selected filter'
            }
          </div>
        ) : (
          filteredEvents.map((event, index) => (
            <EventRow key={`${event.timestamp?.millis}-${index}`} event={event} />
          ))
        )}
      </div>
    </div>
  );
}
