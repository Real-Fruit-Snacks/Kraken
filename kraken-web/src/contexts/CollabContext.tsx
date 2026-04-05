import {
  createContext,
  useContext,
  useEffect,
  useReducer,
  useRef,
  useState,
  useCallback,
  ReactNode,
} from 'react';
import { ConnectError, Code } from '@connectrpc/connect';
import {
  collabClient,
  CollabEvent,
  OperatorPresence,
  SessionLock,
} from '../api/index.js';

// ─── State ────────────────────────────────────────────────────────────────────

// Chat message with parsed timestamp for display
export interface ChatMessage {
  id: string;
  fromOperatorId: string;
  fromUsername: string;
  message: string;
  sessionId?: string;
  timestamp: Date;
}

export interface CollabState {
  onlineOperators: OperatorPresence[];
  sessionLocks: SessionLock[];
  recentEvents: CollabEvent[];
  chatMessages: ChatMessage[];
}

type CollabAction =
  | { type: 'OPERATOR_ONLINE'; op: OperatorPresence }
  | { type: 'OPERATOR_OFFLINE'; username: string }
  | { type: 'SESSION_LOCKED'; lock: SessionLock }
  | { type: 'SESSION_UNLOCKED'; username: string }
  | { type: 'PUSH_EVENT'; event: CollabEvent }
  | { type: 'PUSH_CHAT'; message: ChatMessage }
  | { type: 'SET_OPERATORS'; operators: OperatorPresence[] }
  | { type: 'SET_LOCKS'; locks: SessionLock[] }
  | { type: 'SET_CHAT_HISTORY'; messages: ChatMessage[] };

const MAX_RECENT_EVENTS = 50;
const MAX_CHAT_MESSAGES = 200;

// Helper: compare Uuid values (Uint8Array) by converting to hex string
function uuidBytes(u: { value: Uint8Array } | undefined): string {
  if (!u) return '';
  return Array.from(u.value)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function collabReducer(state: CollabState, action: CollabAction): CollabState {
  switch (action.type) {
    case 'OPERATOR_ONLINE': {
      const id = uuidBytes(action.op.operatorId);
      const exists = state.onlineOperators.some(
        (op) => uuidBytes(op.operatorId) === id
      );
      return {
        ...state,
        onlineOperators: exists
          ? state.onlineOperators.map((op) =>
              uuidBytes(op.operatorId) === id ? action.op : op
            )
          : [...state.onlineOperators, action.op],
      };
    }
    case 'OPERATOR_OFFLINE':
      return {
        ...state,
        onlineOperators: state.onlineOperators.filter(
          (op) => op.username !== action.username
        ),
      };
    case 'SESSION_LOCKED': {
      const sid = uuidBytes(action.lock.sessionId);
      const exists = state.sessionLocks.some(
        (l) => uuidBytes(l.sessionId) === sid
      );
      return {
        ...state,
        sessionLocks: exists
          ? state.sessionLocks.map((l) =>
              uuidBytes(l.sessionId) === sid ? action.lock : l
            )
          : [...state.sessionLocks, action.lock],
      };
    }
    case 'SESSION_UNLOCKED':
      return {
        ...state,
        sessionLocks: state.sessionLocks.filter(
          (l) => l.username !== action.username
        ),
      };
    case 'PUSH_EVENT':
      return {
        ...state,
        recentEvents: [action.event, ...state.recentEvents].slice(
          0,
          MAX_RECENT_EVENTS
        ),
      };
    case 'SET_OPERATORS':
      return { ...state, onlineOperators: action.operators };
    case 'SET_LOCKS':
      return { ...state, sessionLocks: action.locks };
    case 'PUSH_CHAT': {
      // Deduplicate - check if message ID already exists
      const exists = state.chatMessages.some(m => m.id === action.message.id);
      if (exists) return state;
      return {
        ...state,
        chatMessages: [...state.chatMessages, action.message].slice(-MAX_CHAT_MESSAGES),
      };
    }
    case 'SET_CHAT_HISTORY':
      return { ...state, chatMessages: action.messages };
    default:
      return state;
  }
}

const initialState: CollabState = {
  onlineOperators: [],
  sessionLocks: [],
  recentEvents: [],
  chatMessages: [],
};

// ─── Context ──────────────────────────────────────────────────────────────────

interface CollabContextValue {
  state: CollabState;
  collabAvailable: boolean;
  sendChat: (message: string, sessionIdHex?: string) => Promise<void>;
}

const CollabContext = createContext<CollabContextValue | null>(null);

// ─── Provider ─────────────────────────────────────────────────────────────────

export function CollabProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(collabReducer, initialState);
  const [collabAvailable, setCollabAvailable] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchInitial() {
      try {
        const [operatorsRes, locksRes, historyRes] = await Promise.all([
          collabClient.getOnlineOperators({}),
          collabClient.getSessionLocks({}),
          collabClient.getChatHistory({ limit: 100 }),
        ]);
        if (cancelled) return;
        dispatch({ type: 'SET_OPERATORS', operators: operatorsRes.operators });
        dispatch({ type: 'SET_LOCKS', locks: locksRes.locks });

        // Convert history to ChatMessage format
        const historyMessages: ChatMessage[] = historyRes.messages.map(m => ({
          id: uuidBytes(m.id),
          fromOperatorId: uuidBytes(m.fromOperatorId),
          fromUsername: m.fromUsername,
          message: m.message,
          sessionId: m.sessionId ? uuidBytes(m.sessionId) : undefined,
          timestamp: m.createdAt?.millis
            ? new Date(Number(m.createdAt.millis))
            : new Date(),
        }));
        // History comes newest-first, reverse for display order
        dispatch({ type: 'SET_CHAT_HISTORY', messages: historyMessages.reverse() });
      } catch (err: unknown) {
        // Non-fatal; stream events will fill state
        if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
          setCollabAvailable(false);
        }
      }
    }

    async function subscribe() {
      const abort = new AbortController();
      abortRef.current = abort;

      try {
        const stream = collabClient.streamEvents({}, { signal: abort.signal });

        for await (const event of stream) {
          if (cancelled) break;

          dispatch({ type: 'PUSH_EVENT', event });

          const ev = event.event;

          if (ev.case === 'operatorOnline') {
            const v = ev.value;
            const op = new OperatorPresence({
              operatorId: v.operatorId,
              username: v.username,
            });
            dispatch({ type: 'OPERATOR_ONLINE', op });
          } else if (ev.case === 'operatorOffline') {
            dispatch({ type: 'OPERATOR_OFFLINE', username: ev.value.username });
          } else if (ev.case === 'sessionLocked') {
            const v = ev.value;
            const lock = new SessionLock({
              sessionId: v.sessionId,
              operatorId: v.operatorId,
              username: v.username,
            });
            dispatch({ type: 'SESSION_LOCKED', lock });
          } else if (ev.case === 'sessionUnlocked') {
            dispatch({
              type: 'SESSION_UNLOCKED',
              username: ev.value.username,
            });
          } else if (ev.case === 'chatMessage') {
            const v = ev.value;
            const chatMsg: ChatMessage = {
              id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
              fromOperatorId: uuidBytes(v.fromOperatorId),
              fromUsername: v.fromUsername,
              message: v.message,
              sessionId: v.sessionId ? uuidBytes(v.sessionId) : undefined,
              timestamp: event.timestamp?.millis
                ? new Date(Number(event.timestamp.millis))
                : new Date(),
            };
            dispatch({ type: 'PUSH_CHAT', message: chatMsg });
          }
        }
      } catch (err: unknown) {
        if (cancelled) return;
        if ((err as { name?: string }).name === 'AbortError') return;
        // Don't retry on auth failures — they won't resolve without a restart
        if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
          setCollabAvailable(false);
          return;
        }
        // Reconnect after a short delay for transient errors
        setTimeout(() => {
          if (!cancelled) subscribe();
        }, 3000);
      }
    }

    fetchInitial();
    subscribe();

    return () => {
      cancelled = true;
      abortRef.current?.abort();
    };
  }, []);

  // Helper: convert hex string to Uint8Array<ArrayBuffer>
  function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
    const buffer = new ArrayBuffer(hex.length / 2);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  // Send chat message
  const sendChat = useCallback(
    async (message: string, sessionIdHex?: string) => {
      if (!collabAvailable) return;
      try {
        const req: { message: string; sessionId?: { value: Uint8Array<ArrayBuffer> } } = {
          message,
        };
        if (sessionIdHex) {
          req.sessionId = { value: hexToBytes(sessionIdHex) };
        }
        await collabClient.sendChat(req);
      } catch (err) {
        console.error('Failed to send chat message:', err);
        throw err;
      }
    },
    [collabAvailable]
  );

  return (
    <CollabContext.Provider value={{ state, collabAvailable, sendChat }}>
      {children}
    </CollabContext.Provider>
  );
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useCollab(): CollabContextValue {
  const ctx = useContext(CollabContext);
  if (!ctx) {
    throw new Error('useCollab must be used within a CollabProvider');
  }
  return ctx;
}
