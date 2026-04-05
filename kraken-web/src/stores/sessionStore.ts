import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface SessionTab {
  id: string;
  hostname: string;
  username: string;
  state: 'active' | 'dormant' | 'dead' | 'burned';
  os?: string;
}

interface CommandHistoryEntry {
  command: string;
  timestamp: number;
}

interface SessionState {
  // Open session tabs
  openTabs: SessionTab[];
  activeTabId: string | null;

  // Command history per session (sessionId -> commands)
  commandHistory: Record<string, CommandHistoryEntry[]>;

  // Actions
  openSession: (tab: SessionTab) => void;
  closeSession: (sessionId: string) => void;
  setActiveTab: (sessionId: string) => void;
  addCommand: (sessionId: string, command: string) => void;
  getHistory: (sessionId: string) => string[];
  clearHistory: (sessionId: string) => void;
}

const MAX_HISTORY_PER_SESSION = 100;

export const useSessionStore = create<SessionState>()(
  persist(
    (set, get) => ({
      openTabs: [],
      activeTabId: null,
      commandHistory: {},

      openSession: (tab: SessionTab) => {
        const { openTabs } = get();
        const exists = openTabs.some((t) => t.id === tab.id);
        if (!exists) {
          set({
            openTabs: [...openTabs, tab],
            activeTabId: tab.id,
          });
        } else {
          set({ activeTabId: tab.id });
        }
      },

      closeSession: (sessionId: string) => {
        const { openTabs, activeTabId } = get();
        const newTabs = openTabs.filter((t) => t.id !== sessionId);
        const newActiveId =
          activeTabId === sessionId
            ? newTabs.length > 0
              ? newTabs[newTabs.length - 1].id
              : null
            : activeTabId;
        set({ openTabs: newTabs, activeTabId: newActiveId });
      },

      setActiveTab: (sessionId: string) => {
        set({ activeTabId: sessionId });
      },

      addCommand: (sessionId: string, command: string) => {
        const { commandHistory } = get();
        const history = commandHistory[sessionId] ?? [];
        const newEntry: CommandHistoryEntry = {
          command,
          timestamp: Date.now(),
        };
        const newHistory = [...history, newEntry].slice(-MAX_HISTORY_PER_SESSION);
        set({
          commandHistory: {
            ...commandHistory,
            [sessionId]: newHistory,
          },
        });
      },

      getHistory: (sessionId: string) => {
        const { commandHistory } = get();
        return (commandHistory[sessionId] ?? []).map((e) => e.command);
      },

      clearHistory: (sessionId: string) => {
        const { commandHistory } = get();
        const newHistory = { ...commandHistory };
        delete newHistory[sessionId];
        set({ commandHistory: newHistory });
      },
    }),
    {
      name: 'kraken-sessions',
      partialize: (state) => ({
        openTabs: state.openTabs,
        commandHistory: state.commandHistory,
      }),
    },
  ),
);
