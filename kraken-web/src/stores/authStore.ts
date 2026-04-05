import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Operator } from '../gen/kraken_pb';

interface AuthState {
  token: string | null;
  operator: Operator | null;
  isAuthenticated: boolean;
  login: (token: string) => void;
  logout: () => void;
  setOperator: (op: Operator) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      operator: null,
      isAuthenticated: false,

      login: (token: string) => set({ token, isAuthenticated: true }),

      logout: () => set({ token: null, operator: null, isAuthenticated: false }),

      setOperator: (op: Operator) => set({ operator: op }),
    }),
    {
      name: 'kraken-auth',
      partialize: (state) => ({ token: state.token, isAuthenticated: state.isAuthenticated }),
    },
  ),
);
