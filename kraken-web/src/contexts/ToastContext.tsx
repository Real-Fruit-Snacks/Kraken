import { createContext, useCallback, useContext, useState } from 'react';

// ─── Types ─────────────────────────────────────────────────────────────────

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface ToastEntry {
  id: number;
  message: string;
  type: ToastType;
  duration: number;
}

interface ToastContextValue {
  toasts: ToastEntry[];
  showToast: (message: string, type?: ToastType, duration?: number) => void;
  dismissToast: (id: number) => void;
}

// ─── Context ───────────────────────────────────────────────────────────────

const ToastContext = createContext<ToastContextValue | null>(null);

let toastIdCounter = 1000;

// ─── Provider ──────────────────────────────────────────────────────────────

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);

  const showToast = useCallback(
    (message: string, type: ToastType = 'info', duration = 5000) => {
      const id = ++toastIdCounter;
      setToasts((prev) => [...prev, { id, message, type, duration }].slice(-10));
    },
    [],
  );

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, showToast, dismissToast }}>
      {children}
    </ToastContext.Provider>
  );
}

// ─── Hook ──────────────────────────────────────────────────────────────────

export function useToast(): Pick<ToastContextValue, 'showToast' | 'dismissToast'> {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return { showToast: ctx.showToast, dismissToast: ctx.dismissToast };
}

export function useToastState(): ToastEntry[] {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToastState must be used within a ToastProvider');
  }
  return ctx.toasts;
}
