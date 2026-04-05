import { useEffect, useRef, useState } from 'react';
import { useCollab } from '../contexts/CollabContext.js';
import type { CollabEvent } from '../api/index.js';

// ─── Toast model ──────────────────────────────────────────────────────────────

type ToastKind = 'success' | 'error' | 'info';

interface Toast {
  id: number;
  message: string;
  kind: ToastKind;
}

let toastCounter = 0;

function eventToToast(event: CollabEvent): Toast | null {
  const { case: kind, value } = event.event;

  switch (kind) {
    case 'operatorOnline':
      return {
        id: ++toastCounter,
        message: `${value.username} joined`,
        kind: 'info',
      };
    case 'operatorOffline':
      return {
        id: ++toastCounter,
        message: `${value.username} left`,
        kind: 'info',
      };
    case 'sessionLocked':
      return {
        id: ++toastCounter,
        message: `Session locked by ${value.username}`,
        kind: 'info',
      };
    case 'sessionUnlocked':
      return {
        id: ++toastCounter,
        message: `Session unlocked`,
        kind: 'success',
      };
    case 'taskCompleted':
      return {
        id: ++toastCounter,
        message: `Task completed`,
        kind: 'success',
      };
    case 'taskDispatched':
      return {
        id: ++toastCounter,
        message: `Task dispatched`,
        kind: 'info',
      };
    default:
      return null;
  }
}

// ─── Kind styling ─────────────────────────────────────────────────────────────

function kindClasses(kind: ToastKind) {
  switch (kind) {
    case 'success':
      return {
        bar: 'bg-ctp-green',
        icon: 'text-ctp-green',
        border: 'border-ctp-green/30',
        svg: (
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M5 13l4 4L19 7"
          />
        ),
      };
    case 'error':
      return {
        bar: 'bg-ctp-red',
        icon: 'text-ctp-red',
        border: 'border-ctp-red/30',
        svg: (
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M6 18L18 6M6 6l12 12"
          />
        ),
      };
    case 'info':
    default:
      return {
        bar: 'bg-ctp-blue',
        icon: 'text-ctp-blue',
        border: 'border-ctp-blue/30',
        svg: (
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        ),
      };
  }
}

// ─── Single Toast Item ────────────────────────────────────────────────────────

const DISMISS_MS = 5000;

function ToastItem({
  toast,
  onDismiss,
}: {
  toast: Toast;
  onDismiss: (id: number) => void;
}) {
  const [visible, setVisible] = useState(false);
  const { bar, icon, border, svg } = kindClasses(toast.kind);

  useEffect(() => {
    // Animate in
    const show = requestAnimationFrame(() => setVisible(true));
    // Auto-dismiss
    const timer = setTimeout(() => {
      setVisible(false);
      setTimeout(() => onDismiss(toast.id), 300);
    }, DISMISS_MS);
    return () => {
      cancelAnimationFrame(show);
      clearTimeout(timer);
    };
  }, [toast.id, onDismiss]);

  return (
    <div
      className={`flex items-start gap-3 w-72 rounded-xl border ${border} bg-ctp-mantle shadow-lg overflow-hidden transition-all duration-300 ${
        visible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-4'
      }`}
    >
      {/* Left accent bar */}
      <div className={`w-1 self-stretch flex-shrink-0 ${bar}`} />

      {/* Icon */}
      <div className={`flex-shrink-0 mt-3 ${icon}`}>
        <svg
          className="w-5 h-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          {svg}
        </svg>
      </div>

      {/* Message */}
      <p className="flex-1 py-3 pr-2 text-sm text-ctp-text">{toast.message}</p>

      {/* Dismiss button */}
      <button
        onClick={() => {
          setVisible(false);
          setTimeout(() => onDismiss(toast.id), 300);
        }}
        className="flex-shrink-0 mt-2.5 mr-2 p-1 rounded hover:bg-ctp-surface0 text-ctp-subtext0 hover:text-ctp-text transition-colors"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
}

// ─── Container ────────────────────────────────────────────────────────────────

export function EventToast() {
  const { state } = useCollab();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const prevEventsLenRef = useRef(0);

  useEffect(() => {
    const current = state.recentEvents.length;
    const prev = prevEventsLenRef.current;

    if (current > prev) {
      // New events were prepended; the newest is at index 0
      const newCount = current - prev;
      for (let i = newCount - 1; i >= 0; i--) {
        const event = state.recentEvents[i];
        const toast = eventToToast(event);
        if (toast) {
          setToasts((t) => [toast, ...t].slice(0, 5));
        }
      }
    }

    prevEventsLenRef.current = current;
  }, [state.recentEvents]);

  const dismiss = (id: number) => {
    setToasts((t) => t.filter((toast) => toast.id !== id));
  };

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 items-end">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={dismiss} />
      ))}
    </div>
  );
}
