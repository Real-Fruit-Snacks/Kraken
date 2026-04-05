import { useEffect, useState } from 'react';
import { useToastState, useToast } from '../contexts/ToastContext.js';
import type { ToastEntry, ToastType } from '../contexts/ToastContext.js';

// ─── Kind styling ──────────────────────────────────────────────────────────

function typeClasses(type: ToastType) {
  switch (type) {
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
    case 'warning':
      return {
        bar: 'bg-ctp-peach',
        icon: 'text-ctp-peach',
        border: 'border-ctp-peach/30',
        svg: (
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
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

// ─── Single Toast Item ─────────────────────────────────────────────────────

function ToastItem({
  toast,
  onDismiss,
}: {
  toast: ToastEntry;
  onDismiss: (id: number) => void;
}) {
  const [visible, setVisible] = useState(false);
  const { bar, icon, border, svg } = typeClasses(toast.type);

  useEffect(() => {
    const show = requestAnimationFrame(() => setVisible(true));

    const timer = setTimeout(() => {
      setVisible(false);
      setTimeout(() => onDismiss(toast.id), 300);
    }, toast.duration);

    return () => {
      cancelAnimationFrame(show);
      clearTimeout(timer);
    };
  }, [toast.id, toast.duration, onDismiss]);

  function handleDismiss() {
    setVisible(false);
    setTimeout(() => onDismiss(toast.id), 300);
  }

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
        onClick={handleDismiss}
        className="flex-shrink-0 mt-2.5 mr-2 p-1 rounded hover:bg-ctp-surface0 text-ctp-subtext0 hover:text-ctp-text transition-colors"
        aria-label="Dismiss notification"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M6 18L18 6M6 6l12 12"
          />
        </svg>
      </button>
    </div>
  );
}

// ─── Container ─────────────────────────────────────────────────────────────

export function ToastContainer() {
  const toasts = useToastState();
  const { dismissToast } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 items-end">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={dismissToast} />
      ))}
    </div>
  );
}
