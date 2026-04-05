import { useState, useEffect, useRef } from 'react';

type ModalVariant = 'danger' | 'warning' | 'default';

interface ConfirmModalProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  variant?: ModalVariant;
  onConfirm: () => void;
  onCancel: () => void;
}

interface ConfirmModalWithInputProps {
  isOpen: boolean;
  title: string;
  message: string;
  inputLabel: string;
  inputDefault?: string;
  inputPlaceholder?: string;
  confirmText?: string;
  cancelText?: string;
  variant?: ModalVariant;
  onConfirm: (value: string) => void;
  onCancel: () => void;
}

const variantStyles: Record<ModalVariant, { button: string; icon: string }> = {
  danger: {
    button: 'bg-ctp-red hover:bg-ctp-red/80 text-ctp-crust',
    icon: 'text-ctp-red',
  },
  warning: {
    button: 'bg-ctp-peach hover:bg-ctp-peach/80 text-ctp-crust',
    icon: 'text-ctp-peach',
  },
  default: {
    button: 'bg-ctp-mauve hover:bg-ctp-mauve/80 text-ctp-crust',
    icon: 'text-ctp-mauve',
  },
};

function WarningIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

/**
 * Simple confirmation modal without input
 */
export function ConfirmModal({
  isOpen,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'default',
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  const confirmButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (isOpen) {
      // Focus confirm button when modal opens
      setTimeout(() => confirmButtonRef.current?.focus(), 0);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onCancel();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  const styles = variantStyles[variant];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={onCancel}
    >
      <div
        className="bg-ctp-base border border-ctp-surface0 rounded-xl shadow-2xl w-full max-w-md p-6"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header with icon */}
        <div className="flex items-start gap-4">
          <div className={`flex-shrink-0 w-10 h-10 rounded-full bg-ctp-surface0 flex items-center justify-center ${styles.icon}`}>
            <WarningIcon className="w-6 h-6" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-lg font-semibold text-ctp-text">{title}</h2>
            <p className="mt-2 text-sm text-ctp-subtext1 whitespace-pre-line">{message}</p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3 mt-6 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium text-ctp-text transition-colors"
          >
            {cancelText}
          </button>
          <button
            ref={confirmButtonRef}
            onClick={onConfirm}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${styles.button}`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Confirmation modal with text input (e.g., for burn reason)
 */
export function ConfirmModalWithInput({
  isOpen,
  title,
  message,
  inputLabel,
  inputDefault = '',
  inputPlaceholder = '',
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'default',
  onConfirm,
  onCancel,
}: ConfirmModalWithInputProps) {
  const [inputValue, setInputValue] = useState(inputDefault);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setInputValue(inputDefault);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [isOpen, inputDefault]);

  useEffect(() => {
    if (!isOpen) return;

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onCancel();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  const styles = variantStyles[variant];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onConfirm(inputValue);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={onCancel}
    >
      <div
        className="bg-ctp-base border border-ctp-surface0 rounded-xl shadow-2xl w-full max-w-md p-6"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header with icon */}
        <div className="flex items-start gap-4">
          <div className={`flex-shrink-0 w-10 h-10 rounded-full bg-ctp-surface0 flex items-center justify-center ${styles.icon}`}>
            <WarningIcon className="w-6 h-6" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-lg font-semibold text-ctp-text">{title}</h2>
            <p className="mt-2 text-sm text-ctp-subtext1 whitespace-pre-line">{message}</p>
          </div>
        </div>

        {/* Input */}
        <form onSubmit={handleSubmit}>
          <div className="mt-4">
            <label htmlFor="confirm-modal-input" className="block text-sm font-medium text-ctp-subtext0 mb-1.5">
              {inputLabel}
            </label>
            <input
              id="confirm-modal-input"
              ref={inputRef}
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder={inputPlaceholder}
              className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve"
            />
          </div>

          {/* Actions */}
          <div className="flex gap-3 mt-6 justify-end">
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium text-ctp-text transition-colors"
            >
              {cancelText}
            </button>
            <button
              type="submit"
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${styles.button}`}
            >
              {confirmText}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/**
 * Error notification banner (inline, dismissible)
 */
export function ErrorBanner({
  message,
  onDismiss,
}: {
  message: string;
  onDismiss?: () => void;
}) {
  return (
    <div className="mb-4 p-3 bg-ctp-red/20 border border-ctp-red/40 rounded-lg flex items-center justify-between">
      <span className="text-ctp-red text-sm">{message}</span>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-ctp-red/70 hover:text-ctp-red ml-3"
          aria-label="Dismiss"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
    </div>
  );
}
