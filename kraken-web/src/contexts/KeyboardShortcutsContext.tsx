import {
  createContext,
  useContext,
  useCallback,
  useEffect,
  useRef,
  ReactNode,
} from 'react';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';

interface KeyboardShortcutsContextValue {
  /** Register a shortcut. Returns an unregister function. */
  registerShortcut: (key: string, handler: () => void) => () => void;
}

const KeyboardShortcutsContext =
  createContext<KeyboardShortcutsContextValue | null>(null);

/**
 * Provides a global keyboard shortcuts registry.
 *
 * Components can call `useRegisterShortcut` to add shortcuts that are
 * automatically removed when the component unmounts.
 */
export function KeyboardShortcutsProvider({
  children,
}: {
  children: ReactNode;
}) {
  // Map of shortcut string -> handler. Use a ref so mutations don't cause
  // re-renders of this provider.
  const shortcutsRef = useRef<Record<string, () => void>>({});

  const registerShortcut = useCallback(
    (key: string, handler: () => void): (() => void) => {
      shortcutsRef.current[key] = handler;
      return () => {
        delete shortcutsRef.current[key];
      };
    },
    []
  );

  // Build a stable proxy object that reads from shortcutsRef at call time,
  // so newly registered handlers are always invoked without re-subscribing
  // the underlying event listener.
  const proxyShortcuts = useRef<Record<string, () => void>>(
    new Proxy({} as Record<string, () => void>, {
      get(_target, prop: string) {
        return shortcutsRef.current[prop];
      },
      ownKeys() {
        return Object.keys(shortcutsRef.current);
      },
      has(_target, prop: string) {
        return prop in shortcutsRef.current;
      },
      getOwnPropertyDescriptor(_target, prop: string) {
        if (prop in shortcutsRef.current) {
          return {
            enumerable: true,
            configurable: true,
            value: shortcutsRef.current[prop],
          };
        }
        return undefined;
      },
    })
  );

  useKeyboardShortcuts(proxyShortcuts.current);

  return (
    <KeyboardShortcutsContext.Provider value={{ registerShortcut }}>
      {children}
    </KeyboardShortcutsContext.Provider>
  );
}

/**
 * Returns the shortcuts registry. Must be used within KeyboardShortcutsProvider.
 */
export function useKeyboardShortcutsContext(): KeyboardShortcutsContextValue {
  const ctx = useContext(KeyboardShortcutsContext);
  if (!ctx) {
    throw new Error(
      'useKeyboardShortcutsContext must be used within a KeyboardShortcutsProvider'
    );
  }
  return ctx;
}

/**
 * Convenience hook: registers a shortcut and unregisters it on unmount.
 *
 * @param shortcut  e.g. 'ctrl+/', 'ctrl+1', 'escape'
 * @param handler   Called when the shortcut fires
 * @param enabled   Set to false to temporarily disable (default: true)
 */
export function useRegisterShortcut(
  shortcut: string,
  handler: () => void,
  enabled = true
) {
  const { registerShortcut } = useKeyboardShortcutsContext();

  // Keep a stable ref to handler to avoid re-registering on every render
  const handlerRef = useRef(handler);
  handlerRef.current = handler;

  useEffect(() => {
    if (!enabled) return;
    const unregister = registerShortcut(shortcut, () => handlerRef.current());
    return unregister;
  }, [shortcut, enabled, registerShortcut]);
}
