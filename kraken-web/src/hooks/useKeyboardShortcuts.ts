import { useEffect } from 'react';

/**
 * Parses a shortcut string like 'ctrl+k', 'ctrl+/', 'escape', 'ctrl+1'
 * and returns a normalized key for matching against KeyboardEvent.
 */
function parseShortcut(shortcut: string): {
  key: string;
  ctrl: boolean;
  meta: boolean;
  shift: boolean;
  alt: boolean;
} {
  const parts = shortcut.toLowerCase().split('+');
  const key = parts[parts.length - 1];
  return {
    key,
    ctrl: parts.includes('ctrl'),
    meta: parts.includes('meta') || parts.includes('cmd'),
    shift: parts.includes('shift'),
    alt: parts.includes('alt'),
  };
}

function matchesShortcut(
  e: KeyboardEvent,
  shortcut: string
): boolean {
  const parsed = parseShortcut(shortcut);
  const eventKey = e.key.toLowerCase();

  // Treat Ctrl and Cmd (Meta) as equivalent for cross-platform support
  const ctrlOrMeta = e.ctrlKey || e.metaKey;

  if (parsed.ctrl && !ctrlOrMeta) return false;
  if (!parsed.ctrl && ctrlOrMeta) return false;
  if (parsed.shift !== e.shiftKey) return false;
  if (parsed.alt !== e.altKey) return false;
  if (parsed.key !== eventKey) return false;

  return true;
}

/**
 * Registers keyboard shortcuts that fire when the given key combinations are pressed.
 *
 * Shortcut format examples:
 *   'ctrl+k'   — Ctrl+K (or Cmd+K on Mac)
 *   'ctrl+/'   — Ctrl+/ (or Cmd+/)
 *   'escape'   — Escape key alone
 *   'ctrl+1'   — Ctrl+1 (or Cmd+1)
 *
 * Shortcuts are ignored when focus is inside an <input>, <textarea>, or
 * [contenteditable] element unless the shortcut explicitly includes a
 * modifier (ctrl/cmd).  This prevents hijacking normal typing.
 */
export function useKeyboardShortcuts(
  shortcuts: Record<string, () => void>
) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      for (const [shortcut, handler] of Object.entries(shortcuts)) {
        if (matchesShortcut(e, shortcut)) {
          const parsed = parseShortcut(shortcut);
          const target = e.target as HTMLElement | null;
          const isTypingContext =
            target instanceof HTMLInputElement ||
            target instanceof HTMLTextAreaElement ||
            target?.isContentEditable;

          // Allow modifier shortcuts even in inputs (e.g. ctrl+k to clear)
          // but skip bare keys like 'escape' only when NOT in a typing context
          if (isTypingContext && !parsed.ctrl && !parsed.meta && !parsed.alt) {
            continue;
          }

          e.preventDefault();
          handler();
          break;
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [shortcuts]);
}
