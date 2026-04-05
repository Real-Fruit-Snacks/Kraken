// Keyboard Shortcuts Documentation Modal
// Comprehensive reference for all keyboard shortcuts in Kraken

import { Modal } from './Modal';

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ShortcutGroup {
  title: string;
  shortcuts: Array<{
    keys: string[];
    description: string;
  }>;
}

const shortcutGroups: ShortcutGroup[] = [
  {
    title: 'Global',
    shortcuts: [
      { keys: ['Ctrl', 'K'], description: 'Open Command Palette' },
      { keys: ['?'], description: 'Show Keyboard Shortcuts' },
      { keys: ['Esc'], description: 'Close modal / Cancel action' },
    ],
  },
  {
    title: 'Navigation',
    shortcuts: [
      { keys: ['G', 'D'], description: 'Go to Dashboard' },
      { keys: ['G', 'S'], description: 'Go to Sessions' },
      { keys: ['G', 'L'], description: 'Go to Listeners' },
      { keys: ['G', 'T'], description: 'Go to Topology' },
      { keys: ['G', 'F'], description: 'Go to Defender View' },
      { keys: ['G', 'O'], description: 'Go to Loot' },
      { keys: ['G', 'M'], description: 'Go to Modules' },
      { keys: ['G', 'P'], description: 'Go to Operators' },
      { keys: ['G', 'R'], description: 'Go to Reports' },
    ],
  },
  {
    title: 'Session Actions',
    shortcuts: [
      { keys: ['Enter'], description: 'Execute command' },
      { keys: ['U'], description: 'Upload file to session' },
      { keys: ['D'], description: 'Download file from session' },
      { keys: ['Tab'], description: 'Autocomplete command' },
      { keys: ['Up'], description: 'Previous command in history' },
      { keys: ['Down'], description: 'Next command in history' },
      { keys: ['Ctrl', 'C'], description: 'Cancel current operation' },
      { keys: ['Ctrl', 'L'], description: 'Clear terminal output' },
    ],
  },
  {
    title: 'Quick Actions',
    shortcuts: [
      { keys: ['Ctrl', 'Shift', 'L'], description: 'Create new listener' },
      { keys: ['Ctrl', 'Shift', 'P'], description: 'Generate payload' },
      { keys: ['Ctrl', 'Shift', 'N'], description: 'New session tab' },
      { keys: ['Ctrl', 'W'], description: 'Close current tab' },
    ],
  },
  {
    title: 'Command Palette',
    shortcuts: [
      { keys: ['Up'], description: 'Previous result' },
      { keys: ['Down'], description: 'Next result' },
      { keys: ['Enter'], description: 'Execute selected command' },
      { keys: ['Esc'], description: 'Close palette' },
    ],
  },
  {
    title: 'Tables & Lists',
    shortcuts: [
      { keys: ['J'], description: 'Next row' },
      { keys: ['K'], description: 'Previous row' },
      { keys: ['Enter'], description: 'Open selected item' },
      { keys: ['/'], description: 'Focus search / filter' },
    ],
  },
  {
    title: 'Collaboration',
    shortcuts: [
      { keys: ['Ctrl', 'Shift', 'C'], description: 'Toggle collaboration panel' },
      { keys: ['Ctrl', 'Enter'], description: 'Send chat message' },
    ],
  },
];

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex items-center justify-center min-w-[1.75rem] h-7 px-2 text-xs font-mono font-medium rounded bg-ctp-surface0 border border-ctp-surface1 text-ctp-text shadow-sm">
      {children}
    </kbd>
  );
}

export function KeyboardShortcutsModal({ isOpen, onClose }: KeyboardShortcutsModalProps) {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Keyboard Shortcuts"
      size="lg"
    >
      <div className="space-y-6">
        {shortcutGroups.map((group) => (
          <div key={group.title}>
            <h3 className="text-sm font-semibold text-ctp-mauve mb-3 uppercase tracking-wide">
              {group.title}
            </h3>
            <div className="space-y-2">
              {group.shortcuts.map((shortcut, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between py-2 px-3 rounded-lg bg-ctp-mantle"
                >
                  <span className="text-sm text-ctp-subtext1">
                    {shortcut.description}
                  </span>
                  <div className="flex items-center gap-1">
                    {shortcut.keys.map((key, keyIdx) => (
                      <span key={keyIdx} className="flex items-center">
                        <Kbd>{key}</Kbd>
                        {keyIdx < shortcut.keys.length - 1 && (
                          <span className="mx-1 text-ctp-overlay0">+</span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}

        <div className="pt-4 border-t border-ctp-surface0">
          <p className="text-xs text-ctp-overlay0 text-center">
            Press <Kbd>?</Kbd> anywhere to show this help. Press <Kbd>Esc</Kbd> to close.
          </p>
        </div>
      </div>
    </Modal>
  );
}

export default KeyboardShortcutsModal;
