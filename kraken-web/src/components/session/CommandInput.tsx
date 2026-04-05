import { useState, useRef, useEffect, useCallback, forwardRef, useImperativeHandle } from 'react';
import { useMutation } from '@tanstack/react-query';
import { taskClient } from '../../api';
import { ShellTask } from '../../gen/kraken_pb.js';
import type { Implant } from '../../gen/kraken_pb.js';
import { useSessionStore } from '../../stores/sessionStore';
import { OpsecGate, assessTaskRisk, RiskBadge, type OpsecAssessment } from '../opsec';

const COMMON_COMMANDS = [
  'whoami', 'pwd', 'ls', 'cd', 'cat', 'head', 'tail',
  'ps', 'netstat', 'ifconfig', 'ipconfig', 'hostname', 'uname',
  'id', 'groups', 'env', 'set', 'echo', 'mkdir', 'rm', 'cp',
  'mv', 'touch', 'chmod', 'chown', 'grep', 'find', 'curl', 'wget',
];

const MODULE_SUBCOMMANDS = ['load', 'unload', 'list'];

export interface CommandInputHandle {
  focusInput: () => void;
}

interface CommandInputProps {
  sessionId: string;
  implant: Implant;
  onCommandSent?: () => void;
  onClear?: () => void;
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

type TaskMode = 'shell' | 'powershell' | 'assembly';

interface TaskModeConfig {
  value: TaskMode;
  label: string;
  windowsPrompt: string;
  unixPrompt: string;
  windowsOnly?: boolean;
}

const TASK_MODES: TaskModeConfig[] = [
  { value: 'shell', label: 'Shell', windowsPrompt: '>', unixPrompt: '$' },
  { value: 'powershell', label: 'PowerShell', windowsPrompt: 'PS>', unixPrompt: 'PS>', windowsOnly: true },
  { value: 'assembly', label: 'Assembly', windowsPrompt: '#', unixPrompt: '#' },
];

function isWindows(osName: string | undefined): boolean {
  return osName?.toLowerCase().includes('windows') ?? false;
}

function getAvailableModes(osName: string | undefined): TaskModeConfig[] {
  const isWin = isWindows(osName);
  return TASK_MODES.filter(mode => !mode.windowsOnly || isWin);
}

function getPromptSymbol(mode: TaskModeConfig, osName: string | undefined): string {
  return isWindows(osName) ? mode.windowsPrompt : mode.unixPrompt;
}

const HISTORY_MAX = 100;

function loadHistory(sessionId: string): string[] {
  try {
    const raw = localStorage.getItem(`kraken-command-history-${sessionId}`);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveHistory(sessionId: string, history: string[]): void {
  try {
    localStorage.setItem(`kraken-command-history-${sessionId}`, JSON.stringify(history));
  } catch {
    // Ignore storage errors
  }
}

function getSuggestions(value: string): string[] {
  if (!value) return [];
  if (value.startsWith('module ')) {
    const sub = value.slice('module '.length);
    return MODULE_SUBCOMMANDS
      .filter(s => s.startsWith(sub))
      .map(s => `module ${s}`);
  }
  return COMMON_COMMANDS.filter(c => c.startsWith(value));
}

export const CommandInput = forwardRef<CommandInputHandle, CommandInputProps>(
function CommandInput({ sessionId, implant, onCommandSent, onClear }, ref) {
  const [command, setCommand] = useState('');
  const [taskMode, setTaskMode] = useState<TaskMode>('shell');
  const [history, setHistory] = useState<string[]>(() => loadHistory(sessionId));
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [currentInput, setCurrentInput] = useState('');
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [suggestionIndex, setSuggestionIndex] = useState(-1);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // OPSEC gate state
  const [opsecModalOpen, setOpsecModalOpen] = useState(false);
  const [pendingCommand, setPendingCommand] = useState<string | null>(null);
  const [currentAssessment, setCurrentAssessment] = useState<OpsecAssessment | null>(null);

  useImperativeHandle(ref, () => ({
    focusInput: () => inputRef.current?.focus(),
  }));
  const { addCommand } = useSessionStore();

  const osName = implant.systemInfo?.osName;
  const availableModes = getAvailableModes(osName);
  const currentMode = availableModes.find(m => m.value === taskMode) ?? availableModes[0];
  const promptSymbol = getPromptSymbol(currentMode, osName);

  // Sync history to localStorage whenever it changes
  useEffect(() => {
    saveHistory(sessionId, history);
  }, [sessionId, history]);

  // Close suggestions when clicking outside
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node) &&
        inputRef.current &&
        !inputRef.current.contains(e.target as Node)
      ) {
        setShowSuggestions(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const closeSuggestions = useCallback(() => {
    setShowSuggestions(false);
    setSuggestions([]);
    setSuggestionIndex(-1);
  }, []);

  const selectSuggestion = useCallback((value: string) => {
    setCommand(value);
    closeSuggestions();
    inputRef.current?.focus();
  }, [closeSuggestions]);

  const dispatchMutation = useMutation({
    mutationFn: async (cmd: string) => {
      const shellTask = new ShellTask({ command: cmd });
      const taskData = new Uint8Array(shellTask.toBinary()) as Uint8Array<ArrayBuffer>;

      // Use shell task type for all modes currently (expandable later)
      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: taskMode === 'shell' ? 'shell' : taskMode,
        taskData,
      });
    },
    onSuccess: (_, cmd) => {
      addCommand(sessionId, cmd);
      setHistory(prev => {
        const deduped = prev.filter(c => c !== cmd);
        return [...deduped, cmd].slice(-HISTORY_MAX);
      });
      setCommand('');
      setHistoryIndex(-1);
      setCurrentInput('');
      closeSuggestions();
      onCommandSent?.();
    },
  });

  // Extract task type from command for OPSEC assessment
  const getTaskType = (cmd: string): string => {
    const firstWord = cmd.split(/\s+/)[0].toLowerCase();
    // Map common commands to task types
    const taskTypeMap: Record<string, string> = {
      'mimikatz': 'mimikatz',
      'hashdump': 'hashdump',
      'keylog': 'keylogger',
      'keylogger': 'keylogger',
      'screenshot': 'screenshot',
      'inject': 'inject',
      'persist': 'persist',
      'persistence': 'persist',
      'upload': 'upload',
      'download': 'download',
      'shell': 'shell',
      'exec': 'execute',
      'execute': 'execute',
      'run': 'execute',
      'ps': 'ps',
      'netstat': 'netstat',
      'pivot': 'pivot',
      'tunnel': 'pivot',
      'socks': 'pivot',
    };
    return taskTypeMap[firstWord] || firstWord;
  };

  // Execute the command (called directly or after OPSEC confirmation)
  const executeCommand = (cmd: string) => {
    dispatchMutation.mutate(cmd);
  };

  // Handle OPSEC confirmation
  const handleOpsecConfirm = () => {
    if (pendingCommand) {
      executeCommand(pendingCommand);
    }
    setOpsecModalOpen(false);
    setPendingCommand(null);
    setCurrentAssessment(null);
  };

  const handleOpsecCancel = () => {
    setOpsecModalOpen(false);
    setPendingCommand(null);
    setCurrentAssessment(null);
    inputRef.current?.focus();
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = command.trim();
    if (!cmd || dispatchMutation.isPending) return;

    // Assess OPSEC risk
    const taskType = getTaskType(cmd);
    const assessment = assessTaskRisk(taskType);

    // If high risk, show confirmation modal
    if (assessment.requiresConfirmation) {
      setPendingCommand(cmd);
      setCurrentAssessment(assessment);
      setOpsecModalOpen(true);
      return;
    }

    // Low/medium risk - execute directly
    executeCommand(cmd);
  };

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    // Tab - trigger completion
    if (e.key === 'Tab') {
      e.preventDefault();
      if (showSuggestions && suggestions.length > 0) {
        // Tab cycles through suggestions or selects if only one
        const idx = suggestionIndex === -1 ? 0 : (suggestionIndex + 1) % suggestions.length;
        if (suggestions.length === 1) {
          selectSuggestion(suggestions[0]);
        } else {
          setSuggestionIndex(idx);
          setCommand(suggestions[idx]);
        }
      } else {
        const matches = getSuggestions(command);
        if (matches.length === 1) {
          selectSuggestion(matches[0]);
        } else if (matches.length > 1) {
          setSuggestions(matches);
          setSuggestionIndex(-1);
          setShowSuggestions(true);
        }
      }
      return;
    }

    // Escape - close suggestions or blur
    if (e.key === 'Escape') {
      e.preventDefault();
      if (showSuggestions) {
        closeSuggestions();
      } else {
        inputRef.current?.blur();
      }
      return;
    }

    // Arrow up
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (showSuggestions && suggestions.length > 0) {
        const idx = suggestionIndex <= 0 ? suggestions.length - 1 : suggestionIndex - 1;
        setSuggestionIndex(idx);
        setCommand(suggestions[idx]);
        return;
      }
      if (history.length === 0) return;
      if (historyIndex === -1) {
        setCurrentInput(command);
      }
      const newIndex = historyIndex === -1
        ? history.length - 1
        : Math.max(0, historyIndex - 1);
      setHistoryIndex(newIndex);
      setCommand(history[newIndex]);
      return;
    }

    // Arrow down
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (showSuggestions && suggestions.length > 0) {
        const idx = suggestionIndex >= suggestions.length - 1 ? 0 : suggestionIndex + 1;
        setSuggestionIndex(idx);
        setCommand(suggestions[idx]);
        return;
      }
      if (historyIndex === -1) return;
      const newIndex = historyIndex + 1;
      if (newIndex >= history.length) {
        setHistoryIndex(-1);
        setCommand(currentInput);
      } else {
        setHistoryIndex(newIndex);
        setCommand(history[newIndex]);
      }
      return;
    }

    // Enter - select suggestion if open, otherwise submit via form
    if (e.key === 'Enter') {
      if (showSuggestions && suggestionIndex !== -1) {
        e.preventDefault();
        selectSuggestion(suggestions[suggestionIndex]);
        return;
      }
      // Let form's onSubmit handle it
      return;
    }

    // Ctrl+L - clear terminal view (local only, doesn't delete server tasks)
    if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      onClear?.();
      return;
    }

    // Ctrl+K - clear input
    if (e.key === 'k' && e.ctrlKey) {
      e.preventDefault();
      setCommand('');
      setHistoryIndex(-1);
      closeSuggestions();
      return;
    }
  }, [history, historyIndex, currentInput, command, showSuggestions, suggestions, suggestionIndex, selectSuggestion, closeSuggestions]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const info = implant.systemInfo;

  return (
    <div className="border-t border-ctp-surface0 bg-ctp-mantle">
      {/* Context badges */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-ctp-surface0/50 text-xs">
        <ContextBadge label="host" value={info?.hostname ?? '?'} color="text-ctp-mauve" />
        <ContextBadge label="user" value={info?.username ?? '?'} color="text-ctp-green" />
        <ContextBadge label="pid" value={info?.processId?.toString() ?? '?'} color="text-ctp-blue" />
        {info?.processName && (
          <ContextBadge label="proc" value={info.processName} color="text-ctp-peach" />
        )}
      </div>

      {/* Command input area with completion dropdown */}
      <div className="relative">
        {/* Completion dropdown */}
        {showSuggestions && suggestions.length > 0 && (
          <div
            ref={dropdownRef}
            className="absolute bottom-full left-0 right-0 mx-4 mb-1 bg-ctp-surface0 border border-ctp-surface1 rounded shadow-lg z-50 overflow-hidden"
          >
            {suggestions.map((s, i) => (
              <button
                key={s}
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  selectSuggestion(s);
                }}
                className={`w-full text-left px-3 py-1.5 font-mono text-sm transition-colors ${
                  i === suggestionIndex
                    ? 'bg-ctp-mauve text-ctp-crust'
                    : 'text-ctp-text hover:bg-ctp-surface1'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        )}

        {/* Command input form */}
        <form onSubmit={handleSubmit} className="flex items-center gap-2 px-4 py-3">
          <select
            value={taskMode}
            onChange={(e) => setTaskMode(e.target.value as TaskMode)}
            className="bg-ctp-surface0 border border-ctp-surface1 rounded px-2 py-1 text-xs text-ctp-subtext1 focus:outline-none focus:border-ctp-mauve"
          >
            {availableModes.map((mode) => (
              <option key={mode.value} value={mode.value}>
                {mode.label}
              </option>
            ))}
          </select>
          <span className="text-ctp-green font-mono font-bold select-none">{promptSymbol}</span>
          <input
            ref={inputRef}
            type="text"
            value={command}
            onChange={(e) => {
              const val = e.target.value;
              setCommand(val);
              setHistoryIndex(-1);
              setCurrentInput('');
              // Hide suggestions on manual input change
              if (showSuggestions) {
                closeSuggestions();
              }
            }}
            onKeyDown={handleKeyDown}
            placeholder="Enter command... (Tab to complete)"
            disabled={dispatchMutation.isPending}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="flex-1 bg-transparent font-mono text-sm text-ctp-text placeholder-ctp-overlay0 outline-none disabled:opacity-50"
          />
          {/* Live risk indicator */}
          {command.trim() && (
            <RiskBadge level={assessTaskRisk(getTaskType(command)).riskLevel} />
          )}
          <button
            type="submit"
            disabled={dispatchMutation.isPending || !command.trim()}
            className="px-3 py-1.5 bg-ctp-mauve text-ctp-crust text-xs font-medium rounded hover:bg-ctp-mauve/80 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {dispatchMutation.isPending ? 'Sending...' : 'Run'}
          </button>
        </form>
      </div>

      {/* Error display */}
      {dispatchMutation.error && (
        <div className="px-4 pb-3 text-xs text-ctp-red">
          Error: {dispatchMutation.error instanceof Error ? dispatchMutation.error.message : 'Failed to dispatch'}
        </div>
      )}

      {/* Keyboard hints */}
      <div className="px-4 pb-2 flex gap-4 text-[10px] text-ctp-overlay0">
        <span>↑↓ History</span>
        <span>Tab Complete</span>
        <span>Ctrl+K Clear input</span>
        <span>Ctrl+L Clear screen</span>
        <span>Esc Close/Blur</span>
      </div>

      {/* OPSEC Gate Modal */}
      {currentAssessment && (
        <OpsecGate
          isOpen={opsecModalOpen}
          onClose={handleOpsecCancel}
          onConfirm={handleOpsecConfirm}
          taskType={getTaskType(pendingCommand || '')}
          assessment={currentAssessment}
          targetInfo={implant.systemInfo?.hostname}
        />
      )}
    </div>
  );
});

function ContextBadge({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="flex items-center gap-1 bg-ctp-surface0/50 px-2 py-0.5 rounded">
      <span className="text-ctp-overlay0">{label}:</span>
      <span className={`font-mono ${color}`}>{value}</span>
    </div>
  );
}
