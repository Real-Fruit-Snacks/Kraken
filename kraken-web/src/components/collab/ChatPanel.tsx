// ChatPanel - Real-time operator chat
// Based on Mythic's operator chat pattern

import { useState, useRef, useEffect, FormEvent } from 'react';
import { useCollab, ChatMessage } from '../../contexts/CollabContext';

function formatTime(date: Date): string {
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

// Generate consistent color from username
function getUserColor(username: string): string {
  const colors = [
    'text-ctp-red',
    'text-ctp-peach',
    'text-ctp-yellow',
    'text-ctp-green',
    'text-ctp-teal',
    'text-ctp-sky',
    'text-ctp-blue',
    'text-ctp-lavender',
    'text-ctp-mauve',
    'text-ctp-pink',
  ];
  let hash = 0;
  for (let i = 0; i < username.length; i++) {
    hash = username.charCodeAt(i) + ((hash << 5) - hash);
  }
  return colors[Math.abs(hash) % colors.length];
}

// Get initials from username
function getInitials(username: string): string {
  return username
    .split(/[._-]/)
    .map((part) => part[0]?.toUpperCase() || '')
    .slice(0, 2)
    .join('');
}

interface MessageBubbleProps {
  message: ChatMessage;
  isOwnMessage: boolean;
  showAvatar: boolean;
}

function MessageBubble({ message, isOwnMessage, showAvatar }: MessageBubbleProps) {
  const userColor = getUserColor(message.fromUsername);
  const initials = getInitials(message.fromUsername);

  return (
    <div className={`flex gap-2 ${isOwnMessage ? 'flex-row-reverse' : ''}`}>
      {/* Avatar */}
      {showAvatar ? (
        <div
          className={`
            w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0
            bg-ctp-surface0 ${userColor} text-xs font-medium
          `}
        >
          {initials}
        </div>
      ) : (
        <div className="w-8 flex-shrink-0" />
      )}

      {/* Message content */}
      <div className={`flex flex-col ${isOwnMessage ? 'items-end' : 'items-start'} max-w-[75%]`}>
        {showAvatar && (
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-sm font-medium ${userColor}`}>
              {message.fromUsername}
            </span>
            <span className="text-xs text-ctp-subtext0">
              {formatTime(message.timestamp)}
            </span>
          </div>
        )}
        <div
          className={`
            px-3 py-2 rounded-lg text-sm
            ${isOwnMessage
              ? 'bg-ctp-mauve/20 text-ctp-text'
              : 'bg-ctp-surface0 text-ctp-text'
            }
          `}
        >
          {message.message}
          {message.sessionId && (
            <div className="mt-1 pt-1 border-t border-ctp-surface1 text-xs text-ctp-subtext0">
              Session: {message.sessionId.slice(0, 8)}...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface ChatPanelProps {
  currentOperatorId?: string;
  sessionContext?: string;
}

export function ChatPanel({ currentOperatorId, sessionContext }: ChatPanelProps) {
  const { state, sendChat, collabAvailable } = useCollab();
  const { chatMessages } = state;
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll to bottom when new messages arrive
  // Use scrollTop instead of scrollIntoView to prevent page scroll bubbling
  useEffect(() => {
    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
    }
  }, [chatMessages.length]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || sending) return;

    setSending(true);
    setError(null);

    try {
      await sendChat(trimmed, sessionContext);
      setInput('');
    } catch (err) {
      setError('Failed to send message');
      console.error('Chat send error:', err);
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  }

  // Group consecutive messages from same user
  function shouldShowAvatar(msg: ChatMessage, index: number): boolean {
    if (index === 0) return true;
    const prev = chatMessages[index - 1];
    if (prev.fromOperatorId !== msg.fromOperatorId) return true;
    // Show avatar if more than 5 minutes apart
    const timeDiff = msg.timestamp.getTime() - prev.timestamp.getTime();
    return timeDiff > 5 * 60 * 1000;
  }

  if (!collabAvailable) {
    return (
      <div className="flex flex-col h-full items-center justify-center text-ctp-subtext0 text-sm p-4">
        <svg className="w-8 h-8 mb-2 text-ctp-surface1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
        </svg>
        Chat unavailable
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex-none px-4 py-3 border-b border-ctp-surface0">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-ctp-text">Operator Chat</h3>
          {sessionContext && (
            <span className="text-xs bg-ctp-surface0 text-ctp-subtext0 px-2 py-1 rounded">
              Session: {sessionContext.slice(0, 8)}...
            </span>
          )}
        </div>
      </div>

      {/* Messages */}
      <div ref={messagesContainerRef} className="flex-1 overflow-y-auto p-3 space-y-2">
        {chatMessages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-ctp-subtext0 text-sm">
            <svg className="w-8 h-8 mb-2 text-ctp-surface1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 8h2a2 2 0 012 2v6a2 2 0 01-2 2h-2v4l-4-4H9a1.994 1.994 0 01-1.414-.586m0 0L11 14h4a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2v4l.586-.586z" />
            </svg>
            No messages yet
          </div>
        ) : (
          chatMessages.map((msg, idx) => (
            <MessageBubble
              key={msg.id}
              message={msg}
              isOwnMessage={msg.fromOperatorId === currentOperatorId}
              showAvatar={shouldShowAvatar(msg, idx)}
            />
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Error message */}
      {error && (
        <div className="flex-none px-4 py-2 bg-ctp-red/10 text-ctp-red text-sm">
          {error}
        </div>
      )}

      {/* Input */}
      <form onSubmit={handleSubmit} className="flex-none p-3 border-t border-ctp-surface0">
        <div className="flex gap-2">
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type a message..."
            disabled={sending}
            className="
              flex-1 px-3 py-2 rounded-lg text-sm
              bg-ctp-surface0 text-ctp-text placeholder-ctp-subtext0
              border border-ctp-surface1 focus:border-ctp-mauve focus:outline-none
              disabled:opacity-50
            "
          />
          <button
            type="submit"
            disabled={!input.trim() || sending}
            className="
              px-4 py-2 rounded-lg text-sm font-medium
              bg-ctp-mauve text-ctp-crust
              hover:bg-ctp-mauve/90 disabled:opacity-50 disabled:cursor-not-allowed
              transition-colors
            "
          >
            {sending ? (
              <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
