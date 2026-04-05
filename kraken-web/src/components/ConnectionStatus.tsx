/**
 * WebSocket connection status indicator
 *
 * Shows a colored dot in the top-right corner indicating the WebSocket connection state:
 * - Green: Connected
 * - Yellow: Reconnecting
 * - Red: Disconnected
 * - Gray: Connecting (initial state)
 */

import { useState, useEffect, useRef } from 'react';

interface ConnectionStatusProps {
  /** WebSocket URL (default: ws://localhost:8080/ws) */
  url?: string;
  /** Position (default: top-right) */
  position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left';
}

type ConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'disconnected' | 'error';

export function ConnectionStatus({ url = 'ws://localhost:8080/ws', position = 'top-right' }: ConnectionStatusProps) {
  const [status, setStatus] = useState<ConnectionState>('connecting');
  const [reconnectAttempts, setReconnectAttempts] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let isMounted = true;

    const connect = () => {
      if (!isMounted) return;

      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (isMounted) {
          setStatus('connected');
          setReconnectAttempts(0);
        }
      };

      ws.onerror = () => {
        if (isMounted) {
          setStatus('error');
        }
      };

      ws.onclose = () => {
        if (!isMounted) return;

        wsRef.current = null;

        // Reconnect with exponential backoff
        setReconnectAttempts(prev => prev + 1);
        setStatus('reconnecting');

        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        reconnectTimeoutRef.current = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      isMounted = false;

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }

      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [url, reconnectAttempts]);

  const colors: Record<ConnectionState, string> = {
    connecting: 'bg-ctp-overlay0',
    connected: 'bg-ctp-green',
    reconnecting: 'bg-ctp-yellow',
    disconnected: 'bg-ctp-red',
    error: 'bg-ctp-red',
  };

  const labels: Record<ConnectionState, string> = {
    connecting: 'Connecting...',
    connected: 'Connected',
    reconnecting: `Reconnecting... (attempt ${reconnectAttempts})`,
    disconnected: 'Disconnected',
    error: 'Connection error',
  };

  const positions = {
    'top-right': 'top-4 right-4',
    'top-left': 'top-4 left-4',
    'bottom-right': 'bottom-4 right-4',
    'bottom-left': 'bottom-4 left-4',
  };

  return (
    <div className={`fixed ${positions[position]} z-50 pointer-events-none`}>
      <div className="flex items-center gap-2 px-3 py-1.5 bg-ctp-mantle border border-ctp-surface0 rounded-lg shadow-lg">
        <div className={`w-2 h-2 rounded-full ${colors[status]} ${status === 'connected' ? 'animate-pulse' : ''}`} />
        <span className="text-xs text-ctp-subtext1">{labels[status]}</span>
      </div>
    </div>
  );
}
