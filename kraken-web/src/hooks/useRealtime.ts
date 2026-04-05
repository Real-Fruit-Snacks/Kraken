/**
 * WebSocket real-time event hook for Kraken web UI
 *
 * Connects to the server's /ws endpoint and subscribes to real-time events.
 * Automatically reconnects on disconnection with exponential backoff.
 *
 * @example
 * ```tsx
 * useRealtime<SessionData>('SessionNew', (data) => {
 *   setSessions(prev => [...prev, data]);
 * });
 * ```
 */

import { useEffect, useRef } from 'react';
import { useAuthStore } from '../stores/authStore';

export interface WebSocketEvent<T = unknown> {
  type: string;
  timestamp: number;
  data: T;
}

interface UseRealtimeOptions {
  /** WebSocket URL (default: ws://localhost:8080/ws) */
  url?: string;
  /** Enable debug logging */
  debug?: boolean;
  /** Max reconnection attempts (default: 10) */
  maxRetries?: number;
  /** Callback for connection state changes */
  onConnectionState?: (state: ConnectionState) => void;
  /** Callback for error states */
  onError?: (error: ConnectionError) => void;
}

export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'reconnecting' | 'failed';

export interface ConnectionError {
  type: 'connection_failed' | 'max_retries_exceeded' | 'parse_error';
  message: string;
  attempt?: number;
  maxAttempts?: number;
}

/**
 * Subscribe to real-time WebSocket events
 *
 * @param eventType - Event type to subscribe to (e.g., 'SessionNew', 'TaskComplete')
 * @param handler - Callback function when event is received
 * @param options - WebSocket connection options
 */
export function useRealtime<T = unknown>(
  eventType: string,
  handler: (data: T) => void,
  options: UseRealtimeOptions = {}
) {
  const {
    url = 'ws://localhost:8080/ws',
    debug = false,
    maxRetries = 10,
    onConnectionState,
    onError,
  } = options;

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const handlerRef = useRef(handler);
  const connectionStateRef = useRef<ConnectionState>('disconnected');
  const token = useAuthStore((state) => state.token);

  // Update handler ref on every render to avoid stale closures
  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  const updateConnectionState = (state: ConnectionState) => {
    connectionStateRef.current = state;
    onConnectionState?.(state);
  };

  const reportError = (error: ConnectionError) => {
    if (debug) {
      console.error('[useRealtime] Error:', error);
    }
    onError?.(error);
  };

  useEffect(() => {
    let isMounted = true;

    const connect = () => {
      if (!isMounted) return;

      // Don't attempt connection without auth token
      if (!token) {
        if (debug) {
          console.log('[useRealtime] No auth token available, skipping connection');
        }
        return;
      }

      updateConnectionState(reconnectAttemptsRef.current === 0 ? 'connecting' : 'reconnecting');

      if (debug) {
        console.log(`[useRealtime] Connecting to ${url}...`);
      }

      // Append JWT token as query parameter
      const wsUrl = `${url}?token=${token}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (debug) {
          console.log(`[useRealtime] Connected`);
        }
        reconnectAttemptsRef.current = 0;
        updateConnectionState('connected');
      };

      ws.onmessage = (event) => {
        try {
          const message: WebSocketEvent = JSON.parse(event.data);

          if (debug) {
            console.log(`[useRealtime] Received:`, message);
          }

          // Only handle events matching our subscription
          if (message.type === eventType) {
            handlerRef.current(message.data as T);
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown parse error';
          console.error('[useRealtime] Failed to parse WebSocket message:', error);
          reportError({
            type: 'parse_error',
            message: `Failed to parse message: ${errorMessage}`,
          });
        }
      };

      ws.onerror = (error) => {
        console.error('[useRealtime] WebSocket error:', error);
        reportError({
          type: 'connection_failed',
          message: 'WebSocket connection error occurred',
          attempt: reconnectAttemptsRef.current + 1,
          maxAttempts: maxRetries,
        });
      };

      ws.onclose = () => {
        if (debug) {
          console.log('[useRealtime] Connection closed');
        }

        wsRef.current = null;
        updateConnectionState('disconnected');

        // Reconnect with exponential backoff (capped at 30 seconds)
        if (isMounted && reconnectAttemptsRef.current < maxRetries) {
          reconnectAttemptsRef.current++;
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current - 1), 30000);

          if (debug) {
            console.log(`[useRealtime] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current}/${maxRetries})...`);
          }

          reconnectTimeoutRef.current = setTimeout(connect, delay);
        } else if (reconnectAttemptsRef.current >= maxRetries) {
          // Max retries exceeded
          updateConnectionState('failed');
          reportError({
            type: 'max_retries_exceeded',
            message: `Failed to reconnect after ${maxRetries} attempts`,
            attempt: reconnectAttemptsRef.current,
            maxAttempts: maxRetries,
          });

          if (debug) {
            console.error(`[useRealtime] Max reconnection attempts (${maxRetries}) exceeded`);
          }
        }
      };
    };

    connect();

    // Cleanup on unmount
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
  }, [url, eventType, debug, maxRetries, onConnectionState, onError, token]);
}
