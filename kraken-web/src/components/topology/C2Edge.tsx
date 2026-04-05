// Custom edge component with protocol-based colors

import { memo } from 'react';
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type Position,
} from '@xyflow/react';
import type { TopologyEdgeData, EdgeProtocol, EdgeState } from './types';
import { PROTOCOL_COLORS, STATE_COLORS } from './types';

interface C2EdgeProps {
  id: string;
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  sourcePosition: Position;
  targetPosition: Position;
  data?: TopologyEdgeData;
  selected?: boolean;
  markerEnd?: string;
}

function C2EdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
  markerEnd,
}: C2EdgeProps) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const protocol: EdgeProtocol = data?.protocol || 'tcp';
  const state: EdgeState = data?.state || 'established';
  const latencyMs = data?.latencyMs;
  const animated = data?.animated ?? (state === 'established');

  const protocolStyle = PROTOCOL_COLORS[protocol];
  const stateStyle = STATE_COLORS[state];

  // Determine final color - use state color if not established, else protocol color
  const strokeColor = state === 'established' ? protocolStyle.color : stateStyle.color;
  const strokeOpacity = stateStyle.opacity;

  // Line style based on protocol and state
  const strokeDasharray = state === 'failed'
    ? '8 4'
    : protocolStyle.lineStyle === 'dotted'
      ? '4 4'
      : protocolStyle.lineStyle === 'dashed'
        ? '8 4'
        : undefined;

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke: strokeColor,
          strokeWidth: selected ? 3 : 2,
          strokeOpacity,
          strokeDasharray,
          filter: selected ? 'drop-shadow(0 0 4px currentColor)' : undefined,
        }}
        className={animated ? 'react-flow__edge-path-animated' : ''}
      />

      {/* Edge label showing latency if available */}
      {latencyMs !== undefined && latencyMs > 0 && (
        <EdgeLabelRenderer>
          <div
            className="absolute pointer-events-all nodrag nopan"
            style={{
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            }}
          >
            <div
              className={`
                px-1.5 py-0.5 rounded text-[10px] font-mono
                bg-surface0/90 backdrop-blur-sm
                ${latencyMs > 500 ? 'text-red' : latencyMs > 200 ? 'text-yellow' : 'text-green'}
              `}
            >
              {latencyMs}ms
            </div>
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export const C2Edge = memo(C2EdgeComponent);

// Add custom CSS for animated edges
export const edgeAnimationStyles = `
  .react-flow__edge-path-animated {
    stroke-dasharray: 5;
    animation: dash 0.5s linear infinite;
  }

  @keyframes dash {
    to {
      stroke-dashoffset: -10;
    }
  }
`;
