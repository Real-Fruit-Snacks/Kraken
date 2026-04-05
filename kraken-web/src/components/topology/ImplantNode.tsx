// Custom implant node component for topology graph

import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { ImplantNodeData, C2ServerNodeData, TopologyNodeData } from './types';
import { NODE_STATE_COLORS, OS_ICONS } from './types';

interface ImplantNodeProps {
  data: TopologyNodeData;
  selected?: boolean;
}

function ImplantNodeComponent({ data, selected }: ImplantNodeProps) {
  if (data.type === 'c2-server') {
    return <C2ServerNode data={data as C2ServerNodeData} selected={selected} />;
  }

  const implantData = data as ImplantNodeData;
  const stateColors = NODE_STATE_COLORS[implantData.state] || NODE_STATE_COLORS.active;
  const osIcon = OS_ICONS[implantData.os] || OS_ICONS.unknown;

  return (
    <div
      className={`
        relative px-3 py-2 rounded-lg min-w-[140px]
        transition-all duration-200
        ${selected ? 'ring-2 ring-mauve shadow-lg shadow-mauve/20' : ''}
      `}
      style={{
        backgroundColor: stateColors.bg,
        borderWidth: 2,
        borderStyle: implantData.state === 'dead' ? 'dashed' : 'solid',
        borderColor: stateColors.border,
        color: stateColors.text,
        opacity: implantData.state === 'dead' ? 0.6 : 1,
      }}
    >
      {/* Target handle (incoming connections) */}
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-surface2 !border-overlay0 !w-3 !h-3"
      />

      {/* Node content */}
      <div className="flex items-center gap-2">
        {/* OS Icon */}
        <span className="text-lg" role="img" aria-label={implantData.os}>
          {osIcon}
        </span>

        {/* Info */}
        <div className="flex flex-col min-w-0">
          <div className="flex items-center gap-1">
            <span className="font-medium text-sm truncate">
              {implantData.hostname}
            </span>
            {implantData.isElevated && (
              <span
                className="text-red text-xs"
                title="Elevated privileges"
                aria-label="Elevated privileges"
              >
                ⚡
              </span>
            )}
          </div>
          <span className="text-xs text-subtext0 truncate">
            {implantData.username}
          </span>
        </div>
      </div>

      {/* Role badge */}
      {implantData.role !== 'leaf' && (
        <div
          className={`
            absolute -top-2 -right-2 px-1.5 py-0.5 rounded text-[10px] font-medium
            ${implantData.role === 'relay' ? 'bg-blue text-crust' : implantData.role === 'hub' ? 'bg-mauve text-crust' : 'bg-surface1 text-crust'}
          `}
        >
          {implantData.role.toUpperCase()}
        </div>
      )}

      {/* Egress indicator */}
      {implantData.hasEgress && (
        <div
          className="absolute -bottom-2 left-1/2 -translate-x-1/2 px-1.5 py-0.5 rounded text-[10px] font-medium bg-green text-crust"
          title="Has egress to C2"
        >
          EGRESS
        </div>
      )}

      {/* Source handle (outgoing connections) */}
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-surface2 !border-overlay0 !w-3 !h-3"
      />
    </div>
  );
}

// C2 Server node (root of the graph)
function C2ServerNode({ data, selected }: { data: C2ServerNodeData; selected?: boolean }) {
  return (
    <div
      className={`
        relative px-4 py-3 rounded-xl min-w-[120px]
        bg-crust border-2 border-mauve
        transition-all duration-200
        ${selected ? 'ring-2 ring-mauve shadow-lg shadow-mauve/30' : ''}
      `}
    >
      {/* Only source handle - C2 doesn't receive connections */}
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-mauve !border-crust !w-4 !h-4"
      />

      <div className="flex flex-col items-center gap-1">
        <span className="text-2xl">🦑</span>
        <span className="font-bold text-sm text-mauve">
          {data.name}
        </span>
        <span className="text-[10px] text-subtext0 uppercase">
          {data.protocol}
        </span>
      </div>
    </div>
  );
}

export const ImplantNode = memo(ImplantNodeComponent);
