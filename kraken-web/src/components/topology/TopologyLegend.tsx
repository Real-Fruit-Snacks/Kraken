// Topology legend showing edge colors and node states

import { PROTOCOL_COLORS, NODE_STATE_COLORS, OS_ICONS } from './types';

export function TopologyLegend() {
  return (
    <div className="absolute bottom-4 right-4 z-10 bg-surface0/90 backdrop-blur-sm rounded-lg p-3 max-w-xs">
      <h4 className="text-xs font-semibold text-text mb-2">Legend</h4>

      {/* Protocol colors */}
      <div className="mb-3">
        <span className="text-[10px] text-subtext0 uppercase tracking-wide">Connections</span>
        <div className="mt-1 grid grid-cols-2 gap-x-3 gap-y-1">
          {Object.entries(PROTOCOL_COLORS).map(([protocol, style]) => (
            <div key={protocol} className="flex items-center gap-2">
              <div
                className="w-6 h-0.5"
                style={{
                  backgroundColor: style.color,
                  borderStyle: style.lineStyle === 'dotted' ? 'dotted' : 'solid',
                  borderWidth: style.lineStyle === 'dotted' ? '0 0 2px 0' : 0,
                  borderColor: style.color,
                  height: style.lineStyle === 'dotted' ? 0 : 2,
                }}
              />
              <span className="text-[10px] text-subtext1">{style.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Connection states */}
      <div className="mb-3">
        <span className="text-[10px] text-subtext0 uppercase tracking-wide">Link State</span>
        <div className="mt-1 flex flex-wrap gap-2">
          <div className="flex items-center gap-1">
            <div className="w-4 h-0.5 bg-green" />
            <span className="text-[10px] text-subtext1">Active</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-0.5 bg-yellow opacity-60" />
            <span className="text-[10px] text-subtext1">Connecting</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-0.5 bg-peach opacity-80" />
            <span className="text-[10px] text-subtext1">Degraded</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-0.5 bg-red" style={{ borderBottom: '2px dashed #f38ba8', height: 0 }} />
            <span className="text-[10px] text-subtext1">Failed</span>
          </div>
        </div>
      </div>

      {/* Node states */}
      <div className="mb-3">
        <span className="text-[10px] text-subtext0 uppercase tracking-wide">Node State</span>
        <div className="mt-1 flex flex-wrap gap-2">
          {Object.entries(NODE_STATE_COLORS).map(([state, colors]) => (
            <div key={state} className="flex items-center gap-1">
              <div
                className="w-3 h-3 rounded"
                style={{
                  backgroundColor: colors.bg,
                  border: `2px ${state === 'dead' ? 'dashed' : 'solid'} ${colors.border}`,
                }}
              />
              <span className="text-[10px] text-subtext1 capitalize">{state}</span>
            </div>
          ))}
        </div>
      </div>

      {/* OS icons */}
      <div>
        <span className="text-[10px] text-subtext0 uppercase tracking-wide">Operating System</span>
        <div className="mt-1 flex gap-3">
          {Object.entries(OS_ICONS).filter(([os]) => os !== 'unknown').map(([os, icon]) => (
            <div key={os} className="flex items-center gap-1">
              <span className="text-sm">{icon}</span>
              <span className="text-[10px] text-subtext1 capitalize">{os}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Node badges */}
      <div className="mt-3 pt-2 border-t border-surface1">
        <span className="text-[10px] text-subtext0 uppercase tracking-wide">Badges</span>
        <div className="mt-1 flex flex-wrap gap-2">
          <div className="flex items-center gap-1">
            <span className="text-red text-xs">⚡</span>
            <span className="text-[10px] text-subtext1">Elevated</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="px-1 py-0.5 rounded text-[8px] bg-blue text-crust">RELAY</span>
            <span className="text-[10px] text-subtext1">Relay node</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="px-1 py-0.5 rounded text-[8px] bg-green text-crust">EGRESS</span>
            <span className="text-[10px] text-subtext1">Has C2 egress</span>
          </div>
        </div>
      </div>
    </div>
  );
}
