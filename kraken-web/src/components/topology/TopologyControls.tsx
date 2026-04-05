// Topology graph controls - layout, zoom, export

import { useReactFlow } from '@xyflow/react';
import { toPng, toSvg } from 'html-to-image';
import type { LayoutDirection } from './types';

interface TopologyControlsProps {
  direction: LayoutDirection;
  onDirectionChange: (direction: LayoutDirection) => void;
}

export function TopologyControls({ direction, onDirectionChange }: TopologyControlsProps) {
  const { fitView, zoomIn, zoomOut, getNodes } = useReactFlow();

  const handleExportPng = async () => {
    const element = document.querySelector('.react-flow') as HTMLElement;
    if (!element) return;

    try {
      const dataUrl = await toPng(element, {
        backgroundColor: '#1e1e2e', // Catppuccin base
        quality: 1,
        pixelRatio: 2,
      });

      const link = document.createElement('a');
      link.download = `kraken-topology-${new Date().toISOString().slice(0, 10)}.png`;
      link.href = dataUrl;
      link.click();
    } catch (err) {
      console.error('Failed to export PNG:', err);
    }
  };

  const handleExportSvg = async () => {
    const element = document.querySelector('.react-flow') as HTMLElement;
    if (!element) return;

    try {
      const dataUrl = await toSvg(element, {
        backgroundColor: '#1e1e2e',
      });

      const link = document.createElement('a');
      link.download = `kraken-topology-${new Date().toISOString().slice(0, 10)}.svg`;
      link.href = dataUrl;
      link.click();
    } catch (err) {
      console.error('Failed to export SVG:', err);
    }
  };

  const nodeCount = getNodes().length;

  return (
    <div className="absolute top-4 left-4 z-10 flex flex-col gap-2">
      {/* Layout direction */}
      <div className="bg-surface0/90 backdrop-blur-sm rounded-lg p-2 flex flex-col gap-1">
        <span className="text-xs text-subtext0 px-1">Layout</span>
        <div className="flex gap-1">
          {(['LR', 'TB', 'RL', 'BT'] as LayoutDirection[]).map((dir) => (
            <button
              key={dir}
              onClick={() => onDirectionChange(dir)}
              className={`
                px-2 py-1 rounded text-xs font-medium transition-colors
                ${direction === dir
                  ? 'bg-mauve text-crust'
                  : 'bg-surface1 text-subtext1 hover:bg-surface2'}
              `}
              title={getDirectionLabel(dir)}
            >
              {getDirectionIcon(dir)}
            </button>
          ))}
        </div>
      </div>

      {/* Zoom controls */}
      <div className="bg-surface0/90 backdrop-blur-sm rounded-lg p-2 flex flex-col gap-1">
        <span className="text-xs text-subtext0 px-1">Zoom</span>
        <div className="flex gap-1">
          <button
            onClick={() => zoomIn()}
            className="px-3 py-1 rounded text-sm bg-surface1 text-subtext1 hover:bg-surface2 transition-colors"
            title="Zoom in"
          >
            +
          </button>
          <button
            onClick={() => zoomOut()}
            className="px-3 py-1 rounded text-sm bg-surface1 text-subtext1 hover:bg-surface2 transition-colors"
            title="Zoom out"
          >
            −
          </button>
          <button
            onClick={() => fitView({ padding: 0.2 })}
            className="px-2 py-1 rounded text-xs bg-surface1 text-subtext1 hover:bg-surface2 transition-colors"
            title="Fit view"
          >
            Fit
          </button>
        </div>
      </div>

      {/* Export */}
      <div className="bg-surface0/90 backdrop-blur-sm rounded-lg p-2 flex flex-col gap-1">
        <span className="text-xs text-subtext0 px-1">Export</span>
        <div className="flex gap-1">
          <button
            onClick={handleExportPng}
            className="px-2 py-1 rounded text-xs bg-surface1 text-subtext1 hover:bg-surface2 transition-colors"
            title="Export as PNG"
          >
            PNG
          </button>
          <button
            onClick={handleExportSvg}
            className="px-2 py-1 rounded text-xs bg-surface1 text-subtext1 hover:bg-surface2 transition-colors"
            title="Export as SVG"
          >
            SVG
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="bg-surface0/90 backdrop-blur-sm rounded-lg px-3 py-2">
        <span className="text-xs text-subtext0">
          {nodeCount} node{nodeCount !== 1 ? 's' : ''}
        </span>
      </div>
    </div>
  );
}

function getDirectionIcon(dir: LayoutDirection): string {
  switch (dir) {
    case 'LR': return '→';
    case 'RL': return '←';
    case 'TB': return '↓';
    case 'BT': return '↑';
  }
}

function getDirectionLabel(dir: LayoutDirection): string {
  switch (dir) {
    case 'LR': return 'Left to Right (pivot chains)';
    case 'RL': return 'Right to Left';
    case 'TB': return 'Top to Bottom (mesh)';
    case 'BT': return 'Bottom to Top';
  }
}
