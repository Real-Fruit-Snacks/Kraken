// RiskIndicator - Visual risk level badge with tooltip
// Shows operation risk at a glance

import { useState } from 'react';
import { RiskLevel, RISK_COLORS, getRiskLabel } from './types';

// Risk level icons
const RiskIcons: Record<RiskLevel, React.ReactNode> = {
  low: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  medium: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  ),
  high: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  critical: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  ),
};

interface RiskIndicatorProps {
  level: RiskLevel;
  score?: number;
  showLabel?: boolean;
  showTooltip?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function RiskIndicator({
  level,
  score,
  showLabel = false,
  showTooltip = true,
  size = 'md',
  className = '',
}: RiskIndicatorProps) {
  const [tooltipVisible, setTooltipVisible] = useState(false);
  const colors = RISK_COLORS[level];
  const label = getRiskLabel(level);

  const sizeClasses = {
    sm: 'px-1.5 py-0.5 text-xs gap-1',
    md: 'px-2 py-1 text-sm gap-1.5',
    lg: 'px-3 py-1.5 text-base gap-2',
  };

  return (
    <div className={`relative inline-flex ${className}`}>
      <div
        className={`
          inline-flex items-center rounded-full font-medium
          ${colors.bg} ${colors.text} ${colors.border} border
          ${sizeClasses[size]}
          cursor-default
        `}
        onMouseEnter={() => setTooltipVisible(true)}
        onMouseLeave={() => setTooltipVisible(false)}
      >
        <span className={colors.icon}>{RiskIcons[level]}</span>
        {showLabel && <span>{label}</span>}
        {score !== undefined && (
          <span className="font-mono">{score}</span>
        )}
      </div>

      {/* Tooltip */}
      {showTooltip && tooltipVisible && (
        <div
          className="
            absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-50
            px-3 py-2 rounded-lg shadow-lg
            bg-mantle border border-surface0
            text-sm text-text whitespace-nowrap
          "
        >
          <div className="font-medium">{label}</div>
          {score !== undefined && (
            <div className="text-subtext0 text-xs">Risk Score: {score}/100</div>
          )}
          {/* Tooltip arrow */}
          <div
            className="
              absolute top-full left-1/2 -translate-x-1/2
              border-4 border-transparent border-t-mantle
            "
          />
        </div>
      )}
    </div>
  );
}

// Compact inline version for tables
interface RiskBadgeProps {
  level: RiskLevel;
  className?: string;
}

export function RiskBadge({ level, className = '' }: RiskBadgeProps) {
  const colors = RISK_COLORS[level];

  return (
    <span
      className={`
        inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium
        ${colors.bg} ${colors.text}
        ${className}
      `}
    >
      {RiskIcons[level]}
      {level.toUpperCase()}
    </span>
  );
}

// Risk meter visualization
interface RiskMeterProps {
  score: number;
  showLabel?: boolean;
  className?: string;
}

export function RiskMeter({ score, showLabel = true, className = '' }: RiskMeterProps) {
  // Determine color based on score
  let colorClass = 'bg-green';
  if (score >= 70) colorClass = 'bg-red';
  else if (score >= 50) colorClass = 'bg-peach';
  else if (score >= 30) colorClass = 'bg-yellow';

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="flex-1 h-2 bg-surface0 rounded-full overflow-hidden">
        <div
          className={`h-full ${colorClass} transition-all duration-300`}
          style={{ width: `${score}%` }}
        />
      </div>
      {showLabel && (
        <span className="text-xs text-subtext0 font-mono w-8">{score}</span>
      )}
    </div>
  );
}
