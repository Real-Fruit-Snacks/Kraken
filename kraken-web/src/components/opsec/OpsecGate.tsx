// OpsecGate - Pre-execution confirmation modal
// Shows risk assessment and requires explicit confirmation for high-risk operations

import { useEffect, useCallback } from 'react';
import {
  OpsecAssessment,
  RISK_COLORS,
  LIKELIHOOD_COLORS,
  getRiskLabel,
} from './types';
import { RiskIndicator, RiskMeter } from './RiskIndicator';

interface OpsecGateProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  taskType: string;
  assessment: OpsecAssessment;
  targetInfo?: string;
}

export function OpsecGate({
  isOpen,
  onClose,
  onConfirm,
  taskType,
  assessment,
  targetInfo,
}: OpsecGateProps) {
  const colors = RISK_COLORS[assessment.riskLevel];

  // Handle escape key
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    },
    [onClose]
  );

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [isOpen, handleKeyDown]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-crust/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div
        className={`
          relative w-full max-w-lg mx-4
          bg-base rounded-xl shadow-2xl
          border-2 ${colors.border}
          overflow-hidden
        `}
      >
        {/* Header with risk indicator */}
        <div className={`px-6 py-4 ${colors.bg} border-b ${colors.border}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {/* Warning icon */}
              <div className={`p-2 rounded-lg bg-base/50 ${colors.text}`}>
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
              </div>
              <div>
                <h2 className={`text-lg font-bold ${colors.text}`}>
                  OPSEC Warning
                </h2>
                <p className="text-sm text-subtext0">
                  {getRiskLabel(assessment.riskLevel)} Operation
                </p>
              </div>
            </div>
            <RiskIndicator level={assessment.riskLevel} score={assessment.score} showLabel />
          </div>
        </div>

        {/* Body */}
        <div className="px-6 py-4 space-y-4 max-h-[60vh] overflow-y-auto">
          {/* Task info */}
          <div className="p-3 bg-surface0 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-subtext0 uppercase tracking-wide">Operation</div>
                <div className="font-mono text-text font-medium">{taskType}</div>
              </div>
              {targetInfo && (
                <div className="text-right">
                  <div className="text-xs text-subtext0 uppercase tracking-wide">Target</div>
                  <div className="text-text text-sm">{targetInfo}</div>
                </div>
              )}
            </div>
          </div>

          {/* Risk meter */}
          <div>
            <div className="text-xs text-subtext0 uppercase tracking-wide mb-2">
              Detection Probability
            </div>
            <RiskMeter score={assessment.score} />
          </div>

          {/* Detection vectors */}
          {assessment.detectionVectors.length > 0 && (
            <div>
              <div className="text-xs text-subtext0 uppercase tracking-wide mb-2">
                Detection Vectors
              </div>
              <div className="space-y-2">
                {assessment.detectionVectors.map((vector, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-surface0 rounded-lg border border-surface1"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-text text-sm">
                        {vector.name}
                      </span>
                      <span
                        className={`text-xs font-medium ${LIKELIHOOD_COLORS[vector.likelihood]}`}
                      >
                        {vector.likelihood.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-subtext0">{vector.description}</p>
                    {vector.mitigations && vector.mitigations.length > 0 && (
                      <div className="mt-2 pt-2 border-t border-surface1">
                        <div className="text-xs text-subtext0">
                          Mitigations:{' '}
                          <span className="text-green">
                            {vector.mitigations.join(', ')}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {assessment.recommendations.length > 0 && (
            <div>
              <div className="text-xs text-subtext0 uppercase tracking-wide mb-2">
                Recommendations
              </div>
              <ul className="space-y-1">
                {assessment.recommendations.map((rec, idx) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2 text-sm text-subtext1"
                  >
                    <span className="text-mauve mt-0.5">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </span>
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Critical warning for high-risk operations */}
          {(assessment.riskLevel === 'high' || assessment.riskLevel === 'critical') && (
            <div className={`p-3 rounded-lg ${colors.bg} border ${colors.border}`}>
              <div className="flex items-start gap-2">
                <span className={colors.text}>
                  <svg className="w-5 h-5 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </span>
                <div>
                  <div className={`font-medium ${colors.text}`}>
                    {assessment.riskLevel === 'critical'
                      ? 'This operation has a very high detection probability'
                      : 'This operation may trigger defensive alerts'}
                  </div>
                  <div className="text-sm text-subtext0 mt-1">
                    Proceed only if you have proper authorization and understand the risks.
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-mantle border-t border-surface0 flex items-center justify-between">
          <button
            onClick={onClose}
            className="
              px-4 py-2 rounded-lg text-sm font-medium
              bg-surface0 text-subtext0
              hover:bg-surface1 hover:text-text
              transition-colors
            "
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`
              px-4 py-2 rounded-lg text-sm font-medium
              ${assessment.riskLevel === 'critical'
                ? 'bg-red text-crust hover:bg-red/90'
                : assessment.riskLevel === 'high'
                ? 'bg-peach text-crust hover:bg-peach/90'
                : 'bg-mauve text-crust hover:bg-mauve/90'
              }
              transition-colors
            `}
          >
            {assessment.riskLevel === 'critical'
              ? 'Execute Anyway'
              : assessment.riskLevel === 'high'
              ? 'Proceed with Caution'
              : 'Confirm & Execute'}
          </button>
        </div>
      </div>
    </div>
  );
}
