export {
  type RiskLevel,
  type DetectionVector,
  type OpsecAssessment,
  type TaskRiskProfile,
  type InjectionTechnique,
  type InjectionTechniqueProfile,
  RISK_COLORS,
  LIKELIHOOD_COLORS,
  TASK_RISK_PROFILES,
  INJECTION_TECHNIQUE_PROFILES,
  calculateRiskScore,
  assessTaskRisk,
  assessInjectionTechnique,
  getRecommendedTechnique,
  getRiskLabel,
} from './types';

export { RiskIndicator, RiskBadge, RiskMeter } from './RiskIndicator';
export { OpsecGate } from './OpsecGate';
