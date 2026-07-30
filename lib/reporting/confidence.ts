/**
 * Confidence Scoring & Propagation
 * Manages confidence levels across evidence and generates composite scores
 */

import type { ConfidenceLevel, Evidence } from '../intelligence/schema';

export type ConfidenceScore = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

const confidenceWeights: Record<ConfidenceLevel, number> = {
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

export function aggregateConfidence(confidences: ConfidenceLevel[]): ConfidenceLevel {
  if (confidences.length === 0) return 'LOW';
  const avgWeight = confidences.reduce((sum, c) => sum + confidenceWeights[c], 0) / confidences.length;
  if (avgWeight >= 2.5) return 'HIGH';
  if (avgWeight >= 1.5) return 'MEDIUM';
  return 'LOW';
}

export function confidenceToSeverity(confidence: ConfidenceLevel): ConfidenceScore {
  return confidence === 'HIGH' ? 'CRITICAL' : confidence === 'MEDIUM' ? 'HIGH' : 'MEDIUM';
}

export function evidenceHasConfidence(evidence: Evidence): boolean {
  return !!evidence.confidence && evidence.confidence !== 'LOW';
}

export function formatConfidenceLevel(confidence: ConfidenceLevel): string {
  const labels: Record<ConfidenceLevel, string> = {
    HIGH: 'High Confidence',
    MEDIUM: 'Medium Confidence',
    LOW: 'Low Confidence',
  };
  return labels[confidence];
}

export function attributionLabel(attribution: string): string {
  const labels: Record<string, string> = {
    observed_fact: 'Observed Fact',
    analyst_assessment: 'Analyst Assessment',
    hypothesis: 'Hypothesis',
  };
  return labels[attribution] || attribution;
}
