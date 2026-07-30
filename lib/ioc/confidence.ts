/**
 * IOC Confidence Scoring
 * Aggregates component confidence scores (source, observation, analyst, correlation)
 */

import type { Evidence } from '../intelligence/schema';

export interface ConfidenceComponents {
  source_confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  observation_confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  analyst_confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  correlation_confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
}

const confidenceScore: Record<'HIGH' | 'MEDIUM' | 'LOW', number> = {
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const scoreToConfidence = (score: number): 'HIGH' | 'MEDIUM' | 'LOW' => {
  if (score >= 2.5) return 'HIGH';
  if (score >= 1.5) return 'MEDIUM';
  return 'LOW';
};

export function aggregateConfidence(components: ConfidenceComponents): 'HIGH' | 'MEDIUM' | 'LOW' {
  const scores = [
    confidenceScore[components.source_confidence],
    confidenceScore[components.observation_confidence],
  ];

  if (components.analyst_confidence) {
    scores.push(confidenceScore[components.analyst_confidence]);
  }

  if (components.correlation_confidence) {
    scores.push(confidenceScore[components.correlation_confidence]);
  }

  const average = scores.reduce((a, b) => a + b, 0) / scores.length;
  return scoreToConfidence(average);
}

export function scoreEvidence(evidence: Evidence[]): ConfidenceComponents {
  if (evidence.length === 0) {
    return {
      source_confidence: 'LOW',
      observation_confidence: 'LOW',
    };
  }

  const confidences = evidence.map(e => e.confidence);
  const avgConfidence = scoreToConfidence(
    confidences.reduce((sum, c) => sum + confidenceScore[c], 0) / confidences.length
  );

  const attribution = evidence[0].attribution;
  let observationConfidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
  if (attribution === 'observed_fact') {
    observationConfidence = 'HIGH';
  } else if (attribution === 'hypothesis') {
    observationConfidence = 'LOW';
  }

  return {
    source_confidence: avgConfidence,
    observation_confidence: observationConfidence,
  };
}

export function calculateCorrelationConfidence(correlationCount: number): 'HIGH' | 'MEDIUM' | 'LOW' {
  if (correlationCount >= 5) return 'HIGH';
  if (correlationCount >= 2) return 'MEDIUM';
  return 'LOW';
}

export function calculateCompositeScore(components: ConfidenceComponents): {
  aggregate: 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
} {
  const aggregate = aggregateConfidence(components);
  const score =
    (confidenceScore[components.source_confidence] +
      confidenceScore[components.observation_confidence] +
      (components.analyst_confidence ? confidenceScore[components.analyst_confidence] : 0) +
      (components.correlation_confidence ? confidenceScore[components.correlation_confidence] : 0)) /
    (components.analyst_confidence || components.correlation_confidence ? 4 : 2);

  return { aggregate, score };
}

export function formatConfidenceExplanation(components: ConfidenceComponents): string {
  const parts: string[] = [];
  parts.push(`Source confidence: ${components.source_confidence}`);
  parts.push(`Observation confidence: ${components.observation_confidence}`);
  if (components.analyst_confidence) {
    parts.push(`Analyst confidence: ${components.analyst_confidence}`);
  }
  if (components.correlation_confidence) {
    parts.push(`Correlation confidence: ${components.correlation_confidence}`);
  }
  return parts.join(' | ');
}
