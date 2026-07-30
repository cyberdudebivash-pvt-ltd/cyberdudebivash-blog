/**
 * IOC Intelligence Engine - Type Definitions
 * Core interfaces for IOC normalization, validation, correlation
 */

import type { IOCType, Evidence } from '../intelligence/schema';

export type NormalizedIOC = string;

export interface IOCNormalizationResult {
  original: string;
  normalized: NormalizedIOC;
  type: IOCType;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  notes?: string;
}

export interface IOCValidationResult {
  valid: boolean;
  type: IOCType;
  errors: string[];
  warnings: string[];
}

export interface IOCWithMetadata {
  id: string;
  type: IOCType;
  original: string;
  normalized: NormalizedIOC;
  first_observed?: string;
  last_observed?: string;
  source_confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  observation_confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  analyst_confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  aggregate_confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  evidence: Evidence[];
  aliases: string[];
  references: string[];
  notes?: string;
}

export interface IOCRelationship {
  source_ioc_id: string;
  target_ioc_id: string;
  relationship_type: 'related_to' | 'resolves_to' | 'communicates_with' | 'executed_by' | 'hosts' | 'references';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  evidence: Evidence[];
}

export interface IOCCorrelationResult {
  ioc_id: string;
  correlated_malware: string[];
  correlated_campaigns: string[];
  correlated_threat_actors: string[];
  correlated_techniques: string[];
  correlated_reports: string[];
  confidence_score: number;
}

export interface IOCSearchQuery {
  type?: IOCType;
  value?: string;
  normalized?: string;
  confidence_min?: 'HIGH' | 'MEDIUM' | 'LOW';
  first_observed_after?: string;
  last_observed_before?: string;
  tag?: string;
  limit?: number;
  offset?: number;
}

export interface IOCDeduplicationConfig {
  retain_aliases: boolean;
  retain_normalization_history: boolean;
  conflict_resolution: 'first_seen' | 'highest_confidence' | 'most_evidence';
}

export interface NormalizationRule {
  type: IOCType;
  apply: (value: string) => NormalizedIOC;
  reverse?: (normalized: NormalizedIOC) => string;
  description: string;
}

export interface ValidationRule {
  type: IOCType;
  validate: (value: string) => { valid: boolean; errors: string[]; warnings: string[] };
  description: string;
}
