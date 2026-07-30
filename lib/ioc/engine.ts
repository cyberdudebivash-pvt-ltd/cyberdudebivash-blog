/**
 * IOC Intelligence Engine
 * Orchestrates normalization, validation, deduplication, correlation
 */

import type { IOCType, Evidence } from '../intelligence/schema';
import type { IOCWithMetadata, IOCSearchQuery, IOCDeduplicationConfig, IOCCorrelationResult } from './types';
import { normalizeIOC } from './normalizers';
import { validateIOC } from './validators';
import { DeduplicationEngine } from './deduplication';
import { CorrelationEngine } from './correlator';
import { aggregateConfidence, scoreEvidence, calculateCompositeScore } from './confidence';
import { RelationshipGraph } from './relationships';

export class IOCIntelligenceEngine {
  private iocs: Map<string, IOCWithMetadata> = new Map();
  private relationshipGraph = new RelationshipGraph();
  private correlationEngine = new CorrelationEngine();
  private deduplicationEngine: DeduplicationEngine;

  constructor(deduplicationConfig?: Partial<IOCDeduplicationConfig>) {
    this.deduplicationEngine = new DeduplicationEngine(deduplicationConfig);
  }

  addIOC(
    iocId: string,
    type: IOCType,
    value: string,
    sourceConfidence: 'HIGH' | 'MEDIUM' | 'LOW',
    evidence: Evidence[],
    options?: {
      aliases?: string[];
      firstObserved?: string;
      lastObserved?: string;
      notes?: string;
    }
  ): IOCWithMetadata {
    // Validate
    const validation = validateIOC(type, value);
    if (!validation.valid) {
      throw new Error(`IOC validation failed: ${validation.errors.join(', ')}`);
    }

    // Normalize
    const normalized = normalizeIOC(type, value);

    // Score confidence
    const evidenceConfidence = scoreEvidence(evidence);
    const components = {
      source_confidence: sourceConfidence,
      ...evidenceConfidence,
    };
    const aggregated = aggregateConfidence(components);

    const ioc: IOCWithMetadata = {
      id: iocId,
      type,
      original: value,
      normalized,
      first_observed: options?.firstObserved,
      last_observed: options?.lastObserved,
      source_confidence: sourceConfidence,
      observation_confidence: evidenceConfidence.observation_confidence,
      aggregate_confidence: aggregated,
      evidence,
      aliases: options?.aliases || [],
      references: [],
      notes: options?.notes,
    };

    this.iocs.set(iocId, ioc);
    return ioc;
  }

  getIOC(iocId: string): IOCWithMetadata | undefined {
    return this.iocs.get(iocId);
  }

  search(query: IOCSearchQuery): IOCWithMetadata[] {
    let results = Array.from(this.iocs.values());

    if (query.type) {
      results = results.filter(ioc => ioc.type === query.type);
    }

    if (query.value) {
      results = results.filter(ioc => ioc.original === query.value);
    }

    if (query.normalized) {
      results = results.filter(ioc => ioc.normalized === query.normalized);
    }

    if (query.confidence_min) {
      const confidenceScore = { HIGH: 3, MEDIUM: 2, LOW: 1 };
      const minScore = confidenceScore[query.confidence_min];
      results = results.filter(ioc => confidenceScore[ioc.aggregate_confidence] >= minScore);
    }

    if (query.first_observed_after) {
      const afterDate = new Date(query.first_observed_after);
      results = results.filter(ioc => !ioc.first_observed || new Date(ioc.first_observed) >= afterDate);
    }

    if (query.last_observed_before) {
      const beforeDate = new Date(query.last_observed_before);
      results = results.filter(ioc => !ioc.last_observed || new Date(ioc.last_observed) <= beforeDate);
    }

    // Pagination
    const offset = query.offset || 0;
    const limit = query.limit || 100;
    return results.slice(offset, offset + limit);
  }

  deduplicate(iocs?: IOCWithMetadata[]) {
    const iocList = iocs || Array.from(this.iocs.values());
    return this.deduplicationEngine.deduplicate(iocList);
  }

  correlate(iocId: string): IOCCorrelationResult {
    const ioc = this.iocs.get(iocId);
    if (!ioc) throw new Error(`IOC not found: ${iocId}`);
    return this.correlationEngine.correlate(ioc.normalized, ioc.type);
  }

  addRelationship(
    sourceId: string,
    targetId: string,
    relationshipType: 'related_to' | 'resolves_to' | 'communicates_with' | 'executed_by' | 'hosts' | 'references',
    confidence: 'HIGH' | 'MEDIUM' | 'LOW',
    evidence: Evidence[]
  ): void {
    this.relationshipGraph.addRelationship(sourceId, targetId, relationshipType, confidence, evidence);
  }

  getRelationships(iocId: string) {
    return this.relationshipGraph.getRelated(iocId);
  }

  getConnectedIOCs(iocId: string): IOCWithMetadata[] {
    const connectedIds = this.relationshipGraph.getConnectedComponent(iocId);
    return connectedIds
      .map(id => this.iocs.get(id))
      .filter((ioc): ioc is IOCWithMetadata => ioc !== undefined);
  }

  stats(): {
    total_iocs: number;
    by_type: Record<IOCType, number>;
    high_confidence: number;
    relationships: number;
    unique_normalized_forms: number;
  } {
    const byType = {} as Record<IOCType, number>;
    const normalizedForms = new Set<string>();
    let highConfidence = 0;

    for (const ioc of this.iocs.values()) {
      byType[ioc.type] = (byType[ioc.type] || 0) + 1;
      normalizedForms.add(ioc.normalized);
      if (ioc.aggregate_confidence === 'HIGH') highConfidence++;
    }

    return {
      total_iocs: this.iocs.size,
      by_type: byType,
      high_confidence: highConfidence,
      relationships: Array.from(this.iocs.values()).flatMap(ioc => this.relationshipGraph.getRelated(ioc.id)).length,
      unique_normalized_forms: normalizedForms.size,
    };
  }

  export(): {
    iocs: IOCWithMetadata[];
    stats: ReturnType<typeof this.stats>;
  } {
    return {
      iocs: Array.from(this.iocs.values()),
      stats: this.stats(),
    };
  }
}

export function createIOCEngine(config?: Partial<IOCDeduplicationConfig>): IOCIntelligenceEngine {
  return new IOCIntelligenceEngine(config);
}
