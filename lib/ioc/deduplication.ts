/**
 * IOC Deduplication Engine
 * Deterministic deduplication based on canonical forms
 */

import type { IOCType } from '../intelligence/schema';
import type { IOCWithMetadata, IOCDeduplicationConfig } from './types';

export interface DeduplicationResult {
  canonical_id: string;
  merged_iocs: string[];
  aliases: string[];
  original_count: number;
  deduplicated_count: number;
  evidence_consolidated: number;
}

export class DeduplicationEngine {
  private config: IOCDeduplicationConfig = {
    retain_aliases: true,
    retain_normalization_history: true,
    conflict_resolution: 'highest_confidence',
  };

  constructor(config?: Partial<IOCDeduplicationConfig>) {
    if (config) {
      this.config = { ...this.config, ...config };
    }
  }

  deduplicate(iocs: IOCWithMetadata[]): DeduplicationResult[] {
    const groups = this.groupByCanonical(iocs);
    const results: DeduplicationResult[] = [];

    for (const [canonicalForm, group] of Object.entries(groups)) {
      if (group.length === 1) continue; // No deduplication needed

      const canonical = this.selectCanonical(group);
      const aliases = this.extractAliases(group, canonical.id);
      const mergedEvidence = this.consolidateEvidence(group);

      results.push({
        canonical_id: canonical.id,
        merged_iocs: group.map(ioc => ioc.id),
        aliases,
        original_count: group.length,
        deduplicated_count: 1,
        evidence_consolidated: mergedEvidence.length,
      });
    }

    return results;
  }

  private groupByCanonical(iocs: IOCWithMetadata[]): Record<string, IOCWithMetadata[]> {
    return iocs.reduce(
      (groups, ioc) => {
        const key = ioc.normalized;
        if (!groups[key]) groups[key] = [];
        groups[key].push(ioc);
        return groups;
      },
      {} as Record<string, IOCWithMetadata[]>
    );
  }

  private selectCanonical(group: IOCWithMetadata[]): IOCWithMetadata {
    switch (this.config.conflict_resolution) {
      case 'first_seen':
        return group.reduce((earliest, ioc) => {
          if (!ioc.first_observed || !earliest.first_observed) return earliest;
          return new Date(ioc.first_observed) < new Date(earliest.first_observed) ? ioc : earliest;
        });

      case 'highest_confidence':
        const confidenceValue = { HIGH: 3, MEDIUM: 2, LOW: 1 };
        return group.reduce((highest, ioc) => {
          const highestScore = confidenceValue[highest.aggregate_confidence];
          const currentScore = confidenceValue[ioc.aggregate_confidence];
          return currentScore > highestScore ? ioc : highest;
        });

      case 'most_evidence':
        return group.reduce((most, ioc) => (ioc.evidence.length > most.evidence.length ? ioc : most));

      default:
        return group[0];
    }
  }

  private extractAliases(group: IOCWithMetadata[], canonicalId: string): string[] {
    return group
      .filter(ioc => ioc.id !== canonicalId)
      .map(ioc => ioc.original)
      .concat(...group.map(ioc => ioc.aliases))
      .filter((v, i, a) => a.indexOf(v) === i);
  }

  private consolidateEvidence(group: IOCWithMetadata[]) {
    const evidenceMap = new Map();
    for (const ioc of group) {
      for (const evidence of ioc.evidence) {
        const key = `${evidence.source}-${evidence.date}`;
        if (!evidenceMap.has(key)) {
          evidenceMap.set(key, evidence);
        }
      }
    }
    return Array.from(evidenceMap.values());
  }
}

export function deduplicate(iocs: IOCWithMetadata[], config?: Partial<IOCDeduplicationConfig>): DeduplicationResult[] {
  const engine = new DeduplicationEngine(config);
  return engine.deduplicate(iocs);
}
