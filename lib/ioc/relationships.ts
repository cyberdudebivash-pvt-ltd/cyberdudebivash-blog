/**
 * IOC Relationship Management
 * Maps relationships between IOCs and other intelligence entities
 */

import type { IOCRelationship } from './types';
import type { Evidence } from '../intelligence/schema';

export class RelationshipGraph {
  private relationships: Map<string, IOCRelationship[]> = new Map();
  private reverseIndex: Map<string, IOCRelationship[]> = new Map();

  addRelationship(
    sourceId: string,
    targetId: string,
    relationshipType: IOCRelationship['relationship_type'],
    confidence: 'HIGH' | 'MEDIUM' | 'LOW',
    evidence: Evidence[]
  ): void {
    const relationship: IOCRelationship = {
      source_ioc_id: sourceId,
      target_ioc_id: targetId,
      relationship_type: relationshipType,
      confidence,
      evidence,
    };

    if (!this.relationships.has(sourceId)) {
      this.relationships.set(sourceId, []);
    }
    this.relationships.get(sourceId)!.push(relationship);

    if (!this.reverseIndex.has(targetId)) {
      this.reverseIndex.set(targetId, []);
    }
    this.reverseIndex.get(targetId)!.push(relationship);
  }

  getOutgoing(iocId: string): IOCRelationship[] {
    return this.relationships.get(iocId) || [];
  }

  getIncoming(iocId: string): IOCRelationship[] {
    return this.reverseIndex.get(iocId) || [];
  }

  getRelated(iocId: string): IOCRelationship[] {
    return [...(this.relationships.get(iocId) || []), ...(this.reverseIndex.get(iocId) || [])];
  }

  findPath(startId: string, endId: string, maxDepth: number = 3): IOCRelationship[][] {
    const paths: IOCRelationship[][] = [];
    const visited = new Set<string>();

    const dfs = (currentId: string, path: IOCRelationship[], depth: number) => {
      if (depth > maxDepth || visited.has(currentId)) return;
      visited.add(currentId);

      if (currentId === endId && path.length > 0) {
        paths.push([...path]);
        visited.delete(currentId);
        return;
      }

      for (const rel of this.getOutgoing(currentId)) {
        dfs(rel.target_ioc_id, [...path, rel], depth + 1);
      }

      visited.delete(currentId);
    };

    dfs(startId, [], 0);
    return paths;
  }

  getConnectedComponent(iocId: string): string[] {
    const component = new Set<string>();
    const queue = [iocId];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (component.has(current)) continue;
      component.add(current);

      const outgoing = this.getOutgoing(current).map(r => r.target_ioc_id);
      const incoming = this.getIncoming(current).map(r => r.source_ioc_id);

      for (const neighbor of [...outgoing, ...incoming]) {
        if (!component.has(neighbor)) {
          queue.push(neighbor);
        }
      }
    }

    return Array.from(component);
  }
}

export function createEntityRelationship(
  iocId: string,
  entityType: 'malware' | 'campaign' | 'threat_actor' | 'technique' | 'report',
  entityId: string,
  confidence: 'HIGH' | 'MEDIUM' | 'LOW',
  evidence: Evidence[]
): {
  ioc_id: string;
  entity_type: string;
  entity_id: string;
  confidence: string;
  evidence: Evidence[];
} {
  return {
    ioc_id: iocId,
    entity_type: entityType,
    entity_id: entityId,
    confidence,
    evidence,
  };
}

export function deduplicateRelationships(relationships: IOCRelationship[]): IOCRelationship[] {
  const seen = new Set<string>();
  const deduplicated: IOCRelationship[] = [];

  for (const rel of relationships) {
    const key = `${rel.source_ioc_id}:${rel.target_ioc_id}:${rel.relationship_type}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(rel);
    }
  }

  return deduplicated;
}
