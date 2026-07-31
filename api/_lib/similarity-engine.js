'use strict';

class SimilarityEngine {
  constructor(graphEngine) {
    this.graph = graphEngine;
  }

  async findSimilarEntities(entityId, threshold = 0.7, limit = 20) {
    const entity = await this.graph.getEntity(entityId);
    if (!entity) throw new Error(`Entity not found: ${entityId}`);

    const candidates = await this.graph.getEntitiesByType(entity.type, 100);

    const similarities = [];

    for (const candidate of candidates) {
      if (candidate.id === entityId) continue;

      const similarity = await this.calculateSimilarity(entity, candidate);

      if (similarity >= threshold) {
        similarities.push({
          entity: candidate,
          score: similarity,
        });
      }
    }

    return similarities.sort((a, b) => b.score - a.score).slice(0, limit);
  }

  async calculateSimilarity(entity1, entity2) {
    let score = 0;

    if (entity1.type === entity2.type) {
      score += 0.2;
    }

    const nameSim = this.levenshteinSimilarity(entity1.name, entity2.name);
    score += nameSim * 0.3;

    const prop1 = entity1.properties || {};
    const prop2 = entity2.properties || {};
    const propOverlap = this.calculatePropertyOverlap(prop1, prop2);
    score += propOverlap * 0.3;

    const confSim = 1 - Math.abs(
      this.confidenceToScore(entity1.confidence) - this.confidenceToScore(entity2.confidence)
    );
    score += confSim * 0.2;

    return Math.min(Math.max(score, 0), 1);
  }

  async findIOCMatches(iocId) {
    const ioc = await this.graph.getEntity(iocId);
    if (!ioc) throw new Error(`IOC not found: ${iocId}`);

    const matches = {
      exact: [],
      related: [],
    };

    const related = await this.graph.getOutgoingRelationships(iocId, 100);

    for (const rel of related) {
      const target = await this.graph.getEntity(rel.target);
      if (target && ['domain', 'ip_address', 'url', 'file_hash'].includes(target.type)) {
        matches.related.push({
          entity: target,
          relationship: rel.type,
          confidence: rel.confidence,
        });
      }
    }

    const incoming = await this.graph.getIncomingRelationships(iocId, 100);

    for (const rel of incoming) {
      const source = await this.graph.getEntity(rel.source);
      if (source && ['domain', 'ip_address', 'url', 'file_hash'].includes(source.type)) {
        matches.related.push({
          entity: source,
          relationship: rel.type,
          confidence: rel.confidence,
        });
      }
    }

    return matches;
  }

  async detectDuplicates(minSimilarity = 0.9) {
    const allEntities = await this.graph.redis.smembers('graph:entities:all');
    const duplicates = [];
    const processed = new Set();

    for (let i = 0; i < allEntities.length; i++) {
      const entity1Id = allEntities[i];
      if (processed.has(entity1Id)) continue;

      const entity1 = await this.graph.getEntity(entity1Id);

      for (let j = i + 1; j < allEntities.length; j++) {
        const entity2Id = allEntities[j];
        if (processed.has(entity2Id)) continue;

        const entity2 = await this.graph.getEntity(entity2Id);

        const similarity = await this.calculateSimilarity(entity1, entity2);

        if (similarity >= minSimilarity) {
          duplicates.push({
            entity1: entity1Id,
            entity2: entity2Id,
            similarity,
          });
          processed.add(entity2Id);
        }
      }
    }

    return duplicates;
  }

  async mergeDuplicates(keepEntityId, mergeEntityId, analyst, reason) {
    const [keep, merge] = await Promise.all([
      this.graph.getEntity(keepEntityId),
      this.graph.getEntity(mergeEntityId),
    ]);

    if (!keep || !merge) throw new Error('One or both entities not found');

    const [outgoing, incoming] = await Promise.all([
      this.graph.getOutgoingRelationships(mergeEntityId, 1000),
      this.graph.getIncomingRelationships(mergeEntityId, 1000),
    ]);

    for (const rel of outgoing) {
      await this.graph.createRelationship(keepEntityId, rel.target, rel.type, {
        confidence: rel.confidence,
        evidence: rel.evidence,
        sources: rel.sources,
        reason: `Merged from ${mergeEntityId}`,
      });
    }

    for (const rel of incoming) {
      await this.graph.createRelationship(rel.source, keepEntityId, rel.type, {
        confidence: rel.confidence,
        evidence: rel.evidence,
        sources: rel.sources,
        reason: `Merged from ${mergeEntityId}`,
      });
    }

    const mergeKey = `graph:entity:${mergeEntityId}`;
    await this.graph.redis.hset(mergeKey, 'supersededBy', keepEntityId);
    await this.graph.redis.hset(mergeKey, 'supersededAt', new Date().toISOString());

    await this.graph.redis.zadd(
      'graph:audit:merges',
      Date.now(),
      JSON.stringify({
        action: 'MERGE_DUPLICATES',
        keep: keepEntityId,
        merge: mergeEntityId,
        relationshipsRedirected: outgoing.length + incoming.length,
        analyst,
        reason,
        timestamp: new Date().toISOString(),
      })
    );

    return {
      merged: true,
      keepEntity: keepEntityId,
      mergeEntity: mergeEntityId,
      relationshipsRedirected: outgoing.length + incoming.length,
    };
  }

  levenshteinSimilarity(str1, str2) {
    const s1 = str1.toLowerCase();
    const s2 = str2.toLowerCase();
    const len = Math.max(s1.length, s2.length);

    if (len === 0) return 1.0;

    const distance = this.levenshteinDistance(s1, s2);
    return 1 - distance / len;
  }

  levenshteinDistance(s1, s2) {
    const m = s1.length;
    const n = s2.length;
    const dp = Array(m + 1).fill(0).map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (s1[i - 1] === s2[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
        }
      }
    }

    return dp[m][n];
  }

  calculatePropertyOverlap(props1, props2) {
    if (!props1 || !props2) return 0;

    const keys1 = Object.keys(props1);
    const keys2 = Object.keys(props2);
    const common = keys1.filter(k => keys2.includes(k) && props1[k] === props2[k]);

    const union = new Set([...keys1, ...keys2]).size;

    return union === 0 ? 0 : common.length / union;
  }

  confidenceToScore(level) {
    const scores = { HIGH: 0.9, MEDIUM: 0.6, LOW: 0.3 };
    return scores[level] || 0.5;
  }
}

module.exports = {
  SimilarityEngine,
};
