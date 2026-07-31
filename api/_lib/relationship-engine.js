'use strict';

class RelationshipEngine {
  constructor(redis, intelligenceManager, graphEngine) {
    this.redis = redis;
    this.manager = intelligenceManager;
    this.graph = graphEngine;
  }

  async linkIntelligence(sourceId, targetId, relationType, metadata = {}) {
    const [source, target] = await Promise.all([
      this.manager.getIntelligence(sourceId),
      this.manager.getIntelligence(targetId),
    ]);

    if (!source) throw new Error(`Source intelligence not found: ${sourceId}`);
    if (!target) throw new Error(`Target intelligence not found: ${targetId}`);
    if (source.status !== 'published') throw new Error(`Source not published: ${sourceId}`);
    if (target.status !== 'published') throw new Error(`Target not published: ${targetId}`);

    const existingRel = await this.findExistingRelationship(sourceId, targetId, relationType);
    if (existingRel) {
      throw new Error(`Relationship already exists: ${existingRel.id}`);
    }

    const confidence = await this.calculateRelationshipConfidence(source, target, relationType, metadata);

    const relationship = await this.graph.createRelationship(sourceId, targetId, relationType, {
      confidence,
      evidence: metadata.evidence || [],
      sources: metadata.sources || [],
      analystReviewed: metadata.analystReviewed || false,
      reviewedBy: metadata.reviewedBy,
      reason: metadata.reason || '',
    });

    await this.recordRelationshipAudit('CREATE', relationship, metadata.actor || 'system', metadata.reason);

    return relationship;
  }

  async calculateRelationshipConfidence(source, target, relationType, metadata) {
    let confidence = 0.5;

    const sourceConfidence = this.confidenceToScore(source.confidence);
    confidence += sourceConfidence * 0.4;

    const targetConfidence = this.confidenceToScore(target.confidence);
    confidence += targetConfidence * 0.4;

    const evidenceCount = (metadata.evidence || []).length;
    const evidenceScore = Math.min(evidenceCount / 5, 1.0);
    confidence += evidenceScore * 0.2;

    return Math.min(confidence, 1.0);
  }

  async linkEvidence(relationshipId, evidenceId, evidenceType, analyst, reason) {
    const rel = await this.graph.getRelationship(relationshipId);
    if (!rel) throw new Error(`Relationship not found: ${relationshipId}`);

    const evidence = await this.manager.getIntelligence(evidenceId);
    if (!evidence) throw new Error(`Evidence not found: ${evidenceId}`);

    const evidenceRecord = {
      id: evidenceId,
      type: evidenceType,
      title: evidence.title,
      linkedAt: new Date().toISOString(),
      linkedBy: analyst,
    };

    let evidenceList = rel.evidence || [];
    if (typeof evidenceList === 'string') {
      try {
        evidenceList = JSON.parse(evidenceList);
      } catch {
        evidenceList = [];
      }
    }

    if (evidenceList.some(e => e.id === evidenceId)) {
      throw new Error(`Evidence already linked: ${evidenceId}`);
    }

    evidenceList.push(evidenceRecord);

    const relKey = `graph:relationship:${relationshipId}`;
    await this.redis.hset(relKey, 'evidence', JSON.stringify(evidenceList));

    await this.recordEvidenceAudit(relationshipId, 'LINK_EVIDENCE', evidenceId, analyst, reason);

    return { relationshipId, evidence: evidenceRecord };
  }

  async unlinkEvidence(relationshipId, evidenceId, analyst, reason) {
    const rel = await this.graph.getRelationship(relationshipId);
    if (!rel) throw new Error(`Relationship not found: ${relationshipId}`);

    let evidenceList = rel.evidence || [];
    if (typeof evidenceList === 'string') {
      try {
        evidenceList = JSON.parse(evidenceList);
      } catch {
        evidenceList = [];
      }
    }

    const initial = evidenceList.length;
    evidenceList = evidenceList.filter(e => e.id !== evidenceId);

    if (evidenceList.length === initial) {
      throw new Error(`Evidence not found in relationship: ${evidenceId}`);
    }

    const relKey = `graph:relationship:${relationshipId}`;
    await this.redis.hset(relKey, 'evidence', JSON.stringify(evidenceList));

    await this.recordEvidenceAudit(relationshipId, 'UNLINK_EVIDENCE', evidenceId, analyst, reason);

    return { relationshipId, unlinked: true };
  }

  async reviewRelationship(relationshipId, analyst, approved, notes) {
    const rel = await this.graph.getRelationship(relationshipId);
    if (!rel) throw new Error(`Relationship not found: ${relationshipId}`);

    const relKey = `graph:relationship:${relationshipId}`;
    const now = new Date().toISOString();

    await this.redis.hset(relKey, 'analystReviewed', approved ? 'true' : 'false');
    await this.redis.hset(relKey, 'reviewedBy', analyst);
    await this.redis.hset(relKey, 'reviewedAt', now);
    if (notes) {
      await this.redis.hset(relKey, 'reviewNotes', notes);
    }

    if (approved) {
      const newConfidence = Math.min(rel.confidence * 1.1, 1.0);
      await this.redis.hset(relKey, 'confidence', newConfidence.toString());
    }

    await this.recordRelationshipAudit('REVIEW', rel, analyst, `Approved: ${approved}, Notes: ${notes}`);

    return { relationshipId, reviewed: true, approved };
  }

  async findExistingRelationship(sourceId, targetId, relationType) {
    const outgoing = await this.graph.getOutgoingRelationships(sourceId, 1000);
    return outgoing.find(r => r.target === targetId && r.type === relationType) || null;
  }

  async getRelatedEntities(entityId, limit = 50) {
    const outgoing = await this.graph.getOutgoingRelationships(entityId, limit);
    const related = [];

    for (const rel of outgoing) {
      const target = await this.graph.getEntity(rel.target);
      if (target) {
        related.push({
          entity: target,
          relationship: rel,
        });
      }
    }

    return related;
  }

  async getReferencingEntities(entityId, limit = 50) {
    const incoming = await this.graph.getIncomingRelationships(entityId, limit);
    const referencing = [];

    for (const rel of incoming) {
      const source = await this.graph.getEntity(rel.source);
      if (source) {
        referencing.push({
          entity: source,
          relationship: rel,
        });
      }
    }

    return referencing;
  }

  confidenceToScore(confidenceLevel) {
    const scores = {
      HIGH: 0.9,
      MEDIUM: 0.6,
      LOW: 0.3,
    };
    return scores[confidenceLevel] || 0.5;
  }

  async recordRelationshipAudit(action, relationship, actor, reason) {
    await this.redis.zadd(
      'graph:audit:relationships',
      Date.now(),
      JSON.stringify({
        action,
        relationshipId: relationship.id,
        source: relationship.source,
        target: relationship.target,
        type: relationship.type,
        confidence: relationship.confidence,
        actor,
        reason,
        timestamp: new Date().toISOString(),
      })
    );
  }

  async recordEvidenceAudit(relationshipId, action, evidenceId, actor, reason) {
    await this.redis.zadd(
      'graph:audit:evidence',
      Date.now(),
      JSON.stringify({
        action,
        relationshipId,
        evidenceId,
        actor,
        reason,
        timestamp: new Date().toISOString(),
      })
    );
  }

  async getRelationshipAuditTrail(relationshipId) {
    const allAudits = await this.redis.zrange('graph:audit:relationships', 0, -1);
    const relevant = allAudits
      .map(a => JSON.parse(a))
      .filter(a => a.relationshipId === relationshipId);
    return relevant;
  }
}

module.exports = {
  RelationshipEngine,
};
