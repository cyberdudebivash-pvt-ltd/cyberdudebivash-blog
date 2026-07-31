'use strict';

const crypto = require('crypto');

const EVIDENCE_TYPES = {
  ARTICLE: 'article',
  THREAT_REPORT: 'threat_report',
  IOC: 'ioc',
  MALWARE: 'malware',
  FILE: 'file',
  HASH: 'hash',
  PCAP: 'pcap',
  URL: 'url',
  DOMAIN: 'domain',
  SCREENSHOT: 'screenshot',
  EXTERNAL_REFERENCE: 'external_reference',
  DETECTION_RULE: 'detection_rule',
  NOTE: 'note',
};

class EvidenceManager {
  constructor(redis, investigationManager, graphEngine) {
    this.redis = redis;
    this.investigationManager = investigationManager;
    this.graph = graphEngine;
  }

  async addEvidence(investigationId, evidenceType, title, content, metadata = {}) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    if (!EVIDENCE_TYPES[evidenceType]) {
      throw new Error(`Invalid evidence type: ${evidenceType}`);
    }

    const evidenceId = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();

    const evidence = {
      id: evidenceId,
      investigationId,
      type: evidenceType,
      title,
      content,
      metadata: JSON.stringify(metadata),
      sourceUrl: metadata.sourceUrl || null,
      linkedGraphEntities: JSON.stringify(metadata.linkedEntities || []),
      confidence: metadata.confidence || 'MEDIUM',
      createdAt: now,
      createdBy: metadata.createdBy || 'analyst',
      updatedAt: now,
      version: 1,
      tags: JSON.stringify(metadata.tags || []),
    };

    const evidKey = `evidence:${evidenceId}`;
    await this.redis.hset(evidKey, Object.entries(evidence).flat());
    await this.redis.expire(evidKey, 31536000);

    // Index evidence
    await this.redis.zadd(`investigation:evidence:${investigationId}`, Date.now(), evidenceId);
    await this.redis.zadd(`evidence:by:type:${evidenceType}`, Date.now(), evidenceId);
    await this.redis.zadd('evidence:all', Date.now(), evidenceId);

    // Increment evidence count
    await this.redis.hincrby(`investigation:${investigationId}`, 'evidenceCount', 1);

    // Record in timeline
    await this.recordEvidenceEvent(investigationId, 'EVIDENCE_ADDED', evidenceId, {
      type: evidenceType,
      title,
    });

    return evidence;
  }

  async getEvidence(evidenceId) {
    const evidKey = `evidence:${evidenceId}`;
    const data = await this.redis.hgetall(evidKey);

    if (!data || data.length === 0) {
      return null;
    }

    const evidence = {};
    for (let i = 0; i < data.length; i += 2) {
      evidence[data[i]] = data[i + 1];
    }

    if (evidence.metadata) {
      try {
        evidence.metadata = JSON.parse(evidence.metadata);
      } catch {
        evidence.metadata = {};
      }
    }

    if (evidence.linkedGraphEntities) {
      try {
        evidence.linkedGraphEntities = JSON.parse(evidence.linkedGraphEntities);
      } catch {
        evidence.linkedGraphEntities = [];
      }
    }

    if (evidence.tags) {
      try {
        evidence.tags = JSON.parse(evidence.tags);
      } catch {
        evidence.tags = [];
      }
    }

    evidence.version = parseInt(evidence.version);

    return evidence;
  }

  async getInvestigationEvidence(investigationId, limit = 100) {
    const evidenceIds = await this.redis.zrevrange(
      `investigation:evidence:${investigationId}`,
      0,
      limit - 1
    );

    const evidence = [];
    for (const id of evidenceIds) {
      const evid = await this.getEvidence(id);
      if (evid) evidence.push(evid);
    }

    return evidence;
  }

  async linkGraphEntity(evidenceId, entityId) {
    const evidence = await this.getEvidence(evidenceId);
    if (!evidence) throw new Error(`Evidence not found: ${evidenceId}`);

    const entity = await this.graph.getEntity(entityId);
    if (!entity) throw new Error(`Entity not found: ${entityId}`);

    let linkedEntities = evidence.linkedGraphEntities || [];
    if (typeof linkedEntities === 'string') {
      try {
        linkedEntities = JSON.parse(linkedEntities);
      } catch {
        linkedEntities = [];
      }
    }

    if (linkedEntities.some(e => e === entityId)) {
      throw new Error(`Entity already linked: ${entityId}`);
    }

    linkedEntities.push(entityId);

    const evidKey = `evidence:${evidenceId}`;
    await this.redis.hset(evidKey, 'linkedGraphEntities', JSON.stringify(linkedEntities));
    await this.redis.zadd(`evidence:graph:entities:${evidenceId}`, Date.now(), entityId);

    return { linked: true, entityId };
  }

  async updateConfidence(evidenceId, confidenceLevel) {
    const evidence = await this.getEvidence(evidenceId);
    if (!evidence) throw new Error(`Evidence not found: ${evidenceId}`);

    const evidKey = `evidence:${evidenceId}`;
    await this.redis.hset(evidKey, 'confidence', confidenceLevel);
    await this.redis.hset(evidKey, 'updatedAt', new Date().toISOString());

    return { evidenceId, confidence: confidenceLevel };
  }

  async tagEvidence(evidenceId, tags) {
    const evidence = await this.getEvidence(evidenceId);
    if (!evidence) throw new Error(`Evidence not found: ${evidenceId}`);

    let existingTags = evidence.tags || [];
    if (typeof existingTags === 'string') {
      try {
        existingTags = JSON.parse(existingTags);
      } catch {
        existingTags = [];
      }
    }

    const allTags = [...new Set([...existingTags, ...tags])];

    const evidKey = `evidence:${evidenceId}`;
    await this.redis.hset(evidKey, 'tags', JSON.stringify(allTags));

    // Index tags
    for (const tag of tags) {
      await this.redis.sadd(`evidence:tags:${tag}`, evidenceId);
    }

    return { evidenceId, tags: allTags };
  }

  async getEvidenceByTag(tag, limit = 50) {
    const evidenceIds = await this.redis.smembers(`evidence:tags:${tag}`);
    const evidence = [];

    for (const id of evidenceIds.slice(0, limit)) {
      const evid = await this.getEvidence(id);
      if (evid) evidence.push(evid);
    }

    return evidence;
  }

  async getMITREMappings(investigationId) {
    const evidence = await this.getInvestigationEvidence(investigationId);
    const techniques = new Set();

    for (const evid of evidence) {
      if (evid.metadata && evid.metadata.mitreTechniques) {
        for (const tech of evid.metadata.mitreTechniques) {
          techniques.add(tech);
        }
      }
    }

    return Array.from(techniques);
  }

  async recordEvidenceEvent(investigationId, action, evidenceId, metadata) {
    await this.redis.zadd(
      `investigation:timeline:${investigationId}`,
      Date.now(),
      JSON.stringify({
        action,
        evidenceId,
        metadata,
        timestamp: new Date().toISOString(),
      })
    );
  }

  async getEvidenceTimeline(investigationId, limit = 100) {
    const events = await this.redis.zrevrange(
      `investigation:timeline:${investigationId}`,
      0,
      limit - 1
    );

    return events.map(e => {
      try {
        return JSON.parse(e);
      } catch {
        return null;
      }
    }).filter(e => e !== null);
  }
}

module.exports = {
  EvidenceManager,
  EVIDENCE_TYPES,
};
