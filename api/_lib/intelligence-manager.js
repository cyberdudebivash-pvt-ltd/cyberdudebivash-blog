/**
 * SENTINEL APEX — Intelligence Lifecycle Manager
 * Coordinates intelligence object storage, versioning, governance transitions,
 * and publishing. Single source of truth for all intelligence.
 */
'use strict';

const { IntelligenceObject, LIFECYCLE_STATES, validateIntelligenceObject } = require('./intelligence-object');

/**
 * Intelligence Manager — production orchestrator.
 */
class IntelligenceManager {
  constructor(redis) {
    this.redis = redis;
  }

  /**
   * Store a new intelligence object.
   * Generates ID, validates schema, persists to Redis.
   * Returns the stored object with full metadata.
   */
  async storeIntelligence(type, data, actor = 'system') {
    if (!data.title) {
      throw new Error('Intelligence objects require a title');
    }

    const obj = new IntelligenceObject(type, { ...data, createdBy: actor, updatedBy: actor });

    // Validate schema
    const { valid, errors } = validateIntelligenceObject(obj);
    if (!valid) {
      throw new Error(`Validation failed: ${errors.join(', ')}`);
    }

    // Persist to Redis
    const key = `intelligence:${obj.id}`;
    const json = obj.toJSON();

    try {
      await this.redis.hmset(key, {
        id: obj.id,
        type: obj.type,
        version: obj.version,
        status: obj.status,
        title: obj.title,
        description: obj.description,
        content: JSON.stringify(obj.content),
        confidence: obj.confidence,
        severity: obj.severity,
        createdAt: obj.createdAt,
        createdBy: obj.createdBy,
        updatedAt: obj.updatedAt,
        updatedBy: obj.updatedBy,
        json: JSON.stringify(json),
      });

      // Index for queries
      await this.redis.zadd(`intelligence:by:type:${obj.type}`, Date.now(), obj.id);
      await this.redis.zadd(`intelligence:by:status:${obj.status}`, Date.now(), obj.id);
      await this.redis.zadd(`intelligence:by:confidence:${obj.confidence}`, Date.now(), obj.id);
      await this.redis.zadd('intelligence:all', Date.now(), obj.id);

      return json;
    } catch (e) {
      throw new Error(`Failed to store intelligence: ${e.message}`);
    }
  }

  /**
   * Retrieve an intelligence object by ID.
   */
  async getIntelligence(id) {
    try {
      const data = await this.redis.hgetall(`intelligence:${id}`);
      if (!data || data.length === 0) return null;

      const obj = {};
      for (let i = 0; i < data.length; i += 2) obj[data[i]] = data[i + 1];

      // Deserialize nested JSON
      if (obj.json) {
        return JSON.parse(obj.json);
      }

      return obj;
    } catch (e) {
      return null;
    }
  }

  /**
   * Update intelligence object with new content.
   * Creates new version, increments version number, preserves history.
   */
  async updateIntelligence(id, updates, actor = 'system', reason = '') {
    const current = await this.getIntelligence(id);
    if (!current) {
      throw new Error(`Intelligence not found: ${id}`);
    }

    const obj = IntelligenceObject.fromJSON(current);
    obj.createVersion(updates.content || {}, actor, reason);
    if (updates.confidence) obj.setConfidence(updates.confidence, updates.confidenceJustification || '');

    // Re-persist
    const key = `intelligence:${obj.id}`;
    const json = obj.toJSON();

    try {
      await this.redis.hmset(key, {
        id: obj.id,
        type: obj.type,
        version: obj.version,
        status: obj.status,
        title: obj.title,
        description: obj.description,
        content: JSON.stringify(obj.content),
        confidence: obj.confidence,
        severity: obj.severity,
        updatedAt: obj.updatedAt,
        updatedBy: obj.updatedBy,
        json: JSON.stringify(json),
      });

      return json;
    } catch (e) {
      throw new Error(`Failed to update intelligence: ${e.message}`);
    }
  }

  /**
   * Transition intelligence through lifecycle.
   * DRAFT → REVIEW → APPROVED → PUBLISHED → ARCHIVED
   *
   * Each transition is audited and can include approval comments.
   */
  async transitionIntelligence(id, newStatus, actor = 'system', reason = '') {
    const current = await this.getIntelligence(id);
    if (!current) {
      throw new Error(`Intelligence not found: ${id}`);
    }

    const obj = IntelligenceObject.fromJSON(current);
    obj.transitionState(newStatus, actor, reason);

    // Re-persist
    const key = `intelligence:${obj.id}`;
    const json = obj.toJSON();

    try {
      // Remove from old status index
      await this.redis.zrem(`intelligence:by:status:${current.status}`, obj.id);

      // Add to new status index
      await this.redis.zadd(`intelligence:by:status:${newStatus}`, Date.now(), obj.id);

      // Update object
      await this.redis.hmset(key, {
        status: obj.status,
        reviewedAt: obj.reviewedAt || '',
        reviewedBy: obj.reviewedBy || '',
        approvedAt: obj.approvedAt || '',
        approvedBy: obj.approvedBy || '',
        publishedAt: obj.publishedAt || '',
        publishedBy: obj.publishedBy || '',
        json: JSON.stringify(json),
      });

      return json;
    } catch (e) {
      throw new Error(`Failed to transition intelligence: ${e.message}`);
    }
  }

  /**
   * Publish intelligence (make it visible to customers/systems).
   * Only APPROVED intelligence can be published.
   */
  async publishIntelligence(id, actor = 'system') {
    const current = await this.getIntelligence(id);
    if (!current) {
      throw new Error(`Intelligence not found: ${id}`);
    }

    if (current.status !== LIFECYCLE_STATES.APPROVED) {
      throw new Error(`Can only publish APPROVED intelligence. Current status: ${current.status}`);
    }

    return this.transitionIntelligence(id, LIFECYCLE_STATES.PUBLISHED, actor, 'Published to production');
  }

  /**
   * Retract published intelligence (emergency removal).
   * Used when errors are discovered post-publication.
   */
  async retractIntelligence(id, actor = 'system', reason = '') {
    const current = await this.getIntelligence(id);
    if (!current) {
      throw new Error(`Intelligence not found: ${id}`);
    }

    return this.transitionIntelligence(id, LIFECYCLE_STATES.RETRACTED, actor, reason || 'Retracted from production');
  }

  /**
   * Archive intelligence (mark as no longer relevant).
   */
  async archiveIntelligence(id, actor = 'system', reason = '') {
    return this.transitionIntelligence(id, LIFECYCLE_STATES.ARCHIVED, actor, reason || 'Archived');
  }

  /**
   * Search intelligence by filters.
   * Supports type, status, confidence, severity, tags, etc.
   */
  async searchIntelligence(filters = {}) {
    const results = [];

    try {
      let ids = [];

      if (filters.type) {
        ids = await this.redis.zrange(`intelligence:by:type:${filters.type}`, 0, -1);
      } else if (filters.status) {
        ids = await this.redis.zrange(`intelligence:by:status:${filters.status}`, 0, -1);
      } else if (filters.confidence) {
        ids = await this.redis.zrange(`intelligence:by:confidence:${filters.confidence}`, 0, -1);
      } else {
        ids = await this.redis.zrange('intelligence:all', 0, -1);
      }

      // Fetch and filter
      for (const id of ids) {
        const obj = await this.getIntelligence(id);
        if (!obj) continue;

        let match = true;
        if (filters.type && obj.type !== filters.type) match = false;
        if (filters.status && obj.status !== filters.status) match = false;
        if (filters.confidence && obj.confidence !== filters.confidence) match = false;
        if (filters.severity && obj.severity !== filters.severity) match = false;
        if (filters.q && !obj.title.toLowerCase().includes(filters.q.toLowerCase())) match = false;

        if (match) results.push(obj);
      }

      return results;
    } catch (e) {
      return [];
    }
  }

  /**
   * Get intelligence history (all versions).
   */
  async getIntelligenceHistory(id) {
    const obj = await this.getIntelligence(id);
    if (!obj) return null;

    return {
      id: obj.id,
      type: obj.type,
      title: obj.title,
      currentVersion: obj.version,
      history: obj.history,
      auditLog: obj.auditLog,
      lifecycleTimeline: {
        created: { at: obj.createdAt, by: obj.createdBy },
        reviewed: { at: obj.reviewedAt, by: obj.reviewedBy },
        approved: { at: obj.approvedAt, by: obj.approvedBy },
        published: { at: obj.publishedAt, by: obj.publishedBy },
      },
    };
  }

  /**
   * Link related intelligence (bidirectional relationships).
   */
  async linkIntelligence(sourceId, targetId, relationshipType = 'related') {
    try {
      const source = await this.getIntelligence(sourceId);
      const target = await this.getIntelligence(targetId);

      if (!source || !target) {
        throw new Error('One or both intelligence objects not found');
      }

      // Add to source
      if (!source.relatedIntelligence) source.relatedIntelligence = [];
      if (!source.relatedIntelligence.find(r => r.id === targetId)) {
        source.relatedIntelligence.push({
          id: targetId,
          type: target.type,
          title: target.title,
          relationshipType,
        });
      }

      // Add to target (bidirectional)
      if (!target.relatedIntelligence) target.relatedIntelligence = [];
      if (!target.relatedIntelligence.find(r => r.id === sourceId)) {
        target.relatedIntelligence.push({
          id: sourceId,
          type: source.type,
          title: source.title,
          relationshipType,
        });
      }

      // Persist both
      await this.redis.hset(`intelligence:${sourceId}`, 'json', JSON.stringify(source));
      await this.redis.hset(`intelligence:${targetId}`, 'json', JSON.stringify(target));

      return { source, target };
    } catch (e) {
      throw new Error(`Failed to link intelligence: ${e.message}`);
    }
  }

  /**
   * Get published intelligence (what customers see).
   */
  async getPublishedIntelligence(type = null, limit = 100) {
    const publishedIds = await this.redis.zrange('intelligence:by:status:published', 0, limit);
    const results = [];

    for (const id of publishedIds) {
      const obj = await this.getIntelligence(id);
      if (!obj || (type && obj.type !== type)) continue;
      results.push(obj);
    }

    return results;
  }

  /**
   * Get intelligence awaiting review (for analysts).
   */
  async getPendingReview() {
    const pendingIds = await this.redis.zrange('intelligence:by:status:review', 0, -1);
    const results = [];

    for (const id of pendingIds) {
      const obj = await this.getIntelligence(id);
      if (obj) results.push(obj);
    }

    return results;
  }
}

module.exports = {
  IntelligenceManager,
};
