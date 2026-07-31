'use strict';

const crypto = require('crypto');

const ENTITY_TYPES = {
  threat_actor: 'threat_actor',
  malware_family: 'malware_family',
  malware_variant: 'malware_variant',
  campaign: 'campaign',
  threat_group: 'threat_group',
  infrastructure: 'infrastructure',
  domain: 'domain',
  ip_address: 'ip_address',
  url: 'url',
  asn: 'asn',
  certificate: 'certificate',
  hosting_provider: 'hosting_provider',
  c2_server: 'c2_server',
  vulnerability: 'vulnerability',
  cve: 'cve',
  exploit: 'exploit',
  exploit_kit: 'exploit_kit',
  attack_pattern: 'attack_pattern',
  technique: 'technique',
  sub_technique: 'sub_technique',
  tactic: 'tactic',
  file: 'file',
  file_hash: 'file_hash',
  process: 'process',
  registry_key: 'registry_key',
  network_traffic: 'network_traffic',
  incident: 'incident',
  threat_report: 'threat_report',
  alert: 'alert',
  detection_rule: 'detection_rule',
  yara_rule: 'yara_rule',
  sigma_rule: 'sigma_rule',
  organization: 'organization',
  sector: 'sector',
  country: 'country',
  person: 'person',
};

const RELATIONSHIP_TYPES = {
  hosts: 'hosts',
  manages: 'manages',
  operates: 'operates',
  controls: 'controls',
  develops: 'develops',
  uses: 'uses',
  distributes: 'distributes',
  carries_out: 'carries_out',
  targets: 'targets',
  exploits: 'exploits',
  leverages: 'leverages',
  connects_to: 'connects_to',
  beacons_to: 'beacons_to',
  downloads_from: 'downloads_from',
  implements: 'implements',
  mimics: 'mimics',
  exploited_by: 'exploited_by',
  affects: 'affects',
  detects: 'detects',
  hunts_for: 'hunts_for',
  part_of: 'part_of',
  contains: 'contains',
  related_to: 'related_to',
  corroborates: 'corroborates',
  contradicts: 'contradicts',
  derives_from: 'derives_from',
  references: 'references',
  attributed_to: 'attributed_to',
  associated_with: 'associated_with',
  similar_to: 'similar_to',
  variant_of: 'variant_of',
};

class GraphEngine {
  constructor(redis, intelligenceManager) {
    this.redis = redis;
    this.manager = intelligenceManager;
    this.ENTITY_TYPES = ENTITY_TYPES;
    this.RELATIONSHIP_TYPES = RELATIONSHIP_TYPES;
  }

  async registerEntity(intelligenceId, intelligenceType, properties) {
    const entity = {
      id: intelligenceId,
      type: this.mapIntelligenceTypeToEntity(intelligenceType),
      name: properties.title,
      description: properties.description,
      properties: JSON.stringify(properties),
      createdAt: new Date().toISOString(),
      confidence: properties.confidence || 'MEDIUM',
      severity: properties.severity || 'MEDIUM',
      version: 1,
      published: true,
    };

    const entityKey = `graph:entity:${intelligenceId}`;
    await this.redis.hset(entityKey, Object.entries(entity).flat());
    await this.redis.sadd(`graph:entities:by_type:${entity.type}`, intelligenceId);
    await this.redis.sadd('graph:entities:all', intelligenceId);
    await this.redis.expire(entityKey, 31536000);

    return entity;
  }

  async createRelationship(sourceId, targetId, relationType, metadata = {}) {
    const relationshipId = this.generateRelationshipId(sourceId, targetId, relationType);

    const relationship = {
      id: relationshipId,
      source: sourceId,
      target: targetId,
      type: relationType,
      confidence: metadata.confidence || 0.5,
      evidence: JSON.stringify(metadata.evidence || []),
      sources: JSON.stringify(metadata.sources || []),
      timestamp: new Date().toISOString(),
      version: 1,
      analystReviewed: metadata.analystReviewed || false,
      reviewedBy: metadata.reviewedBy || null,
      reviewedAt: metadata.reviewedAt || null,
      reason: metadata.reason || '',
    };

    const relKey = `graph:relationship:${relationshipId}`;
    await this.redis.hset(relKey, Object.entries(relationship).flat());

    await this.redis.zadd(
      `graph:outgoing:${sourceId}`,
      relationship.confidence * 100,
      relationshipId
    );
    await this.redis.zadd(
      `graph:incoming:${targetId}`,
      relationship.confidence * 100,
      relationshipId
    );

    await this.redis.sadd(`graph:relationships:${relationType}`, relationshipId);
    await this.redis.zadd('graph:relationships:all', Date.now(), relationshipId);
    await this.redis.expire(relKey, 31536000);

    return relationship;
  }

  async getEntity(entityId) {
    const entityKey = `graph:entity:${entityId}`;
    const data = await this.redis.hgetall(entityKey);

    if (!data || data.length === 0) {
      return null;
    }

    const entity = {};
    for (let i = 0; i < data.length; i += 2) {
      entity[data[i]] = data[i + 1];
    }

    if (entity.properties) {
      try {
        entity.properties = JSON.parse(entity.properties);
      } catch (e) {
        entity.properties = {};
      }
    }

    return entity;
  }

  async getEntitiesByType(entityType, limit = 100) {
    const entityIds = await this.redis.smembers(`graph:entities:by_type:${entityType}`);
    const entities = [];

    for (const id of entityIds.slice(0, limit)) {
      const entity = await this.getEntity(id);
      if (entity) entities.push(entity);
    }

    return entities;
  }

  async getRelationship(relationshipId) {
    const relKey = `graph:relationship:${relationshipId}`;
    const data = await this.redis.hgetall(relKey);

    if (!data || data.length === 0) {
      return null;
    }

    const rel = {};
    for (let i = 0; i < data.length; i += 2) {
      rel[data[i]] = data[i + 1];
    }

    if (rel.evidence) {
      try {
        rel.evidence = JSON.parse(rel.evidence);
      } catch (e) {
        rel.evidence = [];
      }
    }
    if (rel.sources) {
      try {
        rel.sources = JSON.parse(rel.sources);
      } catch (e) {
        rel.sources = [];
      }
    }

    rel.confidence = parseFloat(rel.confidence);

    return rel;
  }

  async getOutgoingRelationships(entityId, limit = 100) {
    const relIds = await this.redis.zrevrange(`graph:outgoing:${entityId}`, 0, limit - 1);
    const relationships = [];

    for (const id of relIds) {
      const rel = await this.getRelationship(id);
      if (rel) relationships.push(rel);
    }

    return relationships;
  }

  async getIncomingRelationships(entityId, limit = 100) {
    const relIds = await this.redis.zrevrange(`graph:incoming:${entityId}`, 0, limit - 1);
    const relationships = [];

    for (const id of relIds) {
      const rel = await this.getRelationship(id);
      if (rel) relationships.push(rel);
    }

    return relationships;
  }

  async getRelationshipsByType(relationType, limit = 100) {
    const relIds = await this.redis.smembers(`graph:relationships:${relationType}`);
    const relationships = [];

    for (const id of relIds.slice(0, limit)) {
      const rel = await this.getRelationship(id);
      if (rel) relationships.push(rel);
    }

    return relationships;
  }

  async deleteRelationship(relationshipId, actor, reason) {
    const rel = await this.getRelationship(relationshipId);
    if (!rel) return null;

    await this.redis.zadd(
      'graph:audit:relationships',
      Date.now(),
      JSON.stringify({
        action: 'DELETE',
        relationshipId,
        source: rel.source,
        target: rel.target,
        type: rel.type,
        actor,
        reason,
        timestamp: new Date().toISOString(),
      })
    );

    await this.redis.zrem(`graph:outgoing:${rel.source}`, relationshipId);
    await this.redis.zrem(`graph:incoming:${rel.target}`, relationshipId);
    await this.redis.srem(`graph:relationships:${rel.type}`, relationshipId);
    await this.redis.zrem('graph:relationships:all', relationshipId);

    const relKey = `graph:relationship:${relationshipId}`;
    await this.redis.del(relKey);

    return { deleted: true, relationshipId };
  }

  generateRelationshipId(sourceId, targetId, relationType) {
    const data = `${sourceId}→${relationType}→${targetId}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  mapIntelligenceTypeToEntity(intelligenceType) {
    const mapping = {
      detection_rule: 'detection_rule',
      ioc: 'file_hash',
      threat_actor: 'threat_actor',
      malware: 'malware_family',
      campaign: 'campaign',
      vulnerability: 'vulnerability',
      threat_report: 'threat_report',
      incident: 'incident',
      supply_chain: 'infrastructure',
      infrastructure: 'infrastructure',
      technique: 'technique',
      indicator_set: 'file_hash',
    };
    return mapping[intelligenceType] || 'unknown';
  }

  async getGraphStats() {
    const entityCount = await this.redis.scard('graph:entities:all');
    const relationshipCount = await this.redis.zcard('graph:relationships:all');

    const stats = {
      totalEntities: entityCount,
      totalRelationships: relationshipCount,
      entityTypeBreakdown: {},
      relationshipTypeBreakdown: {},
    };

    for (const type of Object.values(ENTITY_TYPES)) {
      const count = await this.redis.scard(`graph:entities:by_type:${type}`);
      if (count > 0) {
        stats.entityTypeBreakdown[type] = count;
      }
    }

    for (const type of Object.values(RELATIONSHIP_TYPES)) {
      const count = await this.redis.scard(`graph:relationships:${type}`);
      if (count > 0) {
        stats.relationshipTypeBreakdown[type] = count;
      }
    }

    return stats;
  }
}

module.exports = {
  GraphEngine,
  ENTITY_TYPES,
  RELATIONSHIP_TYPES,
};
