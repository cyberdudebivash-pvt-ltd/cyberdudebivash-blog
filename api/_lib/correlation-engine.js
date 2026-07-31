'use strict';

class CorrelationEngine {
  constructor(graphEngine, graphTraversal) {
    this.graph = graphEngine;
    this.traversal = graphTraversal;
  }

  async correlateThreatsActors(actorId, confidence = 0.6) {
    const actor = await this.graph.getEntity(actorId);
    if (!actor || actor.type !== 'threat_actor') {
      throw new Error(`Not a threat actor: ${actorId}`);
    }

    const usedEntities = await this.getEntitiesRelatedByType(actorId, 'uses');
    const infrastructureEntities = await this.getEntitiesRelatedByType(actorId, 'operates');

    const correlated = [];

    for (const entity of usedEntities) {
      const otherUsers = await this.getIncomingByType(entity.id, 'uses');
      for (const otherUser of otherUsers) {
        if (otherUser.id !== actorId && otherUser.type === 'threat_actor') {
          const correlationScore = await this.calculateActorSimilarity(actorId, otherUser.id);
          if (correlationScore >= confidence) {
            correlated.push({
              actor: otherUser,
              score: correlationScore,
              commonElements: {
                malware: await this.getCommonElements(actorId, otherUser.id, 'uses'),
                infrastructure: await this.getCommonElements(actorId, otherUser.id, 'operates'),
              },
            });
          }
        }
      }
    }

    return correlated.sort((a, b) => b.score - a.score);
  }

  async detectCampaigns(actorId, timeWindowDays = 90) {
    const actor = await this.graph.getEntity(actorId);
    if (!actor || actor.type !== 'threat_actor') {
      throw new Error(`Not a threat actor: ${actorId}`);
    }

    const incidents = await this.getEntitiesRelatedByType(actorId, 'carries_out');
    const now = Date.now();
    const windowMs = timeWindowDays * 24 * 60 * 60 * 1000;

    const campaigns = [];
    const clustered = new Set();

    for (const incident of incidents) {
      if (clustered.has(incident.id)) continue;

      const campaign = {
        name: `Campaign-${incident.id.substring(0, 8)}`,
        incidents: [incident.id],
        commonTechniques: [],
        commonTargets: [],
        timespan: { start: incident.createdAt, end: incident.createdAt },
        confidence: 0.8,
      };

      clustered.add(incident.id);

      for (const other of incidents) {
        if (clustered.has(other.id) || other.id === incident.id) continue;

        const timeDiff = Math.abs(
          new Date(incident.createdAt).getTime() - new Date(other.createdAt).getTime()
        );

        if (timeDiff <= windowMs) {
          const [tech1, tech2] = await Promise.all([
            this.getEntitiesRelatedByType(incident.id, 'implements'),
            this.getEntitiesRelatedByType(other.id, 'implements'),
          ]);

          const overlap = tech1.filter(t => tech2.some(o => o.id === t.id));
          if (overlap.length >= 2) {
            campaign.incidents.push(other.id);
            clustered.add(other.id);
          }
        }
      }

      campaigns.push(campaign);
    }

    return campaigns;
  }

  async clusterMalwareVariants(malwareFamilyId, similarityThreshold = 0.7) {
    const family = await this.graph.getEntity(malwareFamilyId);
    if (!family || !family.type.includes('malware')) {
      throw new Error(`Not a malware entity: ${malwareFamilyId}`);
    }

    const variants = await this.getEntitiesRelatedByType(malwareFamilyId, 'variant_of');
    const related = await this.getEntitiesRelatedByType(malwareFamilyId, 'similar_to');

    const clusters = [];
    const processed = new Set([malwareFamilyId]);

    for (const variant of [...variants, ...related]) {
      if (processed.has(variant.id)) continue;

      const similarity = await this.calculateEntitySimilarity(malwareFamilyId, variant.id);
      if (similarity >= similarityThreshold) {
        clusters.push({
          entity: variant,
          similarity,
          relationship: 'variant_of',
        });
        processed.add(variant.id);
      }
    }

    return clusters;
  }

  async clusterInfrastructure(infrastructureId) {
    const infra = await this.graph.getEntity(infrastructureId);
    if (!infra) throw new Error(`Infrastructure not found: ${infrastructureId}`);

    const connected = await this.traversal.expandEntity(infrastructureId);

    const cluster = {
      center: infra,
      c2Servers: connected.outgoing.filter(r => r.relationship.type === 'beacons_to'),
      malware: connected.incoming.filter(r => r.relationship.type === 'connects_to'),
      hostedAt: connected.outgoing.filter(r => r.relationship.type === 'hosted_on'),
      operators: connected.incoming.filter(r => r.relationship.type === 'operates'),
    };

    return cluster;
  }

  async correlateIOCs(iocId) {
    const ioc = await this.graph.getEntity(iocId);
    if (!ioc || !['file_hash', 'domain', 'ip_address', 'url'].includes(ioc.type)) {
      throw new Error(`Not an IOC: ${iocId}`);
    }

    const users = await this.getIncomingByType(iocId, 'uses');

    const relatedIOCs = new Set();
    for (const actor of users) {
      const otherIOCs = await this.getEntitiesRelatedByType(actor.id, 'uses');
      for (const otherIOC of otherIOCs) {
        if (otherIOC.id !== iocId && ['file_hash', 'domain', 'ip_address', 'url'].includes(otherIOC.type)) {
          relatedIOCs.add(JSON.stringify(otherIOC));
        }
      }
    }

    return Array.from(relatedIOCs).map(ioc => JSON.parse(ioc));
  }

  async getEntitiesRelatedByType(entityId, relationType) {
    const rels = await this.graph.getOutgoingRelationships(entityId, 100);
    const related = [];

    for (const rel of rels.filter(r => r.type === relationType)) {
      const target = await this.graph.getEntity(rel.target);
      if (target) related.push(target);
    }

    return related;
  }

  async getIncomingByType(entityId, relationType) {
    const rels = await this.graph.getIncomingRelationships(entityId, 100);
    const sources = [];

    for (const rel of rels.filter(r => r.type === relationType)) {
      const source = await this.graph.getEntity(rel.source);
      if (source) sources.push(source);
    }

    return sources;
  }

  async calculateActorSimilarity(actor1Id, actor2Id) {
    const [rels1, rels2] = await Promise.all([
      this.graph.getOutgoingRelationships(actor1Id, 100),
      this.graph.getOutgoingRelationships(actor2Id, 100),
    ]);

    if (rels1.length === 0 || rels2.length === 0) return 0;

    const targets1 = new Set(rels1.map(r => r.target));
    const targets2 = new Set(rels2.map(r => r.target));

    const intersection = [...targets1].filter(t => targets2.has(t)).length;
    const union = new Set([...targets1, ...targets2]).size;

    return intersection / union;
  }

  async calculateEntitySimilarity(entity1Id, entity2Id) {
    const [neighbors1, neighbors2] = await Promise.all([
      this.traversal.expandEntity(entity1Id),
      this.traversal.expandEntity(entity2Id),
    ]);

    const all1 = new Set([
      ...neighbors1.outgoing.map(r => r.entity.id),
      ...neighbors1.incoming.map(r => r.entity.id),
    ]);
    const all2 = new Set([
      ...neighbors2.outgoing.map(r => r.entity.id),
      ...neighbors2.incoming.map(r => r.entity.id),
    ]);

    const intersection = [...all1].filter(id => all2.has(id)).length;
    const union = new Set([...all1, ...all2]).size;

    return union === 0 ? 0 : intersection / union;
  }

  async getCommonElements(actor1Id, actor2Id, relationType) {
    const [rels1, rels2] = await Promise.all([
      this.graph.getOutgoingRelationships(actor1Id, 100),
      this.graph.getOutgoingRelationships(actor2Id, 100),
    ]);

    const targets1 = new Set(
      rels1.filter(r => r.type === relationType).map(r => r.target)
    );
    const targets2 = new Set(
      rels2.filter(r => r.type === relationType).map(r => r.target)
    );

    const common = [...targets1].filter(t => targets2.has(t));
    const entities = [];

    for (const id of common) {
      const entity = await this.graph.getEntity(id);
      if (entity) entities.push(entity);
    }

    return entities;
  }
}

module.exports = {
  CorrelationEngine,
};
