'use strict';

class ThreatActorKnowledgeBaseEngine {
  enrichActorIntelligence(investigation, threatGraphDB = {}) {
    const actors = investigation.threatActors || [];
    const enrichedActors = {};

    actors.forEach(actor => {
      const knownProfile = threatGraphDB[actor.id] || {};
      enrichedActors[actor.id] = this.enrichActorProfile(actor, knownProfile, investigation);
    });

    return {
      enrichedActors,
      knowledgeBaseStatus: this.assessKBCoverage(actors, threatGraphDB),
      actorNetwork: this.buildActorNetwork(enrichedActors),
      enrichedAt: new Date().toISOString(),
    };
  }

  enrichActorProfile(currentActor, knownProfile, investigation) {
    return {
      id: currentActor.id,
      name: currentActor.name || knownProfile.attributes?.name,
      aliases: this.mergeAliases(
        currentActor.aliases,
        knownProfile.attributes?.aliases
      ),
      category: currentActor.category || knownProfile.attributes?.category,
      motivation: currentActor.motivation || knownProfile.attributes?.motivation,
      origin: currentActor.origin || knownProfile.attributes?.origin,
      sophistication: currentActor.sophistication || knownProfile.attributes?.sophistication,
      targetSectors: this.mergeTargets(
        currentActor.targetSectors || currentActor.target_sectors,
        knownProfile.attributes?.target_sectors
      ),
      targetRegions: this.mergeTargets(
        currentActor.targetRegions || currentActor.target_regions,
        knownProfile.attributes?.target_regions
      ),
      ttps: this.mergeTTPs(currentActor.ttps, knownProfile.attributes?.ttps),
      knownIOCs: this.mergeIOCs(currentActor.knownIOCs, investigation),
      knownMalware: this.mergeMalware(currentActor.knownMalware, investigation),
      knownInfrastructure: this.mergeInfrastructure(currentActor.knownInfrastructure, investigation),
      operationalHistory: this.buildOperationalHistory(currentActor, knownProfile),
      recentActivity: this.assessRecentActivity(currentActor),
      knowledgeBaseMatches: this.countKBMatches(currentActor, knownProfile),
    };
  }

  mergeAliases(current, known) {
    const merged = new Set([
      ...(current || []),
      ...(known || []),
    ]);
    return [...merged];
  }

  mergeTargets(current, known) {
    const merged = new Set([
      ...(current || []),
      ...(known || []),
    ]);
    return [...merged];
  }

  mergeTTPs(current, known) {
    const merged = new Set([
      ...(current || []),
      ...(known || []),
    ]);
    return [...merged];
  }

  mergeIOCs(current, investigation) {
    const investigationIOCs = new Set(
      (investigation.iocs || []).map(ioc => ioc.value)
    );

    const merged = new Set([
      ...(current || []),
      ...investigationIOCs,
    ]);

    return [...merged];
  }

  mergeMalware(current, investigation) {
    const investigationMalware = new Set(
      (investigation.malware || []).map(m => m.id)
    );

    const merged = new Set([
      ...(current || []),
      ...investigationMalware,
    ]);

    return [...merged];
  }

  mergeInfrastructure(current, investigation) {
    const investigationInfra = new Set(
      (investigation.infrastructure || [])
        .map(i => i.address || i.ip)
        .filter(Boolean)
    );

    const merged = new Set([
      ...(current || []),
      ...investigationInfra,
    ]);

    return [...merged];
  }

  buildOperationalHistory(actor, knownProfile) {
    const history = {
      firstSeen: actor.firstSeen || knownProfile.attributes?.first_seen,
      lastSeen: actor.lastSeen || knownProfile.attributes?.last_seen,
      active: actor.active !== false,
      yearsActive: this.calculateYearsActive(
        actor.firstSeen || knownProfile.attributes?.first_seen
      ),
      campaigns: actor.campaigns || [],
      victims: actor.victims || [],
      knownIncidents: knownProfile.attributes?.known_cves || [],
    };

    return history;
  }

  calculateYearsActive(firstSeen) {
    if (!firstSeen) return null;
    const years = (new Date().getTime() - new Date(firstSeen).getTime()) / (1000 * 60 * 60 * 24 * 365);
    return Math.floor(years);
  }

  assessRecentActivity(actor) {
    const lastSeen = actor.lastSeen ? new Date(actor.lastSeen) : null;
    if (!lastSeen) return 'unknown';

    const daysSinceLastSeen = (new Date().getTime() - lastSeen.getTime()) / (1000 * 60 * 60 * 24);

    if (daysSinceLastSeen < 30) return 'very_recent';
    if (daysSinceLastSeen < 90) return 'recent';
    if (daysSinceLastSeen < 365) return 'historical';
    return 'inactive';
  }

  countKBMatches(actor, knownProfile) {
    let matches = 0;

    if (knownProfile.attributes) {
      if (actor.name === knownProfile.attributes.name) matches++;
      if (actor.category === knownProfile.attributes.category) matches++;
      if (actor.origin === knownProfile.attributes.origin) matches++;
      if ((actor.aliases || []).some(a => (knownProfile.attributes.aliases || []).includes(a))) matches++;
    }

    return matches;
  }

  buildActorNetwork(enrichedActors) {
    const nodes = [];
    const edges = [];

    Object.values(enrichedActors).forEach(actor => {
      nodes.push({
        id: actor.id,
        label: actor.name,
        type: actor.category,
        sophistication: actor.sophistication,
      });
    });

    Object.values(enrichedActors).forEach(actor1 => {
      Object.values(enrichedActors).forEach(actor2 => {
        if (actor1.id !== actor2.id) {
          const commonElements = this.findCommonElements(actor1, actor2);
          if (commonElements > 0) {
            edges.push({
              source: actor1.id,
              target: actor2.id,
              weight: commonElements,
              type: this.inferRelationship(actor1, actor2),
            });
          }
        }
      });
    });

    return {
      nodes,
      edges,
      networkDensity: edges.length / (nodes.length * (nodes.length - 1) / 2),
    };
  }

  findCommonElements(actor1, actor2) {
    let common = 0;

    const malwareCommon = (actor1.knownMalware || []).filter(m =>
      (actor2.knownMalware || []).includes(m)
    ).length;
    common += malwareCommon;

    const infraCommon = (actor1.knownInfrastructure || []).filter(i =>
      (actor2.knownInfrastructure || []).includes(i)
    ).length;
    common += infraCommon;

    const sectorCommon = (actor1.targetSectors || []).filter(s =>
      (actor2.targetSectors || []).includes(s)
    ).length;
    common += sectorCommon;

    return common;
  }

  inferRelationship(actor1, actor2) {
    const commonMalware = (actor1.knownMalware || []).filter(m =>
      (actor2.knownMalware || []).includes(m)
    ).length;

    if (commonMalware > 0) return 'shared_malware';

    const commonSectors = (actor1.targetSectors || []).filter(s =>
      (actor2.targetSectors || []).includes(s)
    ).length;

    if (commonSectors > 0) return 'similar_targeting';

    return 'related';
  }

  assessKBCoverage(actors, threatGraphDB) {
    let covered = 0;
    let partial = 0;

    actors.forEach(actor => {
      if (threatGraphDB[actor.id]) {
        covered++;
      } else if (threatGraphDB[actor.name]) {
        partial++;
      }
    });

    return {
      totalActors: actors.length,
      fullyMatched: covered,
      partiallyMatched: partial,
      uncovered: actors.length - covered - partial,
      coverage: ((covered + partial / 2) / actors.length),
    };
  }

  generateActorSummaries(enrichedActors) {
    return Object.entries(enrichedActors).map(([id, actor]) => ({
      id,
      name: actor.name,
      aliases: actor.aliases.slice(0, 3),
      sophistication: actor.sophistication,
      targetSectors: actor.targetSectors.slice(0, 3),
      recentActivity: actor.recentActivity,
      yearsActive: actor.operationalHistory.yearsActive,
      summary: `${actor.name} (${actor.category}) - ${actor.recentActivity} activity, targeting ${actor.targetSectors.length} sectors`,
    }));
  }
}

module.exports = { ThreatActorKnowledgeBaseEngine };
