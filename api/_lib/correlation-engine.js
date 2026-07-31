'use strict';

class CorrelationEngine {
  findCorrelations(investigation, product, report) {
    const correlations = {
      threatActorCorrelations: this.correlateThreatActors(investigation),
      campaignCorrelations: this.correlateCampaigns(investigation),
      malwareCorrelations: this.correlateMalware(investigation),
      infrastructureCorrelations: this.correlateInfrastructure(investigation),
      iocCorrelations: this.correlateIOCs(investigation),
      victimCorrelations: this.correlateVictims(investigation),
      techniqueCorrelations: this.correlateTechniques(investigation),
      industryCorrelations: this.correlateIndustries(investigation),
      regionCorrelations: this.correlateRegions(investigation),
      relationshipGraph: this.buildRelationshipGraph(investigation),
      correlatedAt: new Date().toISOString(),
    };

    return correlations;
  }

  correlateThreatActors(investigation) {
    const actors = investigation.threatActors || [];
    const correlations = [];
    const actorMap = new Map(actors.map(a => [a.id, a]));

    for (let i = 0; i < actors.length; i++) {
      for (let j = i + 1; j < actors.length; j++) {
        const actor1 = actors[i];
        const actor2 = actors[j];

        const commonElements = {
          malware: this.findCommonItems((investigation.malware || []), 'usedByActors', [actor1.id, actor2.id]),
          infrastructure: this.findCommonItems((investigation.infrastructure || []), 'operatedByActors', [actor1.id, actor2.id]),
          techniques: this.findCommonItems((investigation.mitreTechniques || []), 'usedByActors', [actor1.id, actor2.id]),
          victims: this.findCommonItems((investigation.victims || []), 'targetedByActors', [actor1.id, actor2.id]),
        };

        const overlap = Object.values(commonElements).reduce((sum, items) => sum + items.length, 0);
        if (overlap > 0) {
          const confidence = Math.min(1.0, 0.3 + (overlap * 0.1));
          correlations.push({
            actor1: actor1.id,
            actor2: actor2.id,
            commonElements,
            overlapCount: overlap,
            confidence,
            possibleReasons: this.generateCorrelationReasons('actor', actor1, actor2, commonElements),
          });
        }
      }
    }

    return correlations.sort((a, b) => b.confidence - a.confidence);
  }

  correlateCampaigns(investigation) {
    const campaigns = investigation.campaigns || [];
    const correlations = [];

    for (let i = 0; i < campaigns.length; i++) {
      for (let j = i + 1; j < campaigns.length; j++) {
        const campaign1 = campaigns[i];
        const campaign2 = campaigns[j];

        const commonElements = {
          techniques: this.findCommonItems([...campaign1.techniques || [], ...campaign2.techniques || []], 'id'),
          victims: this.findCommonItems([...campaign1.victims || [], ...campaign2.victims || []], 'id'),
          infrastructure: this.findCommonItems([...campaign1.infrastructure || [], ...campaign2.infrastructure || []], 'id'),
          malware: this.findCommonItems([...campaign1.malware || [], ...campaign2.malware || []], 'id'),
        };

        const overlap = Object.values(commonElements).reduce((sum, items) => sum + items.length, 0);
        if (overlap > 0) {
          const timeDiffMs = Math.abs(new Date(campaign1.startDate).getTime() - new Date(campaign2.startDate).getTime());
          const timeDiffDays = timeDiffMs / (1000 * 60 * 60 * 24);
          const timeProximity = timeDiffDays < 180 ? 0.3 : 0.1;
          const confidence = Math.min(1.0, timeProximity + (overlap * 0.15));

          correlations.push({
            campaign1: campaign1.id,
            campaign2: campaign2.id,
            commonElements,
            overlapCount: overlap,
            timeframeDays: timeDiffDays,
            confidence,
            possibleReasons: this.generateCorrelationReasons('campaign', campaign1, campaign2, commonElements),
          });
        }
      }
    }

    return correlations.sort((a, b) => b.confidence - a.confidence);
  }

  correlateMalware(investigation) {
    const malware = investigation.malware || [];
    const correlations = [];

    for (let i = 0; i < malware.length; i++) {
      for (let j = i + 1; j < malware.length; j++) {
        const mal1 = malware[i];
        const mal2 = malware[j];

        const commonElements = {
          usedByActors: this.findCommonItems(
            [(mal1.usedByActors || []), (mal2.usedByActors || [])].flat(),
            'id'
          ),
          targetedSectors: this.findCommonItems(
            [(mal1.targetedSectors || []), (mal2.targetedSectors || [])].flat(),
            'name'
          ),
          techniques: this.findCommonItems(
            [(mal1.techniques || []), (mal2.techniques || [])].flat(),
            'id'
          ),
        };

        const overlap = Object.values(commonElements).reduce((sum, items) => sum + items.length, 0);
        if (overlap > 0) {
          const confidence = Math.min(1.0, 0.2 + (overlap * 0.2));
          correlations.push({
            malware1: mal1.id,
            malware2: mal2.id,
            commonElements,
            overlapCount: overlap,
            confidence,
            possibleRelationship: this.inferMalwareRelationship(mal1, mal2),
          });
        }
      }
    }

    return correlations.sort((a, b) => b.confidence - a.confidence);
  }

  correlateInfrastructure(investigation) {
    const infrastructure = investigation.infrastructure || [];
    const correlations = [];

    for (let i = 0; i < infrastructure.length; i++) {
      for (let j = i + 1; j < infrastructure.length; j++) {
        const infra1 = infrastructure[i];
        const infra2 = infrastructure[j];

        const commonElements = {
          operators: this.findCommonItems(
            [(infra1.operatedByActors || []), (infra2.operatedByActors || [])].flat(),
            'id'
          ),
          hostedMalware: this.findCommonItems(
            [(infra1.hostedMalware || []), (infra2.hostedMalware || [])].flat(),
            'id'
          ),
        };

        const overlap = Object.values(commonElements).reduce((sum, items) => sum + items.length, 0);
        if (overlap > 0) {
          const confidence = Math.min(1.0, 0.5 + (overlap * 0.2));
          correlations.push({
            infrastructure1: infra1.id,
            infrastructure2: infra2.id,
            commonElements,
            overlapCount: overlap,
            confidence,
            clusterType: this.inferInfrastructureCluster(infra1, infra2),
          });
        }
      }
    }

    return correlations.sort((a, b) => b.confidence - a.confidence);
  }

  correlateIOCs(investigation) {
    const iocs = investigation.iocs || [];
    const correlations = [];

    for (let i = 0; i < iocs.length; i++) {
      for (let j = i + 1; j < iocs.length; j++) {
        const ioc1 = iocs[i];
        const ioc2 = iocs[j];

        if (ioc1.type !== ioc2.type) continue;

        const commonElements = {
          campaigns: this.findCommonItems(
            [(ioc1.campaigns || []), (ioc2.campaigns || [])].flat(),
            'id'
          ),
          actors: this.findCommonItems(
            [(ioc1.usedByActors || []), (ioc2.usedByActors || [])].flat(),
            'id'
          ),
        };

        const overlap = Object.values(commonElements).reduce((sum, items) => sum + items.length, 0);
        if (overlap > 0) {
          const confidence = Math.min(1.0, 0.4 + (overlap * 0.2));
          correlations.push({
            ioc1: ioc1.id,
            ioc2: ioc2.id,
            type: ioc1.type,
            commonElements,
            overlapCount: overlap,
            confidence,
          });
        }
      }
    }

    return correlations.sort((a, b) => b.confidence - a.confidence);
  }

  correlateVictims(investigation) {
    const victims = investigation.victims || [];
    const correlations = [];

    for (let i = 0; i < victims.length; i++) {
      for (let j = i + 1; j < victims.length; j++) {
        const victim1 = victims[i];
        const victim2 = victims[j];

        const commonElements = {
          attackers: this.findCommonItems(
            [(victim1.attackedByActors || []), (victim2.attackedByActors || [])].flat(),
            'id'
          ),
          sector: victim1.sector === victim2.sector ? [victim1.sector] : [],
          region: victim1.region === victim2.region ? [victim1.region] : [],
        };

        const overlap = Object.values(commonElements).reduce((sum, items) => sum + items.length, 0);
        if (overlap > 0) {
          const confidence = Math.min(1.0, 0.3 + (overlap * 0.15));
          correlations.push({
            victim1: victim1.id,
            victim2: victim2.id,
            commonElements,
            overlapCount: overlap,
            confidence,
          });
        }
      }
    }

    return correlations.sort((a, b) => b.confidence - a.confidence);
  }

  correlateTechniques(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const correlations = [];

    for (let i = 0; i < techniques.length; i++) {
      for (let j = i + 1; j < techniques.length; j++) {
        const tech1 = techniques[i];
        const tech2 = techniques[j];

        if (tech1.tactic === tech2.tactic) {
          correlations.push({
            technique1: tech1.id,
            technique2: tech2.id,
            sameTactic: tech1.tactic,
            confidence: 0.9,
            relationship: 'sequential_execution',
          });
        }
      }
    }

    return correlations;
  }

  correlateIndustries(investigation) {
    const industries = investigation.industryImpact || {};
    const correlations = [];

    const industryList = Object.entries(industries).map(([k, v]) => ({ name: k, affectedCount: v }));

    for (let i = 0; i < industryList.length; i++) {
      for (let j = i + 1; j < industryList.length; j++) {
        const ind1 = industryList[i];
        const ind2 = industryList[j];

        const confidence = Math.min(1.0, 0.3 + ((ind1.affectedCount + ind2.affectedCount) / 1000));

        correlations.push({
          industry1: ind1.name,
          industry2: ind2.name,
          affectedCountIndustry1: ind1.affectedCount,
          affectedCountIndustry2: ind2.affectedCount,
          confidence,
        });
      }
    }

    return correlations.sort((a, b) => b.confidence - a.confidence);
  }

  correlateRegions(investigation) {
    const regions = investigation.geoImpact || {};
    const correlations = [];

    const regionList = Object.entries(regions).map(([k, v]) => ({ name: k, affectedCount: v }));

    for (let i = 0; i < regionList.length; i++) {
      for (let j = i + 1; j < regionList.length; j++) {
        const reg1 = regionList[i];
        const reg2 = regionList[j];

        correlations.push({
          region1: reg1.name,
          region2: reg2.name,
          affectedCountRegion1: reg1.affectedCount,
          affectedCountRegion2: reg2.affectedCount,
          confidence: 0.7,
        });
      }
    }

    return correlations;
  }

  buildRelationshipGraph(investigation) {
    const nodes = [];
    const edges = [];
    const nodeIds = new Set();

    const addNode = (id, type, label, properties = {}) => {
      if (!nodeIds.has(id)) {
        nodes.push({ id, type, label, ...properties });
        nodeIds.add(id);
      }
    };

    const addEdge = (source, target, type, confidence = 0.8) => {
      edges.push({ source, target, type, confidence });
    };

    (investigation.threatActors || []).forEach(actor => {
      addNode(actor.id, 'threat_actor', actor.name, { aliases: actor.aliases });
    });

    (investigation.campaigns || []).forEach(campaign => {
      addNode(campaign.id, 'campaign', campaign.name);
    });

    (investigation.malware || []).forEach(mal => {
      addNode(mal.id, 'malware', mal.name);
    });

    (investigation.infrastructure || []).forEach(infra => {
      addNode(infra.id, 'infrastructure', infra.address || infra.ip);
    });

    (investigation.iocs || []).forEach(ioc => {
      addNode(ioc.id, 'ioc', ioc.value, { type: ioc.type });
    });

    (investigation.threatActors || []).forEach(actor => {
      (investigation.campaigns || []).forEach(campaign => {
        if (campaign.actors?.includes(actor.id) || actor.campaigns?.includes(campaign.id)) {
          addEdge(actor.id, campaign.id, 'carries_out', 0.85);
        }
      });

      (investigation.malware || []).forEach(mal => {
        if (mal.usedByActors?.includes(actor.id)) {
          addEdge(actor.id, mal.id, 'uses', 0.9);
        }
      });

      (investigation.infrastructure || []).forEach(infra => {
        if (infra.operatedByActors?.includes(actor.id)) {
          addEdge(actor.id, infra.id, 'operates', 0.85);
        }
      });
    });

    return { nodes, edges, nodeCount: nodes.length, edgeCount: edges.length };
  }

  findCommonItems(arrays, keyOrCompare) {
    if (!Array.isArray(arrays[0])) return [];
    if (keyOrCompare === 'id') {
      const set1 = new Set((arrays[0] || []).map(x => x.id));
      const common = (arrays[1] || []).filter(x => set1.has(x.id));
      return common;
    }
    const set1 = new Set(arrays[0] || []);
    const common = (arrays[1] || []).filter(x => set1.has(x));
    return common;
  }

  generateCorrelationReasons(type, entity1, entity2, commonElements) {
    const reasons = [];
    if (commonElements.malware?.length > 0) reasons.push(`Both ${type}s use ${commonElements.malware.length} common malware samples`);
    if (commonElements.infrastructure?.length > 0) reasons.push(`Shared infrastructure (${commonElements.infrastructure.length} nodes)`);
    if (commonElements.techniques?.length > 0) reasons.push(`Similar TTPs: ${commonElements.techniques.length} shared techniques`);
    if (commonElements.victims?.length > 0) reasons.push(`Targeting similar victims in same sectors`);
    return reasons;
  }

  inferMalwareRelationship(mal1, mal2) {
    if (mal1.family === mal2.family) return 'variant_of';
    if (mal1.category === mal2.category) return 'related_family';
    return 'potentially_related';
  }

  inferInfrastructureCluster(infra1, infra2) {
    if (infra1.type === infra2.type) return `${infra1.type}_cluster`;
    return 'multi_type_cluster';
  }
}

module.exports = { CorrelationEngine };
