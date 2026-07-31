'use strict';

class ThreatActorIntelligenceEngine {
  constructor() {
    this.products = new Map();
  }

  async composeThreatActorDossier(investigation, report) {
    if (!investigation.threatActors || investigation.threatActors.length === 0) return null;

    const actor = investigation.threatActors[0];
    const product = {
      id: `actor-dossier-${actor.name}-${report.id}`,
      productId: 'threat-actor-dossier',
      type: 'threat_actor',
      investigationId: investigation.id,
      reportId: report.id,
      actor: actor.name,
      audience: ['threat_intel', 'executive', 'incident_response'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Threat Actor Dossier: ${actor.name}`,
        description: 'Comprehensive profile of threat actor including history, capabilities, and targeting',
        createdAt: new Date().toISOString(),
      },
      modules: {
        actorProfile: {
          name: actor.name,
          aliases: actor.aliases || [],
          description: actor.description || '',
          firstSeen: actor.firstSeen,
          lastSeen: actor.lastSeen,
          origin: actor.origin || 'Unknown',
        },
        capabilities: {
          techniques: investigation.techniques || [],
          tools: investigation.toolsUsed || [],
          malware: investigation.malware || [],
          infrastructure: investigation.infrastructure || [],
        },
        targeting: await this.buildActorTargeting(investigation),
        history: investigation.timeline || [],
        evolution: await this.assessActorEvolution(investigation),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-threat-actor-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeCampaignPortfolio(investigation, report) {
    if (!investigation.campaigns || investigation.campaigns.length === 0) return null;

    const campaigns = investigation.campaigns;
    const product = {
      id: `campaign-portfolio-${report.id}`,
      productId: 'campaign-portfolio',
      type: 'campaign',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel', 'executive', 'incident_response'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Campaign Portfolio: ${campaigns.map(c => c.name).join(', ')}`,
        description: 'Analysis of threat actor campaigns including objectives and targeting',
        createdAt: new Date().toISOString(),
      },
      modules: {
        campaigns: campaigns.map(campaign => ({
          name: campaign.name,
          description: campaign.description || '',
          status: campaign.status || 'ONGOING',
          startDate: campaign.startDate,
          endDate: campaign.endDate,
          objectives: campaign.objectives || [],
        })),
        targeting: await this.buildCampaignTargeting(investigation, campaigns),
        timeline: investigation.timeline || [],
        techniques: investigation.techniques || [],
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-threat-actor-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeInfrastructureMap(investigation, report) {
    const product = {
      id: `infra-map-${report.id}`,
      productId: 'infrastructure-map',
      type: 'infrastructure',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel', 'soc'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Infrastructure Map: ${investigation.threatActors?.[0]?.name || investigation.title}`,
        description: 'Network and infrastructure used by threat actor for operations',
        createdAt: new Date().toISOString(),
      },
      modules: {
        infrastructure: {
          resources: investigation.infrastructure || [],
          clustering: await this.clusterInfrastructure(investigation),
          operationalPurposes: await this.classifyInfrastructure(investigation),
        },
        relationships: await this.mapInfrastructureRelationships(investigation),
        operationalPatterns: await this.extractInfrastructurePatterns(investigation),
        timeline: investigation.timeline || [],
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-threat-actor-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeCapabilityAssessment(investigation, report) {
    const product = {
      id: `capability-assessment-${report.id}`,
      productId: 'capability-assessment',
      type: 'assessment',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel', 'executive'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Capability Assessment: ${investigation.threatActors?.[0]?.name || 'Unknown'}`,
        description: 'Evaluation of threat actor technical capabilities and sophistication',
        createdAt: new Date().toISOString(),
      },
      modules: {
        capabilityOverview: {
          sophistication: await this.assessSophistication(investigation),
          techniques: investigation.techniques || [],
          tools: investigation.toolsUsed || [],
        },
        technicalCapabilities: {
          malwareVariants: investigation.malware || [],
          exploits: await this.extractExploits(investigation),
          infrastructure: investigation.infrastructure || [],
        },
        operationalCapabilities: {
          scaling: await this.assessScaling(investigation),
          stealth: await this.assessStealth(investigation),
          resilience: await this.assessResilience(investigation),
        },
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-threat-actor-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeHistoricalActivity(investigation, report) {
    const product = {
      id: `history-${report.id}`,
      productId: 'historical-activity',
      type: 'history',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel', 'executive', 'incident_response'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Historical Activity Profile: ${investigation.threatActors?.[0]?.name || 'Unknown'}`,
        description: 'Timeline and analysis of threat actor historical operations',
        createdAt: new Date().toISOString(),
      },
      modules: {
        timeline: investigation.timeline || [],
        operationalPatterns: await this.extractOperationalPatterns(investigation),
        campaigns: investigation.campaigns || [],
        activityTrends: await this.analyzeActivityTrends(investigation),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-threat-actor-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeTargetingAnalysis(investigation, report) {
    const product = {
      id: `targeting-${report.id}`,
      productId: 'targeting-analysis',
      type: 'targeting',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel', 'executive', 'industry_peers'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Targeting Analysis: ${investigation.threatActors?.[0]?.name || 'Unknown'}`,
        description: 'Analysis of threat actor targeting patterns and victim selection',
        createdAt: new Date().toISOString(),
      },
      modules: {
        victimology: {
          sectors: investigation.targetedSectors || [],
          regions: investigation.targetedRegions || [],
          organizations: investigation.targetedOrganizations || [],
        },
        targetingCriteria: await this.analyzeTargetingCriteria(investigation),
        victimProfile: await this.buildVictimProfile(investigation),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-threat-actor-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeEvolutionTimeline(investigation, report) {
    const product = {
      id: `evolution-${report.id}`,
      productId: 'evolution-timeline',
      type: 'evolution',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel', 'executive'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Evolution Timeline: ${investigation.threatActors?.[0]?.name || 'Unknown'}`,
        description: 'Timeline of threat actor evolution, sophistication growth, and tactical changes',
        createdAt: new Date().toISOString(),
      },
      modules: {
        timeline: investigation.timeline || [],
        sophisticationProgression: await this.buildSophisticationProgression(investigation),
        tacticalEvolution: await this.buildTacticalEvolution(investigation),
        capabilityGrowth: await this.buildCapabilityGrowth(investigation),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-threat-actor-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  // Helper methods

  async buildActorTargeting(investigation) {
    return {
      sectors: investigation.targetedSectors || [],
      regions: investigation.targetedRegions || [],
      organizations: investigation.targetedOrganizations || [],
      victimCount: investigation.affectedUserCount || 'Unknown',
    };
  }

  async assessActorEvolution(investigation) {
    return {
      status: 'Active',
      sophistication: 'High',
      evolution: 'Continuous improvement of tactics and techniques',
    };
  }

  async buildCampaignTargeting(investigation, campaigns) {
    return {
      sectors: investigation.targetedSectors || [],
      regions: investigation.targetedRegions || [],
      objectives: campaigns.flatMap(c => c.objectives || []),
    };
  }

  async clusterInfrastructure(investigation) {
    return {
      clusters: [],
      analysis: 'Grouping related infrastructure by network characteristics',
    };
  }

  async classifyInfrastructure(investigation) {
    const classification = {};
    (investigation.infrastructure || []).forEach(infra => {
      const type = infra.type || 'unknown';
      classification[type] = (classification[type] || 0) + 1;
    });
    return classification;
  }

  async mapInfrastructureRelationships(investigation) {
    return {
      relationships: [],
      operators: investigation.threatActors || [],
    };
  }

  async extractInfrastructurePatterns(investigation) {
    return {
      frequency: 'Regular',
      timezone: 'UTC',
      pattern: 'Continuous operations',
    };
  }

  async assessSophistication(investigation) {
    return {
      level: investigation.severity === 'CRITICAL' ? 'Very High' : 'High',
      indicators: investigation.techniques?.length || 0,
    };
  }

  async extractExploits(investigation) {
    return investigation.techniques?.filter(t => t.type === 'exploit') || [];
  }

  async assessScaling(investigation) {
    return {
      capability: 'Can scale operations',
      evidence: 'Multiple campaigns and victims',
    };
  }

  async assessStealth(investigation) {
    return {
      level: 'Moderate to High',
      techniques: investigation.techniques?.filter(t => t.name.includes('Command')) || [],
    };
  }

  async assessResilience(investigation) {
    return {
      level: 'High',
      backups: true,
      redundancy: 'Multiple infrastructure nodes',
    };
  }

  async extractOperationalPatterns(investigation) {
    return {
      activeHours: '24/7',
      operatingRegion: investigation.targetedRegions?.join(', ') || 'Global',
      frequency: 'Regular',
    };
  }

  async analyzeActivityTrends(investigation) {
    return {
      trend: 'Increasing',
      operationalPace: 'High',
      campaigns: investigation.campaigns?.length || 0,
    };
  }

  async analyzeTargetingCriteria(investigation) {
    return {
      criteria: [
        'Industry sector',
        'Geolocation',
        'Company size',
        'Security posture',
      ],
    };
  }

  async buildVictimProfile(investigation) {
    return {
      sectors: investigation.targetedSectors || [],
      regions: investigation.targetedRegions || [],
      companySize: 'Enterprise',
      characteristics: [],
    };
  }

  async buildSophisticationProgression(investigation) {
    return {
      phases: [
        { period: 'Early', sophistication: 'Low' },
        { period: 'Current', sophistication: investigation.severity === 'CRITICAL' ? 'Very High' : 'High' },
      ],
    };
  }

  async buildTacticalEvolution(investigation) {
    return {
      evolution: investigation.techniques || [],
      improvements: 'Continuous enhancement of attack techniques',
    };
  }

  async buildCapabilityGrowth(investigation) {
    return {
      malware: investigation.malware?.length || 0,
      tools: investigation.toolsUsed?.length || 0,
      infrastructure: investigation.infrastructure?.length || 0,
    };
  }

  getProduct(productId) {
    return this.products.get(productId);
  }

  getAllProducts() {
    return Array.from(this.products.values());
  }
}

module.exports = { ThreatActorIntelligenceEngine };
