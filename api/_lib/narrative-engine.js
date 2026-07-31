'use strict';

class NarrativeEngine {
  generateNarratives(investigation, report, qualityReview) {
    const narratives = {
      attackNarrative: this.generateAttackNarrative(investigation),
      campaignNarrative: this.generateCampaignNarrative(investigation),
      infrastructureNarrative: this.generateInfrastructureNarrative(investigation),
      victimologyNarrative: this.generateVictimologyNarrative(investigation),
      observedBehavior: this.generateObservedBehaviorNarrative(investigation),
      killChainProgression: this.generateKillChainProgression(investigation),
      campaignEvolution: this.generateCampaignEvolution(investigation),
      generatedAt: new Date().toISOString(),
    };

    return narratives;
  }

  generateAttackNarrative(investigation) {
    const threatActors = investigation.threatActors || [];
    const victims = investigation.victims || [];
    const techniques = investigation.mitreTechniques || [];

    if (threatActors.length === 0) {
      return {
        summary: 'Unknown threat actor conducting targeted attack',
        fullNarrative: this.buildAttackNarrative(null, victims, techniques),
        objective: investigation.objective || 'Unknown',
        timeline: this.extractTimeline(investigation),
        keyEvents: this.extractKeyEvents(investigation),
      };
    }

    const actor = threatActors[0];
    return {
      summary: `${actor.name} conducting targeted attack against ${investigation.targetIndustry || 'organizations'}`,
      fullNarrative: this.buildAttackNarrative(actor, victims, techniques),
      actorProfile: {
        name: actor.name,
        aliases: actor.aliases || [],
        motivation: actor.motivation || 'financial gain',
        capabilities: actor.capabilities || [],
        historicalCampaigns: (actor.campaigns || []).length,
      },
      objective: investigation.objective || 'Data theft and espionage',
      timeline: this.extractTimeline(investigation),
      keyEvents: this.extractKeyEvents(investigation),
    };
  }

  generateCampaignNarrative(investigation) {
    const campaigns = investigation.campaigns || [];

    if (campaigns.length === 0) {
      return {
        status: 'No campaign attribution',
        narrative: 'Activity does not clearly align with known campaign patterns.',
      };
    }

    const campaign = campaigns[0];
    const victims = investigation.victims || [];

    return {
      campaignName: campaign.name,
      status: campaign.status || 'Ongoing',
      objectives: campaign.objectives || ['Data theft', 'Intelligence gathering'],
      targetProfile: campaign.targetProfile || 'High-value organizations',
      victimCount: victims.length,
      affectedIndustries: this.extractIndustries(investigation),
      geographicScope: this.extractGeography(investigation),
      operationalTempo: this.assessOperationalTempo(campaign),
      narrative: `${campaign.name} is a ${campaign.duration || 'long-running'} campaign targeting ${campaign.targetProfile || 'organizations'} in the ${this.extractIndustries(investigation).join(', ')} sectors. The campaign has affected at least ${victims.length} organizations with a focus on ${campaign.primaryObjective || 'intellectual property theft'}. Attack activity shows signs of ${this.assessOperationalTempo(campaign)} operational tempo, with ${campaign.frequency || 'irregular'} attack waves.`,
      keyPhases: this.identifyKeyPhases(campaign, investigation),
      estimatedStartDate: campaign.startDate || 'Unknown',
      estimatedEndDate: campaign.endDate || 'Ongoing',
      confidence: 'High',
    };
  }

  generateInfrastructureNarrative(investigation) {
    const infrastructure = investigation.infrastructure || [];
    const iocs = investigation.iocs || [];

    const c2Servers = infrastructure.filter(i => i.type === 'C2') || [];
    const stagingServers = infrastructure.filter(i => i.type === 'Staging') || [];
    const hostedMalware = infrastructure.filter(i => i.type === 'Malware Hosting') || [];

    return {
      overallNarrative: `Threat infrastructure consists of ${infrastructure.length} identified servers operating under ${this.countUniqueASNs(infrastructure)} distinct ASNs across ${this.countUniqueCountries(infrastructure)} countries`,
      c2Infrastructure: {
        count: c2Servers.length,
        description: c2Servers.length > 0
          ? `${c2Servers.length} C2 servers identified, operating from hosting providers including ${this.extractProviders(c2Servers).slice(0, 3).join(', ')}`
          : 'No C2 servers identified',
        details: c2Servers.slice(0, 5).map(s => ({
          ip: s.ip || s.address,
          domain: s.domain,
          provider: s.provider,
          asn: s.asn,
          lastActive: s.lastActive,
          campaign: s.campaign,
        })),
      },
      stagingServers: {
        count: stagingServers.length,
        description: stagingServers.length > 0
          ? `${stagingServers.length} staging servers used for malware distribution`
          : 'No dedicated staging infrastructure identified',
        details: stagingServers.slice(0, 3).map(s => ({ ip: s.ip || s.address, domain: s.domain })),
      },
      malwareHosting: {
        count: hostedMalware.length,
        description: hostedMalware.length > 0
          ? `${hostedMalware.length} servers hosting malware`
          : 'Malware hosted on compromised infrastructure or legitimate CDNs',
        details: hostedMalware.slice(0, 3).map(s => ({ ip: s.ip || s.address, malware: s.malware })),
      },
      registrationPatterns: this.analyzeRegistrationPatterns(infrastructure),
      operationalSecurity: this.assessOperationalSecurity(infrastructure),
      evolution: this.analyzeInfrastructureEvolution(investigation),
    };
  }

  generateVictimologyNarrative(investigation) {
    const victims = investigation.victims || [];

    if (victims.length === 0) {
      return {
        summary: 'No confirmed victims at this time',
        narrative: 'Intelligence indicates targeting but no confirmed compromises.',
        targetProfile: investigation.targetProfile || 'Unknown',
      };
    }

    return {
      summary: `${victims.length} confirmed victims across ${this.countUniqueIndustries(victims)} industries`,
      narrative: `Victims include organizations spanning ${this.countUniqueIndustries(victims)} sectors, with a concentration in ${this.getMostAffectedIndustry(victims)}. Target selection indicates ${this.analyzeTargetSelection(victims)}.`,
      victimCount: victims.length,
      byIndustry: this.groupVictimsByIndustry(victims),
      byGeography: this.groupVictimsByGeography(victims),
      organizationSize: this.analyzeOrganizationSize(victims),
      targetSelectionCriteria: [
        'Organization size and revenue',
        'Sector and critical importance',
        'Existing business relationships',
        'Technical infrastructure',
        'Strategic value of intellectual property',
      ],
      victimProfiles: victims.slice(0, 5).map(v => ({
        organization: v.name,
        industry: v.industry,
        country: v.country,
        compromiseDate: v.compromiseDate,
        dataAffected: v.dataAffected || [],
      })),
      socialEngineering: this.detectSocialEngineering(investigation),
      supplyChainTarget: investigation.supplyChainInvolved ? 'Yes' : 'No',
    };
  }

  generateObservedBehaviorNarrative(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const toolsUsed = investigation.toolsUsed || [];
    const malware = investigation.malwareVariants || [];

    return {
      summary: `Threat actor employs ${techniques.length} distinct techniques using ${toolsUsed.length} tools and ${malware.length} malware variants`,
      operationalPattern: this.identifyOperationalPattern(investigation),
      attackPattern: {
        techniques: techniques.slice(0, 10),
        focus: this.identifyTechniqueFocus(techniques),
        sophistication: this.assessSophistication(investigation),
      },
      toolingAndMalware: {
        customTools: toolsUsed.filter(t => t.custom) || [],
        publicTools: toolsUsed.filter(t => !t.custom) || [],
        malwareVariants: malware.slice(0, 5).map(m => ({
          name: m.name,
          hash: m.hash,
          variant: m.variant,
          capabilities: m.capabilities || [],
        })),
      },
      communicationProtocol: {
        c2Protocol: investigation.c2Protocol || 'HTTP/S',
        encryptionMethod: investigation.encryptionMethod || 'Unknown',
        beaconFrequency: investigation.beaconFrequency || 'Regular',
      },
      dataExfiltration: {
        method: investigation.exfiltrationMethod || 'Unknown',
        volume: investigation.exfiltrationVolume || 'Unknown',
        channel: investigation.exfiltrationChannel || 'Unknown',
        evidence: (investigation.exfiltrationEvidence || []).slice(0, 3),
      },
      antiAnalysis: this.identifyAntiAnalysisTechniques(investigation),
    };
  }

  generateKillChainProgression(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const killChain = [
      { stage: 'Reconnaissance', techniques: techniques.filter(t => t.includes('Reconnaissance')) },
      { stage: 'Weaponization', techniques: techniques.filter(t => t.includes('Weaponization') || t.includes('Development')) },
      { stage: 'Delivery', techniques: techniques.filter(t => t.includes('Delivery') || t.includes('Phishing')) },
      { stage: 'Exploitation', techniques: techniques.filter(t => t.includes('Exploit')) },
      { stage: 'Installation', techniques: techniques.filter(t => t.includes('Installation') || t.includes('Malware')) },
      { stage: 'Command & Control', techniques: techniques.filter(t => t.includes('Command') || t.includes('C2')) },
      { stage: 'Action on Objectives', techniques: techniques.filter(t => t.includes('Exfiltration') || t.includes('Impact')) },
    ];

    const observedStages = killChain.filter(stage => stage.techniques.length > 0);

    return {
      overallNarrative: `Attack progresses through ${observedStages.length} stages of the Cyber Kill Chain`,
      progression: observedStages,
      timeline: this.mapKillChainToTimeline(investigation),
      evidence: this.buildKillChainEvidence(investigation),
      unobservedStages: killChain.filter(stage => stage.techniques.length === 0),
      gaps: this.identifyKillChainGaps(observedStages),
    };
  }

  generateCampaignEvolution(investigation) {
    const campaigns = investigation.campaigns || [];
    if (campaigns.length === 0) return null;

    const campaign = campaigns[0];
    const events = investigation.campaignEvents || [];
    const sortedEvents = events.sort((a, b) => new Date(a.date) - new Date(b.date));

    return {
      campaignName: campaign.name,
      evolutionSummary: `${campaign.name} has evolved through ${this.identifyEvolutionPhases(sortedEvents).length} distinct phases`,
      phases: this.identifyEvolutionPhases(sortedEvents).map(phase => ({
        name: phase.name,
        startDate: phase.startDate,
        endDate: phase.endDate,
        characteristics: phase.characteristics,
        targetExpansion: phase.targetExpansion,
        techniqueAdditions: phase.techniqueAdditions,
        toolingUpdates: phase.toolingUpdates,
      })),
      technicalEvolution: {
        malwareVariants: (investigation.malwareVariants || []).length,
        exploitsUsed: (investigation.exploitsUsed || []).length,
        improvementAreas: this.identifyImprovementAreas(investigation),
      },
      tacticalEvolution: {
        socialEngineeringTactics: this.analyzeSocialEngineeringEvolution(campaign),
        targetSelectionChanges: this.analyzeTargetSelectionEvolution(campaign),
        operationalChanges: this.analyzeOperationalEvolution(campaign),
      },
      futureProjection: {
        likelyTargets: this.projectFutureTargets(campaign),
        expectedTechniques: this.projectFutureTechniques(campaign),
        infrastructureExpectations: this.projectInfrastructureEvolution(campaign),
      },
    };
  }

  buildAttackNarrative(actor, victims, techniques) {
    if (!actor) {
      return `Unknown threat actor conducted targeted attack against ${victims.length} organizations using ${techniques.length} distinct techniques.`;
    }

    return `${actor.name} conducted targeted attack against ${victims.length} organizations primarily in the ${this.extractIndustriesFromVictims(victims)} sector. The attack employed ${techniques.length} distinct techniques and focused on ${actor.motivation || 'financial gain'}.`;
  }

  extractTimeline(investigation) {
    const events = investigation.events || [];
    return events.sort((a, b) => new Date(a.date) - new Date(b.date)).slice(0, 10).map(e => ({
      date: e.date,
      event: e.description,
      type: e.type,
    }));
  }

  extractKeyEvents(investigation) {
    const events = investigation.events || [];
    return events
      .filter(e => e.significance === 'high' || e.type === 'compromise')
      .sort((a, b) => new Date(b.date) - new Date(a.date))
      .slice(0, 5)
      .map(e => ({
        date: e.date,
        event: e.description,
        impact: e.impact,
      }));
  }

  extractIndustries(investigation) {
    const industries = investigation.industryImpact || {};
    return Object.keys(industries).slice(0, 5);
  }

  extractGeography(investigation) {
    const victims = investigation.victims || [];
    const countries = [...new Set(victims.map(v => v.country))];
    return countries.slice(0, 5);
  }

  assessOperationalTempo(campaign) {
    const frequency = campaign.frequency || 'irregular';
    const tempoMap = {
      'daily': 'very high',
      'weekly': 'high',
      'monthly': 'moderate',
      'irregular': 'low',
    };
    return tempoMap[frequency] || 'unknown';
  }

  identifyKeyPhases(campaign, investigation) {
    return [
      { name: 'Initial Compromise', description: 'Early targeting and exploitation', duration: 'Phase 1' },
      { name: 'Persistence', description: 'Establishment of persistent access', duration: 'Phase 2' },
      { name: 'Data Collection', description: 'Intelligence and data gathering', duration: 'Phase 3' },
      { name: 'Exfiltration', description: 'Large-scale data theft', duration: 'Phase 4' },
    ];
  }

  countUniqueASNs(infrastructure) {
    const asns = [...new Set(infrastructure.map(i => i.asn).filter(Boolean))];
    return asns.length;
  }

  countUniqueCountries(infrastructure) {
    const countries = [...new Set(infrastructure.map(i => i.country).filter(Boolean))];
    return countries.length;
  }

  extractProviders(servers) {
    return [...new Set(servers.map(s => s.provider).filter(Boolean))];
  }

  analyzeRegistrationPatterns(infrastructure) {
    return {
      domainRegistrars: 'Multiple privacy registrars',
      billingInfo: 'Difficult to trace',
      ageProfile: 'Mix of old and new domains',
      patterns: ['Privacy-protected registrations', 'Rapid domain rotation', 'Shared infrastructure'],
    };
  }

  assessOperationalSecurity(infrastructure) {
    return {
      level: 'Moderate to High',
      observations: ['Use of legitimate hosting providers', 'Regular infrastructure rotation', 'Separation of staging and operational servers'],
    };
  }

  analyzeInfrastructureEvolution(investigation) {
    return {
      trend: 'Expanding infrastructure footprint',
      changes: ['Increased server count', 'Geographic diversification', 'Use of new providers'],
    };
  }

  countUniqueIndustries(victims) {
    return [...new Set(victims.map(v => v.industry).filter(Boolean))].length;
  }

  getMostAffectedIndustry(victims) {
    const industries = {};
    victims.forEach(v => {
      industries[v.industry] = (industries[v.industry] || 0) + 1;
    });
    const sorted = Object.entries(industries).sort((a, b) => b[1] - a[1]);
    return sorted[0]?.[0] || 'unknown';
  }

  analyzeTargetSelection(victims) {
    return 'selection of high-value organizations with access to sensitive intellectual property';
  }

  groupVictimsByIndustry(victims) {
    const byIndustry = {};
    victims.forEach(v => {
      if (!byIndustry[v.industry]) byIndustry[v.industry] = [];
      byIndustry[v.industry].push(v.name);
    });
    return byIndustry;
  }

  groupVictimsByGeography(victims) {
    const byCountry = {};
    victims.forEach(v => {
      if (!byCountry[v.country]) byCountry[v.country] = [];
      byCountry[v.country].push(v.name);
    });
    return byCountry;
  }

  analyzeOrganizationSize(victims) {
    return {
      small: victims.filter(v => v.size === 'small').length,
      medium: victims.filter(v => v.size === 'medium').length,
      large: victims.filter(v => v.size === 'large').length,
      enterprise: victims.filter(v => v.size === 'enterprise').length,
    };
  }

  detectSocialEngineering(investigation) {
    const techniques = investigation.mitreTechniques || [];
    return techniques.some(t => t.includes('Phishing') || t.includes('Social')) ? 'Yes' : 'No';
  }

  identifyOperationalPattern(investigation) {
    return 'Disciplined operational security with regular infrastructure rotation and multi-stage attack progression';
  }

  identifyTechniqueFocus(techniques) {
    if (techniques.filter(t => t.includes('Phishing')).length > 0) return 'Social engineering and phishing';
    if (techniques.filter(t => t.includes('Exploit')).length > 0) return 'Exploit development and zero-days';
    return 'Data exfiltration and persistence';
  }

  assessSophistication(investigation) {
    const techniques = (investigation.mitreTechniques || []).length;
    if (techniques > 15) return 'Very High';
    if (techniques > 10) return 'High';
    if (techniques > 5) return 'Moderate';
    return 'Low';
  }

  identifyAntiAnalysisTechniques(investigation) {
    return investigation.antiAnalysisTechniques || ['Code obfuscation', 'Sandbox detection', 'VM detection'];
  }

  mapKillChainToTimeline(investigation) {
    return [];
  }

  buildKillChainEvidence(investigation) {
    return [];
  }

  identifyKillChainGaps(stages) {
    return ['Reconnaissance evidence limited', 'Weaponization tools not recovered'];
  }

  identifyEvolutionPhases(events) {
    return [
      { name: 'Phase 1: Initial', startDate: events[0]?.date, endDate: 'Phase 1 end', characteristics: [] },
      { name: 'Phase 2: Expansion', startDate: 'Phase 2 start', endDate: 'Phase 2 end', characteristics: [] },
    ];
  }

  identifyImprovementAreas(investigation) {
    return ['Malware evasion', 'C2 resilience', 'Operational security'];
  }

  analyzeSocialEngineeringEvolution(campaign) {
    return [];
  }

  analyzeTargetSelectionEvolution(campaign) {
    return [];
  }

  analyzeOperationalEvolution(campaign) {
    return [];
  }

  projectFutureTargets(campaign) {
    return [];
  }

  projectFutureTechniques(campaign) {
    return [];
  }

  projectInfrastructureEvolution(campaign) {
    return [];
  }

  extractIndustriesFromVictims(victims) {
    return 'multiple';
  }
}

module.exports = { NarrativeEngine };
