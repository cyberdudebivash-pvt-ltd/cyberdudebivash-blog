'use strict';

class IOCIntelligenceEngine {
  groupIOCs(investigation) {
    const iocs = investigation.iocs || [];

    return {
      byType: this.groupByType(iocs),
      byTimeframe: this.groupByTimeframe(iocs),
      byConfidence: this.groupByConfidence(iocs),
      withContext: this.addContextToIOCs(iocs, investigation),
      firstLastSeen: this.calculateTimeframes(iocs),
      validation: this.assessIOCValidation(iocs),
    };
  }

  groupByType(iocs) {
    const grouped = {};
    iocs.forEach(ioc => {
      if (!grouped[ioc.type]) grouped[ioc.type] = [];
      grouped[ioc.type].push(ioc);
    });
    return grouped;
  }

  groupByTimeframe(iocs) {
    const now = new Date();
    return {
      last_24h: iocs.filter(i => this.isWithin(new Date(i.firstSeen), 24)),
      last_7d: iocs.filter(i => this.isWithin(new Date(i.firstSeen), 7 * 24)),
      last_30d: iocs.filter(i => this.isWithin(new Date(i.firstSeen), 30 * 24)),
      older: iocs.filter(i => !this.isWithin(new Date(i.firstSeen), 30 * 24)),
    };
  }

  groupByConfidence(iocs) {
    return {
      high: iocs.filter(i => (i.confidence || 0) >= 0.8),
      moderate: iocs.filter(i => (i.confidence || 0) >= 0.5 && (i.confidence || 0) < 0.8),
      low: iocs.filter(i => (i.confidence || 0) < 0.5),
    };
  }

  addContextToIOCs(iocs, investigation) {
    return iocs.slice(0, 20).map(ioc => ({
      ...ioc,
      relatedFindings: (investigation.findings || []).filter(f =>
        f.description?.includes(ioc.value)
      ).length,
      relatedTechniques: (investigation.mitreTechniques || []).filter(t =>
        (investigation.iocsForTechniques?.[t] || []).includes(ioc.id)
      ),
      infrastructure: (investigation.infrastructure || []).find(i =>
        i.ip === ioc.value || i.domain === ioc.value
      ),
    }));
  }

  calculateTimeframes(iocs) {
    if (iocs.length === 0) return { firstSeen: null, lastSeen: null };

    const dates = iocs
      .map(i => ({ first: new Date(i.firstSeen), last: new Date(i.lastSeen) }))
      .filter(d => d.first && d.last);

    if (dates.length === 0) return { firstSeen: null, lastSeen: null };

    return {
      firstSeen: new Date(Math.min(...dates.map(d => d.first))),
      lastSeen: new Date(Math.max(...dates.map(d => d.last))),
      duration: this.calculateDuration(
        new Date(Math.min(...dates.map(d => d.first))),
        new Date(Math.max(...dates.map(d => d.last)))
      ),
    };
  }

  assessIOCValidation(iocs) {
    const validated = iocs.filter(i => i.validated || i.validation);
    return {
      validated: validated.length,
      total: iocs.length,
      validationRate: parseFloat(((validated.length / iocs.length) * 100).toFixed(1)) + '%',
    };
  }

  isWithin(date, hours) {
    const now = new Date();
    const diffMs = now - date;
    const diffHours = diffMs / (1000 * 60 * 60);
    return diffHours <= hours;
  }

  calculateDuration(start, end) {
    const diffMs = end - start;
    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    return `${days} days`;
  }
}

class InfrastructureIntelligenceEngine {
  analyzeInfrastructure(investigation) {
    const infrastructure = investigation.infrastructure || [];

    return {
      byType: this.groupByType(infrastructure),
      asn: this.analyzeASNs(infrastructure),
      providers: this.analyzeProviders(infrastructure),
      geography: this.analyzeGeography(infrastructure),
      clustering: this.identifyClusters(infrastructure),
      opsec: this.assessOperationalSecurity(infrastructure),
    };
  }

  groupByType(infrastructure) {
    return {
      c2_servers: infrastructure.filter(i => i.type === 'C2'),
      staging: infrastructure.filter(i => i.type === 'Staging'),
      malware_hosting: infrastructure.filter(i => i.type === 'Malware Hosting'),
      phishing: infrastructure.filter(i => i.type === 'Phishing'),
      bulletproof_hosting: infrastructure.filter(i => i.bulletproof),
    };
  }

  analyzeASNs(infrastructure) {
    const asns = infrastructure.map(i => i.asn).filter(Boolean);
    const unique = [...new Set(asns)];
    return {
      unique_asns: unique.length,
      asns: unique,
      distribution: this.countDistribution(asns),
    };
  }

  analyzeProviders(infrastructure) {
    const providers = infrastructure.map(i => i.provider).filter(Boolean);
    const unique = [...new Set(providers)];
    return {
      unique_providers: unique.length,
      providers: unique,
    };
  }

  analyzeGeography(infrastructure) {
    const countries = infrastructure.map(i => i.country).filter(Boolean);
    const unique = [...new Set(countries)];
    return {
      countries: unique.length,
      distribution: this.countDistribution(countries),
    };
  }

  identifyClusters(infrastructure) {
    // Infrastructure that shares providers, ASNs, or registration info
    return infrastructure.slice(0, 5).map(i => ({
      server: i.ip || i.domain,
      related: infrastructure.filter(
        x => (x.asn === i.asn || x.provider === i.provider) && x.id !== i.id
      ).length,
    }));
  }

  assessOperationalSecurity(infrastructure) {
    return {
      level: 'High',
      observations: [
        'Use of bulletproof hosting providers',
        'Geographic distribution of servers',
        'Rapid domain rotation',
        'Use of privacy registrations',
      ],
    };
  }

  countDistribution(items) {
    const dist = {};
    items.forEach(item => {
      dist[item] = (dist[item] || 0) + 1;
    });
    return dist;
  }
}

class ThreatActorIntelligenceEngine {
  generateActorProfile(investigation) {
    const actors = investigation.threatActors || [];
    if (actors.length === 0) return null;

    const actor = actors[0];

    return {
      profile: {
        name: actor.name,
        aliases: actor.aliases || [],
        attribution: actor.attributionConfidence,
        capability_level: this.assessCapability(investigation),
        motivation: actor.motivation,
        origin: actor.origin || 'Unknown',
      },
      history: {
        first_observed: actor.firstObserved,
        campaigns: actor.campaigns?.length || 0,
        known_targets: actor.knownTargets?.length || 0,
      },
      tactics_techniques: {
        count: (investigation.mitreTechniques || []).length,
        tactics: [...new Set((investigation.mitreTechniques || []).map(t => t.tactic))],
      },
      infrastructure: this.actorInfrastructure(investigation, actor),
      malware: (investigation.malwareVariants || []).slice(0, 5),
    };
  }

  assessCapability(investigation) {
    const techniques = (investigation.mitreTechniques || []).length;
    if (techniques > 15) return 'Very High';
    if (techniques > 10) return 'High';
    if (techniques > 5) return 'Moderate';
    return 'Low';
  }

  actorInfrastructure(investigation, actor) {
    const infrastructure = (investigation.infrastructure || []).filter(i =>
      i.associatedActors?.includes(actor.name)
    );
    return {
      count: infrastructure.length,
      c2: infrastructure.filter(i => i.type === 'C2'),
    };
  }
}

class CampaignIntelligenceEngine {
  generateCampaignAnalysis(investigation) {
    const campaigns = investigation.campaigns || [];
    if (campaigns.length === 0) return null;

    const campaign = campaigns[0];
    const victims = investigation.victims || [];

    return {
      campaign: {
        name: campaign.name,
        aliases: campaign.aliases || [],
        status: campaign.status || 'Ongoing',
      },
      timeline: {
        firstObserved: campaign.startDate,
        lastObserved: campaign.endDate,
        duration: this.calculateDuration(campaign.startDate, campaign.endDate),
      },
      scope: {
        confirmed_victims: victims.length,
        industries: Object.keys(investigation.industryImpact || {}),
        geographic: [...new Set(victims.map(v => v.country))],
      },
      objectives: {
        primary: campaign.primaryObjective || 'Data theft',
        secondary: campaign.secondaryObjectives || [],
      },
      targeting: {
        industry_focus: this.identifyIndustryFocus(victims),
        organization_size: this.analyzeTargetSize(victims),
        strategic_value: 'High-value data and intellectual property',
      },
      infrastructure: {
        domains: (investigation.infrastructure || []).filter(i => i.type === 'C2').length,
        servers: (investigation.infrastructure || []).length,
        evolution: 'Increasing sophistication',
      },
    };
  }

  calculateDuration(start, end) {
    if (!start || !end) return 'Unknown';
    const diffMs = new Date(end) - new Date(start);
    return Math.floor(diffMs / (1000 * 60 * 60 * 24)) + ' days';
  }

  identifyIndustryFocus(victims) {
    const industries = {};
    victims.forEach(v => {
      industries[v.industry] = (industries[v.industry] || 0) + 1;
    });
    const sorted = Object.entries(industries).sort((a, b) => b[1] - a[1]);
    return sorted.slice(0, 3).map(([ind, count]) => `${ind} (${count})`);
  }

  analyzeTargetSize(victims) {
    return {
      small: victims.filter(v => v.size === 'small').length,
      medium: victims.filter(v => v.size === 'medium').length,
      large: victims.filter(v => v.size === 'large').length,
      enterprise: victims.filter(v => v.size === 'enterprise').length,
    };
  }
}

module.exports = {
  IOCIntelligenceEngine,
  InfrastructureIntelligenceEngine,
  ThreatActorIntelligenceEngine,
  CampaignIntelligenceEngine,
};
