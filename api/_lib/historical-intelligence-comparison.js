'use strict';

class HistoricalIntelligenceComparisonEngine {
  compareIntelligence(currentIntelligence, historicalRecords = []) {
    if (historicalRecords.length === 0) {
      return {
        status: 'no_historical_baseline',
        comparison: null,
        comparedAt: new Date().toISOString(),
      };
    }

    const comparison = {
      actorComparison: this.compareActors(currentIntelligence, historicalRecords),
      campaignComparison: this.compareCampaigns(currentIntelligence, historicalRecords),
      tacticalComparison: this.compareTactics(currentIntelligence, historicalRecords),
      infrastructureComparison: this.compareInfrastructure(currentIntelligence, historicalRecords),
      victimologyComparison: this.compareVictimology(currentIntelligence, historicalRecords),
      sophisticationProgression: this.assessSophisticationProgression(currentIntelligence, historicalRecords),
      trendAnalysis: this.analyzeTrends(currentIntelligence, historicalRecords),
      comparedAt: new Date().toISOString(),
    };

    return comparison;
  }

  compareActors(current, historical) {
    const currentActors = new Map((current.threatActors || []).map(a => [a.id, a]));
    const historicalActors = historical.length > 0
      ? new Map((historical[historical.length - 1].threatActors || []).map(a => [a.id, a]))
      : new Map();

    return {
      newActors: [...currentActors.keys()].filter(id => !historicalActors.has(id)),
      retiredActors: [...historicalActors.keys()].filter(id => !currentActors.has(id)),
      persistentActors: [...currentActors.keys()].filter(id => historicalActors.has(id)),
      actorChanges: this.detailActorChanges(currentActors, historicalActors),
    };
  }

  detailActorChanges(current, historical) {
    const changes = [];

    current.forEach((actor, actorId) => {
      const prevActor = historical.get(actorId);
      if (prevActor) {
        const malwareChange = (actor.knownMalware || []).length - (prevActor.knownMalware || []).length;
        const infraChange = (actor.knownInfrastructure || []).length - (prevActor.knownInfrastructure || []).length;

        if (malwareChange !== 0 || infraChange !== 0) {
          changes.push({
            actor: actorId,
            malwareChange,
            infraChange,
            trend: malwareChange > 0 || infraChange > 0 ? 'expanding' : 'contracting',
          });
        }
      }
    });

    return changes;
  }

  compareCampaigns(current, historical) {
    const currentCampaigns = new Map((current.campaigns || []).map(c => [c.id, c]));
    const historicalCampaigns = historical.length > 0
      ? new Map((historical[historical.length - 1].campaigns || []).map(c => [c.id, c]))
      : new Map();

    return {
      newCampaigns: [...currentCampaigns.keys()].filter(id => !historicalCampaigns.has(id)),
      concludedCampaigns: [...historicalCampaigns.keys()].filter(id => !currentCampaigns.has(id)),
      ongoingCampaigns: [...currentCampaigns.keys()].filter(id => historicalCampaigns.has(id)),
      campaignChanges: this.detailCampaignChanges(currentCampaigns, historicalCampaigns),
    };
  }

  detailCampaignChanges(current, historical) {
    const changes = [];

    current.forEach((campaign, campaignId) => {
      const prevCampaign = historical.get(campaignId);
      if (prevCampaign) {
        const victimDiff = (campaign.victims?.length || 0) - (prevCampaign.victims?.length || 0);
        const expansionRate = victimDiff / Math.max(1, prevCampaign.victims?.length || 0);

        changes.push({
          campaign: campaignId,
          victimGrowth: victimDiff,
          expansionRate,
          status: expansionRate > 0.1 ? 'active' : 'stable',
        });
      }
    });

    return changes;
  }

  compareTactics(current, historical) {
    const currentTactics = new Set((current.mitreTechniques || []).map(t => t.tactic).filter(Boolean));
    const historicalTactics = historical.length > 0
      ? new Set((historical[historical.length - 1].mitreTechniques || []).map(t => t.tactic).filter(Boolean))
      : new Set();

    return {
      newTactics: [...currentTactics].filter(t => !historicalTactics.has(t)),
      abandonedTactics: [...historicalTactics].filter(t => !currentTactics.has(t)),
      persistentTactics: [...currentTactics].filter(t => historicalTactics.has(t)),
      tacticalShift: currentTactics.size > historicalTactics.size ? 'expanding' : 'consolidating',
    };
  }

  compareInfrastructure(current, historical) {
    const currentInfra = new Set((current.infrastructure || []).map(i => i.address || i.ip));
    const historicalInfra = historical.length > 0
      ? new Set((historical[historical.length - 1].infrastructure || []).map(i => i.address || i.ip))
      : new Set();

    return {
      newInfra: [...currentInfra].filter(i => !historicalInfra.has(i)),
      retiredInfra: [...historicalInfra].filter(i => !currentInfra.has(i)),
      reusedInfra: [...currentInfra].filter(i => historicalInfra.has(i)),
      infraRefresh: (([...currentInfra].filter(i => !historicalInfra.has(i)).length) / currentInfra.size) > 0.5
        ? 'high'
        : 'low',
    };
  }

  compareVictimology(current, historical) {
    const currentSectors = new Set((current.victims || []).map(v => v.sector));
    const currentRegions = new Set((current.victims || []).map(v => v.region));

    const historicalSectors = historical.length > 0
      ? new Set((historical[historical.length - 1].victims || []).map(v => v.sector))
      : new Set();
    const historicalRegions = historical.length > 0
      ? new Set((historical[historical.length - 1].victims || []).map(v => v.region))
      : new Set();

    return {
      newSectors: [...currentSectors].filter(s => !historicalSectors.has(s)),
      newRegions: [...currentRegions].filter(r => !historicalRegions.has(r)),
      abandonedSectors: [...historicalSectors].filter(s => !currentSectors.has(s)),
      targetingExpansion: currentSectors.size > historicalSectors.size || currentRegions.size > historicalRegions.size,
    };
  }

  assessSophisticationProgression(current, historical) {
    const currentScore = this.calculateSophisticationScore(current);
    const historicalScores = historical.map(h => this.calculateSophisticationScore(h));

    const progression = {
      currentScore,
      historicalScores,
      trend: this.calculateTrend(historicalScores, currentScore),
      acceleration: historicalScores.length > 1
        ? (currentScore - historicalScores[historicalScores.length - 1]) -
          (historicalScores[historicalScores.length - 1] - historicalScores[historicalScores.length - 2])
        : 0,
    };

    return progression;
  }

  calculateSophisticationScore(intel) {
    let score = 0;
    score += Math.min(0.2, (intel.mitreTechniques?.length || 0) / 20);
    score += Math.min(0.2, (intel.malware?.length || 0) / 10);
    score += Math.min(0.2, (intel.infrastructure?.length || 0) / 30);
    score += Math.min(0.2, (intel.campaigns?.length || 0) / 5);
    score += Math.min(0.2, intel.opsec ? 0.2 : 0.1);
    return Math.min(1.0, score);
  }

  analyzeTrends(current, historical) {
    const trends = {
      activityLevel: this.assessActivityLevel(current, historical),
      operationalPace: this.assessOperationalPace(current, historical),
      targetExpansion: this.assessTargetExpansion(current, historical),
      capabilityGrowth: this.assessCapabilityGrowth(current, historical),
      operationalSecurity: this.assessOpsecTrend(current, historical),
    };

    return trends;
  }

  assessActivityLevel(current, historical) {
    const currentVictims = current.victims?.length || 0;
    const historicalVictims = historical.length > 0 ? historical[historical.length - 1].victims?.length || 0 : 0;

    if (currentVictims > historicalVictims * 1.5) return 'escalating';
    if (currentVictims < historicalVictims * 0.7) return 'declining';
    return 'stable';
  }

  assessOperationalPace(current, historical) {
    const currentCampaigns = current.campaigns?.length || 0;
    const historicalCampaigns = historical.length > 0 ? historical[historical.length - 1].campaigns?.length || 0 : 0;

    if (currentCampaigns > historicalCampaigns) return 'increased';
    if (currentCampaigns < historicalCampaigns) return 'decreased';
    return 'maintained';
  }

  assessTargetExpansion(current, historical) {
    const currentSectors = new Set((current.victims || []).map(v => v.sector)).size;
    const historicalSectors = historical.length > 0
      ? new Set((historical[historical.length - 1].victims || []).map(v => v.sector)).size
      : 0;

    if (currentSectors > historicalSectors) return 'expanding';
    if (currentSectors < historicalSectors) return 'contracting';
    return 'stable';
  }

  assessCapabilityGrowth(current, historical) {
    const currentCapabilities = (current.mitreTechniques?.length || 0) + (current.malware?.length || 0);
    const historicalCapabilities = historical.length > 0
      ? ((historical[historical.length - 1].mitreTechniques || []).length +
        (historical[historical.length - 1].malware || []).length)
      : 0;

    if (currentCapabilities > historicalCapabilities * 1.3) return 'rapidly_expanding';
    if (currentCapabilities > historicalCapabilities) return 'growing';
    if (currentCapabilities < historicalCapabilities) return 'declining';
    return 'static';
  }

  assessOpsecTrend(current, historical) {
    const currentOpsecScore = (current.opsec || current.operationalSecurity) ? 0.8 : 0.4;
    const historicalOpsecScore = historical.length > 0
      ? ((historical[historical.length - 1].opsec || historical[historical.length - 1].operationalSecurity) ? 0.8 : 0.4)
      : 0.5;

    if (currentOpsecScore > historicalOpsecScore) return 'improving';
    if (currentOpsecScore < historicalOpsecScore) return 'degrading';
    return 'consistent';
  }

  calculateTrend(historicalValues, currentValue) {
    if (historicalValues.length === 0) return 'new';
    const lastValue = historicalValues[historicalValues.length - 1];
    if (currentValue > lastValue * 1.1) return 'increasing';
    if (currentValue < lastValue * 0.9) return 'decreasing';
    return 'stable';
  }
}

module.exports = { HistoricalIntelligenceComparisonEngine };
