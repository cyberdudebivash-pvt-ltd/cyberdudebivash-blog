'use strict';

class CampaignEvolutionEngine {
  trackCampaignEvolution(investigation, historicalData = {}) {
    const campaigns = investigation.campaigns || [];
    const evolution = {
      campaignEvolutions: campaigns.map(campaign => this.analyzeCampaignEvolution(campaign, historicalData[campaign.id])),
      evolutionPatterns: this.identifyEvolutionPatterns(campaigns, historicalData),
      timelineView: this.generateTimelineView(campaigns),
      tacticalShifts: this.detectTacticalShifts(campaigns, historicalData),
      expandedFootprint: this.assessFootprintExpansion(campaigns, historicalData),
      trackedAt: new Date().toISOString(),
    };

    return evolution;
  }

  analyzeCampaignEvolution(campaign, history = {}) {
    const phases = this.identifyCampaignPhases(campaign, history);

    return {
      campaign: campaign.id || campaign.name,
      phases,
      scopeEvolution: this.assessScopeEvolution(campaign, history),
      techniqueEvolution: this.assessTechniqueEvolution(campaign, history),
      targetEvolution: this.assessTargetEvolution(campaign, history),
      malwareEvolution: this.assessMalwareEvolution(campaign, history),
      infrastructureEvolution: this.assessInfrastructureEvolution(campaign, history),
      sophisticationTrend: this.assessSophisticationTrend(campaign, history),
      timeline: this.buildCampaignTimeline(campaign),
    };
  }

  identifyCampaignPhases(campaign, history) {
    const phases = [];
    const startDate = new Date(campaign.startDate);
    const endDate = new Date(campaign.endDate || new Date());
    const durationDays = (endDate - startDate) / (1000 * 60 * 60 * 24);

    if (durationDays <= 7) {
      phases.push({ phase: 'Reconnaissance', duration: '0-2 days', active: true });
      phases.push({ phase: 'Initial Compromise', duration: '2-4 days', active: true });
      phases.push({ phase: 'Post-Exploitation', duration: '4+ days', active: true });
    } else if (durationDays <= 30) {
      phases.push({ phase: 'Reconnaissance', start: startDate, end: new Date(startDate.getTime() + 2 * 24 * 60 * 60 * 1000) });
      phases.push({ phase: 'Initial Compromise', start: new Date(startDate.getTime() + 2 * 24 * 60 * 60 * 1000), end: new Date(startDate.getTime() + 10 * 24 * 60 * 60 * 1000) });
      phases.push({ phase: 'Post-Exploitation', start: new Date(startDate.getTime() + 10 * 24 * 60 * 60 * 1000), end: endDate });
    } else {
      phases.push({ phase: 'Early Phase', percentage: 25, characteristics: 'Low detection rate, infrastructure setup' });
      phases.push({ phase: 'Mid Phase', percentage: 50, characteristics: 'Active exploitation, lateral movement' });
      phases.push({ phase: 'Late Phase', percentage: 75, characteristics: 'Data exfiltration, persistence' });
    }

    return phases;
  }

  assessScopeEvolution(campaign, history) {
    const historicalVictimCounts = history.victimCounts || [];
    const currentCount = campaign.victims?.length || 0;

    return {
      current: currentCount,
      historical: historicalVictimCounts,
      trend: this.calculateTrend(historicalVictimCounts, currentCount),
      expansion: currentCount > (historicalVictimCounts[historicalVictimCounts.length - 1] || 0),
    };
  }

  assessTechniqueEvolution(campaign, history) {
    const historicalTechniques = history.techniques || [];
    const currentTechniques = campaign.techniques || [];

    const newTechniques = currentTechniques.filter(t => !historicalTechniques.includes(t));
    const abandonedTechniques = historicalTechniques.filter(t => !currentTechniques.includes(t));

    return {
      newTechniquesAdopted: newTechniques,
      abandonedTechniques,
      currentTechniqueCount: currentTechniques.length,
      totalHistoricalTechniques: new Set([...historicalTechniques, ...currentTechniques]).size,
      sophisticationChange: newTechniques.length > 0 ? 'increased' : 'maintained',
    };
  }

  assessTargetEvolution(campaign, history) {
    const historicalSectors = new Set(history.sectors || []);
    const historicalRegions = new Set(history.regions || []);
    const currentSectors = new Set((campaign.victims || []).map(v => v.sector));
    const currentRegions = new Set((campaign.victims || []).map(v => v.region));

    const newSectors = [...currentSectors].filter(s => !historicalSectors.has(s));
    const newRegions = [...currentRegions].filter(r => !historicalRegions.has(r));

    return {
      newSectorsTargeted: newSectors,
      newRegionsTargeted: newRegions,
      sectorCount: currentSectors.size,
      regionCount: currentRegions.size,
      expansionTrend: newSectors.length + newRegions.length > 0 ? 'expanding' : 'focused',
    };
  }

  assessMalwareEvolution(campaign, history) {
    const historicalMalware = history.malware || [];
    const currentMalware = campaign.malware || [];

    const newMalware = currentMalware.filter(m => !historicalMalware.includes(m));
    const evolvedMalware = currentMalware.filter(m => historicalMalware.includes(m));

    return {
      newMalwareVariants: newMalware,
      evolvedSamples: evolvedMalware,
      totalMalwareUsed: currentMalware.length,
      malwareRefresh: newMalware.length > 0 ? 'active' : 'stable',
    };
  }

  assessInfrastructureEvolution(campaign, history) {
    const historicalInfra = new Set(history.infrastructure || []);
    const currentInfra = new Set((campaign.infrastructure || []).map(i => i.address || i.ip));

    const newInfra = [...currentInfra].filter(i => !historicalInfra.has(i));
    const reusedInfra = [...currentInfra].filter(i => historicalInfra.has(i));

    return {
      newInfrastructureNodes: newInfra.length,
      reusedInfrastructure: reusedInfra.length,
      totalInfra: currentInfra.size,
      infraRefresh: (newInfra.length / currentInfra.size) > 0.5 ? 'high' : 'low',
    };
  }

  assessSophisticationTrend(campaign, history) {
    const indicators = {
      techniqueCount: campaign.techniques?.length || 0,
      malwareVariety: campaign.malware?.length || 0,
      infraComplexity: campaign.infrastructure?.length || 0,
      operationalSecurity: campaign.opsec ? 'advanced' : 'moderate',
    };

    const score = (indicators.techniqueCount * 0.1) + (indicators.malwareVariety * 0.15) + (indicators.infraComplexity * 0.15) + (indicators.operationalSecurity === 'advanced' ? 0.3 : 0);
    const trend = history.previousSophisticationScore
      ? score > history.previousSophisticationScore ? 'increasing' : 'decreasing'
      : 'unknown';

    return {
      currentScore: Math.min(1.0, score),
      trend,
      indicators,
    };
  }

  buildCampaignTimeline(campaign) {
    const events = [];

    if (campaign.startDate) {
      events.push({
        date: campaign.startDate,
        event: 'Campaign Start',
        detail: 'Initial reconnaissance or compromise observed',
      });
    }

    if (campaign.firstVictim) {
      events.push({
        date: campaign.firstVictim,
        event: 'First Victim Compromised',
      });
    }

    if (campaign.peakActivity) {
      events.push({
        date: campaign.peakActivity,
        event: 'Peak Activity',
        detail: 'Highest concentration of attacks',
      });
    }

    if (campaign.endDate) {
      events.push({
        date: campaign.endDate,
        event: 'Campaign Paused/End',
      });
    }

    return events.sort((a, b) => new Date(a.date) - new Date(b.date));
  }

  identifyEvolutionPatterns(campaigns, historicalData) {
    const patterns = [];

    campaigns.forEach(campaign => {
      const history = historicalData[campaign.id];
      if (!history) return;

      const scopeGrowth = campaign.victims?.length - (history.lastVictimCount || 0);
      if (scopeGrowth > 50) {
        patterns.push({
          type: 'Rapid Scope Expansion',
          campaign: campaign.id,
          description: `${scopeGrowth} new victims in short timeframe`,
          severity: 'high',
        });
      }

      if (campaign.techniques?.length > (history.techniques?.length || 0) + 3) {
        patterns.push({
          type: 'Increased Sophistication',
          campaign: campaign.id,
          description: 'Significant addition of new attack techniques',
          severity: 'medium',
        });
      }

      if (new Set([...(campaign.sectors || []), ...(history.sectors || [])]).size > 5) {
        patterns.push({
          type: 'Multi-Sector Targeting',
          campaign: campaign.id,
          description: 'Broadening targeting across multiple industries',
          severity: 'high',
        });
      }
    });

    return patterns;
  }

  detectTacticalShifts(campaigns, historicalData) {
    const shifts = [];

    campaigns.forEach(campaign => {
      const history = historicalData[campaign.id];
      if (!history) return;

      const oldTactics = new Set(history.tactics || []);
      const newTactics = new Set(campaign.tactics || []);

      const abandonedTactics = [...oldTactics].filter(t => !newTactics.has(t));
      const addedTactics = [...newTactics].filter(t => !oldTactics.has(t));

      if (abandonedTactics.length > 0 || addedTactics.length > 0) {
        shifts.push({
          campaign: campaign.id,
          abandonedTactics,
          newTactics: addedTactics,
          reason: this.inferTacticalShiftReason(history, campaign),
        });
      }
    });

    return shifts;
  }

  inferTacticalShiftReason(history, campaign) {
    if (campaign.detectionRate > (history.detectionRate || 0)) {
      return 'Likely response to increased detection/defense';
    }
    if (campaign.victims?.length > (history.lastVictimCount || 0) * 2) {
      return 'Shift to scale operations';
    }
    return 'Possible response to law enforcement pressure or defensive improvements';
  }

  assessFootprintExpansion(campaigns, historicalData) {
    const expansion = {
      totalNewVictims: 0,
      totalNewSectors: new Set(),
      totalNewRegions: new Set(),
      campaigns: [],
    };

    campaigns.forEach(campaign => {
      const history = historicalData[campaign.id] || {};
      const newVictims = (campaign.victims?.length || 0) - (history.lastVictimCount || 0);

      (campaign.victims || []).forEach(v => {
        if (!history.sectors?.includes(v.sector)) expansion.totalNewSectors.add(v.sector);
        if (!history.regions?.includes(v.region)) expansion.totalNewRegions.add(v.region);
      });

      if (newVictims > 0) {
        expansion.campaigns.push({
          campaign: campaign.id,
          newVictims,
          newSectors: [...expansion.totalNewSectors].length,
          newRegions: [...expansion.totalNewRegions].length,
        });
      }

      expansion.totalNewVictims += Math.max(0, newVictims);
    });

    return {
      ...expansion,
      totalNewSectors: [...expansion.totalNewSectors],
      totalNewRegions: [...expansion.totalNewRegions],
    };
  }

  generateTimelineView(campaigns) {
    const timeline = [];

    campaigns.forEach(campaign => {
      if (campaign.startDate) {
        timeline.push({
          date: campaign.startDate,
          campaign: campaign.id,
          event: 'start',
          victimCount: campaign.victims?.length || 0,
        });
      }
      if (campaign.endDate) {
        timeline.push({
          date: campaign.endDate,
          campaign: campaign.id,
          event: 'end',
          victimCount: campaign.victims?.length || 0,
        });
      }
    });

    return timeline.sort((a, b) => new Date(a.date) - new Date(b.date));
  }

  calculateTrend(historicalValues, currentValue) {
    if (historicalValues.length === 0) return 'new';
    const lastValue = historicalValues[historicalValues.length - 1];
    if (currentValue > lastValue * 1.2) return 'increasing';
    if (currentValue < lastValue * 0.8) return 'decreasing';
    return 'stable';
  }
}

module.exports = { CampaignEvolutionEngine };
