'use strict';

class IntelligenceChangeDetectionEngine {
  detectChanges(currentIntelligence, previousIntelligence = {}) {
    if (!previousIntelligence || Object.keys(previousIntelligence).length === 0) {
      return {
        status: 'baseline_established',
        changes: [],
        detectionTime: new Date().toISOString(),
      };
    }

    const changes = {
      actorChanges: this.detectActorChanges(currentIntelligence, previousIntelligence),
      campaignChanges: this.detectCampaignChanges(currentIntelligence, previousIntelligence),
      malwareChanges: this.detectMalwareChanges(currentIntelligence, previousIntelligence),
      infrastructureChanges: this.detectInfrastructureChanges(currentIntelligence, previousIntelligence),
      iocChanges: this.detectIOCChanges(currentIntelligence, previousIntelligence),
      attributionChanges: this.detectAttributionChanges(currentIntelligence, previousIntelligence),
      confidenceChanges: this.detectConfidenceChanges(currentIntelligence, previousIntelligence),
      detectionTime: new Date().toISOString(),
      changeCount: 0,
      significantChanges: [],
    };

    changes.changeCount = Object.values(changes)
      .filter(v => Array.isArray(v))
      .reduce((sum, arr) => sum + arr.length, 0);

    changes.significantChanges = this.identifySignificantChanges(changes);

    return changes;
  }

  detectActorChanges(current, previous) {
    const changes = [];
    const currentActors = new Map((current.threatActors || []).map(a => [a.id, a]));
    const previousActors = new Map((previous.threatActors || []).map(a => [a.id, a]));

    currentActors.forEach((actor, actorId) => {
      const prevActor = previousActors.get(actorId);
      if (!prevActor) {
        changes.push({
          type: 'new_actor',
          actor: actorId,
          detail: `New threat actor identified: ${actor.name}`,
          severity: 'medium',
        });
      } else {
        if (JSON.stringify(actor.knownMalware) !== JSON.stringify(prevActor.knownMalware)) {
          changes.push({
            type: 'actor_malware_update',
            actor: actorId,
            detail: 'Known malware portfolio changed',
            severity: 'medium',
          });
        }
        if (actor.lastSeen !== prevActor.lastSeen) {
          changes.push({
            type: 'actor_activity_update',
            actor: actorId,
            previousLastSeen: prevActor.lastSeen,
            newLastSeen: actor.lastSeen,
            severity: 'high',
          });
        }
      }
    });

    previousActors.forEach((actor, actorId) => {
      if (!currentActors.has(actorId)) {
        changes.push({
          type: 'actor_removed',
          actor: actorId,
          detail: 'Actor removed from analysis (may indicate dismantling)',
          severity: 'low',
        });
      }
    });

    return changes;
  }

  detectCampaignChanges(current, previous) {
    const changes = [];
    const currentCampaigns = new Map((current.campaigns || []).map(c => [c.id, c]));
    const previousCampaigns = new Map((previous.campaigns || []).map(c => [c.id, c]));

    currentCampaigns.forEach((campaign, campaignId) => {
      const prevCampaign = previousCampaigns.get(campaignId);
      if (!prevCampaign) {
        changes.push({
          type: 'new_campaign',
          campaign: campaignId,
          detail: `New campaign discovered: ${campaign.name}`,
          severity: 'high',
        });
      } else {
        const victimDiff = (campaign.victims?.length || 0) - (prevCampaign.victims?.length || 0);
        if (victimDiff !== 0) {
          changes.push({
            type: 'campaign_scope_change',
            campaign: campaignId,
            previousVictims: prevCampaign.victims?.length || 0,
            currentVictims: campaign.victims?.length || 0,
            victimDiff,
            severity: victimDiff > 10 ? 'high' : 'medium',
          });
        }

        if (JSON.stringify(campaign.tactics) !== JSON.stringify(prevCampaign.tactics)) {
          changes.push({
            type: 'campaign_tactic_change',
            campaign: campaignId,
            detail: 'Tactical approach has changed',
            severity: 'medium',
          });
        }
      }
    });

    return changes;
  }

  detectMalwareChanges(current, previous) {
    const changes = [];
    const currentMalware = new Map((current.malware || []).map(m => [m.id, m]));
    const previousMalware = new Map((previous.malware || []).map(m => [m.id, m]));

    currentMalware.forEach((malware, malwareId) => {
      const prevMalware = previousMalware.get(malwareId);
      if (!prevMalware) {
        changes.push({
          type: 'new_malware',
          malware: malwareId,
          detail: `New malware sample/family: ${malware.name}`,
          severity: 'high',
        });
      } else {
        if (malware.detectionRate > prevMalware.detectionRate) {
          changes.push({
            type: 'malware_detection_increase',
            malware: malwareId,
            previousDetectionRate: prevMalware.detectionRate,
            currentDetectionRate: malware.detectionRate,
            severity: 'medium',
          });
        }
      }
    });

    return changes;
  }

  detectInfrastructureChanges(current, previous) {
    const changes = [];
    const currentInfra = new Map((current.infrastructure || []).map(i => [i.id, i]));
    const previousInfra = new Map((previous.infrastructure || []).map(i => [i.id, i]));

    currentInfra.forEach((infra, infraId) => {
      const prevInfra = previousInfra.get(infraId);
      if (!prevInfra) {
        changes.push({
          type: 'new_infrastructure',
          infrastructure: infraId,
          detail: `New infrastructure node: ${infra.address || infra.ip}`,
          severity: 'high',
        });
      } else {
        if (infra.lastActive !== prevInfra.lastActive) {
          changes.push({
            type: 'infrastructure_activity_change',
            infrastructure: infraId,
            previousLastActive: prevInfra.lastActive,
            newLastActive: infra.lastActive,
            severity: 'medium',
          });
        }
      }
    });

    return changes;
  }

  detectIOCChanges(current, previous) {
    const changes = [];
    const currentIOCs = new Map((current.iocs || []).map(i => [i.id, i]));
    const previousIOCs = new Map((previous.iocs || []).map(i => [i.id, i]));

    const newIOCs = [...currentIOCs.keys()].filter(id => !previousIOCs.has(id));
    if (newIOCs.length > 0) {
      changes.push({
        type: 'new_iocs_discovered',
        count: newIOCs.length,
        detail: `${newIOCs.length} new IOCs identified`,
        severity: 'medium',
      });
    }

    return changes;
  }

  detectAttributionChanges(current, previous) {
    const changes = [];

    const currentTopActor = (current.threatActors || [])[0];
    const previousTopActor = (previous.threatActors || [])[0];

    if (currentTopActor && previousTopActor && currentTopActor.id !== previousTopActor.id) {
      changes.push({
        type: 'attribution_shift',
        previousAttribution: previousTopActor.id,
        currentAttribution: currentTopActor.id,
        detail: 'Primary threat attribution has changed',
        severity: 'high',
      });
    }

    return changes;
  }

  detectConfidenceChanges(current, previous) {
    const changes = [];

    if (current.confidence && previous.confidence && current.confidence !== previous.confidence) {
      const confidenceDiff = current.confidence - previous.confidence;
      const severity = Math.abs(confidenceDiff) > 0.2 ? 'high' : 'medium';

      changes.push({
        type: 'confidence_change',
        previousConfidence: previous.confidence,
        currentConfidence: current.confidence,
        change: confidenceDiff > 0 ? 'increased' : 'decreased',
        severity,
      });
    }

    return changes;
  }

  identifySignificantChanges(allChanges) {
    const significant = [];

    const severityMap = {
      'actor_activity_update': { type: 'Actor Activity Update', priority: 1 },
      'new_campaign': { type: 'New Campaign', priority: 2 },
      'new_actor': { type: 'New Actor Identified', priority: 3 },
      'new_infrastructure': { type: 'New Infrastructure', priority: 4 },
      'new_malware': { type: 'New Malware', priority: 5 },
      'attribution_shift': { type: 'Attribution Change', priority: 6 },
      'campaign_scope_change': { type: 'Campaign Scope Change', priority: 7 },
    };

    Object.entries(allChanges).forEach(([key, changes]) => {
      if (Array.isArray(changes)) {
        changes.forEach(change => {
          if (severityMap[change.type] && change.severity === 'high') {
            significant.push({
              ...severityMap[change.type],
              detail: change,
              notificationRecommended: true,
            });
          }
        });
      }
    });

    return significant.sort((a, b) => a.priority - b.priority);
  }

  generateChangeNotification(changes) {
    if (changes.significantChanges.length === 0) {
      return null;
    }

    const notification = {
      title: 'Intelligence Update - Significant Changes Detected',
      summary: `${changes.changeCount} changes detected across intelligence holdings`,
      details: changes.significantChanges.slice(0, 5).map(c => `${c.type}: ${JSON.stringify(c.detail)}`),
      priority: changes.significantChanges.some(c => c.detail.severity === 'high') ? 'urgent' : 'normal',
      timestamp: changes.detectionTime,
    };

    return notification;
  }
}

module.exports = { IntelligenceChangeDetectionEngine };
