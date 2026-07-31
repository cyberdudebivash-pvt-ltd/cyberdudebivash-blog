'use strict';

class AttributionEngine {
  assessAttribution(investigation, report) {
    const attributions = {
      threatActorAttributions: this.assessThreatActorAttribution(investigation),
      campaignAttributions: this.assessCampaignAttribution(investigation),
      attributionConfidenceFramework: this.buildAttributionConfidenceFramework(investigation),
      uncertaintyFactors: this.identifyUncertaintyFactors(investigation),
      attributionNarrative: this.generateAttributionNarrative(investigation),
      assessedAt: new Date().toISOString(),
    };

    return attributions;
  }

  assessThreatActorAttribution(investigation) {
    const findings = investigation.findings || [];
    const iocs = investigation.iocs || [];
    const techniques = investigation.mitreTechniques || [];
    const infrastructure = investigation.infrastructure || [];

    const attributions = [];

    (investigation.threatActors || []).forEach(actor => {
      const evidence = {
        iopOverlap: this.calculateIOCOverlap(actor, iocs),
        techniqueMatch: this.calculateTechniqueMatch(actor, techniques),
        infrastructureMatch: this.calculateInfrastructureMatch(actor, infrastructure),
        historicalPattern: this.assessHistoricalPattern(actor, investigation),
        victimologyMatch: this.assessVictimologyMatch(actor, investigation),
        malwareMatch: this.assessMalwareMatch(actor, investigation),
      };

      const confidence = this.calculateAttributionConfidence(evidence);

      attributions.push({
        actor: actor.id || actor.name,
        aliases: actor.aliases || [],
        confidence,
        confidenceLevel: this.confidenceToLevel(confidence),
        evidence,
        supportingFindings: this.extractSupportingFindings(actor, findings),
        contradictingEvidence: this.extractContradictingEvidence(actor, findings, investigation),
        reasoning: this.generateAttributionReasoning(actor, evidence),
        alternativeAttributions: this.suggestAlternatives(actor, investigation),
      });
    });

    return attributions.sort((a, b) => b.confidence - a.confidence);
  }

  assessCampaignAttribution(investigation) {
    const campaigns = investigation.campaigns || [];
    const attributions = [];

    campaigns.forEach(campaign => {
      const evidence = {
        tacticalPattern: this.assessTacticalPattern(campaign),
        temporalPattern: this.assessTemporalPattern(campaign),
        geographicPattern: this.assessGeographicPattern(campaign, investigation),
        targetingPattern: this.assessTargetingPattern(campaign),
        toolUsage: this.assessToolUsage(campaign),
      };

      const confidence = this.calculateCampaignConfidence(evidence);

      attributions.push({
        campaign: campaign.id || campaign.name,
        confidence,
        confidenceLevel: this.confidenceToLevel(confidence),
        evidence,
        possibleActors: this.attributeCampaignToActors(campaign, investigation),
        timeline: campaign.timeline || [],
        reasoning: this.generateCampaignAttributionReasoning(campaign, evidence),
      });
    });

    return attributions;
  }

  calculateIOCOverlap(actor, iocs) {
    const actorIOCs = new Set(actor.knownIOCs || []);
    const investigationIOCs = new Set(iocs.map(ioc => ioc.value));

    const overlap = [...investigationIOCs].filter(ioc => actorIOCs.has(ioc));
    const overlapScore = overlap.length / Math.max(1, investigationIOCs.size);

    return {
      matchingIOCs: overlap.length,
      totalIOCs: investigationIOCs.size,
      overlapPercentage: (overlapScore * 100).toFixed(1),
      score: Math.min(1.0, overlapScore * 1.5),
    };
  }

  calculateTechniqueMatch(actor, techniques) {
    const actorTechniques = new Set(actor.ttps || []);
    const investigationTechniques = new Set(techniques.map(t => t.id));

    const matches = [...investigationTechniques].filter(t => actorTechniques.has(t));
    const matchScore = matches.length / Math.max(1, investigationTechniques.size);

    return {
      matchingTechniques: matches.length,
      totalTechniques: investigationTechniques.size,
      matchPercentage: (matchScore * 100).toFixed(1),
      score: Math.min(1.0, matchScore),
    };
  }

  calculateInfrastructureMatch(actor, infrastructure) {
    const actorInfra = new Set(actor.knownInfrastructure || []);
    const investigationInfra = new Set(infrastructure.map(i => i.address || i.ip));

    const matches = [...investigationInfra].filter(i => actorInfra.has(i));
    const matchScore = matches.length / Math.max(1, investigationInfra.size);

    return {
      matchingInfra: matches.length,
      totalInfra: investigationInfra.size,
      matchPercentage: (matchScore * 100).toFixed(1),
      score: Math.min(1.0, matchScore * 2.0),
    };
  }

  assessHistoricalPattern(actor, investigation) {
    const investigationDate = investigation.incidentDate || new Date().toISOString();
    const lastSeenDate = actor.lastSeen || investigation.lastActivity;

    if (!lastSeenDate) {
      return {
        lastKnownActivity: 'unknown',
        timeGap: 'unknown',
        score: 0.5,
      };
    }

    const timeDiffMs = new Date(investigationDate).getTime() - new Date(lastSeenDate).getTime();
    const timeDiffDays = timeDiffMs / (1000 * 60 * 60 * 24);

    let score = 0.9;
    if (timeDiffDays > 365) score = 0.6;
    if (timeDiffDays > 730) score = 0.3;

    return {
      lastKnownActivity: lastSeenDate,
      timeGap: `${Math.floor(timeDiffDays)} days`,
      score,
    };
  }

  assessVictimologyMatch(actor, investigation) {
    const investigationVictimSectors = new Set((investigation.victims || []).map(v => v.sector));
    const investigationVictimRegions = new Set((investigation.victims || []).map(v => v.region));
    const actorVictimSectors = new Set(actor.targetSectors || actor.target_sectors || []);
    const actorVictimRegions = new Set(actor.targetRegions || actor.target_regions || []);

    const sectorMatches = [...investigationVictimSectors].filter(s => actorVictimSectors.has(s));
    const regionMatches = [...investigationVictimRegions].filter(r => actorVictimRegions.has(r));

    const sectorScore = sectorMatches.length / Math.max(1, investigationVictimSectors.size);
    const regionScore = regionMatches.length / Math.max(1, investigationVictimRegions.size);

    return {
      matchingSectors: sectorMatches,
      matchingRegions: regionMatches,
      sectorScore: sectorScore,
      regionScore: regionScore,
      score: (sectorScore + regionScore) / 2,
    };
  }

  assessMalwareMatch(actor, investigation) {
    const actorMalware = new Set(actor.knownMalware || []);
    const investigationMalware = new Set((investigation.malware || []).map(m => m.id));

    const matches = [...investigationMalware].filter(m => actorMalware.has(m));
    const matchScore = matches.length / Math.max(1, investigationMalware.size);

    return {
      matchingMalware: matches.length,
      totalMalware: investigationMalware.size,
      matchPercentage: (matchScore * 100).toFixed(1),
      score: Math.min(1.0, matchScore * 1.2),
    };
  }

  calculateAttributionConfidence(evidence) {
    const scores = [
      evidence.iopOverlap?.score || 0,
      evidence.techniqueMatch?.score || 0,
      evidence.infrastructureMatch?.score || 0,
      evidence.historicalPattern?.score || 0.5,
      evidence.victimologyMatch?.score || 0,
      evidence.malwareMatch?.score || 0,
    ];

    const weights = [0.25, 0.20, 0.25, 0.10, 0.12, 0.08];
    const weightedScore = scores.reduce((sum, score, i) => sum + (score * weights[i]), 0);

    return Math.min(1.0, Math.max(0.0, weightedScore));
  }

  calculateCampaignConfidence(evidence) {
    const scores = [
      evidence.tacticalPattern?.score || 0.5,
      evidence.temporalPattern?.score || 0.5,
      evidence.geographicPattern?.score || 0.5,
      evidence.targetingPattern?.score || 0.5,
      evidence.toolUsage?.score || 0.5,
    ];

    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    return Math.min(1.0, avgScore);
  }

  confidenceToLevel(confidence) {
    if (confidence >= 0.9) return 'High';
    if (confidence >= 0.7) return 'Moderate-High';
    if (confidence >= 0.5) return 'Moderate';
    if (confidence >= 0.3) return 'Low-Moderate';
    return 'Low';
  }

  extractSupportingFindings(actor, findings) {
    return findings.filter(f => {
      const text = JSON.stringify(f).toLowerCase();
      const actorName = (actor.name || actor.id || '').toLowerCase();
      return text.includes(actorName) || (f.attribution && f.attribution.includes(actor.id));
    });
  }

  extractContradictingEvidence(actor, findings, investigation) {
    const contradicting = [];

    findings.forEach(f => {
      if (f.attributedActor && f.attributedActor !== actor.id && f.confidence > 0.7) {
        contradicting.push({
          finding: f.id,
          attributedTo: f.attributedActor,
          confidence: f.confidence,
          reasoning: `Finding attributed to different actor with higher confidence`,
        });
      }
    });

    return contradicting;
  }

  generateAttributionReasoning(actor, evidence) {
    const reasons = [];

    if (evidence.iopOverlap.score > 0.6) {
      reasons.push(`${evidence.iopOverlap.matchingIOCs} IOCs match known infrastructure (${evidence.iopOverlap.overlapPercentage}% overlap)`);
    }

    if (evidence.techniqueMatch.score > 0.6) {
      reasons.push(`${evidence.techniqueMatch.matchingTechniques} MITRE techniques align with known TTPs`);
    }

    if (evidence.infrastructureMatch.score > 0.6) {
      reasons.push(`Direct infrastructure overlap with ${evidence.infrastructureMatch.matchingInfra} known nodes`);
    }

    if (evidence.victimologyMatch.score > 0.5) {
      reasons.push(`Victim profile (sectors/regions) consistent with known targeting patterns`);
    }

    if (evidence.historicalPattern.score > 0.6) {
      reasons.push(`Activity timeframe aligns with recent ${actor.name} campaigns`);
    }

    return reasons;
  }

  generateCampaignAttributionReasoning(campaign, evidence) {
    const reasons = [];
    if (evidence.temporalPattern?.score > 0.6) reasons.push('Temporal pattern consistent with historical campaigns');
    if (evidence.geographicPattern?.score > 0.6) reasons.push('Geographic targeting follows known pattern');
    if (evidence.targetingPattern?.score > 0.6) reasons.push('Victim selection matches historical targeting');
    return reasons;
  }

  suggestAlternatives(actor, investigation) {
    return (investigation.threatActors || [])
      .filter(a => a.id !== actor.id)
      .slice(0, 3)
      .map(a => ({
        actor: a.id,
        name: a.name,
        reason: 'Similar TTPs or targeting patterns',
        confidence: 0.3,
      }));
  }

  assessTacticalPattern(campaign) {
    return {
      patternType: campaign.tactics || 'mixed',
      score: 0.7,
    };
  }

  assessTemporalPattern(campaign) {
    const startDate = new Date(campaign.startDate);
    const endDate = new Date(campaign.endDate || new Date());
    const durationDays = (endDate - startDate) / (1000 * 60 * 60 * 24);

    return {
      duration: `${Math.floor(durationDays)} days`,
      score: Math.min(0.9, 0.5 + (durationDays / 365 * 0.1)),
    };
  }

  assessGeographicPattern(campaign, investigation) {
    const regions = investigation.geoImpact ? Object.keys(investigation.geoImpact) : [];
    return {
      affectedRegions: regions.length,
      score: Math.min(0.9, 0.5 + (regions.length * 0.1)),
    };
  }

  assessTargetingPattern(campaign) {
    const victims = campaign.victims || [];
    return {
      targetCount: victims.length,
      score: Math.min(0.9, victims.length / 100),
    };
  }

  assessToolUsage(campaign) {
    const tools = campaign.tools || [];
    return {
      toolCount: tools.length,
      score: Math.min(0.9, tools.length / 10),
    };
  }

  attributeCampaignToActors(campaign, investigation) {
    const possibleActors = [];

    (investigation.threatActors || []).forEach(actor => {
      const commonCampaigns = (actor.campaigns || []).filter(c => c === campaign.id);
      if (commonCampaigns.length > 0) {
        possibleActors.push({
          actor: actor.id,
          confidence: 0.85,
        });
      }
    });

    return possibleActors;
  }

  buildAttributionConfidenceFramework(investigation) {
    return {
      framework: 'MITRE ATT&CK + IoC overlap + Victimology + Infrastructure match',
      factors: [
        { factor: 'IOC Overlap', weight: 0.25, evidence: 'Direct matches in IP, domain, file hash' },
        { factor: 'Technique Match', weight: 0.20, evidence: 'MITRE ATT&CK TTP overlap' },
        { factor: 'Infrastructure', weight: 0.25, evidence: 'Overlapping C2, hosting, or proxy infrastructure' },
        { factor: 'Historical Pattern', weight: 0.10, evidence: 'Timeline alignment with known operations' },
        { factor: 'Victimology', weight: 0.12, evidence: 'Sector/region targeting consistency' },
        { factor: 'Malware', weight: 0.08, evidence: 'Known malware family usage' },
      ],
    };
  }

  identifyUncertaintyFactors(investigation) {
    const factors = [];

    if (!investigation.incidentDate) factors.push('Incomplete incident timeline');
    if ((investigation.findings || []).length < 3) factors.push('Limited forensic findings');
    if ((investigation.iocs || []).length < 5) factors.push('Small IOC dataset');
    if ((investigation.threatActors || []).length === 0) factors.push('No known actor profiles for comparison');
    if ((investigation.infrastructure || []).length === 0) factors.push('No infrastructure evidence');

    return factors;
  }

  generateAttributionNarrative(investigation) {
    const topActor = (investigation.threatActors || []).sort((a, b) =>
      (b.confidence || 0) - (a.confidence || 0)
    )[0];

    if (!topActor) {
      return 'Attribution to a specific threat actor cannot be determined with available evidence. The attack pattern may represent a new actor, a variant of a known group, or a false flag operation.';
    }

    return `Based on IOC overlap, MITRE ATT&CK technique clustering, and infrastructure analysis, attribution to ${topActor.name} is assessed with moderate-high confidence. However, this assessment is subject to change as additional forensic evidence is collected and analyzed.`;
  }
}

module.exports = { AttributionEngine };
