'use strict';

class EvidenceConflictEngine {
  detectConflicts(investigation, report) {
    const conflicts = {
      attributionConflicts: this.detectAttributionConflicts(investigation),
      timelineConflicts: this.detectTimelineConflicts(investigation),
      motioneConflicts: this.detectMotivationConflicts(investigation),
      tacticalConflicts: this.detectTacticalConflicts(investigation),
      victimologyConflicts: this.detectVictimologyConflicts(investigation),
      scopeConflicts: this.detectScopeConflicts(investigation),
      conflictCount: 0,
      conflictSeverity: 'none',
      resolutionRecommendations: [],
      analyzedAt: new Date().toISOString(),
    };

    conflicts.conflictCount = Object.values(conflicts)
      .filter(v => Array.isArray(v))
      .reduce((sum, arr) => sum + arr.length, 0);

    conflicts.conflictSeverity = this.assessConflictSeverity(conflicts.conflictCount);
    conflicts.resolutionRecommendations = this.generateResolutionRecommendations(conflicts);

    return conflicts;
  }

  detectAttributionConflicts(investigation) {
    const conflicts = [];
    const threatActors = investigation.threatActors || [];

    for (let i = 0; i < threatActors.length; i++) {
      for (let j = i + 1; j < threatActors.length; j++) {
        const actor1 = threatActors[i];
        const actor2 = threatActors[j];

        const actor1Confidence = actor1.confidence || 0.5;
        const actor2Confidence = actor2.confidence || 0.5;

        if (Math.abs(actor1Confidence - actor2Confidence) < 0.15 && actor1.id !== actor2.id) {
          conflicts.push({
            type: 'competing_attribution',
            actor1: actor1.id,
            actor2: actor2.id,
            actor1Confidence,
            actor2Confidence,
            severityGap: Math.abs(actor1Confidence - actor2Confidence),
            evidenceConflict: this.identifyAttributionEvidenceConflict(actor1, actor2),
            resolution: 'Requires additional forensic evidence to disambiguate',
          });
        }

        const commonInfra = (actor1.knownInfrastructure || []).filter(i =>
          (actor2.knownInfrastructure || []).includes(i)
        );

        if (commonInfra.length > 0) {
          conflicts.push({
            type: 'shared_infrastructure_ambiguity',
            actor1: actor1.id,
            actor2: actor2.id,
            sharedInfra: commonInfra,
            detail: 'Both actors share known infrastructure - possible collaboration or infrastructure theft',
          });
        }
      }
    }

    return conflicts;
  }

  detectTimelineConflicts(investigation) {
    const conflicts = [];
    const findings = investigation.findings || [];
    const campaigns = investigation.campaigns || [];

    findings.forEach(f => {
      campaigns.forEach(c => {
        const findingDate = new Date(f.date);
        const campaignStart = new Date(c.startDate);
        const campaignEnd = new Date(c.endDate || new Date());

        if (findingDate < campaignStart || findingDate > campaignEnd) {
          const inceptionDate = Math.min(findingDate, campaignStart);
          conflicts.push({
            type: 'finding_outside_campaign_timeline',
            finding: f.id,
            campaign: c.id,
            findingDate,
            campaignWindow: { start: campaignStart, end: campaignEnd },
            discrepancy: 'Finding timestamp predates campaign start or exceeds documented end',
            resolution: 'Investigate if this indicates earlier campaign inception or data quality issue',
          });
        }
      });
    });

    return conflicts;
  }

  detectMotivationConflicts(investigation) {
    const conflicts = [];
    const threatActors = investigation.threatActors || [];

    threatActors.forEach(actor => {
      const motivations = new Set((actor.motivation || []).flat());

      if (motivations.has('financial') && motivations.has('espionage')) {
        conflicts.push({
          type: 'dual_motivation_ambiguity',
          actor: actor.id,
          motivations: [...motivations],
          conflict: 'Actor exhibits both financial crime and state espionage characteristics',
          interpretation: 'May indicate hybrid threat, false flag, or compartmentalized operations',
          severity: 'medium',
        });
      }
    });

    return conflicts;
  }

  detectTacticalConflicts(investigation) {
    const conflicts = [];
    const campaigns = investigation.campaigns || [];

    campaigns.forEach(campaign => {
      const tactics = campaign.tactics || [];
      const techniques = campaign.techniques || [];

      techniques.forEach(technique => {
        const expectedTactic = this.getTacticForTechnique(technique);
        if (expectedTactic && !tactics.includes(expectedTactic)) {
          conflicts.push({
            type: 'technique_tactic_mismatch',
            campaign: campaign.id,
            technique,
            expectedTactic,
            documentedTactics: tactics,
            detail: 'Observed technique does not align with documented tactical approach',
            severity: 'low',
          });
        }
      });
    });

    return conflicts;
  }

  detectVictimologyConflicts(investigation) {
    const conflicts = [];
    const threatActors = investigation.threatActors || [];
    const victims = investigation.victims || [];

    threatActors.forEach(actor => {
      const targetSectors = new Set(actor.targetSectors || actor.target_sectors || []);
      const targetRegions = new Set(actor.targetRegions || actor.target_regions || []);

      victims.forEach(victim => {
        const sectorMatch = targetSectors.has(victim.sector);
        const regionMatch = targetRegions.has(victim.region);

        if (!sectorMatch || !regionMatch) {
          conflicts.push({
            type: 'victim_outside_targeting_profile',
            actor: actor.id,
            victim: victim.id,
            victimSector: victim.sector,
            victimRegion: victim.region,
            actorTargetSectors: [...targetSectors],
            actorTargetRegions: [...targetRegions],
            conflict: 'Victim does not match known targeting profile',
            interpretation: 'Possible expansion into new sectors/regions or misattribution',
            severity: 'medium',
          });
        }
      });
    });

    return conflicts;
  }

  detectScopeConflicts(investigation) {
    const conflicts = [];

    const totalVictims = (investigation.victims || []).length;
    const documentedVictims = (investigation.campaigns || []).reduce((sum, c) => sum + (c.victims?.length || 0), 0);

    if (totalVictims > documentedVictims * 1.5) {
      conflicts.push({
        type: 'undocumented_victim_count',
        totalVictims,
        documentedVictims,
        undocumented: totalVictims - documentedVictims,
        conflict: 'More victims identified than accounted for in campaign documentation',
        interpretation: 'May indicate additional campaign phases or spillover from other operations',
        severity: 'medium',
      });
    }

    return conflicts;
  }

  identifyAttributionEvidenceConflict(actor1, actor2) {
    const conflicts = [];

    const infra1 = new Set(actor1.knownInfrastructure || []);
    const infra2 = new Set(actor2.knownInfrastructure || []);
    const malware1 = new Set(actor1.knownMalware || []);
    const malware2 = new Set(actor2.knownMalware || []);

    if ([...infra1].filter(i => infra2.has(i)).length > 0) {
      conflicts.push('Shared infrastructure usage');
    }
    if ([...malware1].filter(m => malware2.has(m)).length > 0) {
      conflicts.push('Shared malware family');
    }

    return conflicts.length > 0 ? conflicts : ['Different evidence profiles'];
  }

  getTacticForTechnique(techniqueId) {
    const tacticMap = {
      'T1190': 'Exploitation',
      'T1486': 'Impact',
      'T1041': 'Exfiltration',
      'T1078': 'Privilege Escalation',
      'T1021': 'Lateral Movement',
    };
    return tacticMap[techniqueId];
  }

  assessConflictSeverity(conflictCount) {
    if (conflictCount === 0) return 'none';
    if (conflictCount <= 2) return 'low';
    if (conflictCount <= 5) return 'medium';
    return 'high';
  }

  generateResolutionRecommendations(conflicts) {
    const recommendations = [];

    if (conflicts.attributionConflicts.length > 0) {
      recommendations.push({
        area: 'Attribution',
        priority: 1,
        actions: [
          'Conduct additional forensic analysis to disambiguate actors',
          'Review IOC temporal analysis for timeline misalignment',
          'Assess for possible false flag or attribution evasion tactics',
        ],
      });
    }

    if (conflicts.timelineConflicts.length > 0) {
      recommendations.push({
        area: 'Timeline Integrity',
        priority: 2,
        actions: [
          'Verify finding timestamps against system logs and forensic artifacts',
          'Review campaign date ranges for accuracy',
          'Investigate evidence of earlier campaign inception',
        ],
      });
    }

    if (conflicts.victimologyConflicts.length > 0) {
      recommendations.push({
        area: 'Targeting Profile',
        priority: 3,
        actions: [
          'Assess if actor is expanding targeting profile',
          'Review for possible misattribution of victims',
          'Investigate potential collaboration or shared infrastructure',
        ],
      });
    }

    return recommendations;
  }
}

module.exports = { EvidenceConflictEngine };
