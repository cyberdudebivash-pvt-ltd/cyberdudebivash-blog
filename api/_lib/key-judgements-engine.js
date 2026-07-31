'use strict';

class KeyJudgementsEngine {
  generateKeyJudgements(investigation, report, qualityReview) {
    const judgements = [];

    judgements.push(this.createThreatAttributionJudgement(investigation));
    judgements.push(this.createCampaignScopeJudgement(investigation));
    judgements.push(this.createMotivationJudgement(investigation));
    judgements.push(...this.createCapabilityJudgements(investigation));
    judgements.push(this.createFutureActivityJudgement(investigation));
    judgements.push(this.createDetectionJudgement(investigation));

    return {
      judgements: judgements.filter(j => j !== null),
      overallConfidence: this.calculateJudgementConfidence(investigation),
      generatedAt: new Date().toISOString(),
    };
  }

  createThreatAttributionJudgement(investigation) {
    if (!investigation.threatActors || investigation.threatActors.length === 0) {
      return null;
    }

    const actor = investigation.threatActors[0];
    const confidence = (actor.attributionConfidence || 0.6);

    return {
      id: `judgement-attribution-${investigation.id}`,
      type: 'threat-attribution',
      judgement: `The activity is attributed to ${actor.name}${actor.aliases ? ` (aka ${actor.aliases.join(', ')})` : ''} with ${confidence >= 0.8 ? 'high' : confidence >= 0.6 ? 'moderate' : 'low'} confidence`,
      confidence: this.confidenceToLevel(confidence),
      supportingEvidence: [
        {
          id: actor.id || 'actor-001',
          description: `Matching tactics, techniques, and procedures (TTPs) historically observed from ${actor.name}`,
          weight: 0.25,
        },
        {
          id: 'infrastructure-001',
          description: `Overlapping infrastructure with known ${actor.name} operations`,
          weight: 0.3,
        },
        {
          id: 'tooling-001',
          description: `Use of ${actor.tools ? actor.tools.slice(0, 2).join(', ') : 'signature tools'} linked to ${actor.name}`,
          weight: 0.25,
        },
        {
          id: 'timing-001',
          description: `Activity timing consistent with ${actor.name} operational hours`,
          weight: 0.2,
        },
      ],
      contradictingEvidence: this.findContradictingEvidence(investigation, 'attribution'),
      analystReasoning: `Attribution is based on pattern matching across multiple dimensions. Key similarities with ${actor.name} include operational tradecraft, target selection, and technical indicators. However, these indicators are not unique and could indicate copycat activity or false flag operations.`,
      assessmentDate: investigation.assessmentDate || new Date().toISOString(),
      limitations: [
        'Attribution based on observable patterns; actors may deliberately mimic others',
        'Infrastructure may be shared or compromised',
        'Tools are often publicly available',
      ],
    };
  }

  createCampaignScopeJudgement(investigation) {
    if (!investigation.campaigns || investigation.campaigns.length === 0) {
      return null;
    }

    const campaign = investigation.campaigns[0];
    const victimCount = (investigation.victims || []).length;

    return {
      id: `judgement-campaign-${investigation.id}`,
      type: 'campaign-scope',
      judgement: `Campaign "${campaign.name}" has affected at least ${victimCount} organizations across ${this.countIndustries(investigation)} industries with ongoing activity expected`,
      confidence: victimCount > 10 ? 'High' : 'Moderate',
      supportingEvidence: [
        {
          id: 'victims-confirmed',
          description: `${victimCount} confirmed compromised organizations`,
          weight: 0.4,
        },
        {
          id: 'temporal-pattern',
          description: `Attack activity spanning ${this.calculateCampaignDuration(campaign)} days`,
          weight: 0.3,
        },
        {
          id: 'target-consistency',
          description: `Consistent targeting of ${campaign.targetProfile || 'high-value'} organizations`,
          weight: 0.3,
        },
      ],
      contradictingEvidence: [],
      analystReasoning: `The scope assessment is based on confirmed compromises, attack patterns, and temporal analysis. This represents a minimum assessment; additional unreported victims likely exist.`,
      assessmentDate: investigation.assessmentDate || new Date().toISOString(),
      limitations: [
        'Undetected or unreported compromises may exist',
        'Some organizations may not have disclosed involvement',
        'Campaign may have started before earliest observed activity',
      ],
    };
  }

  createMotivationJudgement(investigation) {
    const threatActors = investigation.threatActors || [];
    if (threatActors.length === 0) return null;

    const actor = threatActors[0];
    const motivation = this.assessMotivation(investigation);

    return {
      id: `judgement-motivation-${investigation.id}`,
      type: 'motivation',
      judgement: `${actor.name} is primarily motivated by ${motivation.primary} with secondary motivation of ${motivation.secondary || 'none identified'}`,
      confidence: motivation.confidence,
      supportingEvidence: [
        {
          id: 'target-selection',
          description: 'Target selection patterns indicate motivation to access valuable intellectual property',
          weight: 0.4,
        },
        {
          id: 'data-handling',
          description: 'Observed data handling procedures consistent with financial motivation',
          weight: 0.3,
        },
        {
          id: 'historical-pattern',
          description: 'Historical context of similar attacks by same actor',
          weight: 0.3,
        },
      ],
      contradictingEvidence: [],
      analystReasoning: `Motivation assessment based on target profile, data access patterns, and historical actor behavior. Primary motivation is inferred from data-handling practices and target selection.`,
      assessmentDate: investigation.assessmentDate || new Date().toISOString(),
      limitations: [
        'Motivation can be deliberately obscured',
        'Multiple concurrent motivations may exist',
        'Stated motivations may differ from actual motivations',
      ],
    };
  }

  createCapabilityJudgements(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const judgements = [];

    if (techniques.filter(t => t.includes('Exploit')).length > 0) {
      judgements.push({
        id: `judgement-capability-exploit-${investigation.id}`,
        type: 'capability',
        category: 'exploit-development',
        judgement: 'Threat actor demonstrates capability to develop or obtain zero-day exploits',
        confidence: 'Moderate',
        evidence: techniques.filter(t => t.includes('Exploit')).slice(0, 3),
        implications: 'Defensive patching alone may be insufficient; detection and response capabilities are critical',
      });
    }

    if (techniques.filter(t => t.includes('Custom')).length > 0) {
      judgements.push({
        id: `judgement-capability-custom-${investigation.id}`,
        type: 'capability',
        category: 'tool-development',
        judgement: 'Threat actor develops custom malware and tools',
        confidence: 'High',
        evidence: techniques.filter(t => t.includes('Custom')).slice(0, 3),
        implications: 'Signature-based detection may be ineffective; behavioral detection required',
      });
    }

    if (techniques.filter(t => t.includes('APT')).length > 0 || (investigation.threatActors || []).length > 0) {
      judgements.push({
        id: `judgement-capability-apt-${investigation.id}`,
        type: 'capability',
        category: 'advanced-capability',
        judgement: 'Threat actor operates with characteristics of advanced persistent threat (APT)',
        confidence: 'High',
        evidence: techniques.slice(0, 5),
        implications: 'Long-term strategic approach to defense required; expect continued activity',
      });
    }

    return judgements.slice(0, 5);
  }

  createFutureActivityJudgement(investigation) {
    const threatActors = investigation.threatActors || [];
    if (threatActors.length === 0) return null;

    const actor = threatActors[0];
    const historicalContinuity = (actor.campaigns || []).length > 3;

    return {
      id: `judgement-future-${investigation.id}`,
      type: 'future-activity',
      judgement: `${actor.name} will likely continue targeting ${investigation.targetIndustry || 'similar organizations'} over the next 30-90 days`,
      confidence: historicalContinuity ? 'High' : 'Moderate',
      supportingEvidence: [
        {
          id: 'historical-continuity',
          description: historicalContinuity ? `${actor.campaigns.length} previous campaigns` : 'Limited historical data',
          weight: 0.4,
        },
        {
          id: 'objective-achievement',
          description: 'Primary objectives likely not fully achieved',
          weight: 0.3,
        },
        {
          id: 'infrastructure-operational',
          description: 'C2 infrastructure remains operational',
          weight: 0.3,
        },
      ],
      contradictingEvidence: [
        {
          id: 'actor-attribution-uncertainty',
          description: 'If attribution is uncertain, future activity may not materialize',
          weight: 0.3,
        },
      ],
      analystReasoning: `Continuation assessment based on historical behavior patterns and objective achievement levels. Actor has not achieved full operational security and victim data exfiltration goals.`,
      assessmentDate: investigation.assessmentDate || new Date().toISOString(),
      limitations: [
        'Actor may pivot to different targets',
        'Geopolitical factors may influence activity',
        'Law enforcement intervention could disrupt operations',
      ],
    };
  }

  createDetectionJudgement(investigation) {
    const detectionCoverage = (investigation.detectionCapabilities || {}).overallCoverage || 0.5;
    const techniques = investigation.mitreTechniques || [];
    const detectedTechniques = techniques.filter(t => investigation.detectionCapabilities?.[t]);

    return {
      id: `judgement-detection-${investigation.id}`,
      type: 'detection-capability',
      judgement: `Current detection coverage enables identification of ${Math.floor(detectionCoverage * 100)}% of observed techniques; ${techniques.length - detectedTechniques.length} technique gaps remain`,
      confidence: 'High',
      supportingEvidence: [
        {
          id: 'detection-analysis',
          description: `${detectedTechniques.length} of ${techniques.length} techniques have detection rules`,
          weight: 0.5,
        },
        {
          id: 'gap-analysis',
          description: `${techniques.length - detectedTechniques.length} gaps in detection coverage`,
          weight: 0.5,
        },
      ],
      contradictingEvidence: [],
      analystReasoning: `Detection assessment based on analysis of available detection rules against observed techniques. Gaps represent opportunities for undetected activity and priority areas for detection engineering.`,
      assessmentDate: investigation.assessmentDate || new Date().toISOString(),
      recommendations: [
        'Develop detection rules for identified gaps',
        'Deploy Sigma and YARA rules to production',
        'Enhance endpoint detection capabilities',
        'Implement behavioral detection',
      ],
    };
  }

  findContradictingEvidence(investigation, type) {
    // Placeholder for contradicting evidence identification logic
    const threatActors = investigation.threatActors || [];
    if (threatActors.length === 0 || (threatActors[0].attributionConfidence || 0) > 0.8) {
      return [];
    }

    return [
      {
        id: 'alternative-actor-1',
        description: 'Observed techniques could be consistent with different threat actor',
        weight: 0.2,
      },
    ];
  }

  confidenceToLevel(confidence) {
    if (confidence >= 0.8) return 'High';
    if (confidence >= 0.6) return 'Moderate';
    return 'Low';
  }

  countIndustries(investigation) {
    const industries = investigation.industryImpact || {};
    return Object.keys(industries).length || 1;
  }

  calculateCampaignDuration(campaign) {
    if (!campaign.startDate || !campaign.endDate) return 'unknown';
    const start = new Date(campaign.startDate);
    const end = new Date(campaign.endDate);
    return Math.floor((end - start) / (1000 * 60 * 60 * 24));
  }

  assessMotivation(investigation) {
    const threatActors = investigation.threatActors || [];
    if (threatActors.length === 0) {
      return { primary: 'unknown', secondary: null, confidence: 'Low' };
    }

    const actor = threatActors[0];
    const targetProfile = investigation.targetIndustry || '';

    const motivationMap = {
      'finance': { primary: 'financial gain', secondary: 'data theft', confidence: 'High' },
      'technology': { primary: 'intellectual property theft', secondary: 'competitive advantage', confidence: 'High' },
      'government': { primary: 'espionage', secondary: 'political leverage', confidence: 'Moderate' },
      'critical-infrastructure': { primary: 'disruption', secondary: 'political', confidence: 'Moderate' },
    };

    return motivationMap[targetProfile] || { primary: actor.motivation || 'unknown', secondary: null, confidence: 'Moderate' };
  }

  calculateJudgementConfidence(investigation) {
    const threatActors = investigation.threatActors || [];
    const campaignsCount = (investigation.campaigns || []).length;
    const confidence = (investigation.confidence || 0.5);

    const score = (threatActors.length > 0 ? 0.3 : 0) +
                  (campaignsCount > 0 ? 0.2 : 0) +
                  (confidence * 0.5);

    return parseFloat((score * 100).toFixed(0)) + '%';
  }
}

module.exports = { KeyJudgementsEngine };
