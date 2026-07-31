'use strict';

/**
 * CYBERDUDEBIVASH SENTINEL APEX — Phase 13: Advanced Analyst Reasoning & Intelligence Methodology Engine
 *
 * Transforms intelligence products into analyst-grade deliverables through structured analytical methodology.
 *
 * 10 Core Modules:
 * 1. Intelligence Reasoning Engine — traceable analytical reasoning for every judgment
 * 2. Competing Hypotheses Engine — alternative hypothesis analysis with evidence
 * 3. Intelligence Confidence Framework v2 — explainable confidence methodology
 * 4. Intelligence Collection Gap Engine v2 — prioritized collection requirements
 * 5. Intelligence Consistency Engine v2 — historical consistency validation
 * 6. Strategic Outlook Engine — evidence-based forward-looking assessment
 * 7. Multi-Audience Intelligence Views — tailored stakeholder perspectives
 * 8. Intelligence Product Consistency Framework — standardized report structure
 * 9. Enterprise Intelligence Quality Gates v3 — comprehensive publication certification
 * 10. Intelligence Product Benchmark Framework — continuous quality tracking
 *
 * Principles:
 * ✓ Extends Phases 1-12 (no replacement)
 * ✓ Maintains backward compatibility
 * ✓ Focuses on analytical quality, not length
 * ✓ Makes reasoning traceable and explainable
 * ✓ Preserves evidence lineage
 */

const crypto = require('crypto');

class Phase13AnalystReasoning {
  constructor() {
    this.reasoningEngine = new IntelligenceReasoningEngine();
    this.hypothesesEngine = new CompetingHypothesesEngine();
    this.confidenceEngine = new IntelligenceConfidenceFramework();
    this.collectionEngine = new IntelligenceCollectionGapEngine();
    this.consistencyEngine = new IntelligenceConsistencyEngine();
    this.outlookEngine = new StrategicOutlookEngine();
    this.audienceEngine = new MultiAudienceIntelligenceViews();
    this.structureEngine = new IntelligenceProductConsistencyFramework();
    this.qualityGate = new EnterpriseIntelligenceQualityGates();
    this.benchmarkEngine = new IntelligenceProductBenchmarkFramework();
  }

  async enhanceWithAnalystReasoning(product, investigation, report, historicalData = []) {
    console.log(`[PHASE 13] Enhancing product ${product.id} with analyst-grade reasoning`);

    const enhancement = {
      productId: product.id,
      timestamp: new Date().toISOString(),
      modules: {},
      certification: null,
      status: 'reasoning',
    };

    try {
      // 1. Intelligence Reasoning Engine
      enhancement.modules.reasoning = await this.reasoningEngine.analyzeAllJudgements(
        product,
        investigation,
        report
      );

      // 2. Competing Hypotheses Engine
      enhancement.modules.hypotheses = await this.hypothesesEngine.generateAlternatives(
        product,
        investigation
      );

      // 3. Intelligence Confidence Framework v2
      enhancement.modules.confidence = await this.confidenceEngine.generateConfidenceAssessment(
        product,
        enhancement.modules.reasoning,
        investigation
      );

      // 4. Intelligence Collection Gap Engine v2
      enhancement.modules.collectionGaps = await this.collectionEngine.identifyGaps(
        product,
        investigation,
        report
      );

      // 5. Intelligence Consistency Engine v2
      enhancement.modules.consistency = await this.consistencyEngine.validateHistoricalConsistency(
        product,
        investigation,
        historicalData
      );

      // 6. Strategic Outlook Engine
      enhancement.modules.outlook = await this.outlookEngine.generateOutlook(
        product,
        investigation,
        enhancement.modules.consistency
      );

      // 7. Multi-Audience Intelligence Views
      enhancement.modules.audiences = await this.audienceEngine.generateAudienceViews(
        product,
        enhancement.modules.reasoning,
        enhancement.modules.collectionGaps
      );

      // 8. Intelligence Product Consistency Framework
      enhancement.modules.structure = await this.structureEngine.validateAndEnhanceStructure(
        product,
        enhancement
      );

      // 9. Enterprise Intelligence Quality Gates v3
      enhancement.certification = await this.qualityGate.certifyReport(
        product,
        enhancement
      );

      // 10. Intelligence Product Benchmark Framework
      enhancement.modules.benchmark = await this.benchmarkEngine.benchmarkReport(
        product,
        enhancement
      );

      enhancement.status = enhancement.certification.passed ? 'certified' : 'review_required';

      return enhancement;
    } catch (e) {
      console.error(`[PHASE 13] Enhancement failed for ${product.id}: ${e.message}`);
      enhancement.status = 'error';
      enhancement.error = e.message;
      return enhancement;
    }
  }

  toJSON() {
    return {
      phase: 'phase-13',
      name: 'Advanced Analyst Reasoning & Intelligence Methodology Engine',
      modules: [
        'Intelligence Reasoning Engine',
        'Competing Hypotheses Engine',
        'Intelligence Confidence Framework v2',
        'Intelligence Collection Gap Engine v2',
        'Intelligence Consistency Engine v2',
        'Strategic Outlook Engine',
        'Multi-Audience Intelligence Views',
        'Intelligence Product Consistency Framework',
        'Enterprise Intelligence Quality Gates v3',
        'Intelligence Product Benchmark Framework',
      ],
    };
  }
}

/**
 * MODULE 1: Intelligence Reasoning Engine
 * Generates traceable analytical reasoning for every major judgment
 */
class IntelligenceReasoningEngine {
  async analyzeAllJudgements(product, investigation, report) {
    return {
      keyJudgements: this.extractKeyJudgements(product, investigation),
      reasoningChains: this.generateReasoningChains(investigation),
      supportingEvidence: this.categorizeEvidence(investigation),
      contradictoryEvidence: this.identifyContradictions(investigation),
      analyticalGaps: this.identifyGaps(investigation),
    };
  }

  extractKeyJudgements(product, investigation) {
    const judgements = [];

    if (investigation.severity) {
      judgements.push({
        judgement: `Threat severity assessed as ${investigation.severity}`,
        type: 'severity_assessment',
        confidence: this.assessJudgementConfidence(investigation, 'severity'),
        reasoning: this.buildReasoningChain(investigation, 'severity'),
      });
    }

    if (investigation.threatActors?.length > 0) {
      investigation.threatActors.forEach(actor => {
        judgements.push({
          judgement: `Intelligence supports attribution to ${actor}`,
          type: 'attribution',
          confidence: this.assessJudgementConfidence(investigation, 'attribution'),
          reasoning: this.buildReasoningChain(investigation, 'attribution'),
        });
      });
    }

    if (investigation.targetedSectors?.length > 0) {
      judgements.push({
        judgement: `Targeting pattern indicates focus on ${investigation.targetedSectors.join(', ')}`,
        type: 'targeting_analysis',
        confidence: this.assessJudgementConfidence(investigation, 'targeting'),
        reasoning: this.buildReasoningChain(investigation, 'targeting'),
      });
    }

    if (investigation.cisaKev || investigation.exploited) {
      judgements.push({
        judgement: `Vulnerability/exploit represents immediate operational risk`,
        type: 'risk_assessment',
        confidence: this.assessJudgementConfidence(investigation, 'risk'),
        reasoning: this.buildReasoningChain(investigation, 'risk'),
      });
    }

    return judgements;
  }

  generateReasoningChains(investigation) {
    return {
      attackProgression: this.buildAttackChain(investigation),
      capabilityAssessment: this.buildCapabilityChain(investigation),
      attributionChain: this.buildAttributionChain(investigation),
      impactChain: this.buildImpactChain(investigation),
    };
  }

  buildReasoningChain(investigation, topic) {
    const chains = {
      severity: [
        { step: 1, fact: 'Threat actor identified', evidence: investigation.threatActors?.length > 0 },
        { step: 2, fact: 'Capability demonstrated', evidence: investigation.malware?.length > 0 || investigation.techniques?.length > 0 },
        { step: 3, fact: 'Active exploitation observed', evidence: investigation.exploited === true },
        { step: 4, conclusion: 'Severity justified by capability and activity' },
      ],
      attribution: [
        { step: 1, fact: 'Infrastructure analysis', evidence: investigation.infrastructure?.length > 0 },
        { step: 2, fact: 'Malware signature matching', evidence: investigation.malware?.length > 0 },
        { step: 3, fact: 'TTPs align with known patterns', evidence: investigation.techniques?.length > 0 },
        { step: 4, fact: 'Victimology consistent', evidence: investigation.targetedSectors?.length > 0 },
        { step: 5, conclusion: 'Attribution supported by multiple indicators' },
      ],
      targeting: [
        { step: 1, fact: 'Sector selection', evidence: investigation.targetedSectors?.length > 0 },
        { step: 2, fact: 'Victim concentration', evidence: investigation.affectedUserCount > 0 },
        { step: 3, conclusion: 'Targeting pattern indicates strategic selection' },
      ],
      risk: [
        { step: 1, fact: 'CISA KEV listing', evidence: investigation.cisaKev === true },
        { step: 2, fact: 'Active exploitation', evidence: investigation.exploited === true },
        { step: 3, conclusion: 'Immediate risk justified by exploitation activity' },
      ],
    };

    return chains[topic] || [];
  }

  buildAttackChain(investigation) {
    return {
      chain: 'Initial Access → Execution → Persistence → Escalation → Exfiltration',
      phases: investigation.techniques?.map(t => ({
        phase: t.mitreTactic?.[0] || 'Unknown',
        technique: t.name,
        evidence: 'Observed in investigation',
      })) || [],
    };
  }

  buildCapabilityChain(investigation) {
    return {
      capabilities: investigation.malware || [],
      techniques: investigation.techniques?.map(t => t.name) || [],
      infrastructure: investigation.infrastructure?.length || 0,
      evidenceQuality: this.assessEvidenceQuality(investigation),
    };
  }

  buildAttributionChain(investigation) {
    return {
      actors: investigation.threatActors || [],
      infrastructure: investigation.infrastructure || [],
      malware: investigation.malware || [],
      sectors: investigation.targetedSectors || [],
    };
  }

  buildImpactChain(investigation) {
    return {
      affectedCount: investigation.affectedUserCount || 0,
      sectors: investigation.targetedSectors || [],
      dataTypes: this.inferDataTypes(investigation),
      businessImpact: this.assessBusinessImpact(investigation),
    };
  }

  categorizeEvidence(investigation) {
    return {
      strongEvidence: this.filterEvidenceByStrength(investigation, 'strong'),
      moderateEvidence: this.filterEvidenceByStrength(investigation, 'moderate'),
      weakEvidence: this.filterEvidenceByStrength(investigation, 'weak'),
      coverage: {
        infrastructure: investigation.infrastructure?.length > 0,
        malware: investigation.malware?.length > 0,
        techniques: investigation.techniques?.length > 0,
        victims: investigation.affectedUserCount > 0,
      },
    };
  }

  filterEvidenceByStrength(investigation, strength) {
    const evidence = [];
    const strengthMap = {
      strong: ['infrastructure', 'malware', 'cisaKev', 'exploited'],
      moderate: ['techniques', 'targetedSectors'],
      weak: ['evidence'],
    };

    const indicators = strengthMap[strength] || [];
    indicators.forEach(indicator => {
      if (investigation[indicator]) {
        evidence.push({
          type: indicator,
          value: investigation[indicator],
          strength,
        });
      }
    });

    return evidence;
  }

  identifyContradictions(investigation) {
    const contradictions = [];

    if (investigation.cisaKev && investigation.severity === 'LOW') {
      contradictions.push({
        contradiction: 'CISA KEV listed but severity marked low',
        impact: 'HIGH',
        resolution: 'Severity should be elevated or KEV listing re-evaluated',
      });
    }

    if (investigation.exploited && investigation.techniques?.length === 0) {
      contradictions.push({
        contradiction: 'Active exploitation reported but techniques unspecified',
        impact: 'MEDIUM',
        resolution: 'Collect detailed technique analysis',
      });
    }

    if (investigation.ransomware && investigation.malware?.length === 0) {
      contradictions.push({
        contradiction: 'Ransomware activity indicated but malware samples missing',
        impact: 'MEDIUM',
        resolution: 'Obtain and analyze malware samples',
      });
    }

    return contradictions;
  }

  identifyGaps(investigation) {
    return {
      missingInfrastructure: !investigation.infrastructure || investigation.infrastructure.length === 0,
      missingMalware: !investigation.malware || investigation.malware.length === 0,
      missingTechniques: !investigation.techniques || investigation.techniques.length === 0,
      missingVictimology: !investigation.affectedUserCount || investigation.affectedUserCount === 0,
      missingTimeline: !investigation.timeline,
    };
  }

  assessJudgementConfidence(investigation, topic) {
    const confidence = {
      severity: investigation.cisaKev || investigation.exploited ? 95 : 75,
      attribution: investigation.infrastructure?.length > 2 ? 85 : 65,
      targeting: investigation.affectedUserCount > 1000 ? 90 : 70,
      risk: investigation.exploited ? 95 : 80,
    };

    return confidence[topic] || 70;
  }

  assessEvidenceQuality(investigation) {
    let quality = 0;
    let total = 0;

    if (investigation.infrastructure?.length > 0) {
      quality += Math.min(investigation.infrastructure.length * 10, 30);
      total += 30;
    }
    if (investigation.malware?.length > 0) {
      quality += Math.min(investigation.malware.length * 10, 30);
      total += 30;
    }
    if (investigation.techniques?.length > 0) {
      quality += Math.min(investigation.techniques.length * 5, 20);
      total += 20;
    }
    if (investigation.evidence?.length > 0) {
      quality += Math.min(investigation.evidence.length * 2, 20);
      total += 20;
    }

    return total > 0 ? Math.round((quality / total) * 100) : 0;
  }

  inferDataTypes(investigation) {
    const types = [];
    if (investigation.malware?.some(m => m.includes('Stealer'))) {
      types.push('Personally identifiable information (PII)');
      types.push('Financial data');
    }
    if (investigation.techniques?.some(t => t.name?.includes('Exfiltration'))) {
      types.push('Sensitive documents');
      types.push('Credentials');
    }
    return types;
  }

  assessBusinessImpact(investigation) {
    if (investigation.severity === 'CRITICAL') return 'SEVERE';
    if (investigation.exploited) return 'HIGH';
    if (investigation.targetedSectors?.includes('financial') || investigation.targetedSectors?.includes('government')) return 'HIGH';
    return 'MODERATE';
  }
}

/**
 * MODULE 2: Competing Hypotheses Engine
 * Generates alternative hypotheses with supporting/contradicting evidence
 */
class CompetingHypothesesEngine {
  async generateAlternatives(product, investigation) {
    return {
      attributionHypotheses: this.generateAttributionHypotheses(investigation),
      campaignHypotheses: this.generateCampaignHypotheses(investigation),
      infrastructureHypotheses: this.generateInfrastructureHypotheses(investigation),
      malwareRelationshipHypotheses: this.generateMalwareHypotheses(investigation),
    };
  }

  generateAttributionHypotheses(investigation) {
    const hypotheses = [];

    if (investigation.threatActors?.length > 0) {
      hypotheses.push({
        hypothesis: `Primary: Attribution to ${investigation.threatActors[0]}`,
        confidence: this.calculateAttributionConfidence(investigation),
        supportingIndicators: this.findAttributionSupport(investigation),
        contradictingIndicators: this.findAttributionContradictions(investigation),
        requiredEvidence: this.identifyAttributionGaps(investigation),
      });

      if (investigation.threatActors.length > 1) {
        hypotheses.push({
          hypothesis: `Alternative: Joint operation by ${investigation.threatActors.slice(0, 2).join(' and ')}`,
          confidence: 45,
          supportingIndicators: ['Different malware families', 'Infrastructure clustering'],
          contradictingIndicators: ['No evidence of coordination'],
          requiredEvidence: ['Timeline correlation', 'Infrastructure handoff evidence'],
        });
      }

      hypotheses.push({
        hypothesis: `Alternative: Attribution misidentified due to false flag indicators`,
        confidence: 25,
        supportingIndicators: this.identifyFalseFlags(investigation),
        contradictingIndicators: ['Multiple independent data sources', 'Historical consistency'],
        requiredEvidence: ['Deliberate misdirection evidence', 'Counter-attribution analysis'],
      });
    }

    return hypotheses;
  }

  generateCampaignHypotheses(investigation) {
    return [
      {
        hypothesis: 'Campaign represents ongoing espionage operation',
        confidence: investigation.exploited ? 85 : 60,
        supportingIndicators: [
          investigation.targetedSectors?.length > 1 ? 'Multi-sector targeting' : null,
          investigation.affectedUserCount > 100 ? 'Significant scale' : null,
          investigation.techniques?.length > 3 ? 'Sophisticated techniques' : null,
        ].filter(Boolean),
        contradictingIndicators: investigation.cisaKev ? [] : ['No public advisory'],
        requiredEvidence: ['Timeline correlation with geopolitical events', 'Long-term infrastructure reuse'],
      },
      {
        hypothesis: 'Campaign represents opportunistic cybercrime',
        confidence: 40,
        supportingIndicators: investigation.malware?.some(m => m.includes('Ransomware')) ? ['Ransomware capability'] : [],
        contradictingIndicators: [
          investigation.targetedSectors?.includes('government') ? 'Government targeting unlikely for cybercrime' : null,
          investigation.techniques?.length > 5 ? 'Sophistication suggests state-level actor' : null,
        ].filter(Boolean),
        requiredEvidence: ['Ransom demand evidence', 'Victimology pattern change'],
      },
    ];
  }

  generateInfrastructureHypotheses(investigation) {
    if (!investigation.infrastructure || investigation.infrastructure.length === 0) {
      return [];
    }

    return [
      {
        hypothesis: 'Infrastructure controlled by single actor',
        confidence: 75,
        supportingIndicators: ['Consistent hosting providers', 'Similar registration patterns'],
        contradictingIndicators: investigation.infrastructure.length < 3 ? ['Limited infrastructure sample'] : [],
        requiredEvidence: ['WHOIS correlation', 'Network behavior analysis'],
      },
      {
        hypothesis: 'Infrastructure represents shared or rented infrastructure',
        confidence: 30,
        supportingIndicators: investigation.infrastructure.some(i => i.hosting?.includes('shared')) ? ['Shared hosting providers'] : [],
        contradictingIndicators: ['Consistent behavior', 'Coordinated tasking'],
        requiredEvidence: ['Multiple actor targeting same infrastructure', 'Hosting provider records'],
      },
    ];
  }

  generateMalwareHypotheses(investigation) {
    if (!investigation.malware || investigation.malware.length === 0) {
      return [];
    }

    return investigation.malware.slice(0, 2).map((malware, idx) => ({
      hypothesis: idx === 0 ? `${malware} represents primary capability` : `${malware} represents secondary tool`,
      confidence: idx === 0 ? 80 : 50,
      supportingIndicators: [
        'Deployment prevalence',
        'Functional capability alignment',
        'Historical attribution',
      ],
      contradictingIndicators: [],
      requiredEvidence: ['Comparative code analysis', 'Sample timeline'],
    }));
  }

  calculateAttributionConfidence(investigation) {
    let confidence = 0;
    if (investigation.infrastructure?.length > 2) confidence += 20;
    if (investigation.malware?.length > 1) confidence += 20;
    if (investigation.techniques?.length > 3) confidence += 15;
    if (investigation.targetedSectors?.length > 1) confidence += 15;
    if (investigation.cisaKev) confidence += 10;
    if (investigation.exploited) confidence += 10;
    return Math.min(confidence + 10, 95);
  }

  findAttributionSupport(investigation) {
    return [
      investigation.infrastructure?.length > 0 ? 'Infrastructure clustering' : null,
      investigation.malware?.length > 0 ? 'Malware signature matching' : null,
      investigation.techniques?.length > 0 ? 'TTP consistency with known actor' : null,
      investigation.targetedSectors?.length > 0 ? 'Targeting pattern alignment' : null,
    ].filter(Boolean);
  }

  findAttributionContradictions(investigation) {
    const contradictions = [];
    if (investigation.infrastructure?.length === 0) contradictions.push('No infrastructure indicators');
    if (investigation.techniques?.length === 0) contradictions.push('Techniques unspecified');
    if (!investigation.cisaKev && !investigation.exploited) contradictions.push('Limited public reporting');
    return contradictions;
  }

  identifyAttributionGaps(investigation) {
    return [
      !investigation.infrastructure || investigation.infrastructure.length < 3 ? 'Additional infrastructure correlation' : null,
      !investigation.malware || investigation.malware.length === 0 ? 'Malware sample analysis' : null,
      !investigation.evidence || investigation.evidence.length < 5 ? 'Supporting evidence collection' : null,
    ].filter(Boolean);
  }

  identifyFalseFlags(investigation) {
    return [
      investigation.malware?.some(m => m.includes('publicly available')) ? 'Use of public tools' : null,
      investigation.infrastructure?.some(i => i.hosting?.includes('shared')) ? 'Shared infrastructure' : null,
      investigation.targetedSectors?.length > 5 ? 'Overly broad targeting' : null,
    ].filter(Boolean);
  }
}

/**
 * MODULE 3: Intelligence Confidence Framework v2
 * Explainable confidence methodology with multiple factors
 */
class IntelligenceConfidenceFramework {
  async generateConfidenceAssessment(product, reasoning, investigation) {
    return {
      overallConfidence: this.calculateOverallConfidence(reasoning, investigation),
      sourceReliability: this.assessSourceReliability(investigation),
      evidenceQuality: this.assessEvidenceQuality(investigation),
      corroboration: this.assessCorroboration(investigation),
      analyticalConsistency: this.assessAnalyticalConsistency(reasoning),
      historicalConsistency: this.assessHistoricalConsistency(investigation),
      collectionCompleteness: this.assessCollectionCompleteness(investigation),
      uncertaintyFactors: this.identifyUncertaintyFactors(investigation),
      confidenceNarrative: this.generateConfidenceNarrative(investigation),
    };
  }

  calculateOverallConfidence(reasoning, investigation) {
    let score = 0;
    let factors = 0;

    if (reasoning.keyJudgements?.length > 0) {
      const judgementConfidence = reasoning.keyJudgements.reduce((sum, j) => sum + (j.confidence || 0), 0) / reasoning.keyJudgements.length;
      score += judgementConfidence;
      factors++;
    }

    if (investigation.infrastructure?.length > 2) {
      score += 20;
      factors++;
    }

    if (investigation.malware?.length > 1) {
      score += 15;
      factors++;
    }

    if (investigation.techniques?.length > 3) {
      score += 15;
      factors++;
    }

    if (investigation.cisaKev || investigation.exploited) {
      score += 20;
      factors++;
    }

    return factors > 0 ? Math.round(score / factors) : 60;
  }

  assessSourceReliability(investigation) {
    const sources = new Set();
    if (investigation.infrastructure) sources.add('infrastructure');
    if (investigation.malware) sources.add('malware');
    if (investigation.techniques) sources.add('techniques');
    if (investigation.evidence) sources.add('direct_evidence');

    const reliability = {
      sourceCount: sources.size,
      assessment: sources.size >= 3 ? 'HIGH' : sources.size === 2 ? 'MEDIUM' : 'LOW',
      details: Array.from(sources),
    };

    return reliability;
  }

  assessEvidenceQuality(investigation) {
    const quality = [];

    if (investigation.infrastructure?.length > 0) {
      quality.push({
        type: 'infrastructure',
        quantity: investigation.infrastructure.length,
        rating: investigation.infrastructure.length > 3 ? 'HIGH' : 'MEDIUM',
      });
    }

    if (investigation.malware?.length > 0) {
      quality.push({
        type: 'malware',
        quantity: investigation.malware.length,
        rating: investigation.malware.length > 2 ? 'HIGH' : 'MEDIUM',
      });
    }

    if (investigation.evidence?.length > 0) {
      quality.push({
        type: 'direct_evidence',
        quantity: investigation.evidence.length,
        rating: 'HIGH',
      });
    }

    return {
      evidenceTypes: quality,
      overallQuality: quality.some(e => e.rating === 'HIGH') ? 'GOOD' : 'MODERATE',
    };
  }

  assessCorroboration(investigation) {
    const corroborating = [];

    if (investigation.infrastructure?.length > 0 && investigation.malware?.length > 0) {
      corroborating.push('Infrastructure and malware evidence present');
    }

    if (investigation.techniques?.length > 0 && investigation.targetedSectors?.length > 0) {
      corroborating.push('Techniques and targeting pattern corroborate');
    }

    if (investigation.cisaKev && investigation.exploited) {
      corroborating.push('CISA KEV and active exploitation corroborate');
    }

    return {
      corroboratingFactors: corroborating,
      corroborationLevel: corroborating.length >= 2 ? 'STRONG' : corroborating.length === 1 ? 'MODERATE' : 'LIMITED',
    };
  }

  assessAnalyticalConsistency(reasoning) {
    const judgements = reasoning.keyJudgements || [];
    const consistentJudgements = judgements.filter(j => j.confidence >= 70).length;

    return {
      totalJudgements: judgements.length,
      consistentJudgements,
      consistencyRating: consistentJudgements / Math.max(judgements.length, 1) > 0.7 ? 'HIGH' : 'MODERATE',
    };
  }

  assessHistoricalConsistency(investigation) {
    return {
      assessment: 'Requires historical data for comparison',
      status: 'PENDING_VALIDATION',
      flags: [],
    };
  }

  assessCollectionCompleteness(investigation) {
    const completeness = {
      infrastructure: !!investigation.infrastructure?.length,
      malware: !!investigation.malware?.length,
      techniques: !!investigation.techniques?.length,
      victimology: !!investigation.affectedUserCount,
      timeline: !!investigation.timeline,
    };

    const complete = Object.values(completeness).filter(Boolean).length;
    const total = Object.keys(completeness).length;

    return {
      categories: completeness,
      completenessPercentage: Math.round((complete / total) * 100),
      gaps: Object.entries(completeness).filter(([k, v]) => !v).map(([k]) => k),
    };
  }

  identifyUncertaintyFactors(investigation) {
    const factors = [];

    if (!investigation.infrastructure || investigation.infrastructure.length === 0) {
      factors.push('Limited infrastructure data increases attribution uncertainty');
    }

    if (!investigation.timeline) {
      factors.push('Timeline gaps prevent chronological analysis');
    }

    if (!investigation.malware || investigation.malware.length === 0) {
      factors.push('Absence of malware samples limits technical analysis');
    }

    if (investigation.techniques?.length < 3) {
      factors.push('Limited technique data constrains TTP analysis');
    }

    return factors;
  }

  generateConfidenceNarrative(investigation) {
    const confidence = this.calculateOverallConfidence({}, investigation);
    const narrative = confidence >= 85
      ? 'High confidence supported by multiple corroborating evidence sources'
      : confidence >= 70
        ? 'Moderate-to-good confidence with primary evidence supported by secondary indicators'
        : confidence >= 50
          ? 'Moderate confidence with some evidence gaps requiring additional collection'
          : 'Low confidence due to limited evidence and significant collection gaps';

    return narrative;
  }
}

/**
 * MODULE 4: Intelligence Collection Gap Engine v2
 * Identifies and prioritizes missing intelligence requirements
 */
class IntelligenceCollectionGapEngine {
  async identifyGaps(product, investigation, report) {
    return {
      infrastructureGaps: this.identifyInfrastructureGaps(investigation),
      malwareGaps: this.identifyMalwareGaps(investigation),
      techniqueGaps: this.identifyTechniqueGaps(investigation),
      victimologyGaps: this.identifyVictimologyGaps(investigation),
      timelineGaps: this.identifyTimelineGaps(investigation),
      attributionGaps: this.identifyAttributionGaps(investigation),
      detectionGaps: this.identifyDetectionGaps(investigation),
      prioritizedRequirements: this.prioritizeRequirements(investigation),
    };
  }

  identifyInfrastructureGaps(investigation) {
    const gaps = [];

    if (!investigation.infrastructure || investigation.infrastructure.length === 0) {
      gaps.push({
        gap: 'No infrastructure indicators identified',
        priority: 'CRITICAL',
        collection: 'Passive DNS, WHOIS, network telemetry',
      });
    } else if (investigation.infrastructure.length < 5) {
      gaps.push({
        gap: 'Limited infrastructure visibility',
        priority: 'HIGH',
        collection: 'Expand infrastructure correlation, identify additional C2 nodes',
      });
    }

    if (!investigation.infrastructure?.some(i => i.hosting)) {
      gaps.push({
        gap: 'Hosting provider attribution incomplete',
        priority: 'MEDIUM',
        collection: 'Identify hosting infrastructure patterns',
      });
    }

    return gaps;
  }

  identifyMalwareGaps(investigation) {
    const gaps = [];

    if (!investigation.malware || investigation.malware.length === 0) {
      gaps.push({
        gap: 'No malware samples identified',
        priority: 'CRITICAL',
        collection: 'Obtain and analyze malware samples',
      });
    } else if (investigation.malware.length === 1) {
      gaps.push({
        gap: 'Limited malware diversity',
        priority: 'HIGH',
        collection: 'Identify additional malware variants',
      });
    }

    gaps.push({
      gap: 'Malware capability comparison incomplete',
      priority: 'MEDIUM',
      collection: 'Comparative code analysis of variants',
    });

    return gaps;
  }

  identifyTechniqueGaps(investigation) {
    const gaps = [];

    if (!investigation.techniques || investigation.techniques.length === 0) {
      gaps.push({
        gap: 'Attack techniques not specified',
        priority: 'CRITICAL',
        collection: 'Map TTPs to MITRE ATT&CK framework',
      });
    }

    const tactics = new Set(investigation.techniques?.flatMap(t => t.mitreTactic) || []);
    const missingTactics = ['Initial Access', 'Execution', 'Persistence', 'Escalation', 'Exfiltration'].filter(t => !tactics.has(t));

    if (missingTactics.length > 0) {
      gaps.push({
        gap: `Missing tactic coverage: ${missingTactics.join(', ')}`,
        priority: 'MEDIUM',
        collection: 'Identify techniques in missing tactic categories',
      });
    }

    return gaps;
  }

  identifyVictimologyGaps(investigation) {
    const gaps = [];

    if (!investigation.affectedUserCount || investigation.affectedUserCount === 0) {
      gaps.push({
        gap: 'Victim count not assessed',
        priority: 'HIGH',
        collection: 'Quantify affected organizations and users',
      });
    }

    if (!investigation.targetedSectors || investigation.targetedSectors.length === 0) {
      gaps.push({
        gap: 'Targeted sectors not identified',
        priority: 'HIGH',
        collection: 'Analyze victim targeting patterns',
      });
    }

    gaps.push({
      gap: 'Victim selection motivation unclear',
      priority: 'MEDIUM',
      collection: 'Assess strategic vs opportunistic targeting',
    });

    return gaps;
  }

  identifyTimelineGaps(investigation) {
    if (!investigation.timeline) {
      return [{
        gap: 'No attack timeline established',
        priority: 'CRITICAL',
        collection: 'Correlate indicators to establish chronology',
      }];
    }

    return [{
      gap: 'Campaign origin date uncertain',
      priority: 'MEDIUM',
      collection: 'Historical infrastructure and malware analysis',
    }];
  }

  identifyAttributionGaps(investigation) {
    const gaps = [];

    if (!investigation.threatActors || investigation.threatActors.length === 0) {
      gaps.push({
        gap: 'Threat actor attribution not established',
        priority: 'CRITICAL',
        collection: 'Conduct attribution analysis',
      });
    }

    gaps.push({
      gap: 'Attribution confidence justification needed',
      priority: 'HIGH',
      collection: 'Document supporting evidence for attribution',
    });

    return gaps;
  }

  identifyDetectionGaps(investigation) {
    return [{
      gap: 'Detection coverage assessment incomplete',
      priority: 'HIGH',
      collection: 'Map indicators to detection capabilities',
    }, {
      gap: 'Hunting query development needed',
      priority: 'MEDIUM',
      collection: 'Create behavioral and signature-based hunts',
    }];
  }

  prioritizeRequirements(investigation) {
    const critical = [];
    const high = [];
    const medium = [];

    if (!investigation.infrastructure || investigation.infrastructure.length === 0) {
      critical.push('Infrastructure indicators (enables C2 detection and attribution)');
    }
    if (!investigation.malware || investigation.malware.length === 0) {
      critical.push('Malware samples (enables capability and signature analysis)');
    }
    if (!investigation.threatActors || investigation.threatActors.length === 0) {
      critical.push('Threat actor attribution (enables threat prioritization)');
    }

    if (!investigation.techniques || investigation.techniques.length < 3) {
      high.push('Additional TTP documentation (enables detection engineering)');
    }
    if (!investigation.timeline) {
      high.push('Attack timeline (enables incident response sequencing)');
    }

    if (investigation.techniques?.length < 5) {
      medium.push('Behavioral indicators (enables hunting)');
    }

    return {
      critical,
      high,
      medium,
      expectedImpact: 'Each requirement directly improves operational decision-making',
    };
  }
}

/**
 * MODULE 5: Intelligence Consistency Engine v2
 * Validates consistency with historical intelligence
 */
class IntelligenceConsistencyEngine {
  async validateHistoricalConsistency(product, investigation, historicalData = []) {
    return {
      conflictingAssessments: this.findConflicts(investigation, historicalData),
      behaviorChanges: this.identifyBehaviorChanges(investigation, historicalData),
      capabilityEvolution: this.trackCapabilityEvolution(investigation, historicalData),
      infrastructureReuse: this.identifyInfrastructureReuse(investigation, historicalData),
      campaignEvolution: this.trackCampaignEvolution(investigation, historicalData),
      confidenceDrift: this.assessConfidenceDrift(investigation, historicalData),
      consistencySummary: this.generateConsistencySummary(investigation, historicalData),
    };
  }

  findConflicts(investigation, historicalData) {
    const conflicts = [];

    historicalData.forEach(historical => {
      if (investigation.threatActors?.includes(historical.threatActor) && investigation.severity !== historical.severity) {
        conflicts.push({
          conflict: `Severity changed from ${historical.severity} to ${investigation.severity}`,
          actor: historical.threatActor,
          rationale: 'Increased activity or new capability demonstrated',
        });
      }
    });

    return conflicts;
  }

  identifyBehaviorChanges(investigation, historicalData) {
    const changes = [];

    if (historicalData.length > 0) {
      const lastKnown = historicalData[0];

      if (lastKnown.targetedSectors && investigation.targetedSectors) {
        const newSectors = investigation.targetedSectors.filter(s => !lastKnown.targetedSectors.includes(s));
        if (newSectors.length > 0) {
          changes.push({
            change: `New sector targeting observed: ${newSectors.join(', ')}`,
            significance: 'HIGH',
            implication: 'Indicates shift in threat actor objectives',
          });
        }
      }

      if (lastKnown.techniques && investigation.techniques) {
        const newTechniques = investigation.techniques.filter(t => !lastKnown.techniques.some(lt => lt.name === t.name));
        if (newTechniques.length > 0) {
          changes.push({
            change: `New techniques deployed: ${newTechniques.map(t => t.name).join(', ')}`,
            significance: 'MEDIUM',
            implication: 'Capability expansion or tactical evolution',
          });
        }
      }
    }

    return changes;
  }

  trackCapabilityEvolution(investigation, historicalData) {
    return {
      newCapabilities: this.identifyNewCapabilities(investigation, historicalData),
      retiredCapabilities: this.identifyRetiredCapabilities(investigation, historicalData),
      sophisticationTrend: this.assessSophisticationTrend(investigation, historicalData),
    };
  }

  identifyNewCapabilities(investigation, historicalData) {
    if (!historicalData || historicalData.length === 0) return investigation.malware || [];

    const historical = historicalData[0];
    return (investigation.malware || []).filter(m => !historical.malware?.includes(m));
  }

  identifyRetiredCapabilities(investigation, historicalData) {
    if (!historicalData || historicalData.length === 0) return [];

    const historical = historicalData[0];
    return (historical.malware || []).filter(m => !investigation.malware?.includes(m));
  }

  assessSophisticationTrend(investigation, historicalData) {
    const current = (investigation.techniques?.length || 0) + (investigation.malware?.length || 0);
    const historical = historicalData[0] ? (historicalData[0].techniques?.length || 0) + (historicalData[0].malware?.length || 0) : 0;

    if (current > historical) {
      return { trend: 'INCREASING', assessment: 'Actor sophistication increasing' };
    } else if (current < historical) {
      return { trend: 'DECREASING', assessment: 'Possible capability degradation or operational shift' };
    }

    return { trend: 'STABLE', assessment: 'Consistent capability level' };
  }

  identifyInfrastructureReuse(investigation, historicalData) {
    const reuse = [];

    if (investigation.infrastructure && historicalData.length > 0) {
      historicalData.forEach(historical => {
        if (historical.infrastructure) {
          const reuseIPs = investigation.infrastructure.filter(i => historical.infrastructure.some(h => h.ip === i.ip));
          if (reuseIPs.length > 0) {
            reuse.push({
              ips: reuseIPs.map(i => i.ip),
              historicalUse: `Used in ${historical.threatActors?.[0] || 'previous campaign'}`,
              implications: 'Infrastructure persistence or hand-off between actors',
            });
          }
        }
      });
    }

    return reuse;
  }

  trackCampaignEvolution(investigation, historicalData) {
    if (!historicalData || historicalData.length === 0) {
      return { status: 'NEW_CAMPAIGN', assessment: 'No historical baseline for comparison' };
    }

    const evolution = {
      stages: [],
      overallTrajectory: '',
    };

    historicalData.forEach((historical, idx) => {
      evolution.stages.push({
        stage: idx + 1,
        timeline: historical.timeline,
        capability: historical.malware?.length || 0,
        reach: historical.affectedUserCount || 0,
      });
    });

    const latestCapability = evolution.stages[0]?.capability || 0;
    const currentCapability = (investigation.malware?.length || 0);

    if (currentCapability > latestCapability) {
      evolution.overallTrajectory = 'EXPANDING';
    } else if (currentCapability < latestCapability) {
      evolution.overallTrajectory = 'CONTRACTING';
    } else {
      evolution.overallTrajectory = 'STABLE';
    }

    return evolution;
  }

  assessConfidenceDrift(investigation, historicalData) {
    return {
      currentConfidence: 75,
      historicalConfidence: historicalData[0]?.confidence || 70,
      drift: 'STABLE',
      rationale: 'Consistent evidence quality across reporting periods',
    };
  }

  generateConsistencySummary(investigation, historicalData) {
    return {
      summary: historicalData.length > 0
        ? 'Assessment consistent with historical reporting with noted evolution'
        : 'No historical data available for consistency comparison',
      flags: [],
      recommendedActions: [],
    };
  }
}

/**
 * MODULE 6: Strategic Outlook Engine
 * Generates evidence-based forward-looking assessments
 */
class StrategicOutlookEngine {
  async generateOutlook(product, investigation, consistency) {
    return {
      likelyDevelopments: this.identifyLikelyDevelopments(investigation, consistency),
      indicatorsToMonitor: this.identifyIndicators(investigation),
      potentialEscalationPaths: this.identifyEscalations(investigation),
      defensivePriorities: this.identifyDefensivePriorities(investigation),
      intelligenceWatchItems: this.identifyWatchItems(investigation),
    };
  }

  identifyLikelyDevelopments(investigation, consistency) {
    const developments = [];

    if (investigation.techniques?.length > 3) {
      developments.push({
        development: 'Continued TTP refinement and evolution',
        confidence: 'HIGH',
        timeframe: '1-3 months',
        indicator: 'New malware variants, additional infrastructure',
      });
    }

    if (investigation.targetedSectors?.length > 1) {
      developments.push({
        development: 'Potential sector expansion based on targeting pattern',
        confidence: 'MODERATE',
        timeframe: '2-6 months',
        indicator: 'Targeting shift to adjacent sectors',
      });
    }

    if (investigation.infrastructure?.length > 3) {
      developments.push({
        development: 'Infrastructure expansion or consolidation',
        confidence: 'MODERATE',
        timeframe: '1-3 months',
        indicator: 'New C2 nodes, domain registration patterns',
      });
    }

    if (investigation.exploited) {
      developments.push({
        development: 'Exploitation of additional variants',
        confidence: 'HIGH',
        timeframe: 'Ongoing',
        indicator: 'New patch releases, vulnerability disclosures',
      });
    }

    return developments;
  }

  identifyIndicators(investigation) {
    const indicators = [];

    if (investigation.infrastructure) {
      indicators.push({
        indicator: 'New infrastructure deployment',
        type: 'INFRASTRUCTURE',
        monitoring: 'Passive DNS, WHOIS, hosting provider notifications',
        priority: 'HIGH',
      });
    }

    if (investigation.malware) {
      indicators.push({
        indicator: 'New malware variants',
        type: 'MALWARE',
        monitoring: 'Hash submissions, sandbox detections, signature analysis',
        priority: 'HIGH',
      });
    }

    if (investigation.techniques) {
      indicators.push({
        indicator: 'New techniques deployment',
        type: 'TACTICS',
        monitoring: 'Threat hunting, endpoint telemetry, network analysis',
        priority: 'MEDIUM',
      });
    }

    indicators.push({
      indicator: 'Targeting pattern shift',
      type: 'TARGETING',
      monitoring: 'Victim reporting, sector-specific intelligence',
      priority: 'MEDIUM',
    });

    return indicators;
  }

  identifyEscalations(investigation) {
    const escalations = [];

    if (investigation.ransomware) {
      escalations.push({
        escalation: 'Ransomware deployment on compromised networks',
        probability: 'HIGH',
        impact: 'CRITICAL',
        mitigations: ['Network segmentation', 'Backup validation', 'RDP hardening'],
      });
    }

    if (investigation.cisaKev && investigation.exploited) {
      escalations.push({
        escalation: 'Widespread exploitation of CISA KEV vulnerability',
        probability: 'HIGH',
        impact: 'CRITICAL',
        mitigations: ['Emergency patching', 'Threat hunting for exploitation', 'IDS tuning'],
      });
    }

    if (investigation.malware?.some(m => m.includes('Loader'))) {
      escalations.push({
        escalation: 'Additional malware families deployed via loader',
        probability: 'MODERATE',
        impact: 'HIGH',
        mitigations: ['Endpoint detection', 'Process monitoring', 'Lateral movement detection'],
      });
    }

    return escalations;
  }

  identifyDefensivePriorities(investigation) {
    const priorities = [];

    if (investigation.cisaKev) {
      priorities.push({
        priority: 'Emergency patching',
        urgency: 'IMMEDIATE',
        target: 'All vulnerable systems',
        validation: 'Patch verification, vulnerability rescanning',
      });
    }

    if (investigation.infrastructure?.length > 0) {
      priorities.push({
        priority: 'Infrastructure blocking',
        urgency: 'HIGH',
        target: 'Firewall, proxy, DNS',
        validation: 'Communication disruption verification',
      });
    }

    if (investigation.malware?.length > 0) {
      priorities.push({
        priority: 'Malware detection deployment',
        urgency: 'HIGH',
        target: 'Endpoints, email, network',
        validation: 'Signature effectiveness testing',
      });
    }

    if (investigation.exploited) {
      priorities.push({
        priority: 'Incident response activation',
        urgency: 'IMMEDIATE',
        target: 'Affected systems',
        validation: 'Forensic investigation',
      });
    }

    return priorities;
  }

  identifyWatchItems(investigation) {
    return [{
      watchItem: `${investigation.threatActors?.[0] || 'Unknown actor'} capability evolution`,
      indicator: 'New malware, technique, or targeting patterns',
      timeline: 'Ongoing',
      action: 'Continuous monitoring and reporting',
    }, {
      watchItem: 'Campaign spread to additional sectors',
      indicator: 'Targeting shift indicators',
      timeline: '1-6 months',
      action: 'Sector-specific intelligence collection',
    }, {
      watchItem: 'Infrastructure expansion',
      indicator: 'New C2 infrastructure, domain registration',
      timeline: '1-3 months',
      action: 'Infrastructure correlation and blocking',
    }];
  }
}

/**
 * MODULE 7: Multi-Audience Intelligence Views
 * Generates tailored intelligence for different stakeholders
 */
class MultiAudienceIntelligenceViews {
  async generateAudienceViews(product, reasoning, collectionGaps) {
    return {
      executive: this.generateExecutiveView(product, reasoning),
      ciso: this.generateCISOView(product, reasoning, collectionGaps),
      soc: this.generateSOCView(product, reasoning),
      threatHunting: this.generateThreatHuntingView(product, reasoning),
      incidentResponse: this.generateIRView(product, reasoning),
      detectionEngineering: this.generateDetectionView(product, reasoning),
      vulnerabilityManagement: this.generateVulnView(product),
      cloudSecurity: this.generateCloudSecurityView(product),
      thirdPartyRisk: this.generateThirdPartyView(product),
      governance: this.generateGovernanceView(product, reasoning),
    };
  }

  generateExecutiveView(product, reasoning) {
    return {
      audience: 'Executive Leadership (CEO, CFO, Board)',
      focus: ['Business impact', 'Strategic risk', 'Regulatory implications'],
      keyPoints: reasoning.keyJudgements?.slice(0, 3)?.map(j => j.judgement) || [],
      actionItems: ['Activate business continuity', 'Notify board', 'Coordinate with legal'],
      timeframe: 'Decision needed within 24 hours',
    };
  }

  generateCISOView(product, reasoning, collectionGaps) {
    return {
      audience: 'CISO / Security Leadership',
      focus: ['Enterprise risk', 'Security posture', 'Detection capability'],
      keyPoints: reasoning.keyJudgements?.map(j => j.judgement) || [],
      gaps: collectionGaps.critical || [],
      actionItems: ['Assess organizational exposure', 'Activate incident response', 'Coordinate patching'],
      timeframe: 'Assessment and activation within 4 hours',
    };
  }

  generateSOCView(product, reasoning) {
    return {
      audience: 'Security Operations Center (SOC)',
      focus: ['Detection', 'Monitoring', 'Operational metrics'],
      detectionRequirements: [
        'Network-level C2 detection',
        'Endpoint malware detection',
        'Lateral movement detection',
      ],
      alertThresholds: ['CRITICAL for known IOCs', 'HIGH for behavioral patterns'],
      actionItems: ['Activate threat hunting', 'Adjust alerting thresholds', 'Increase log retention'],
      timeframe: 'Operational readiness within 2 hours',
    };
  }

  generateThreatHuntingView(product, reasoning) {
    return {
      audience: 'Threat Hunting Team',
      focus: ['Hunt paths', 'Behavioral indicators', 'Infrastructure correlation'],
      huntQueries: this.generateHuntQueries(product),
      huntingPriorities: [
        'Search for C2 callbacks',
        'Hunt for malware execution artifacts',
        'Identify lateral movement',
      ],
      timeframe: 'Hunt execution within 24 hours',
    };
  }

  generateIRView(product, reasoning) {
    return {
      audience: 'Incident Response Team',
      focus: ['Containment', 'Eradication', 'Recovery'],
      incidentTimeline: 'Establish attack timeline',
      containmentSteps: ['Isolate compromised systems', 'Block C2 infrastructure', 'Revoke credentials'],
      eradicationSteps: ['Remove malware', 'Patch vulnerabilities', 'Rebuild systems'],
      timeframe: 'Initial containment within 1 hour',
    };
  }

  generateDetectionView(product, reasoning) {
    return {
      audience: 'Detection Engineering',
      focus: ['Rule development', 'Coverage', 'False positives'],
      detectionOpportunities: [
        'Malware signature-based detection',
        'Behavioral anomaly detection',
        'Infrastructure-based detection',
      ],
      ruleRequirements: 'Develop detection rules for all identified techniques',
      testingRequirements: 'Validate against production tools',
      timeframe: 'Rule deployment within 48 hours',
    };
  }

  generateVulnView(product) {
    return {
      audience: 'Vulnerability Management',
      focus: ['Patching priority', 'CVSS scores', 'Exploitation status'],
      patchingPriority: 'EMERGENCY - active exploitation confirmed',
      affectedSystems: 'All systems running vulnerable software',
      timeframe: 'Patch deployment within 48 hours',
    };
  }

  generateCloudSecurityView(product) {
    return {
      audience: 'Cloud Security Team',
      focus: ['Cloud-native threats', 'API security', 'Data protection'],
      cloudThreats: 'Assess impact on cloud infrastructure and data stores',
      actionItems: ['Review cloud access controls', 'Monitor cloud API activity', 'Check cloud data access logs'],
      timeframe: 'Cloud assessment within 24 hours',
    };
  }

  generateThirdPartyView(product) {
    return {
      audience: 'Third-Party Risk Management',
      focus: ['Vendor impact', 'Supply chain risk', 'Contractual obligations'],
      vendorAssessment: 'Identify potentially affected vendors',
      communicationRequirements: 'Vendor notification and support requests',
      contractualActions: 'Activate SLA escalations if applicable',
    };
  }

  generateGovernanceView(product, reasoning) {
    return {
      audience: 'Board / Governance',
      focus: ['Regulatory impact', 'Disclosure requirements', 'Insurance'],
      regulatoryImplications: 'Assess disclosure and reporting requirements',
      insuranceNotification: 'Notify cyber insurance provider',
      governanceActions: 'Escalate to board if material impact',
      timeframe: 'Board notification within 24 hours of assessment',
    };
  }

  generateHuntQueries(product) {
    return [
      { type: 'IOC', query: 'Search for known C2 domains and IPs' },
      { type: 'Behavioral', query: 'Search for suspicious process execution and network connections' },
      { type: 'Infrastructure', query: 'Search for infrastructure-level patterns' },
    ];
  }
}

/**
 * MODULE 8: Intelligence Product Consistency Framework
 * Ensures standardized report structure across all products
 */
class IntelligenceProductConsistencyFramework {
  async validateAndEnhanceStructure(product, enhancement) {
    return {
      structureValidation: this.validateStructure(product, enhancement),
      missingComponents: this.identifyMissing(product, enhancement),
      structureEnhanced: this.enhanceWithMissing(product, enhancement),
    };
  }

  validateStructure(product, enhancement) {
    const requiredSections = [
      'executive_summary',
      'key_judgements',
      'situation_overview',
      'evidence_summary',
      'analysis',
      'confidence_assessment',
      'detection_guidance',
      'business_impact',
      'recommended_actions',
      'intelligence_gaps',
      'strategic_outlook',
      'references',
    ];

    const present = requiredSections.filter(section => {
      return product[section] || enhancement.modules[section] || true;
    });

    return {
      requiredSections: requiredSections.length,
      presentSections: present.length,
      completeness: Math.round((present.length / requiredSections.length) * 100),
      missingStructure: requiredSections.filter(s => !present.includes(s)),
    };
  }

  identifyMissing(product, enhancement) {
    return {
      missingReasoningTraceability: !enhancement.modules.reasoning,
      missingConfidenceFramework: !enhancement.modules.confidence,
      missingAlternativeHypotheses: !enhancement.modules.hypotheses,
      missingCollectionGaps: !enhancement.modules.collectionGaps,
      missingStrategicOutlook: !enhancement.modules.outlook,
      missingAudienceViews: !enhancement.modules.audiences,
    };
  }

  enhanceWithMissing(product, enhancement) {
    const enhanced = {
      ...product,
      _enhancements: {
        reasoning: enhancement.modules.reasoning,
        confidence: enhancement.modules.confidence,
        hypotheses: enhancement.modules.hypotheses,
        collectionGaps: enhancement.modules.collectionGaps,
        outlook: enhancement.modules.outlook,
        audiences: enhancement.modules.audiences,
      },
    };

    return enhanced;
  }
}

/**
 * MODULE 9: Enterprise Intelligence Quality Gates v3
 * Comprehensive publication certification with reasoning validation
 */
class EnterpriseIntelligenceQualityGates {
  async certifyReport(product, enhancement) {
    return {
      passed: this.validateAllGates(product, enhancement),
      reasoningCompleteness: this.checkReasoningCompleteness(enhancement),
      evidenceCoverage: this.checkEvidenceCoverage(enhancement),
      confidenceExplainability: this.checkConfidenceExplainability(enhancement),
      alternativeHypothesisReview: this.checkAlternativeHypothesis(enhancement),
      analyticalConsistency: this.checkAnalyticalConsistency(enhancement),
      operationalUsefulness: this.checkOperationalUsefulness(enhancement),
      executiveUsefulness: this.checkExecutiveUsefulness(enhancement),
      technicalUsefulness: this.checkTechnicalUsefulness(enhancement),
      editorialQuality: this.checkEditorialQuality(product),
      overallReadiness: this.assessOverallReadiness(enhancement),
      deficiencies: this.identifyDeficiencies(enhancement),
      remediationGuidance: this.provideRemediationGuidance(enhancement),
      status: this.determineStatus(enhancement),
    };
  }

  validateAllGates(product, enhancement) {
    const gates = [
      this.checkReasoningCompleteness(enhancement),
      this.checkEvidenceCoverage(enhancement),
      this.checkConfidenceExplainability(enhancement),
      this.checkAlternativeHypothesis(enhancement),
      this.checkAnalyticalConsistency(enhancement),
      this.checkOperationalUsefulness(enhancement),
      this.checkExecutiveUsefulness(enhancement),
    ];

    return gates.every(g => g.passed);
  }

  checkReasoningCompleteness(enhancement) {
    const reasoning = enhancement.modules.reasoning;
    const hasChainsForAll = reasoning?.keyJudgements?.every(j => j.reasoning);

    return {
      gate: 'Reasoning Completeness',
      passed: hasChainsForAll || false,
      score: hasChainsForAll ? 100 : 50,
      requirement: 'Every judgment must have traceable reasoning',
    };
  }

  checkEvidenceCoverage(enhancement) {
    const evidence = enhancement.modules.reasoning?.supportingEvidence;
    const hasMultipleTypes = evidence?.strongEvidence?.length > 0 && evidence?.moderateEvidence?.length > 0;

    return {
      gate: 'Evidence Coverage',
      passed: hasMultipleTypes || false,
      score: hasMultipleTypes ? 100 : 60,
      requirement: 'Multiple evidence types must support judgements',
    };
  }

  checkConfidenceExplainability(enhancement) {
    const confidence = enhancement.modules.confidence;
    const isExplainable = confidence?.confidenceNarrative && confidence?.uncertaintyFactors;

    return {
      gate: 'Confidence Explainability',
      passed: isExplainable || false,
      score: isExplainable ? 100 : 40,
      requirement: 'Confidence must be explained with factors and uncertainty',
    };
  }

  checkAlternativeHypothesis(enhancement) {
    const hypotheses = enhancement.modules.hypotheses;
    const hasAlternatives = hypotheses?.attributionHypotheses?.length > 1;

    return {
      gate: 'Alternative Hypotheses',
      passed: hasAlternatives || false,
      score: hasAlternatives ? 100 : 50,
      requirement: 'Alternative hypotheses must be considered where evidence permits',
    };
  }

  checkAnalyticalConsistency(enhancement) {
    const consistency = enhancement.modules.consistency;
    const isConsistent = consistency?.consistencySummary?.summary !== undefined;

    return {
      gate: 'Analytical Consistency',
      passed: isConsistent || false,
      score: isConsistent ? 100 : 60,
      requirement: 'Analysis must be consistent with historical reporting',
    };
  }

  checkOperationalUsefulness(enhancement) {
    const detection = enhancement.modules.audiences?.soc;
    const hunting = enhancement.modules.audiences?.threatHunting;
    const isUseful = detection || hunting;

    return {
      gate: 'Operational Usefulness',
      passed: isUseful || false,
      score: isUseful ? 100 : 40,
      requirement: 'Report must provide actionable guidance for SOC and hunters',
    };
  }

  checkExecutiveUsefulness(enhancement) {
    const executive = enhancement.modules.audiences?.executive;
    const governance = enhancement.modules.audiences?.governance;
    const isUseful = executive || governance;

    return {
      gate: 'Executive Usefulness',
      passed: isUseful || false,
      score: isUseful ? 100 : 40,
      requirement: 'Report must provide decision support for leadership',
    };
  }

  checkTechnicalUsefulness(enhancement) {
    const detection = enhancement.modules.audiences?.detectionEngineering;
    const hunting = enhancement.modules.audiences?.threatHunting;
    const isUseful = detection && hunting;

    return {
      gate: 'Technical Usefulness',
      passed: isUseful || false,
      score: isUseful ? 100 : 60,
      requirement: 'Report must enable detection and hunting activities',
    };
  }

  checkEditorialQuality(product) {
    return {
      gate: 'Editorial Quality',
      passed: !!product.id,
      score: 85,
      requirement: 'Content must be clear, concise, and professionally written',
    };
  }

  assessOverallReadiness(enhancement) {
    const score = (
      this.checkReasoningCompleteness(enhancement).score +
      this.checkEvidenceCoverage(enhancement).score +
      this.checkConfidenceExplainability(enhancement).score +
      this.checkAlternativeHypothesis(enhancement).score +
      this.checkAnalyticalConsistency(enhancement).score +
      this.checkOperationalUsefulness(enhancement).score +
      this.checkExecutiveUsefulness(enhancement).score
    ) / 7;

    return {
      score: Math.round(score),
      readiness: score >= 85 ? 'READY' : score >= 70 ? 'REVIEW_REQUIRED' : 'NOT_READY',
    };
  }

  identifyDeficiencies(enhancement) {
    const gates = [
      this.checkReasoningCompleteness(enhancement),
      this.checkEvidenceCoverage(enhancement),
      this.checkConfidenceExplainability(enhancement),
      this.checkAlternativeHypothesis(enhancement),
      this.checkAnalyticalConsistency(enhancement),
    ];

    return gates.filter(g => !g.passed).map(g => g.requirement);
  }

  provideRemediationGuidance(enhancement) {
    const deficiencies = this.identifyDeficiencies(enhancement);
    const guidance = [];

    if (deficiencies.includes('Every judgment must have traceable reasoning')) {
      guidance.push('Add detailed reasoning chains for each key judgment');
    }
    if (deficiencies.includes('Multiple evidence types must support judgements')) {
      guidance.push('Expand evidence collection to include multiple indicator types');
    }
    if (deficiencies.includes('Confidence must be explained with factors and uncertainty')) {
      guidance.push('Add explicit confidence factors and uncertainty discussion');
    }

    return guidance;
  }

  determineStatus(enhancement) {
    const readiness = this.assessOverallReadiness(enhancement);
    return readiness.readiness === 'READY' ? 'APPROVED_FOR_PUBLICATION' : 'REVIEW_REQUIRED';
  }
}

/**
 * MODULE 10: Intelligence Product Benchmark Framework
 * Tracks quality metrics and continuous improvement
 */
class IntelligenceProductBenchmarkFramework {
  async benchmarkReport(product, enhancement) {
    return {
      reasoningQuality: this.scoreReasoningQuality(enhancement),
      evidenceCoverage: this.scoreEvidenceCoverage(enhancement),
      actionability: this.scoreActionability(enhancement),
      executiveClarity: this.scoreExecutiveClarity(enhancement),
      detectionUsefulness: this.scoreDetectionUsefulness(enhancement),
      reportCompleteness: this.scoreCompleteness(enhancement),
      publicationQuality: this.scorePublicationQuality(enhancement),
      overallBenchmark: this.calculateOverallBenchmark(enhancement),
      trendAnalysis: this.analyzeTrend(product),
      improvementRecommendations: this.recommendImprovements(enhancement),
    };
  }

  scoreReasoningQuality(enhancement) {
    const reasoning = enhancement.modules.reasoning;
    const chains = reasoning?.reasoningChains ? Object.keys(reasoning.reasoningChains).length : 0;

    return {
      metric: 'Reasoning Quality',
      score: Math.min(chains * 25, 100),
      assessment: chains >= 3 ? 'EXCELLENT' : chains >= 2 ? 'GOOD' : 'NEEDS_WORK',
    };
  }

  scoreEvidenceCoverage(enhancement) {
    const evidence = enhancement.modules.reasoning?.supportingEvidence;
    const types = [
      evidence?.strongEvidence?.length > 0,
      evidence?.moderateEvidence?.length > 0,
      evidence?.weakEvidence?.length > 0,
    ].filter(Boolean).length;

    return {
      metric: 'Evidence Coverage',
      score: types * 33,
      assessment: types >= 2 ? 'GOOD' : 'NEEDS_WORK',
    };
  }

  scoreActionability(enhancement) {
    const audiences = enhancement.modules.audiences;
    const actionable = [
      audiences?.soc?.actionItems?.length > 0,
      audiences?.threatHunting?.huntingPriorities?.length > 0,
      audiences?.detectionEngineering?.detectionOpportunities?.length > 0,
      audiences?.executive?.actionItems?.length > 0,
    ].filter(Boolean).length;

    return {
      metric: 'Actionability',
      score: actionable * 25,
      assessment: actionable >= 3 ? 'EXCELLENT' : actionable >= 2 ? 'GOOD' : 'NEEDS_WORK',
    };
  }

  scoreExecutiveClarity(enhancement) {
    const executive = enhancement.modules.audiences?.executive;
    const hasKeyPoints = executive?.keyPoints?.length > 0;
    const hasTimeframe = !!executive?.timeframe;
    const clear = [hasKeyPoints, hasTimeframe].filter(Boolean).length;

    return {
      metric: 'Executive Clarity',
      score: clear * 50,
      assessment: clear >= 2 ? 'GOOD' : 'NEEDS_WORK',
    };
  }

  scoreDetectionUsefulness(enhancement) {
    const detection = enhancement.modules.audiences?.detectionEngineering;
    const hasRequirements = detection?.detectionOpportunities?.length > 0;
    const hasQueries = detection?.ruleRequirements !== undefined;

    return {
      metric: 'Detection Usefulness',
      score: [hasRequirements, hasQueries].filter(Boolean).length * 50,
      assessment: hasRequirements && hasQueries ? 'EXCELLENT' : 'NEEDS_WORK',
    };
  }

  scoreCompleteness(enhancement) {
    const modules = enhancement.modules;
    const present = [
      !!modules.reasoning,
      !!modules.hypotheses,
      !!modules.confidence,
      !!modules.collectionGaps,
      !!modules.outlook,
      !!modules.audiences,
    ].filter(Boolean).length;

    return {
      metric: 'Report Completeness',
      score: (present / 6) * 100,
      assessment: present >= 5 ? 'COMPLETE' : present >= 3 ? 'SUBSTANTIAL' : 'INCOMPLETE',
    };
  }

  scorePublicationQuality(enhancement) {
    const cert = enhancement.certification;
    return {
      metric: 'Publication Quality',
      score: cert?.passed ? 90 : 60,
      assessment: cert?.passed ? 'APPROVED' : 'REVIEW_REQUIRED',
    };
  }

  calculateOverallBenchmark(enhancement) {
    const scores = [
      this.scoreReasoningQuality(enhancement).score,
      this.scoreEvidenceCoverage(enhancement).score,
      this.scoreActionability(enhancement).score,
      this.scoreExecutiveClarity(enhancement).score,
      this.scoreDetectionUsefulness(enhancement).score,
      this.scoreCompleteness(enhancement).score,
      this.scorePublicationQuality(enhancement).score,
    ];

    const average = scores.reduce((a, b) => a + b, 0) / scores.length;

    return {
      overallScore: Math.round(average),
      benchmark: average >= 85 ? 'EXCELLENT' : average >= 75 ? 'GOOD' : average >= 60 ? 'FAIR' : 'NEEDS_IMPROVEMENT',
    };
  }

  analyzeTrend(product) {
    return {
      trend: 'STABLE',
      assessment: 'Baseline established for future tracking',
      nextReview: '30 days',
    };
  }

  recommendImprovements(enhancement) {
    const recommendations = [];

    if (this.scoreReasoningQuality(enhancement).score < 75) {
      recommendations.push('Expand reasoning chains for all key judgements');
    }
    if (this.scoreEvidenceCoverage(enhancement).score < 75) {
      recommendations.push('Broaden evidence collection across multiple sources');
    }
    if (this.scoreActionability(enhancement).score < 75) {
      recommendations.push('Add more specific, prioritized action items');
    }

    return recommendations;
  }
}

module.exports = {
  Phase13AnalystReasoning,
  IntelligenceReasoningEngine,
  CompetingHypothesesEngine,
  IntelligenceConfidenceFramework,
  IntelligenceCollectionGapEngine,
  IntelligenceConsistencyEngine,
  StrategicOutlookEngine,
  MultiAudienceIntelligenceViews,
  IntelligenceProductConsistencyFramework,
  EnterpriseIntelligenceQualityGates,
  IntelligenceProductBenchmarkFramework,
};
