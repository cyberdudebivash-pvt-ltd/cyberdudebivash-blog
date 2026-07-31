'use strict';

const { CorrelationEngine } = require('./correlation-engine');
const { AttributionEngine } = require('./attribution-engine');
const { CampaignEvolutionEngine } = require('./campaign-evolution-engine');
const { IntelligenceChangeDetectionEngine } = require('./intelligence-change-detection');
const { HistoricalIntelligenceComparisonEngine } = require('./historical-intelligence-comparison');
const { EvidenceConflictEngine } = require('./evidence-conflict-engine');
const { CollectionRecommendationEngine } = require('./collection-recommendation-engine');

class Phase9Orchestrator {
  constructor() {
    this.correlation = new CorrelationEngine();
    this.attribution = new AttributionEngine();
    this.campaignEvolution = new CampaignEvolutionEngine();
    this.changeDetection = new IntelligenceChangeDetectionEngine();
    this.historicalComparison = new HistoricalIntelligenceComparisonEngine();
    this.conflictDetection = new EvidenceConflictEngine();
    this.collectionAnalysis = new CollectionRecommendationEngine();
  }

  async enhanceProduct(product, investigation, report, previousIntelligence = {}, historicalRecords = []) {
    console.log(`[PHASE 9] Enhancing product ${product.id} with enterprise correlation & attribution`);

    try {
      product.modules.intelligence = product.modules.intelligence || {};

      // Phase 9A: Correlation across all dimensions
      product.modules.intelligence.correlations = this.correlation.findCorrelations(investigation, product, report);

      // Phase 9B: Attribution assessment with confidence levels
      product.modules.intelligence.attributions = this.attribution.assessAttribution(investigation, report);

      // Phase 9C: Campaign evolution tracking
      product.modules.intelligence.campaignEvolution = this.campaignEvolution.trackCampaignEvolution(
        investigation,
        historicalRecords[historicalRecords.length - 1] || {}
      );

      // Phase 9D: Intelligence change detection
      product.modules.intelligence.changeDetection = this.changeDetection.detectChanges(investigation, previousIntelligence);

      // Phase 9E: Historical comparison and trend analysis
      product.modules.intelligence.historicalComparison = this.historicalComparison.compareIntelligence(
        investigation,
        historicalRecords
      );

      // Phase 9F: Evidence conflict detection
      product.modules.intelligence.evidenceConflicts = this.conflictDetection.detectConflicts(investigation, report);

      // Phase 9G: Collection gap analysis and recommendations
      product.modules.intelligence.collectionGaps = this.collectionAnalysis.analyzeCollectionGaps(investigation);

      // Phase 9H: Intelligence quality assessment
      product.modules.intelligence.qualityAssessment = this.assessIntelligenceQuality(
        product.modules.intelligence,
        investigation
      );

      // Phase 9I: Enterprise correlation APIs metadata
      product.modules.intelligence.correlationAPIs = this.generateCorrelationAPIMetadata(
        product.modules.intelligence
      );

      // Phase 9J: Operational intelligence outputs
      product.modules.intelligence.operationalOutputs = this.generateOperationalOutputs(product, investigation);

      // Mark product as Phase 9 enhanced
      product.phase9Enhanced = true;
      product.phase9EnhancedAt = new Date().toISOString();

      console.log(`[PHASE 9] Product enhancement complete. Correlations found: ${product.modules.intelligence.correlations?.relationshipGraph?.edgeCount || 0} relationships`);

      return {
        product,
        correlationResult: product.modules.intelligence.correlations,
        attributionResult: product.modules.intelligence.attributions,
        changeDetectionResult: product.modules.intelligence.changeDetection,
      };
    } catch (e) {
      console.error(`[PHASE 9] Enhancement failed: ${e.message}`);
      throw e;
    }
  }

  assessIntelligenceQuality(intelligence, investigation) {
    const assessments = {
      correlationQuality: this.assessCorrelationQuality(intelligence.correlations),
      attributionQuality: this.assessAttributionQuality(intelligence.attributions),
      evolutionQuality: this.assessEvolutionQuality(intelligence.campaignEvolution),
      completeness: this.assessIntelligenceCompleteness(investigation),
      confidence: this.assessOverallConfidence(intelligence),
      qualityScore: 0,
      assessedAt: new Date().toISOString(),
    };

    assessments.qualityScore = (
      (assessments.correlationQuality || 0.5) * 0.25 +
      (assessments.attributionQuality || 0.5) * 0.25 +
      (assessments.evolutionQuality || 0.5) * 0.15 +
      (assessments.completeness || 0.5) * 0.2 +
      (assessments.confidence || 0.5) * 0.15
    );

    return assessments;
  }

  assessCorrelationQuality(correlations) {
    if (!correlations) return 0;
    const edgeCount = correlations.relationshipGraph?.edgeCount || 0;
    const nodeCount = correlations.relationshipGraph?.nodeCount || 1;
    const density = edgeCount / Math.max(1, nodeCount * (nodeCount - 1) / 2);
    return Math.min(1.0, density);
  }

  assessAttributionQuality(attributions) {
    if (!attributions || attributions.length === 0) return 0;
    const avgConfidence = attributions.reduce((sum, a) => sum + (a.confidence || 0), 0) / attributions.length;
    return Math.min(1.0, avgConfidence);
  }

  assessEvolutionQuality(evolution) {
    if (!evolution) return 0.5;
    const campaignCount = evolution.campaignEvolutions?.length || 0;
    return Math.min(1.0, 0.5 + (campaignCount * 0.1));
  }

  assessIntelligenceCompleteness(investigation) {
    let score = 0;
    if (investigation.threatActors?.length > 0) score += 0.15;
    if (investigation.campaigns?.length > 0) score += 0.15;
    if (investigation.malware?.length > 0) score += 0.15;
    if (investigation.infrastructure?.length > 0) score += 0.15;
    if (investigation.iocs?.length > 0) score += 0.15;
    if (investigation.victims?.length > 0) score += 0.15;
    if (investigation.mitreTechniques?.length > 0) score += 0.1;
    return Math.min(1.0, score);
  }

  assessOverallConfidence(intelligence) {
    const topAttribution = intelligence.attributions?.[0];
    return topAttribution?.confidence || 0.5;
  }

  generateCorrelationAPIMetadata(intelligence) {
    return {
      correlationEndpoints: [
        {
          path: '/api/correlations/threat-actors',
          method: 'GET',
          description: 'Retrieve correlated threat actors and relationships',
          dataPoints: intelligence.correlations?.threatActorCorrelations?.length || 0,
        },
        {
          path: '/api/correlations/campaigns',
          method: 'GET',
          description: 'Retrieve correlated campaigns',
          dataPoints: intelligence.correlations?.campaignCorrelations?.length || 0,
        },
        {
          path: '/api/correlations/infrastructure',
          method: 'GET',
          description: 'Retrieve correlated infrastructure clusters',
          dataPoints: intelligence.correlations?.infrastructureCorrelations?.length || 0,
        },
        {
          path: '/api/graph/relationships',
          method: 'GET',
          description: 'Full relationship graph with nodes and edges',
          nodeCount: intelligence.correlations?.relationshipGraph?.nodeCount || 0,
          edgeCount: intelligence.correlations?.relationshipGraph?.edgeCount || 0,
        },
      ],
      rateLimit: '100 req/min',
      authentication: 'API key required',
      documentation: '/docs/api/correlations',
    };
  }

  generateOperationalOutputs(product, investigation) {
    return {
      threatSummary: this.generateThreatSummary(investigation),
      actionableIntelligence: this.generateActionableIntelligence(product, investigation),
      investigativeLeads: this.generateInvestigativeLeads(product),
      uncertaintyFactors: this.identifyUncertaintyFactors(product),
      outputs: {
        hunterBriefing: this.generateHunterBriefing(investigation),
        executiveSummary: this.generateExecutiveBrief(investigation),
        technicalReport: this.generateTechnicalReport(investigation),
      },
    };
  }

  generateThreatSummary(investigation) {
    const topActor = (investigation.threatActors || [])[0];
    const topCampaign = (investigation.campaigns || [])[0];

    return {
      primaryThreat: topActor?.name || 'Unknown',
      campaignName: topCampaign?.name || 'Unnamed Campaign',
      affectedVictims: investigation.victims?.length || 0,
      geographicScope: Object.keys(investigation.geoImpact || {}).length,
      industryScope: Object.keys(investigation.industryImpact || {}).length,
      severity: this.calculateSeverity(investigation),
    };
  }

  generateActionableIntelligence(product, investigation) {
    return [
      {
        action: 'Block Known Infrastructure',
        targets: (investigation.infrastructure || []).slice(0, 5),
        timeline: 'Immediate',
        expectedImpact: 'Disrupt C2 communications',
      },
      {
        action: 'Hunt for Known IOCs',
        iocs: (investigation.iocs || []).slice(0, 10),
        timeline: '1 hour',
        expectedImpact: 'Identify additional compromises',
      },
      {
        action: 'Implement Detection Rules',
        techniques: (investigation.mitreTechniques || []).slice(0, 5),
        timeline: '4 hours',
        expectedImpact: 'Detect future attacks',
      },
    ];
  }

  generateInvestigativeLeads(product) {
    return [
      {
        area: 'Infrastructure Deep Dive',
        recommendation: 'Analyze ASN, provider, and geo-location patterns for additional operator infrastructure',
        priority: 'high',
      },
      {
        area: 'Malware Reverse Engineering',
        recommendation: 'Conduct in-depth analysis of binary samples to identify additional capabilities',
        priority: 'high',
      },
      {
        area: 'Timeline Reconstruction',
        recommendation: 'Develop comprehensive attack timeline across all victim organizations',
        priority: 'medium',
      },
    ];
  }

  identifyUncertaintyFactors(product) {
    const factors = [];
    if (!product.modules?.intelligence?.attributions?.[0]?.confidence || product.modules.intelligence.attributions[0].confidence < 0.7) {
      factors.push('Attribution confidence below 70% - additional evidence needed');
    }
    if ((product.modules?.intelligence?.correlations?.relationshipGraph?.nodeCount || 0) < 5) {
      factors.push('Limited correlation data - may indicate sparse intelligence collection');
    }
    return factors;
  }

  generateHunterBriefing(investigation) {
    return {
      type: 'HUNTER_BRIEFING',
      title: `Threat Hunt Brief: ${(investigation.threatActors || [])[0]?.name || 'Unknown Actor'}`,
      priority: 'high',
      keyIndicators: (investigation.iocs || []).slice(0, 20).map(ioc => ioc.value),
      techniques: (investigation.mitreTechniques || []).slice(0, 10),
      expectedFindings: ['Lateral movement artifacts', 'Data staging activities', 'Persistence mechanisms'],
    };
  }

  generateExecutiveBrief(investigation) {
    return {
      type: 'EXECUTIVE_BRIEF',
      businessImpact: `${investigation.victims?.length || 0} organizations affected`,
      riskLevel: 'critical',
      summary: 'Multi-actor, multi-campaign threat with significant scope and sophistication',
    };
  }

  generateTechnicalReport(investigation) {
    return {
      type: 'TECHNICAL_REPORT',
      killChain: this.reconstructKillChain(investigation),
      indicators: investigation.iocs?.length || 0,
      artifacts: investigation.findings?.length || 0,
    };
  }

  reconstructKillChain(investigation) {
    return (investigation.mitreTechniques || [])
      .map(t => ({ technique: t.id, tactic: t.tactic }))
      .sort((a, b) => this.getTacticOrder(a.tactic) - this.getTacticOrder(b.tactic));
  }

  getTacticOrder(tactic) {
    const order = {
      'Reconnaissance': 1,
      'Resource Development': 2,
      'Initial Access': 3,
      'Execution': 4,
      'Persistence': 5,
      'Privilege Escalation': 6,
      'Defense Evasion': 7,
      'Credential Access': 8,
      'Discovery': 9,
      'Lateral Movement': 10,
      'Collection': 11,
      'Command and Control': 12,
      'Exfiltration': 13,
      'Impact': 14,
    };
    return order[tactic] || 99;
  }

  calculateSeverity(investigation) {
    const victimCount = investigation.victims?.length || 0;
    const hasFinancialImpact = (investigation.findings || []).some(f => f.dataExfiltrated);

    if (victimCount > 100 || hasFinancialImpact) return 'critical';
    if (victimCount > 20) return 'high';
    if (victimCount > 5) return 'medium';
    return 'low';
  }

  async validateEnhancedProduct(product, investigation) {
    const intelligence = product.modules?.intelligence;
    if (!intelligence) {
      return { valid: false, reason: 'Phase 9 enhancement not applied' };
    }

    const hasCorrelations = intelligence.correlations?.relationshipGraph?.edgeCount > 0;
    const hasAttributions = intelligence.attributions?.length > 0;
    const hasQualityAssessment = intelligence.qualityAssessment?.qualityScore > 0;

    return {
      valid: hasCorrelations && hasAttributions && hasQualityAssessment,
      correlationsFound: hasCorrelations,
      attributionsAssessed: hasAttributions,
      qualityScore: intelligence.qualityAssessment?.qualityScore || 0,
    };
  }

  getEnhancementSummary(product) {
    if (!product.phase9Enhanced) {
      return {
        status: 'Not enhanced',
        phase: 'Pre-Phase 9',
      };
    }

    const intel = product.modules?.intelligence;
    return {
      status: 'Enhanced',
      phase: 'Phase 9',
      enhancedAt: product.phase9EnhancedAt,
      correlations: intel?.correlations?.relationshipGraph?.edgeCount || 0,
      attributions: intel?.attributions?.length || 0,
      changes: intel?.changeDetection?.changeCount || 0,
      qualityScore: intel?.qualityAssessment?.qualityScore || 0,
    };
  }
}

module.exports = { Phase9Orchestrator };
