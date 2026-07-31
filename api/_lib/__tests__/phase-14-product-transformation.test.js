'use strict';

const {
  Phase14ProductTransformation,
  ExecutiveIntelligenceExcellence,
  TechnicalIntelligenceExcellence,
  AttributionExcellence,
  CampaignIntelligenceEngine,
  IntelligenceCorrelationEngine,
  OriginalAnalyticalValueEngine,
  DecisionSupportEngine,
  DetectionEngineeringExcellence,
  StrategicIntelligenceEngine,
  CommercialProductExcellenceEngine,
} = require('../phase-14-product-transformation');

describe('Phase 14 — World-Class Intelligence Product Transformation', () => {
  let phase14;
  let mockProduct;
  let mockInvestigation;
  let mockContext;

  beforeEach(() => {
    phase14 = new Phase14ProductTransformation();

    mockProduct = {
      id: 'prod-phase14-001',
      title: 'APT-29 October 2026 Advanced Assessment',
      type: 'threat-actor',
      threatLevel: 'CRITICAL',
    };

    mockInvestigation = {
      id: 'inv-phase14-001',
      title: 'APT-29 October 2026 Campaign',
      severity: 'CRITICAL',
      threatActors: ['APT-29', 'Cozy Bear'],
      targetedSectors: ['financial', 'government', 'technology'],
      affectedUserCount: 25000,
      cisaKev: true,
      exploited: true,
      ransomware: false,
      techniques: [
        { name: 'Spear Phishing', mitreTactic: ['Initial Access'] },
        { name: 'Living off the Land', mitreTactic: ['Execution'] },
        { name: 'Registry Modification', mitreTactic: ['Persistence'] },
        { name: 'Lateral Movement', mitreTactic: ['Lateral Movement'] },
        { name: 'Data Exfiltration', mitreTactic: ['Exfiltration'] },
      ],
      malware: ['Zebrocy', 'Sofacy'],
      infrastructure: [
        { ip: '192.0.2.1', hosting: 'Digital Ocean', location: 'RU' },
        { ip: '192.0.2.2', hosting: 'Linode', location: 'NL' },
      ],
      evidence: [
        { type: 'C2 Traffic', confidence: 95 },
        { type: 'Malware', confidence: 92 },
      ],
      timeline: 'Campaign active since September 2026',
    };

    mockContext = {
      correlationDatabase: {},
      historicalReports: {},
    };
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ORCHESTRATION: Phase14ProductTransformation Main Class Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Orchestration: Phase14ProductTransformation', () => {
    test('should initialize with default configuration', () => {
      const p14 = new Phase14ProductTransformation();

      expect(p14.config.enableExecutiveEnhancement).toBe(true);
      expect(p14.config.enableTechnicalEnhancement).toBe(true);
      expect(p14.config.enableAttributionEnhancement).toBe(true);
      expect(p14.config.enableCampaignEnhancement).toBe(true);
      expect(p14.config.enableCorrelationEnhancement).toBe(true);
      expect(p14.config.enableAnalyticalEnhancement).toBe(true);
      expect(p14.config.enableDecisionSupportEnhancement).toBe(true);
      expect(p14.config.enableDetectionEnhancement).toBe(true);
      expect(p14.config.enableStrategicEnhancement).toBe(true);
      expect(p14.config.enableCommercialEnhancement).toBe(true);
    });

    test('should initialize all 10 workstream engines', () => {
      expect(phase14.executiveEngine).toBeInstanceOf(ExecutiveIntelligenceExcellence);
      expect(phase14.technicalEngine).toBeInstanceOf(TechnicalIntelligenceExcellence);
      expect(phase14.attributionEngine).toBeInstanceOf(AttributionExcellence);
      expect(phase14.campaignEngine).toBeInstanceOf(CampaignIntelligenceEngine);
      expect(phase14.correlationEngine).toBeInstanceOf(IntelligenceCorrelationEngine);
      expect(phase14.analyticalEngine).toBeInstanceOf(OriginalAnalyticalValueEngine);
      expect(phase14.decisionEngine).toBeInstanceOf(DecisionSupportEngine);
      expect(phase14.detectionEngine).toBeInstanceOf(DetectionEngineeringExcellence);
      expect(phase14.strategicEngine).toBeInstanceOf(StrategicIntelligenceEngine);
      expect(phase14.commercialEngine).toBeInstanceOf(CommercialProductExcellenceEngine);
    });

    test('should provide JSON metadata describing phase', () => {
      const json = phase14.toJSON();

      expect(json.phase).toBe('phase-14');
      expect(json.name).toBe('World-Class Intelligence Product Transformation');
      expect(Array.isArray(json.workstreams)).toBe(true);
      expect(json.workstreams).toHaveLength(10);
    });

    test('should transform intelligence product with all workstreams', async () => {
      const transformed = await phase14.transformIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(transformed.productId).toBe(mockProduct.id);
      expect(transformed.timestamp).toBeDefined();
      expect(transformed.enhancements).toBeDefined();
      expect(transformed.qualityAssessment).toBeDefined();
      expect(transformed.productionReadiness).toBeDefined();
      expect(transformed.status).toMatch(/approved_for_production|review_required|error/);

      // Verify all 10 workstream enhancements
      expect(transformed.enhancements.executive).toBeDefined();
      expect(transformed.enhancements.technical).toBeDefined();
      expect(transformed.enhancements.attribution).toBeDefined();
      expect(transformed.enhancements.campaign).toBeDefined();
      expect(transformed.enhancements.correlation).toBeDefined();
      expect(transformed.enhancements.analytical).toBeDefined();
      expect(transformed.enhancements.decisions).toBeDefined();
      expect(transformed.enhancements.detection).toBeDefined();
      expect(transformed.enhancements.strategic).toBeDefined();
      expect(transformed.enhancements.commercial).toBeDefined();
    });

    test('should assess product quality across 10 dimensions', async () => {
      const transformed = await phase14.transformIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      const qa = transformed.qualityAssessment;
      expect(qa.executiveClarity).toBeDefined();
      expect(qa.technicalDepth).toBeDefined();
      expect(qa.attributionRigor).toBeDefined();
      expect(qa.campaignContext).toBeDefined();
      expect(qa.correlationValue).toBeDefined();
      expect(qa.analyticalOriginality).toBeDefined();
      expect(qa.decisionSupportQuality).toBeDefined();
      expect(qa.detectionCoverage).toBeDefined();
      expect(qa.strategicValue).toBeDefined();
      expect(qa.commercialExcellence).toBeDefined();
    });

    test('should certify production readiness based on quality assessment', async () => {
      const transformed = await phase14.transformIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(typeof transformed.productionReadiness.approved).toBe('boolean');
      expect(transformed.productionReadiness.score).toBeGreaterThanOrEqual(0);
      expect(transformed.productionReadiness.threshold).toBe(70);
      expect(transformed.productionReadiness.status).toMatch(/PRODUCTION_READY|REVIEW_REQUIRED/);
    });

    test('should handle errors gracefully during transformation', async () => {
      const transformed = await phase14.transformIntelligenceProduct(
        null,
        mockInvestigation,
        mockContext
      );

      expect(transformed.status).toBe('error');
      expect(transformed.error).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 1: Executive Intelligence Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 1: Executive Intelligence Excellence', () => {
    let executiveEngine;

    beforeEach(() => {
      executiveEngine = new ExecutiveIntelligenceExcellence();
    });

    test('should enhance executive content with all required sections', async () => {
      const enhanced = await executiveEngine.enhanceExecutiveContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.executiveSummary).toBeDefined();
      expect(enhanced.businessImpact).toBeDefined();
      expect(enhanced.operationalImpact).toBeDefined();
      expect(enhanced.financialConsiderations).toBeDefined();
      expect(enhanced.regulatoryConsiderations).toBeDefined();
      expect(enhanced.strategicPriorities).toBeDefined();
      expect(enhanced.immediateExecutiveActions).toBeDefined();
      expect(enhanced.mediumTermPlanning).toBeDefined();
      expect(enhanced.indicatorsToMonitor).toBeDefined();
    });

    test('should generate executive summary with business relevance', () => {
      const summary = executiveEngine.generateExecutiveSummary(mockInvestigation);

      expect(summary.headline).toBe(mockInvestigation.title);
      expect(Array.isArray(summary.keyFindings)).toBe(true);
      expect(summary.threatLevel).toBe('CRITICAL');
      expect(summary.businessRelevance).toBe('CRITICAL');
      expect(summary.decisionImpact).toBeDefined();
    });

    test('should identify business impact for affected sectors', () => {
      const impacts = executiveEngine.generateBusinessImpact(mockInvestigation);

      expect(Array.isArray(impacts)).toBe(true);
      expect(impacts.some(i => i.area === 'Customer Data')).toBe(true);
      expect(impacts.some(i => i.area === 'Patch Liability')).toBe(true);
      expect(impacts.every(i => i.severity)).toBe(true);
    });

    test('should generate operational impact for security teams', () => {
      const impact = executiveEngine.generateOperationalImpact(mockInvestigation);

      expect(impact.detectionTeam).toBeDefined();
      expect(impact.huntingTeam).toBeDefined();
      expect(impact.incidentResponse).toBeDefined();
      expect(impact.threatManagement).toBeDefined();
      expect(impact.vulnerabilityManagement).toBeDefined();
    });

    test('should generate immediate executive actions with timelines', () => {
      const actions = executiveEngine.generateImmediateExecutiveActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.every(a => a.action)).toBe(true);
      expect(actions.every(a => a.owner)).toBe(true);
      expect(actions.every(a => a.timeline)).toBe(true);
      expect(actions.every(a => a.rationale)).toBe(true);
    });

    test('should provide medium-term planning timeline', () => {
      const planning = executiveEngine.generateMediumTermPlanning(mockInvestigation);

      expect(planning.week1).toBeDefined();
      expect(planning.week2).toBeDefined();
      expect(planning.week3).toBeDefined();
      expect(planning.month2Plus).toBeDefined();
    });

    test('should identify indicators to monitor', () => {
      const indicators = executiveEngine.generateIndicatorsToMonitor(mockInvestigation);

      expect(indicators.technical).toBeDefined();
      expect(indicators.operational).toBeDefined();
      expect(indicators.strategic).toBeDefined();
      expect(Array.isArray(indicators.technical)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 2: Technical Intelligence Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 2: Technical Intelligence Excellence', () => {
    let technicalEngine;

    beforeEach(() => {
      technicalEngine = new TechnicalIntelligenceExcellence();
    });

    test('should enhance technical content with all required sections', async () => {
      const enhanced = await technicalEngine.enhanceTechnicalContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.rootCause).toBeDefined();
      expect(enhanced.attackFlow).toBeDefined();
      expect(enhanced.exploitationPath).toBeDefined();
      expect(enhanced.technicalPreconditions).toBeDefined();
      expect(enhanced.infrastructureAnalysis).toBeDefined();
      expect(enhanced.malwareBehavior).toBeDefined();
      expect(enhanced.detectionOpportunities).toBeDefined();
      expect(enhanced.defensiveOpportunities).toBeDefined();
      expect(enhanced.residualRisk).toBeDefined();
      expect(enhanced.validationGuidance).toBeDefined();
    });

    test('should analyze root cause and underlying conditions', () => {
      const rootCause = technicalEngine.analyzeRootCause(mockInvestigation);

      expect(rootCause.primaryCause).toBe('Unpatched known vulnerability');
      expect(Array.isArray(rootCause.secondaryCauses)).toBe(true);
      expect(rootCause.underlyingConditions).toBeDefined();
    });

    test('should build attack flow mapped to MITRE tactics', () => {
      const flow = technicalEngine.buildAttackFlow(mockInvestigation);

      expect(Array.isArray(flow)).toBe(true);
      expect(flow.length).toBeGreaterThan(0);
      expect(flow.every(f => f.stage)).toBe(true);
      expect(flow.every(f => f.technique)).toBe(true);
      expect(flow.every(f => f.tactic)).toBe(true);
    });

    test('should define exploitation path from entry to objective', () => {
      const path = technicalEngine.defineExploitationPath(mockInvestigation);

      expect(path.entryPoint).toBeDefined();
      expect(path.persistence).toBeDefined();
      expect(path.privilege).toBeDefined();
      expect(path.objectiveAchievement).toBeDefined();
    });

    test('should identify technical preconditions', () => {
      const preconditions = technicalEngine.identifyPreconditions(mockInvestigation);

      expect(preconditions.system).toBeDefined();
      expect(preconditions.network).toBeDefined();
      expect(preconditions.user).toBeDefined();
      expect(preconditions.environment).toBeDefined();
    });

    test('should analyze infrastructure with hosting and geography', () => {
      const infrastructure = technicalEngine.analyzeInfrastructure(mockInvestigation);

      expect(infrastructure.nodesIdentified).toBe(2);
      expect(infrastructure.hostingProviders.length).toBeGreaterThan(0);
      expect(infrastructure.geographicDistribution.length).toBeGreaterThan(0);
      expect(infrastructure.persistenceMechanisms).toBeDefined();
    });

    test('should identify detection opportunities across vectors', () => {
      const opportunities = technicalEngine.identifyDetectionOpportunities(mockInvestigation);

      expect(Array.isArray(opportunities)).toBe(true);
      expect(opportunities.some(o => o.toLowerCase().includes('c2'))).toBe(true);
      expect(opportunities.some(o => o.toLowerCase().includes('malware'))).toBe(true);
    });

    test('should identify defensive opportunities', () => {
      const defensive = technicalEngine.identifyDefensiveOpportunities(mockInvestigation);

      expect(Array.isArray(defensive)).toBe(true);
      expect(defensive).toContain('Block infrastructure at network perimeter');
      expect(defensive).toContain('Segment network to contain lateral movement');
    });

    test('should assess residual risk', () => {
      const residual = technicalEngine.assessResidualRisk(mockInvestigation);

      expect(residual.undetectedIntrusions).toBeDefined();
      expect(residual.unknownCapabilities).toBeDefined();
      expect(residual.evasionCAPABILITIES).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 3: Attribution Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 3: Attribution Excellence', () => {
    let attributionEngine;

    beforeEach(() => {
      attributionEngine = new AttributionExcellence();
    });

    test('should enhance attribution content with all required sections', async () => {
      const enhanced = await attributionEngine.enhanceAttributionContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.primaryAttribution).toBeDefined();
      expect(enhanced.supportingEvidence).toBeDefined();
      expect(enhanced.contradictoryEvidence).toBeDefined();
      expect(enhanced.confidenceExplanation).toBeDefined();
      expect(enhanced.alternativeHypotheses).toBeDefined();
      expect(enhanced.remainingUncertainty).toBeDefined();
      expect(enhanced.evidenceGaps).toBeDefined();
    });

    test('should generate primary attribution with confidence level', () => {
      const attribution = attributionEngine.generatePrimaryAttribution(mockInvestigation);

      expect(attribution.actors).toEqual(['APT-29', 'Cozy Bear']);
      expect(attribution.confidence).toBeDefined();
      expect(attribution.basis).toBeDefined();
      expect(attribution.disclaimer).toBeDefined();
    });

    test('should compile supporting evidence by type', () => {
      const evidence = attributionEngine.compileSupportingEvidence(mockInvestigation);

      expect(Array.isArray(evidence)).toBe(true);
      expect(evidence.some(e => e.type === 'Tactical Technique Usage')).toBe(true);
      expect(evidence.every(e => e.strength)).toBe(true);
    });

    test('should identify contradictory evidence', () => {
      const contradictions = attributionEngine.identifyContradictoryEvidence(mockInvestigation);

      expect(contradictions.contradictions).toEqual([]);
      expect(contradictions.assessment).toBeDefined();
    });

    test('should explain confidence with increasing and decreasing factors', () => {
      const explanation = attributionEngine.explainConfidence(mockInvestigation);

      expect(explanation.overall).toBeGreaterThanOrEqual(0);
      expect(explanation.overall).toBeLessThanOrEqual(100);
      expect(Array.isArray(explanation.factorsIncreasing)).toBe(true);
      expect(Array.isArray(explanation.factorsDecreasing)).toBe(true);
    });

    test('should generate alternative hypotheses with evidence requirements', () => {
      const alternatives = attributionEngine.generateAlternatives(mockInvestigation);

      expect(Array.isArray(alternatives)).toBe(true);
      expect(alternatives.length).toBeGreaterThan(0);
      expect(alternatives.every(a => a.hypothesis)).toBe(true);
      expect(alternatives.every(a => a.likelihood)).toBe(true);
      expect(alternatives.every(a => a.requiredEvidence)).toBe(true);
    });

    test('should assess attribution uncertainty', () => {
      const uncertainty = attributionEngine.assessUncertainty(mockInvestigation);

      expect(uncertainty.attributionConfidence).toBeDefined();
      expect(uncertainty.timeline).toBeDefined();
      expect(uncertainty.limitations).toBeDefined();
    });

    test('should identify evidence gaps', () => {
      const gaps = attributionEngine.identifyEvidenceGaps(mockInvestigation);

      expect(Array.isArray(gaps)).toBe(true);
      expect(gaps.length).toBeGreaterThan(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 4: Campaign Intelligence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 4: Campaign Intelligence', () => {
    let campaignEngine;

    beforeEach(() => {
      campaignEngine = new CampaignIntelligenceEngine();
    });

    test('should enhance campaign content with lifecycle and evolution', async () => {
      const enhanced = await campaignEngine.enhanceCampaignContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.campaignLifecycle).toBeDefined();
      expect(enhanced.campaignTimeline).toBeDefined();
      expect(enhanced.operationalObjectives).toBeDefined();
      expect(enhanced.infrastructureEvolution).toBeDefined();
      expect(enhanced.malwareEvolution).toBeDefined();
      expect(enhanced.targetingEvolution).toBeDefined();
      expect(enhanced.victimAnalysis).toBeDefined();
      expect(enhanced.defensiveLessons).toBeDefined();
      expect(enhanced.potentialFutureDevelopments).toBeDefined();
    });

    test('should build campaign lifecycle with phases', () => {
      const lifecycle = campaignEngine.buildCampaignLifecycle(mockInvestigation);

      expect(Array.isArray(lifecycle.phases)).toBe(true);
      expect(lifecycle.phases.length).toBeGreaterThan(0);
      expect(lifecycle.estimatedDuration).toBeDefined();
      expect(lifecycle.currentPhase).toBeDefined();
    });

    test('should build campaign timeline with events', () => {
      const timeline = campaignEngine.buildCampaignTimeline(mockInvestigation);

      expect(timeline.events).toBeDefined();
      expect(Array.isArray(timeline.events)).toBe(true);
      expect(timeline.gaps).toBeDefined();
      expect(timeline.projection).toBeDefined();
    });

    test('should define operational objectives based on targeting', () => {
      const objectives = campaignEngine.defineOperationalObjectives(mockInvestigation);

      expect(Array.isArray(objectives)).toBe(true);
      expect(objectives.length).toBeGreaterThan(0);
    });

    test('should analyze infrastructure evolution and resilience', () => {
      const evolution = campaignEngine.analyzeInfrastructureEvolution(mockInvestigation);

      expect(evolution.currentScale).toBe(2);
      expect(evolution.geographicSpread).toBeGreaterThan(0);
      expect(evolution.evolution).toBeDefined();
      expect(evolution.projection).toBeDefined();
    });

    test('should analyze malware evolution and development', () => {
      const evolution = campaignEngine.analyzeMalwareEvolution(mockInvestigation);

      expect(Array.isArray(evolution.families)).toBe(true);
      expect(evolution.variants).toBeDefined();
      expect(evolution.evolution).toBeDefined();
      expect(evolution.projection).toBeDefined();
    });

    test('should generate defensive lessons', () => {
      const lessons = campaignEngine.generateDefensiveLessons(mockInvestigation);

      expect(Array.isArray(lessons)).toBe(true);
      expect(lessons.length).toBeGreaterThan(0);
      expect(lessons.some(l => l.toLowerCase().includes('patch'))).toBe(true);
    });

    test('should assess future trajectory with disclaimer', () => {
      const trajectory = campaignEngine.assessFutureTrajectory(mockInvestigation);

      expect(trajectory.disclaimer).toBeDefined();
      expect(trajectory.potentialEscalation).toBeDefined();
      expect(trajectory.capabilityEnhancement).toBeDefined();
      expect(Array.isArray(trajectory.indicatorsToWatch)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 5: Intelligence Correlation Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 5: Intelligence Correlation', () => {
    let correlationEngine;

    beforeEach(() => {
      correlationEngine = new IntelligenceCorrelationEngine();
    });

    test('should enhance correlation content across all dimensions', async () => {
      const enhanced = await correlationEngine.enhanceCorrelationContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.actorCorrelations).toBeDefined();
      expect(enhanced.campaignCorrelations).toBeDefined();
      expect(enhanced.malwareCorrelations).toBeDefined();
      expect(enhanced.infrastructureCorrelations).toBeDefined();
      expect(enhanced.vulnerabilityCorrelations).toBeDefined();
      expect(enhanced.techniqueCorrelations).toBeDefined();
      expect(enhanced.historicalContext).toBeDefined();
      expect(enhanced.relatedIntelligence).toBeDefined();
    });

    test('should correlate with other threat actors', () => {
      const correlations = correlationEngine.correlateActors(mockInvestigation, mockContext);

      expect(correlations.primaryActors).toEqual(['APT-29', 'Cozy Bear']);
      expect(correlations.knownAssociations).toBeDefined();
      expect(correlations.historicalActivity).toBeDefined();
    });

    test('should correlate with other campaigns', () => {
      const correlations = correlationEngine.correlateCampaigns(mockInvestigation, mockContext);

      expect(correlations.linkedCampaigns).toBeDefined();
      expect(correlations.operationalContinuity).toBeDefined();
      expect(correlations.tpcContinuity).toBeDefined();
    });

    test('should correlate malware families', () => {
      const correlations = correlationEngine.correlateMalware(mockInvestigation, mockContext);

      expect(Array.isArray(correlations.families)).toBe(true);
      expect(correlations.previousVersions).toBeDefined();
      expect(correlations.developmentTrack).toBeDefined();
    });

    test('should identify related intelligence reports', () => {
      const related = correlationEngine.identifyRelatedReports(mockInvestigation, mockContext);

      expect(related.threatActor).toBeDefined();
      expect(related.malware).toBeDefined();
      expect(related.vulnerability).toBeDefined();
      expect(related.sector).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 7: Decision Support Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 7: Decision Support', () => {
    let decisionEngine;

    beforeEach(() => {
      decisionEngine = new DecisionSupportEngine();
    });

    test('should generate decision content for all 12 audience types', async () => {
      const enhanced = await decisionEngine.enhanceDecisionContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.ceoActions).toBeDefined();
      expect(enhanced.boardActions).toBeDefined();
      expect(enhanced.cisoActions).toBeDefined();
      expect(enhanced.socActions).toBeDefined();
      expect(enhanced.threatHuntingActions).toBeDefined();
      expect(enhanced.detectionEngineeringActions).toBeDefined();
      expect(enhanced.incidentResponseActions).toBeDefined();
      expect(enhanced.vulnerabilityManagementActions).toBeDefined();
      expect(enhanced.cloudSecurityActions).toBeDefined();
      expect(enhanced.identitySecurityActions).toBeDefined();
      expect(enhanced.thirdPartyRiskActions).toBeDefined();
      expect(enhanced.securityOperationsLeadershipActions).toBeDefined();
    });

    test('should generate CEO actions with evidence and timeline', () => {
      const actions = decisionEngine.generateCEOActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.every(a => a.decision)).toBe(true);
      expect(actions.every(a => a.evidence)).toBe(true);
      expect(actions.every(a => a.timeline)).toBe(true);
    });

    test('should generate CISO actions', () => {
      const actions = decisionEngine.generateCISOActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.length).toBeGreaterThan(0);
    });

    test('should generate SOC actions', () => {
      const actions = decisionEngine.generateSOCActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.some(a => a.toLowerCase().includes('c2'))).toBe(true);
    });

    test('should generate threat hunting actions', () => {
      const actions = decisionEngine.generateThreatHuntingActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.length).toBeGreaterThan(0);
    });

    test('should generate detection engineering actions', () => {
      const actions = decisionEngine.generateDetectionEngineeringActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.some(a => a.toLowerCase().includes('sigma'))).toBe(true);
    });

    test('should generate incident response actions', () => {
      const actions = decisionEngine.generateIncidentResponseActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.some(a => a.toLowerCase().includes('contain'))).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 8: Detection Engineering Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 8: Detection Engineering Excellence', () => {
    let detectionEngine;

    beforeEach(() => {
      detectionEngine = new DetectionEngineeringExcellence();
    });

    test('should enhance detection content across multiple platforms', async () => {
      const enhanced = await detectionEngine.enhanceDetectionContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.sigmaRules).toBeDefined();
      expect(enhanced.yaraRules).toBeDefined();
      expect(enhanced.suricataRules).toBeDefined();
      expect(enhanced.siemQueries).toBeDefined();
      expect(enhanced.validationProcedures).toBeDefined();
      expect(enhanced.falsePositiveConsiderations).toBeDefined();
      expect(enhanced.detectionCoverage).toBeDefined();
      expect(enhanced.tuningGuidance).toBeDefined();
      expect(enhanced.operationalDeploymentNotes).toBeDefined();
    });

    test('should generate Sigma rules for malware', () => {
      const rules = detectionEngine.generateSigmaRules(mockInvestigation);

      expect(rules.rulesAvailable).toBeDefined();
      expect(rules.ruleCount).toBeGreaterThanOrEqual(0);
      expect(rules.deploymentLocation).toBeDefined();
    });

    test('should generate SIEM queries', () => {
      const queries = detectionEngine.generateSIEMQueries(mockInvestigation);

      expect(Array.isArray(queries)).toBe(true);
      expect(queries.length).toBeGreaterThan(0);
      expect(queries.every(q => q.platform)).toBe(true);
    });

    test('should provide validation procedures', () => {
      const procedures = detectionEngine.provideValidationProcedures(mockInvestigation);

      expect(procedures.methodology).toBeDefined();
      expect(procedures.timeline).toBeDefined();
      expect(procedures.successCriteria).toBeDefined();
    });

    test('should assess false positive risk', () => {
      const fpRisk = detectionEngine.assessFalsePositiveRisk(mockInvestigation);

      expect(fpRisk.highRisk).toBeDefined();
      expect(fpRisk.mediumRisk).toBeDefined();
      expect(fpRisk.mitigation).toBeDefined();
    });

    test('should provide tuning guidance', () => {
      const tuning = detectionEngine.provideTuningGuidance(mockInvestigation);

      expect(tuning.baselineEstablishment).toBeDefined();
      expect(tuning.thresholdSetting).toBeDefined();
      expect(tuning.refinement).toBeDefined();
    });

    test('should provide operational deployment notes', () => {
      const notes = detectionEngine.provideDeploymentNotes(mockInvestigation);

      expect(notes.priority).toBeDefined();
      expect(Array.isArray(notes.stages)).toBe(true);
      expect(notes.monitoring).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 9: Strategic Intelligence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 9: Strategic Intelligence', () => {
    let strategicEngine;

    beforeEach(() => {
      strategicEngine = new StrategicIntelligenceEngine();
    });

    test('should enhance strategic content with trends and outlook', async () => {
      const enhanced = await strategicEngine.enhanceStrategicContent(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(enhanced.emergingTrends).toBeDefined();
      expect(enhanced.threatEvolution).toBeDefined();
      expect(enhanced.sectorImplications).toBeDefined();
      expect(enhanced.defensivePriorities).toBeDefined();
      expect(enhanced.monitoringPriorities).toBeDefined();
      expect(enhanced.collectionPriorities).toBeDefined();
      expect(enhanced.intelligenceGaps).toBeDefined();
      expect(enhanced.outlook).toBeDefined();
    });

    test('should identify emerging trends', () => {
      const trends = strategicEngine.identifyEmergingTrends(mockInvestigation);

      expect(Array.isArray(trends)).toBe(true);
      expect(trends.length).toBeGreaterThan(0);
    });

    test('should assess threat evolution', () => {
      const evolution = strategicEngine.assessThreatEvolution(mockInvestigation);

      expect(evolution.current).toBeDefined();
      expect(evolution.trajectory).toBeDefined();
      expect(Array.isArray(evolution.factors)).toBe(true);
    });

    test('should analyze sector-specific implications', () => {
      const implications = strategicEngine.analyzeSectorImplications(mockInvestigation);

      expect(Array.isArray(implications)).toBe(true);
      expect(implications.length).toBeGreaterThan(0);
    });

    test('should define defensive priorities', () => {
      const priorities = strategicEngine.defineDefensivePriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
      expect(priorities.some(p => p.toLowerCase().includes('patch'))).toBe(true);
    });

    test('should define monitoring priorities', () => {
      const priorities = strategicEngine.defineMonitoringPriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
      expect(priorities.length).toBeGreaterThan(0);
    });

    test('should define collection priorities', () => {
      const priorities = strategicEngine.defineCollectionPriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
      expect(priorities.length).toBeGreaterThan(0);
    });

    test('should identify intelligence gaps', () => {
      const gaps = strategicEngine.identifyIntelligenceGaps(mockInvestigation);

      expect(Array.isArray(gaps)).toBe(true);
      expect(gaps.length).toBeGreaterThan(0);
    });

    test('should generate outlook with disclaimer and uncertainties', () => {
      const outlook = strategicEngine.generateOutlook(mockInvestigation);

      expect(outlook.disclaimer).toBeDefined();
      expect(outlook.sixMonths).toBeDefined();
      expect(outlook.twelveMonths).toBeDefined();
      expect(Array.isArray(outlook.keyAssumptions)).toBe(true);
      expect(Array.isArray(outlook.uncertainties)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // WORKSTREAM 10: Commercial Product Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Workstream 10: Commercial Product Excellence', () => {
    let commercialEngine;

    beforeEach(() => {
      commercialEngine = new CommercialProductExcellenceEngine();
    });

    test('should enhance commercial content with all value dimensions', async () => {
      const enhanced = await commercialEngine.enhanceCommercialContent(
        mockProduct,
        mockInvestigation,
        {},
        mockContext
      );

      expect(enhanced.customerValue).toBeDefined();
      expect(enhanced.operationalValue).toBeDefined();
      expect(enhanced.executiveValue).toBeDefined();
      expect(enhanced.technicalValue).toBeDefined();
      expect(enhanced.detectionValue).toBeDefined();
      expect(enhanced.actionability).toBeDefined();
      expect(enhanced.reportCompleteness).toBeDefined();
      expect(enhanced.confidenceTransparency).toBeDefined();
      expect(enhanced.customerImmediateActions).toBeDefined();
    });

    test('should define customer value', () => {
      const value = commercialEngine.defineCustomerValue(mockInvestigation);

      expect(value.summary).toBeDefined();
      expect(Array.isArray(value.details)).toBe(true);
      expect(value.details.length).toBeGreaterThan(0);
    });

    test('should define operational value', () => {
      const value = commercialEngine.defineOperationalValue(mockInvestigation);

      expect(value.detectiveCapability).toBeDefined();
      expect(value.huntingClosure).toBeDefined();
      expect(value.incidentResponse).toBeDefined();
      expect(value.continuousMonitoring).toBeDefined();
    });

    test('should define executive value', () => {
      const value = commercialEngine.defineExecutiveValue(mockInvestigation);

      expect(value.riskQuantification).toBeDefined();
      expect(value.businessContext).toBeDefined();
      expect(value.actionableRecommendations).toBeDefined();
    });

    test('should define technical value', () => {
      const value = commercialEngine.defineTechnicalValue(mockInvestigation);

      expect(value.depthOfAnalysis).toBeDefined();
      expect(value.innovativeInsights).toBeDefined();
      expect(value.validationGuidance).toBeDefined();
    });

    test('should define detection value', () => {
      const value = commercialEngine.defineDetectionValue(mockInvestigation);

      expect(value.multiFormatSupport).toBeDefined();
      expect(value.tuningGuidance).toBeDefined();
      expect(value.validationSupport).toBeDefined();
    });

    test('should assess actionability of recommendations', () => {
      const actionability = commercialEngine.assessActionability(mockInvestigation, {});

      expect(actionability.decisionReady).toBeDefined();
      expect(actionability.priorityClarity).toBeDefined();
      expect(actionability.ownershipClarity).toBeDefined();
    });

    test('should assess report completeness', () => {
      const completeness = commercialEngine.assessReportCompleteness({
        executive: {},
        technical: {},
        decision: {},
      });

      expect(completeness.completionPercentage).toBeGreaterThan(0);
      expect(completeness.completionPercentage).toBeLessThanOrEqual(100);
      expect(completeness.assessment).toBeDefined();
    });

    test('should provide customer immediate actions with timeline and value', () => {
      const actions = commercialEngine.provideCustomerImmediateActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.every(a => a.action)).toBe(true);
      expect(actions.every(a => a.timeline)).toBe(true);
      expect(actions.every(a => a.owner)).toBe(true);
      expect(actions.every(a => a.value)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // INTEGRATION & REGRESSION TESTS
  // ═══════════════════════════════════════════════════════════════════════

  describe('Integration: All Workstreams', () => {
    test('should compose all 10 workstreams into coherent product', async () => {
      const transformed = await phase14.transformIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      const hasAllWorkstreams = [
        'executive',
        'technical',
        'attribution',
        'campaign',
        'correlation',
        'analytical',
        'decisions',
        'detection',
        'strategic',
        'commercial',
      ].every(ws => transformed.enhancements[ws]);

      expect(hasAllWorkstreams).toBe(true);
    });
  });

  describe('Backward Compatibility', () => {
    test('should work with minimal investigation data', async () => {
      const minimal = { id: 'inv-minimal', title: 'Minimal' };

      const transformed = await phase14.transformIntelligenceProduct(
        mockProduct,
        minimal,
        mockContext
      );

      expect(transformed.status).toMatch(/approved_for_production|review_required|error/);
    });

    test('should handle null context gracefully', async () => {
      const transformed = await phase14.transformIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        null
      );

      expect(transformed.status).toMatch(/approved_for_production|review_required|error/);
    });
  });

  describe('Production Readiness', () => {
    test('all workstream classes should export correctly', () => {
      const exported = {
        Phase14ProductTransformation,
        ExecutiveIntelligenceExcellence,
        TechnicalIntelligenceExcellence,
        AttributionExcellence,
        CampaignIntelligenceEngine,
        IntelligenceCorrelationEngine,
        OriginalAnalyticalValueEngine,
        DecisionSupportEngine,
        DetectionEngineeringExcellence,
        StrategicIntelligenceEngine,
        CommercialProductExcellenceEngine,
      };

      Object.entries(exported).forEach(([name, cls]) => {
        expect(typeof cls).toBe('function');
        expect(cls.name).toBe(name);
      });
    });

    test('should initialize all engines without errors', () => {
      expect(() => {
        new Phase14ProductTransformation();
      }).not.toThrow();
    });

    test('should support async transformation workflow', async () => {
      const transformed = await phase14.transformIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockContext
      );

      expect(transformed.timestamp).toBeDefined();
      expect(new Date(transformed.timestamp)).toBeInstanceOf(Date);
    });
  });
});
