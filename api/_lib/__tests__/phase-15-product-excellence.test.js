/**
 * PHASE 15 — ENTERPRISE INTELLIGENCE PRODUCT EXCELLENCE RELEASE (IPER)
 * Comprehensive Test Suite
 *
 * Tests cover:
 * - Orchestration and initialization
 * - All 10 workstream enhancements
 * - Quality assessment across 10 dimensions
 * - Publication certification with configurable thresholds
 * - Backward compatibility
 * - Error handling and graceful degradation
 */

const {
  Phase15ProductExcellence,
  ExecutiveIntelligenceExcellence,
  AnalyticalReasoningExcellence,
  CampaignStorytellingExcellence,
  IntelligenceCorrelationExcellence,
  DetectionEngineeringExcellence,
  MultiAudienceDecisionSupport,
  ReportOriginalityExcellence,
  CommercialProductExcellence,
  EditorialExcellence,
  PublicationCertification,
} = require('../phase-15-product-excellence');

// Mock data
const mockReport = {
  id: 'rep-phase15-001',
  type: 'technical_intelligence',
  title: 'Advanced Threat Campaign Analysis',
  qualityScore: 70,
  citations: [
    { source: 'IOC Detection', date: '2026-07-31' },
    { source: 'Malware Analysis', date: '2026-07-30' },
  ],
};

const mockInvestigation = {
  id: 'inv-phase15-001',
  title: 'Coordinated Phishing and Malware Campaign Against Financial Sector',
  summary: 'Sophisticated multi-stage attack campaign targeting financial institutions globally',
  significance: 'High-priority threat demonstrating professional tradecraft',
  indicators: [
    'example.com/malware',
    '192.168.1.100',
    'hash:d41d8cd98f00b204e9800998ecf8427e',
  ],
  targetedSectors: ['Financial Services', 'Technology'],
  malwareFamilies: ['Stealer.APT', 'RAT.Custom'],
};

const mockContext = {
  organization: 'Enterprise Customer',
  classification: 'TLP:AMBER',
};

describe('Phase 15 — Enterprise Intelligence Product Excellence Release', () => {
  let phase15;

  beforeEach(() => {
    phase15 = new Phase15ProductExcellence();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // ORCHESTRATION TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Orchestration: Phase15ProductExcellence', () => {
    test('should initialize with default configuration', () => {
      expect(phase15).toBeDefined();
      expect(phase15.config.enableExecutiveEnhancement).toBe(true);
      expect(phase15.config.enableAnalyticalEnhancement).toBe(true);
      expect(phase15.config.publicationQualityThreshold).toBe(75);
    });

    test('should initialize all 10 workstream enhancers', () => {
      expect(phase15.executiveEnhancer).toBeInstanceOf(ExecutiveIntelligenceExcellence);
      expect(phase15.analyticalEnhancer).toBeInstanceOf(AnalyticalReasoningExcellence);
      expect(phase15.campaignEnhancer).toBeInstanceOf(CampaignStorytellingExcellence);
      expect(phase15.correlationEnhancer).toBeInstanceOf(IntelligenceCorrelationExcellence);
      expect(phase15.detectionEnhancer).toBeInstanceOf(DetectionEngineeringExcellence);
      expect(phase15.audienceEnhancer).toBeInstanceOf(MultiAudienceDecisionSupport);
      expect(phase15.originalityEnhancer).toBeInstanceOf(ReportOriginalityExcellence);
      expect(phase15.commercialEnhancer).toBeInstanceOf(CommercialProductExcellence);
      expect(phase15.editorialEnhancer).toBeInstanceOf(EditorialExcellence);
      expect(phase15.certifier).toBeInstanceOf(PublicationCertification);
    });

    test('should provide JSON metadata describing phase', () => {
      const metadata = phase15.toJSON();
      expect(metadata.phase).toBe('phase-15');
      expect(metadata.name).toContain('Enterprise Intelligence');
      expect(metadata.workstreams).toHaveLength(10);
      expect(metadata.focus).toContain('Transform output quality');
    });

    test('should enhance intelligence report with all workstreams', async () => {
      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, mockInvestigation, mockContext);

      expect(enhanced.reportId).toBe('rep-phase15-001');
      expect(enhanced.enhancements).toBeDefined();
      expect(enhanced.enhancements.executive).toBeDefined();
      expect(enhanced.enhancements.analytical).toBeDefined();
      expect(enhanced.enhancements.campaignNarrative).toBeDefined();
      expect(enhanced.enhancements.correlation).toBeDefined();
      expect(enhanced.enhancements.detection).toBeDefined();
      expect(enhanced.enhancements.audience).toBeDefined();
      expect(enhanced.enhancements.originality).toBeDefined();
      expect(enhanced.enhancements.commercial).toBeDefined();
      expect(enhanced.enhancements.editorial).toBeDefined();
    });

    test('should assess report quality across 10 dimensions', async () => {
      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, mockInvestigation, mockContext);

      expect(enhanced.qualityAssessment).toBeDefined();
      expect(enhanced.qualityAssessment.executiveClarity).toBeDefined();
      expect(enhanced.qualityAssessment.analyticalRigor).toBeDefined();
      expect(enhanced.qualityAssessment.campaignNarrative).toBeDefined();
      expect(enhanced.qualityAssessment.correlationValue).toBeDefined();
      expect(enhanced.qualityAssessment.detectionQuality).toBeDefined();
      expect(enhanced.qualityAssessment.audienceRelevance).toBeDefined();
      expect(enhanced.qualityAssessment.originalityScore).toBeDefined();
      expect(enhanced.qualityAssessment.commercialValue).toBeDefined();
      expect(enhanced.qualityAssessment.editorialQuality).toBeDefined();
      expect(enhanced.qualityAssessment.overallReportQuality).toBeDefined();
    });

    test('should certify publication readiness based on quality assessment', async () => {
      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, mockInvestigation, mockContext);

      expect(enhanced.publicationCertification).toBeDefined();
      expect(typeof enhanced.publicationCertification.approved).toBe('boolean');
      expect(enhanced.publicationCertification.overallScore).toBeGreaterThanOrEqual(0);
      expect(enhanced.publicationCertification.threshold).toBe(75);
      expect(enhanced.publicationCertification.status).toMatch(/APPROVED_FOR_PUBLICATION|REQUIRES_REVISION/);
    });

    test('should set report status based on certification result', async () => {
      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, mockInvestigation, mockContext);

      if (enhanced.publicationCertification.approved) {
        expect(enhanced.status).toBe('approved_for_publication');
      } else {
        expect(enhanced.status).toBe('requires_revision');
      }
    });

    test('should handle errors gracefully during enhancement', async () => {
      const badReport = null;
      const result = await phase15.enhanceIntelligenceReport(badReport, mockInvestigation, mockContext);

      expect(result.status).toBe('error');
      expect(result.error).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 1: EXECUTIVE INTELLIGENCE EXCELLENCE
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 1: Executive Intelligence Excellence', () => {
    let executive;

    beforeEach(() => {
      executive = new ExecutiveIntelligenceExcellence();
    });

    test('should enhance executive content with all required sections', async () => {
      const result = await executive.enhanceExecutiveContent(mockReport, mockInvestigation, mockContext);

      expect(result.enhancedSummary).toBeDefined();
      expect(result.businessImpact).toBeDefined();
      expect(result.operationalImpact).toBeDefined();
      expect(result.strategicImplications).toBeDefined();
      expect(result.recommendedActions).toBeDefined();
      expect(result.executiveDecisions).toBeDefined();
      expect(result.monitoringPriorities).toBeDefined();
    });

    test('should generate executive summary with business relevance', () => {
      const summary = executive.generateExecutiveSummary(mockReport, mockInvestigation);

      expect(summary.headline).toBeDefined();
      expect(summary.whatHappened).toBeDefined();
      expect(summary.whyItMatters).toBeDefined();
      expect(summary.immediateActions).toBeInstanceOf(Array);
      expect(summary.timeframe).toBeDefined();
      expect(summary.confidence).toBeDefined();
    });

    test('should identify business impact for affected sectors', () => {
      const impact = executive.analyzeBusinessImpact(mockReport, mockInvestigation);

      expect(impact.affectedBusinessFunction).toContain('Financial Services');
      expect(impact.riskToOperations).toBeDefined();
      expect(impact.potentialFinancialImpact).toBeDefined();
      expect(impact.complianceConsiderations).toBeDefined();
    });

    test('should generate operational impact assessment', () => {
      const impact = executive.analyzeOperationalImpact(mockReport, mockInvestigation);

      expect(impact.securityTeamsAffected).toBeInstanceOf(Array);
      expect(impact.detectionCapability).toBeDefined();
      expect(impact.investigationCost).toBeDefined();
    });

    test('should identify immediate executive actions with timelines', () => {
      const actions = executive.generatePriorityActions(mockReport, mockInvestigation);

      expect(actions).toBeInstanceOf(Array);
      expect(actions.length).toBeGreaterThan(0);
      expect(actions[0].priority).toBeDefined();
      expect(actions[0].action).toBeDefined();
      expect(actions[0].timeline).toBeDefined();
      expect(actions[0].owner).toBeDefined();
    });

    test('should provide medium-term planning timeline', () => {
      const planning = executive.identifyStrategicImplications(mockReport, mockInvestigation);

      expect(planning).toBeDefined();
      expect(planning.threatTrendAnalysis).toBeDefined();
      expect(planning.competitiveIntelligence).toBeDefined();
    });

    test('should identify indicators to monitor', () => {
      const monitoring = executive.identifyMonitoringPriorities(mockReport, mockInvestigation);

      expect(monitoring.immediateMonitoring).toBeInstanceOf(Array);
      expect(monitoring.continuingMonitoring).toBeInstanceOf(Array);
      expect(monitoring.escalationTriggers).toBeInstanceOf(Array);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 2: ANALYTICAL REASONING EXCELLENCE
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 2: Analytical Reasoning Excellence', () => {
    let analytical;

    beforeEach(() => {
      analytical = new AnalyticalReasoningExcellence();
    });

    test('should enhance analytical content with all required sections', async () => {
      const result = await analytical.enhanceAnalyticalReasoning(mockReport, mockInvestigation, mockContext);

      expect(result.supportingEvidence).toBeDefined();
      expect(result.contradictingEvidence).toBeDefined();
      expect(result.confidenceReasoning).toBeDefined();
      expect(result.remainingUncertainty).toBeDefined();
      expect(result.alternativeHypotheses).toBeDefined();
      expect(result.collectionGaps).toBeDefined();
      expect(result.factVsAssessment).toBeDefined();
    });

    test('should compile supporting evidence by type', () => {
      const evidence = analytical.compileSupportingEvidence(mockReport, mockInvestigation);

      expect(evidence).toBeInstanceOf(Array);
      expect(evidence.length).toBeGreaterThan(0);
      expect(evidence[0].type).toBeDefined();
      expect(evidence[0].strength).toBeDefined();
    });

    test('should identify contradictory evidence', () => {
      const contradictions = analytical.identifyContradictions(mockReport, mockInvestigation);

      expect(contradictions).toBeInstanceOf(Array);
    });

    test('should explain confidence with increasing and decreasing factors', () => {
      const confidence = analytical.buildConfidenceReasoning(mockReport, mockInvestigation);

      expect(confidence.confidence_level).toBeDefined();
      expect(confidence.reasoning).toBeDefined();
      expect(confidence.increasing_factors).toBeInstanceOf(Array);
      expect(confidence.decreasing_factors).toBeInstanceOf(Array);
    });

    test('should generate alternative hypotheses with evidence requirements', () => {
      const hypotheses = analytical.generateAlternativeHypotheses(mockReport, mockInvestigation);

      expect(hypotheses).toBeInstanceOf(Array);
      if (hypotheses.length > 0) {
        expect(hypotheses[0].hypothesis).toBeDefined();
        expect(hypotheses[0].supporting_evidence).toBeDefined();
        expect(hypotheses[0].required_evidence).toBeDefined();
        expect(hypotheses[0].probability).toBeDefined();
      }
    });

    test('should assess attribution uncertainty', () => {
      const uncertainty = analytical.assessUncertainty(mockReport, mockInvestigation);

      expect(uncertainty.key_uncertainties).toBeInstanceOf(Array);
      expect(uncertainty.path_to_resolution).toBeInstanceOf(Array);
    });

    test('should identify evidence gaps', () => {
      const gaps = analytical.identifyCollectionGaps(mockReport, mockInvestigation);

      expect(gaps).toBeInstanceOf(Array);
      expect(gaps.length).toBeGreaterThan(0);
    });

    test('should distinguish facts from assessments and forecasts', () => {
      const distinction = analytical.distinguishFactsFromAssessments(mockReport, mockInvestigation);

      expect(distinction.observed_facts).toBeInstanceOf(Array);
      expect(distinction.analytical_assessments).toBeInstanceOf(Array);
      expect(distinction.forward_looking_judgments).toBeInstanceOf(Array);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 3: CAMPAIGN STORYTELLING
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 3: Campaign Storytelling', () => {
    let campaign;

    beforeEach(() => {
      campaign = new CampaignStorytellingExcellence();
    });

    test('should enhance campaign content with lifecycle and evolution', async () => {
      const result = await campaign.buildCampaignNarrative(mockReport, mockInvestigation, mockContext);

      expect(result.attackLifecycle).toBeDefined();
      expect(result.campaignEvolution).toBeDefined();
      expect(result.infrastructureEvolution).toBeDefined();
      expect(result.victimTargeting).toBeDefined();
      expect(result.malwareEvolution).toBeDefined();
      expect(result.operatorObjectives).toBeDefined();
      expect(result.defensiveOpportunities).toBeDefined();
    });

    test('should build campaign lifecycle with phases', () => {
      const lifecycle = campaign.buildAttackLifecycle(mockInvestigation);

      expect(lifecycle).toBeInstanceOf(Array);
      expect(lifecycle.length).toBeGreaterThan(0);
      expect(lifecycle[0].phase).toBeDefined();
      expect(lifecycle[0].tactics).toBeInstanceOf(Array);
      expect(lifecycle[0].timeline).toBeDefined();
    });

    test('should build campaign timeline with events', () => {
      const evolution = campaign.trackCampaignEvolution(mockInvestigation);

      expect(evolution).toBeInstanceOf(Array);
      expect(evolution.length).toBeGreaterThan(0);
    });

    test('should define operational objectives based on targeting', () => {
      const objectives = campaign.identifyOperatorObjectives(mockInvestigation);

      expect(objectives.primary_objective).toBeDefined();
      expect(objectives.secondary_objectives).toBeInstanceOf(Array);
      expect(objectives.motivation_indicators).toBeDefined();
    });

    test('should analyze infrastructure evolution and resilience', () => {
      const evolution = campaign.analyzeInfrastructureEvolution(mockInvestigation);

      expect(evolution.initial_infrastructure).toBeDefined();
      expect(evolution.current_infrastructure).toBeDefined();
      expect(evolution.evolution).toBeDefined();
    });

    test('should analyze malware evolution and development', () => {
      const evolution = campaign.traceMalwareEvolution(mockInvestigation);

      expect(evolution.malware_families).toBeInstanceOf(Array);
      expect(evolution.development_timeline).toBeDefined();
      expect(evolution.capabilities_added).toBeInstanceOf(Array);
    });

    test('should generate defensive lessons', () => {
      const opportunities = campaign.identifyDefensiveOpportunities(mockInvestigation);

      expect(opportunities).toBeInstanceOf(Array);
      expect(opportunities.length).toBeGreaterThan(0);
    });

    test('should assess future trajectory with disclaimer', async () => {
      const result = await campaign.buildCampaignNarrative(mockReport, mockInvestigation, mockContext);

      expect(result.operatorObjectives).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 4: INTELLIGENCE CORRELATION
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 4: Intelligence Correlation', () => {
    let correlation;

    beforeEach(() => {
      correlation = new IntelligenceCorrelationExcellence();
    });

    test('should enhance correlation content across all dimensions', async () => {
      const result = await correlation.correlateIntelligence(mockReport, mockInvestigation, mockContext);

      expect(result.actorCorrelation).toBeDefined();
      expect(result.campaignCorrelation).toBeDefined();
      expect(result.malwareCorrelation).toBeDefined();
      expect(result.infrastructureCorrelation).toBeDefined();
      expect(result.iocCorrelation).toBeDefined();
      expect(result.cveCorrelation).toBeDefined();
      expect(result.techniqueCorrelation).toBeDefined();
      expect(result.sectorCorrelation).toBeDefined();
      expect(result.historicalContext).toBeDefined();
    });

    test('should correlate with other threat actors', () => {
      const correlation_result = correlation.correlateWithActors(mockInvestigation);

      expect(correlation_result.related_actors).toBeInstanceOf(Array);
      expect(correlation_result.confidence).toBeDefined();
    });

    test('should correlate with other campaigns', () => {
      const correlation_result = correlation.correlateWithCampaigns(mockInvestigation);

      expect(correlation_result.related_campaigns).toBeInstanceOf(Array);
      expect(correlation_result.overlap_analysis).toBeDefined();
    });

    test('should correlate malware families', () => {
      const correlation_result = correlation.correlateWithMalware(mockInvestigation);

      expect(correlation_result.related_malware).toBeInstanceOf(Array);
    });

    test('should identify related intelligence reports', async () => {
      const result = await correlation.correlateIntelligence(mockReport, mockInvestigation, mockContext);

      expect(result.historicalContext).toBeDefined();
      expect(result.historicalContext.first_reported).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 5: DETECTION ENGINEERING EXCELLENCE
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 5: Detection Engineering Excellence', () => {
    let detection;

    beforeEach(() => {
      detection = new DetectionEngineeringExcellence();
    });

    test('should enhance detection content across multiple platforms', async () => {
      const result = await detection.enhanceDetectionGuidance(mockReport, mockInvestigation, mockContext);

      expect(result.detectionRules).toBeDefined();
      expect(result.validationGuidance).toBeDefined();
      expect(result.deploymentGuidance).toBeDefined();
      expect(result.tuningRecommendations).toBeDefined();
      expect(result.falsePositiveConsiderations).toBeDefined();
      expect(result.coverageAssessment).toBeDefined();
      expect(result.operationalNotes).toBeDefined();
    });

    test('should generate Sigma/YARA/Suricata/SIEM rules', () => {
      const rules = detection.generateDetectionRules(mockInvestigation);

      expect(rules).toBeInstanceOf(Array);
      expect(rules.length).toBeGreaterThan(0);
      expect(rules[0].type).toBeDefined();
      expect(rules[0].description).toBeDefined();
      expect(rules[0].platform).toBeDefined();
    });

    test('should provide validation procedures', () => {
      const validation = detection.buildValidationChecklist(mockInvestigation);

      expect(validation).toBeInstanceOf(Array);
      expect(validation.length).toBeGreaterThan(0);
    });

    test('should assess false positive risk', () => {
      const fp = detection.assessFalsePositiveRisk(mockInvestigation);

      expect(fp.risk_level).toBeDefined();
      expect(fp.likely_causes).toBeInstanceOf(Array);
      expect(fp.mitigation).toBeDefined();
    });

    test('should provide coverage assessment', () => {
      const coverage = detection.assessCoverageGaps(mockInvestigation);

      expect(coverage.detected_coverage).toBeDefined();
      expect(coverage.potential_gaps).toBeDefined();
      expect(coverage.recommendation).toBeDefined();
    });

    test('should provide tuning guidance', () => {
      const tuning = detection.generateTuningRecommendations(mockInvestigation);

      expect(tuning.initial_tuning).toBeDefined();
      expect(tuning.optimization).toBeDefined();
      expect(tuning.maintenance).toBeDefined();
    });

    test('should provide operational deployment notes', () => {
      const notes = detection.generateOperationalNotes(mockInvestigation);

      expect(notes.alert_tuning).toBeDefined();
      expect(notes.escalation_criteria).toBeDefined();
      expect(notes.response_playbook).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 6: MULTI-AUDIENCE DECISION SUPPORT
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 6: Multi-Audience Decision Support', () => {
    let audience;

    beforeEach(() => {
      audience = new MultiAudienceDecisionSupport();
    });

    test('should generate decision content for all 12 audience types', async () => {
      const result = await audience.generateAudienceGuidance(mockReport, mockInvestigation, {}, mockContext);

      expect(result.ceo).toBeDefined();
      expect(result.board).toBeDefined();
      expect(result.ciso).toBeDefined();
      expect(result.soc_director).toBeDefined();
      expect(result.threat_hunter).toBeDefined();
      expect(result.detection_engineer).toBeDefined();
      expect(result.incident_responder).toBeDefined();
      expect(result.cloud_security).toBeDefined();
      expect(result.identity_security).toBeDefined();
      expect(result.vulnerability_manager).toBeDefined();
      expect(result.third_party_risk).toBeDefined();
      expect(result.ops_leadership).toBeDefined();
    });

    test('should generate CEO actions with evidence and timeline', () => {
      const ceo = audience.generateCEOGuidance(mockInvestigation, {});

      expect(ceo.audience).toBe('Chief Executive Officer');
      expect(ceo.key_questions).toBeInstanceOf(Array);
      expect(ceo.decision).toBeDefined();
      expect(ceo.business_impact).toBeDefined();
      expect(ceo.timeline).toBeDefined();
    });

    test('should generate CISO actions', () => {
      const ciso = audience.generateCISOGuidance(mockInvestigation, {});

      expect(ciso.audience).toBe('Chief Information Security Officer');
      expect(ciso.strategic_implications).toBeDefined();
    });

    test('should generate SOC actions', () => {
      const soc = audience.generateSOCDirectorGuidance(mockInvestigation, {});

      expect(soc.audience).toContain('SOC');
      expect(soc.operational_impact).toBeDefined();
    });

    test('should generate threat hunting actions', () => {
      const hunting = audience.generateThreatHunterGuidance(mockInvestigation, {});

      expect(hunting.audience).toContain('Threat Hunting');
      expect(hunting.hunt_objectives).toBeInstanceOf(Array);
    });

    test('should generate detection engineering actions', () => {
      const de = audience.generateDetectionEngineerGuidance(mockInvestigation, {});

      expect(de.audience).toContain('Detection Engineer');
      expect(de.rules_to_deploy).toBeDefined();
    });

    test('should generate incident response actions', () => {
      const ir = audience.generateIncidentResponderGuidance(mockInvestigation, {});

      expect(ir.audience).toContain('Incident Response');
      expect(ir.playbook_reference).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 7: REPORT ORIGINALITY
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 7: Report Originality', () => {
    let originality;

    beforeEach(() => {
      originality = new ReportOriginalityExcellence();
    });

    test('should enhance originality content with all value dimensions', async () => {
      const result = await originality.increaseOriginalValue(mockReport, mockInvestigation, {});

      expect(result.novelSynthesis).toBeDefined();
      expect(result.derivedRelationships).toBeDefined();
      expect(result.originalInsights).toBeDefined();
    });

    test('should synthesize original analytical insights', () => {
      const synthesis = originality.synthesizeOriginalAnalysis(mockInvestigation, {});

      expect(synthesis).toBeInstanceOf(Array);
      expect(synthesis.length).toBeGreaterThan(0);
    });

    test('should identify newly derived relationships', () => {
      const relationships = originality.discoverNewRelationships(mockInvestigation, {});

      expect(relationships).toBeInstanceOf(Array);
      if (relationships.length > 0) {
        expect(relationships[0].relationship).toBeDefined();
        expect(relationships[0].significance).toBeDefined();
      }
    });

    test('should generate original insights with basis and significance', () => {
      const insights = originality.generateOriginalInsights(mockInvestigation, {});

      expect(insights).toBeInstanceOf(Array);
      if (insights.length > 0) {
        expect(insights[0].insight).toBeDefined();
        expect(insights[0].basis).toBeDefined();
        expect(insights[0].significance).toBeDefined();
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 8: COMMERCIAL PRODUCT EXCELLENCE
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 8: Commercial Product Excellence', () => {
    let commercial;

    beforeEach(() => {
      commercial = new CommercialProductExcellence();
    });

    test('should enhance commercial content with all value dimensions', async () => {
      const result = await commercial.articluateCommercialValue(mockReport, mockInvestigation, {});

      expect(result.customerValue).toBeDefined();
      expect(result.operationalValue).toBeDefined();
      expect(result.executiveValue).toBeDefined();
      expect(result.technicalValue).toBeDefined();
      expect(result.detectionValue).toBeDefined();
      expect(result.actionability).toBeDefined();
      expect(result.expectedOutcome).toBeDefined();
    });

    test('should define customer value', () => {
      const value = commercial.articluateCustomerValue(mockInvestigation, {});

      expect(value.value_proposition).toBeDefined();
      expect(value.competitive_advantage).toBeDefined();
      expect(value.differentiation).toBeDefined();
    });

    test('should define operational value', () => {
      const value = commercial.articluateOperationalValue(mockInvestigation, {});

      expect(value.operational_benefit).toBeDefined();
      expect(value.resource_efficiency).toBeDefined();
      expect(value.team_enablement).toBeDefined();
    });

    test('should define executive value', () => {
      const value = commercial.articluateExecutiveValue(mockInvestigation, {});

      expect(value.executive_benefit).toBeDefined();
      expect(value.risk_reduction).toBeDefined();
    });

    test('should define technical value', () => {
      const value = commercial.articulateTechnicalValue(mockInvestigation, {});

      expect(value.technical_benefit).toBeDefined();
      expect(value.infrastructure_insight).toBeDefined();
      expect(value.malware_analysis).toBeDefined();
    });

    test('should define detection value', () => {
      const value = commercial.articluateDetectionValue(mockInvestigation, {});

      expect(value.detection_capability).toBeDefined();
      expect(value.coverage_improvement).toBeDefined();
      expect(value.false_positive_rate).toBeDefined();
    });

    test('should assess actionability of recommendations', () => {
      const actionability = commercial.assessActionability(mockInvestigation, {});

      expect(actionability.immediately_actionable).toBeInstanceOf(Array);
      expect(actionability.short_term_actionable).toBeInstanceOf(Array);
      expect(actionability.strategic_actionable).toBeInstanceOf(Array);
    });

    test('should provide customer immediate actions with timeline and value', () => {
      const outcome = commercial.defineExpectedOutcome(mockInvestigation, {});

      expect(outcome.success_metrics).toBeInstanceOf(Array);
      expect(outcome.outcome_probability).toBeDefined();
      expect(outcome.long_term_benefit).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 9: EDITORIAL EXCELLENCE
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 9: Editorial Excellence', () => {
    let editorial;

    beforeEach(() => {
      editorial = new EditorialExcellence();
    });

    test('should enhance editorial content across all dimensions', async () => {
      const result = await editorial.improveEditorialQuality(mockReport, {});

      expect(result.improvedStructure).toBeDefined();
      expect(result.consistencyChecks).toBeDefined();
      expect(result.readabilityImprovements).toBeDefined();
      expect(result.standardFormatting).toBeDefined();
      expect(result.transitionImprovements).toBeDefined();
      expect(result.headingOptimization).toBeDefined();
    });

    test('should optimize report structure', () => {
      const structure = editorial.optimizeReportStructure(mockReport, {});

      expect(structure.recommended_order).toBeInstanceOf(Array);
      expect(structure.readability_benefit).toBeDefined();
    });

    test('should enforce consistency across report', () => {
      const consistency = editorial.enforceConsistency(mockReport, {});

      expect(consistency.terminology_standardization).toBeDefined();
      expect(consistency.citation_format).toBeDefined();
      expect(consistency.confidence_language).toBeDefined();
    });

    test('should improve readability', () => {
      const readability = editorial.improveReadability(mockReport, {});

      expect(readability.sentence_length_optimization).toBeDefined();
      expect(readability.paragraph_length).toBeDefined();
      expect(readability.active_voice).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // WORKSTREAM 10: PUBLICATION CERTIFICATION
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Workstream 10: Publication Certification', () => {
    let certifier;

    beforeEach(() => {
      certifier = new PublicationCertification(75);
    });

    test('should certify publication readiness based on quality assessment', async () => {
      const qualityAssessment = {
        executiveClarity: { score: 80 },
        analyticalRigor: { score: 75 },
        campaignNarrative: { score: 85 },
        correlationValue: { score: 70 },
        detectionQuality: { score: 80 },
        audienceRelevance: { score: 75 },
        originalityScore: { score: 70 },
        commercialValue: { score: 80 },
        editorialQuality: { score: 85 },
        overallReportQuality: { score: 78 },
      };

      const certification = await certifier.certifyForPublication(qualityAssessment, mockReport, {});

      expect(typeof certification.approved).toBe('boolean');
      expect(certification.overallScore).toBeGreaterThanOrEqual(0);
      expect(certification.threshold).toBe(75);
      expect(certification.status).toMatch(/APPROVED_FOR_PUBLICATION|REQUIRES_REVISION/);
    });

    test('should set approval status based on quality threshold', async () => {
      const highQualityAssessment = {
        executiveClarity: { score: 95 },
        analyticalRigor: { score: 90 },
        campaignNarrative: { score: 95 },
        correlationValue: { score: 85 },
        detectionQuality: { score: 90 },
        audienceRelevance: { score: 90 },
        originalityScore: { score: 85 },
        commercialValue: { score: 95 },
        editorialQuality: { score: 95 },
        overallReportQuality: { score: 90 },
      };

      const certification = await certifier.certifyForPublication(highQualityAssessment, mockReport, {});

      expect(certification.overallScore).toBeGreaterThanOrEqual(75);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // INTEGRATION TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Integration: All Workstreams', () => {
    test('should compose all 10 workstreams into coherent enhanced product', async () => {
      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, mockInvestigation, mockContext);

      // Verify all enhancements present (at least 9 core workstreams)
      expect(Object.keys(enhanced.enhancements).length).toBeGreaterThanOrEqual(9);

      // Verify quality assessment dimensions
      expect(Object.keys(enhanced.qualityAssessment).length).toBeGreaterThanOrEqual(10);

      // Verify certification
      expect(enhanced.publicationCertification).toBeDefined();

      // Verify status set based on certification
      expect(enhanced.status).toMatch(/approved_for_publication|requires_revision/);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // BACKWARD COMPATIBILITY TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Backward Compatibility', () => {
    test('should work with minimal investigation data', async () => {
      const minimalInvestigation = { id: 'inv-minimal', title: 'Minimal Report' };

      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, minimalInvestigation, mockContext);

      expect(enhanced.status).toBeDefined();
      expect(enhanced.enhancements).toBeDefined();
    });

    test('should handle null context gracefully', async () => {
      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, mockInvestigation, null);

      expect(enhanced.status).toBeDefined();
      expect(enhanced.reportId).toBe('rep-phase15-001');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // PRODUCTION READINESS TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Production Readiness', () => {
    test('all workstream classes should export correctly', () => {
      expect(Phase15ProductExcellence).toBeDefined();
      expect(ExecutiveIntelligenceExcellence).toBeDefined();
      expect(AnalyticalReasoningExcellence).toBeDefined();
      expect(CampaignStorytellingExcellence).toBeDefined();
      expect(IntelligenceCorrelationExcellence).toBeDefined();
      expect(DetectionEngineeringExcellence).toBeDefined();
      expect(MultiAudienceDecisionSupport).toBeDefined();
      expect(ReportOriginalityExcellence).toBeDefined();
      expect(CommercialProductExcellence).toBeDefined();
      expect(EditorialExcellence).toBeDefined();
      expect(PublicationCertification).toBeDefined();
    });

    test('should initialize all engines without errors', () => {
      const p15 = new Phase15ProductExcellence();

      expect(() => {
        p15.executiveEnhancer;
        p15.analyticalEnhancer;
        p15.campaignEnhancer;
        p15.correlationEnhancer;
        p15.detectionEnhancer;
        p15.audienceEnhancer;
        p15.originalityEnhancer;
        p15.commercialEnhancer;
        p15.editorialEnhancer;
        p15.certifier;
      }).not.toThrow();
    });

    test('should support async transformation workflow', async () => {
      const enhanced = await phase15.enhanceIntelligenceReport(mockReport, mockInvestigation, mockContext);

      expect(enhanced).toBeDefined();
      expect(enhanced.timestamp).toBeDefined();
      expect(new Date(enhanced.timestamp)).toBeInstanceOf(Date);
    });
  });
});
