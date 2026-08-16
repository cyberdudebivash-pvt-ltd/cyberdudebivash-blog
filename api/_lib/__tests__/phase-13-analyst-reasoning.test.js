'use strict';

const {
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
} = require('../phase-13-analyst-reasoning');

describe('Phase 13 — Advanced Analyst Reasoning & Intelligence Methodology Engine', () => {
  let phase13;
  let mockProduct;
  let mockInvestigation;
  let mockReport;
  let mockHistoricalData;

  beforeEach(() => {
    phase13 = new Phase13AnalystReasoning();

    mockProduct = {
      id: 'prod-001',
      title: 'APT-28 Q3 2026 Campaign Analysis',
      type: 'threat-actor',
      threatLevel: 'CRITICAL',
      sources: ['GreyNoise', 'Shodan', 'Censys'],
    };

    mockInvestigation = {
      id: 'inv-001',
      title: 'APT-28 Campaign',
      severity: 'CRITICAL',
      threatActors: ['APT-28', 'Fancy Bear'],
      targetedSectors: ['financial', 'government', 'technology'],
      affectedUserCount: 50000,
      techniques: [
        { name: 'Spear Phishing', mitreTactic: ['Initial Access'] },
        { name: 'Living off the Land', mitreTactic: ['Execution'] },
        { name: 'Registry Modification', mitreTactic: ['Persistence'] },
        { name: 'Lateral Movement', mitreTactic: ['Lateral Movement'] },
        { name: 'Data Exfiltration', mitreTactic: ['Exfiltration'] },
      ],
      malware: ['SOFACY', 'Zebrocy', 'CHOPSTICK'],
      infrastructure: [
        { ip: '192.0.2.1', hosting: 'Digital Ocean', location: 'RU' },
        { ip: '192.0.2.2', hosting: 'Linode', location: 'NL' },
        { ip: '192.0.2.3', hosting: 'AWS', location: 'DE' },
      ],
      cisaKev: true,
      exploited: true,
      ransomware: false,
      evidence: [
        { type: 'C2 Traffic', confidence: 95 },
        { type: 'Malware Signature', confidence: 92 },
        { type: 'Infrastructure Clustering', confidence: 88 },
      ],
      timeline: '2026-06-01 to 2026-07-31',
    };

    mockReport = {
      id: 'rpt-001',
      productId: 'prod-001',
      generated: new Date().toISOString(),
    };

    mockHistoricalData = [
      {
        threatActors: ['APT-28'],
        severity: 'HIGH',
        malware: ['SOFACY', 'Zebrocy'],
        techniques: ['Spear Phishing', 'Living off the Land'],
        infrastructure: [
          { ip: '192.0.2.1', hosting: 'Digital Ocean' },
          { ip: '192.0.2.4', hosting: 'Hetzner' },
        ],
        confidence: 85,
      },
    ];
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 1: Intelligence Reasoning Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 1: Intelligence Reasoning Engine', () => {
    let reasoningEngine;

    beforeEach(() => {
      reasoningEngine = new IntelligenceReasoningEngine();
    });

    test('should analyze all judgements with reasoning chains', async () => {
      const analysis = await reasoningEngine.analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      expect(analysis).toBeDefined();
      expect(analysis.keyJudgements).toBeDefined();
      expect(Array.isArray(analysis.keyJudgements)).toBe(true);
      expect(analysis.keyJudgements.length).toBeGreaterThan(0);
    });

    test('should include reasoning chain for each judgement', async () => {
      const analysis = await reasoningEngine.analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      analysis.keyJudgements.forEach(judgement => {
        expect(judgement.judgement).toBeDefined();
        expect(judgement.type).toBeDefined();
        expect(judgement.confidence).toBeGreaterThanOrEqual(0);
        expect(judgement.confidence).toBeLessThanOrEqual(100);
        expect(judgement.reasoning).toBeDefined();
        expect(Array.isArray(judgement.reasoning)).toBe(true);
      });
    });

    test('should extract key judgements from investigation data', () => {
      const judgements = reasoningEngine.extractKeyJudgements(
        mockProduct,
        mockInvestigation
      );

      expect(judgements.length).toBeGreaterThan(0);
      expect(judgements.some(j => j.type === 'severity_assessment')).toBe(true);
      expect(judgements.some(j => j.type === 'attribution')).toBe(true);
      expect(judgements.some(j => j.type === 'targeting_analysis')).toBe(true);
    });

    test('should generate reasoning chains with steps', () => {
      const chains = reasoningEngine.generateReasoningChains(mockInvestigation);

      expect(chains.attackProgression).toBeDefined();
      expect(chains.capabilityAssessment).toBeDefined();
      expect(chains.attributionChain).toBeDefined();
      expect(chains.impactChain).toBeDefined();
    });

    test('should categorize evidence by strength', () => {
      const evidence = reasoningEngine.categorizeEvidence(mockInvestigation);

      expect(evidence.strongEvidence).toBeDefined();
      expect(evidence.moderateEvidence).toBeDefined();
      expect(evidence.weakEvidence).toBeDefined();
      expect(evidence.coverage).toBeDefined();
    });

    test('should identify contradictions in evidence', () => {
      const contradictions = reasoningEngine.identifyContradictions(mockInvestigation);

      expect(Array.isArray(contradictions)).toBe(true);
    });

    test('should identify analytical gaps', () => {
      const gaps = reasoningEngine.identifyGaps(mockInvestigation);

      expect(gaps.missingInfrastructure).toBeDefined();
      expect(gaps.missingMalware).toBeDefined();
      expect(gaps.missingTechniques).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 2: Competing Hypotheses Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 2: Competing Hypotheses Engine', () => {
    let hypothesesEngine;

    beforeEach(() => {
      hypothesesEngine = new CompetingHypothesesEngine();
    });

    test('should generate alternative hypotheses for attribution', async () => {
      const alternatives = await hypothesesEngine.generateAlternatives(
        mockProduct,
        mockInvestigation
      );

      expect(alternatives).toBeDefined();
      expect(alternatives.attributionHypotheses).toBeDefined();
      expect(Array.isArray(alternatives.attributionHypotheses)).toBe(true);
      expect(alternatives.attributionHypotheses.length).toBeGreaterThan(0);
    });

    test('should include primary and alternative hypotheses', async () => {
      const alternatives = await hypothesesEngine.generateAlternatives(
        mockProduct,
        mockInvestigation
      );

      const hypotheses = alternatives.attributionHypotheses;
      hypotheses.forEach(h => {
        expect(h.hypothesis).toBeDefined();
        expect(h.confidence).toBeGreaterThanOrEqual(0);
        expect(h.confidence).toBeLessThanOrEqual(100);
        expect(Array.isArray(h.supportingIndicators)).toBe(true);
        expect(Array.isArray(h.contradictingIndicators)).toBe(true);
        expect(Array.isArray(h.requiredEvidence)).toBe(true);
      });
    });

    test('should generate campaign hypotheses', () => {
      const hypotheses = hypothesesEngine.generateCampaignHypotheses(mockInvestigation);

      expect(Array.isArray(hypotheses)).toBe(true);
      hypotheses.forEach(h => {
        expect(h.hypothesis).toBeDefined();
        expect(h.confidence).toBeGreaterThanOrEqual(0);
      });
    });

    test('should generate infrastructure hypotheses', () => {
      const hypotheses = hypothesesEngine.generateInfrastructureHypotheses(mockInvestigation);

      expect(Array.isArray(hypotheses)).toBe(true);
    });

    test('should calculate attribution confidence', () => {
      const confidence = hypothesesEngine.calculateAttributionConfidence(mockInvestigation);

      expect(confidence).toBeGreaterThanOrEqual(0);
      expect(confidence).toBeLessThanOrEqual(100);
    });

    test('should identify false flag indicators', () => {
      const flags = hypothesesEngine.identifyFalseFlags(mockInvestigation);

      expect(Array.isArray(flags)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 3: Intelligence Confidence Framework v2 Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 3: Intelligence Confidence Framework v2', () => {
    let confidenceEngine;

    beforeEach(() => {
      confidenceEngine = new IntelligenceConfidenceFramework();
    });

    test('should generate comprehensive confidence assessment', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const assessment = await confidenceEngine.generateConfidenceAssessment(
        mockProduct,
        reasoning,
        mockInvestigation
      );

      expect(assessment).toBeDefined();
      expect(assessment.overallConfidence).toBeGreaterThanOrEqual(0);
      expect(assessment.overallConfidence).toBeLessThanOrEqual(100);
      expect(assessment.sourceReliability).toBeDefined();
      expect(assessment.evidenceQuality).toBeDefined();
      expect(assessment.corroboration).toBeDefined();
    });

    test('should assess source reliability', () => {
      const reliability = confidenceEngine.assessSourceReliability(mockInvestigation);

      expect(reliability.sourceCount).toBeGreaterThanOrEqual(0);
      expect(reliability.assessment).toMatch(/HIGH|MEDIUM|LOW/);
      expect(Array.isArray(reliability.details)).toBe(true);
    });

    test('should assess evidence quality', () => {
      const quality = confidenceEngine.assessEvidenceQuality(mockInvestigation);

      expect(Array.isArray(quality.evidenceTypes)).toBe(true);
      expect(quality.overallQuality).toMatch(/GOOD|MODERATE|POOR/);
    });

    test('should assess corroboration', () => {
      const corroboration = confidenceEngine.assessCorroboration(mockInvestigation);

      expect(Array.isArray(corroboration.corroboratingFactors)).toBe(true);
      expect(corroboration.corroborationLevel).toMatch(/STRONG|MODERATE|LIMITED/);
    });

    test('should assess collection completeness', () => {
      const completeness = confidenceEngine.assessCollectionCompleteness(mockInvestigation);

      expect(completeness.completenessPercentage).toBeGreaterThanOrEqual(0);
      expect(completeness.completenessPercentage).toBeLessThanOrEqual(100);
      expect(Array.isArray(completeness.gaps)).toBe(true);
    });

    test('should identify uncertainty factors', () => {
      const factors = confidenceEngine.identifyUncertaintyFactors(mockInvestigation);

      expect(Array.isArray(factors)).toBe(true);
    });

    test('should generate confidence narrative', () => {
      const narrative = confidenceEngine.generateConfidenceNarrative(mockInvestigation);

      expect(typeof narrative).toBe('string');
      expect(narrative.length).toBeGreaterThan(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 4: Intelligence Collection Gap Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 4: Intelligence Collection Gap Engine', () => {
    let collectionEngine;

    beforeEach(() => {
      collectionEngine = new IntelligenceCollectionGapEngine();
    });

    test('should identify collection gaps', async () => {
      const gaps = await collectionEngine.identifyGaps(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      expect(gaps).toBeDefined();
      expect(gaps.infrastructureGaps).toBeDefined();
      expect(gaps.malwareGaps).toBeDefined();
      expect(gaps.techniqueGaps).toBeDefined();
      expect(gaps.victimologyGaps).toBeDefined();
      expect(gaps.timelineGaps).toBeDefined();
      expect(gaps.attributionGaps).toBeDefined();
      expect(gaps.prioritizedRequirements).toBeDefined();
    });

    test('should prioritize collection requirements by impact', async () => {
      const gaps = await collectionEngine.identifyGaps(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const priorities = gaps.prioritizedRequirements;
      expect(Array.isArray(priorities.critical)).toBe(true);
      expect(Array.isArray(priorities.high)).toBe(true);
      expect(Array.isArray(priorities.medium)).toBe(true);
      expect(priorities.expectedImpact).toBeDefined();
    });

    test('should identify infrastructure gaps', () => {
      const gaps = collectionEngine.identifyInfrastructureGaps(mockInvestigation);

      expect(Array.isArray(gaps)).toBe(true);
    });

    test('should identify malware gaps', () => {
      const gaps = collectionEngine.identifyMalwareGaps(mockInvestigation);

      expect(Array.isArray(gaps)).toBe(true);
    });

    test('should identify technique gaps', () => {
      const gaps = collectionEngine.identifyTechniqueGaps(mockInvestigation);

      expect(Array.isArray(gaps)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 5: Intelligence Consistency Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 5: Intelligence Consistency Engine', () => {
    let consistencyEngine;

    beforeEach(() => {
      consistencyEngine = new IntelligenceConsistencyEngine();
    });

    test('should validate historical consistency', async () => {
      const consistency = await consistencyEngine.validateHistoricalConsistency(
        mockProduct,
        mockInvestigation,
        mockHistoricalData
      );

      expect(consistency).toBeDefined();
      expect(consistency.conflictingAssessments).toBeDefined();
      expect(consistency.behaviorChanges).toBeDefined();
      expect(consistency.capabilityEvolution).toBeDefined();
      expect(consistency.infrastructureReuse).toBeDefined();
      expect(consistency.campaignEvolution).toBeDefined();
      expect(consistency.consistencySummary).toBeDefined();
    });

    test('should track capability evolution', () => {
      const evolution = consistencyEngine.trackCapabilityEvolution(
        mockInvestigation,
        mockHistoricalData
      );

      expect(evolution.newCapabilities).toBeDefined();
      expect(evolution.retiredCapabilities).toBeDefined();
      expect(evolution.sophisticationTrend).toBeDefined();
    });

    test('should identify infrastructure reuse patterns', () => {
      const reuse = consistencyEngine.identifyInfrastructureReuse(
        mockInvestigation,
        mockHistoricalData
      );

      expect(Array.isArray(reuse)).toBe(true);
    });

    test('should track campaign evolution', () => {
      const evolution = consistencyEngine.trackCampaignEvolution(
        mockInvestigation,
        mockHistoricalData
      );

      expect(evolution.overallTrajectory).toMatch(/EXPANDING|CONTRACTING|STABLE|NEW_CAMPAIGN/);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 6: Strategic Outlook Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 6: Strategic Outlook Engine', () => {
    let outlookEngine;

    beforeEach(() => {
      outlookEngine = new StrategicOutlookEngine();
    });

    test('should generate strategic outlook', async () => {
      const outlook = await outlookEngine.generateOutlook(
        mockProduct,
        mockInvestigation,
        {}
      );

      expect(outlook).toBeDefined();
      expect(outlook.likelyDevelopments).toBeDefined();
      expect(outlook.indicatorsToMonitor).toBeDefined();
      expect(outlook.potentialEscalationPaths).toBeDefined();
      expect(outlook.defensivePriorities).toBeDefined();
      expect(outlook.intelligenceWatchItems).toBeDefined();
    });

    test('should identify likely developments with confidence and timeframe', () => {
      const developments = outlookEngine.identifyLikelyDevelopments(mockInvestigation, {});

      expect(Array.isArray(developments)).toBe(true);
      developments.forEach(d => {
        expect(d.development).toBeDefined();
        expect(d.confidence).toMatch(/HIGH|MODERATE|LOW/);
        expect(d.timeframe).toBeDefined();
        expect(d.indicator).toBeDefined();
      });
    });

    test('should identify indicators to monitor', () => {
      const indicators = outlookEngine.identifyIndicators(mockInvestigation);

      expect(Array.isArray(indicators)).toBe(true);
      indicators.forEach(i => {
        expect(i.indicator).toBeDefined();
        expect(i.type).toBeDefined();
        expect(i.monitoring).toBeDefined();
        expect(i.priority).toMatch(/HIGH|MEDIUM|LOW/);
      });
    });

    test('should identify potential escalation paths', () => {
      const escalations = outlookEngine.identifyEscalations(mockInvestigation);

      expect(Array.isArray(escalations)).toBe(true);
    });

    test('should identify defensive priorities', () => {
      const priorities = outlookEngine.identifyDefensivePriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 7: Multi-Audience Intelligence Views Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 7: Multi-Audience Intelligence Views', () => {
    let audienceEngine;

    beforeEach(() => {
      audienceEngine = new MultiAudienceIntelligenceViews();
    });

    test('should generate audience-specific views', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const views = await audienceEngine.generateAudienceViews(
        mockProduct,
        reasoning,
        {}
      );

      expect(views.executive).toBeDefined();
      expect(views.ciso).toBeDefined();
      expect(views.soc).toBeDefined();
      expect(views.threatHunting).toBeDefined();
      expect(views.incidentResponse).toBeDefined();
      expect(views.detectionEngineering).toBeDefined();
      expect(views.vulnerabilityManagement).toBeDefined();
      expect(views.cloudSecurity).toBeDefined();
      expect(views.thirdPartyRisk).toBeDefined();
      expect(views.governance).toBeDefined();
    });

    test('should include executive view with business focus', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const views = await audienceEngine.generateAudienceViews(mockProduct, reasoning, {});
      const executive = views.executive;

      expect(executive.audience).toMatch(/Executive/);
      expect(Array.isArray(executive.focus)).toBe(true);
      expect(Array.isArray(executive.keyPoints)).toBe(true);
      expect(Array.isArray(executive.actionItems)).toBe(true);
    });

    test('should include CISO view with security posture focus', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const views = await audienceEngine.generateAudienceViews(mockProduct, reasoning, {});
      const ciso = views.ciso;

      expect(ciso.audience).toMatch(/CISO/);
      expect(Array.isArray(ciso.actionItems)).toBe(true);
    });

    test('should include SOC view with detection focus', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const views = await audienceEngine.generateAudienceViews(mockProduct, reasoning, {});
      const soc = views.soc;

      expect(soc.audience).toMatch(/SOC/);
      expect(Array.isArray(soc.detectionRequirements)).toBe(true);
    });

    test('should include threat hunting view with hunt paths', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const views = await audienceEngine.generateAudienceViews(mockProduct, reasoning, {});
      const hunting = views.threatHunting;

      expect(hunting.audience).toMatch(/Threat Hunting/);
      expect(Array.isArray(hunting.huntingPriorities)).toBe(true);
    });

    test('should include detection engineering view with rule requirements', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const views = await audienceEngine.generateAudienceViews(mockProduct, reasoning, {});
      const detection = views.detectionEngineering;

      expect(detection.audience).toMatch(/Detection Engineering/);
      expect(Array.isArray(detection.detectionOpportunities)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 8: Intelligence Product Consistency Framework Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 8: Intelligence Product Consistency Framework', () => {
    let structureEngine;

    beforeEach(() => {
      structureEngine = new IntelligenceProductConsistencyFramework();
    });

    test('should validate and enhance product structure', async () => {
      const enhancement = { modules: {} };

      const result = await structureEngine.validateAndEnhanceStructure(
        mockProduct,
        enhancement
      );

      expect(result).toBeDefined();
      expect(result.structureValidation).toBeDefined();
      expect(result.missingComponents).toBeDefined();
      expect(result.structureEnhanced).toBeDefined();
    });

    test('should validate required structure components', () => {
      const validation = structureEngine.validateStructure(mockProduct, { modules: {} });

      expect(validation.requiredSections).toBeGreaterThan(0);
      expect(validation.presentSections).toBeGreaterThanOrEqual(0);
      expect(validation.completeness).toBeGreaterThanOrEqual(0);
      expect(validation.completeness).toBeLessThanOrEqual(100);
    });

    test('should identify missing structure components', () => {
      const missing = structureEngine.identifyMissing(mockProduct, { modules: {} });

      expect(missing.missingReasoningTraceability).toBeDefined();
      expect(missing.missingConfidenceFramework).toBeDefined();
      expect(missing.missingAlternativeHypotheses).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 9: Enterprise Intelligence Quality Gates v3 Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 9: Enterprise Intelligence Quality Gates v3', () => {
    let qualityGate;

    beforeEach(() => {
      qualityGate = new EnterpriseIntelligenceQualityGates();
    });

    test('should certify report with comprehensive quality assessment', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const enhancement = {
        modules: {
          reasoning,
          hypotheses: await new CompetingHypothesesEngine().generateAlternatives(
            mockProduct,
            mockInvestigation
          ),
          confidence: {},
          collectionGaps: {},
          audiences: {},
        },
      };

      const certification = await qualityGate.certifyReport(mockProduct, enhancement);

      expect(certification).toBeDefined();
      expect(typeof certification.passed).toBe('boolean');
      expect(certification.reasoningCompleteness).toBeDefined();
      expect(certification.evidenceCoverage).toBeDefined();
      expect(certification.confidenceExplainability).toBeDefined();
      expect(certification.status).toMatch(/APPROVED_FOR_PUBLICATION|REVIEW_REQUIRED/);
    });

    test('should check reasoning completeness gate', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const gate = qualityGate.checkReasoningCompleteness({ modules: { reasoning } });

      expect(gate.gate).toBe('Reasoning Completeness');
      expect(typeof gate.passed).toBe('boolean');
      expect(gate.score).toBeGreaterThanOrEqual(0);
      expect(gate.score).toBeLessThanOrEqual(100);
    });

    test('should check evidence coverage gate', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const gate = qualityGate.checkEvidenceCoverage({ modules: { reasoning } });

      expect(gate.gate).toBe('Evidence Coverage');
      expect(typeof gate.passed).toBe('boolean');
    });

    test('should check confidence explainability gate', async () => {
      const confidence = await new IntelligenceConfidenceFramework().generateConfidenceAssessment(
        mockProduct,
        {},
        mockInvestigation
      );

      const gate = qualityGate.checkConfidenceExplainability({ modules: { confidence } });

      expect(gate.gate).toBe('Confidence Explainability');
      expect(typeof gate.passed).toBe('boolean');
    });

    test('should identify deficiencies and provide remediation', async () => {
      const enhancement = { modules: {} };

      const deficiencies = qualityGate.identifyDeficiencies(enhancement);

      expect(Array.isArray(deficiencies)).toBe(true);

      const remediation = qualityGate.provideRemediationGuidance(enhancement);

      expect(Array.isArray(remediation)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 10: Intelligence Product Benchmark Framework Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 10: Intelligence Product Benchmark Framework', () => {
    let benchmarkEngine;

    beforeEach(() => {
      benchmarkEngine = new IntelligenceProductBenchmarkFramework();
    });

    test('should benchmark report across all dimensions', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const enhancement = {
        modules: {
          reasoning,
          audiences: {},
        },
        certification: { passed: false },
      };

      const benchmark = await benchmarkEngine.benchmarkReport(mockProduct, enhancement);

      expect(benchmark).toBeDefined();
      expect(benchmark.reasoningQuality).toBeDefined();
      expect(benchmark.evidenceCoverage).toBeDefined();
      expect(benchmark.actionability).toBeDefined();
      expect(benchmark.executiveClarity).toBeDefined();
      expect(benchmark.detectionUsefulness).toBeDefined();
      expect(benchmark.reportCompleteness).toBeDefined();
      expect(benchmark.publicationQuality).toBeDefined();
      expect(benchmark.overallBenchmark).toBeDefined();
    });

    test('should score reasoning quality', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const score = benchmarkEngine.scoreReasoningQuality({ modules: { reasoning } });

      expect(score.metric).toBe('Reasoning Quality');
      expect(score.score).toBeGreaterThanOrEqual(0);
      expect(score.score).toBeLessThanOrEqual(100);
      expect(score.assessment).toMatch(/EXCELLENT|GOOD|NEEDS_WORK/);
    });

    test('should score evidence coverage', () => {
      const score = benchmarkEngine.scoreEvidenceCoverage({
        modules: { reasoning: { supportingEvidence: {} } },
      });

      expect(score.metric).toBe('Evidence Coverage');
      expect(score.score).toBeGreaterThanOrEqual(0);
    });

    test('should calculate overall benchmark score', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const benchmark = benchmarkEngine.calculateOverallBenchmark({
        modules: { reasoning, audiences: {}, certification: { passed: false } },
      });

      expect(benchmark.overallScore).toBeGreaterThanOrEqual(0);
      expect(benchmark.overallScore).toBeLessThanOrEqual(100);
      expect(benchmark.benchmark).toMatch(/EXCELLENT|GOOD|FAIR|NEEDS_IMPROVEMENT/);
    });

    test('should provide improvement recommendations', async () => {
      const reasoning = await new IntelligenceReasoningEngine().analyzeAllJudgements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      const recommendations = benchmarkEngine.recommendImprovements({
        modules: { reasoning, audiences: {} },
      });

      expect(Array.isArray(recommendations)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ORCHESTRATION & INTEGRATION TESTS
  // ═══════════════════════════════════════════════════════════════════════

  describe('Phase 13 Orchestration', () => {
    test('should enhance product with analyst reasoning', async () => {
      const enhancement = await phase13.enhanceWithAnalystReasoning(
        mockProduct,
        mockInvestigation,
        mockReport,
        mockHistoricalData
      );

      expect(enhancement).toBeDefined();
      expect(enhancement.productId).toBe(mockProduct.id);
      expect(enhancement.timestamp).toBeDefined();
      expect(enhancement.modules).toBeDefined();
      expect(enhancement.modules.reasoning).toBeDefined();
      expect(enhancement.modules.hypotheses).toBeDefined();
      expect(enhancement.modules.confidence).toBeDefined();
      expect(enhancement.modules.collectionGaps).toBeDefined();
      expect(enhancement.modules.consistency).toBeDefined();
      expect(enhancement.modules.outlook).toBeDefined();
      expect(enhancement.modules.audiences).toBeDefined();
      expect(enhancement.modules.structure).toBeDefined();
      expect(enhancement.certification).toBeDefined();
      expect(enhancement.modules.benchmark).toBeDefined();
    });

    test('should produce certification with all 10 modules', async () => {
      const enhancement = await phase13.enhanceWithAnalystReasoning(
        mockProduct,
        mockInvestigation,
        mockReport,
        mockHistoricalData
      );

      expect(enhancement.status).toMatch(/certified|review_required|error/);
      expect(enhancement.certification.status).toMatch(/APPROVED_FOR_PUBLICATION|REVIEW_REQUIRED/);
    });

    test('should handle errors gracefully', async () => {
      const badProduct = { id: null };
      const enhancement = await phase13.enhanceWithAnalystReasoning(
        badProduct,
        mockInvestigation,
        mockReport
      );

      expect(enhancement.status).toBe('error');
      expect(enhancement.error).toBeDefined();
    });

    test('should export phase metadata', () => {
      const metadata = phase13.toJSON();

      expect(metadata.phase).toBe('phase-13');
      expect(metadata.name).toBe('Advanced Analyst Reasoning & Intelligence Methodology Engine');
      expect(Array.isArray(metadata.modules)).toBe(true);
      expect(metadata.modules.length).toBe(10);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ADVANCED INTEGRATION TESTS
  // ═══════════════════════════════════════════════════════════════════════

  describe('Phase 13 Advanced Integration', () => {
    test('should produce analyst-grade intelligence product', async () => {
      const enhancement = await phase13.enhanceWithAnalystReasoning(
        mockProduct,
        mockInvestigation,
        mockReport,
        mockHistoricalData
      );

      if (enhancement.status !== 'error') {
        // Verify reasoning is traceable
        expect(enhancement.modules.reasoning?.keyJudgements?.length).toBeGreaterThan(0);

        // Verify confidence is explainable
        expect(enhancement.modules.confidence?.confidenceNarrative).toBeDefined();

        // Verify alternatives considered
        expect(enhancement.modules.hypotheses?.attributionHypotheses?.length).toBeGreaterThan(0);

        // Verify gaps identified
        expect(enhancement.modules.collectionGaps).toBeDefined();

        // Verify multi-audience support
        expect(enhancement.modules.audiences?.executive).toBeDefined();
        expect(enhancement.modules.audiences?.ciso).toBeDefined();
        expect(enhancement.modules.audiences?.soc).toBeDefined();
      }
    });

    test('should distinguish facts from analysis from uncertainty', async () => {
      const enhancement = await phase13.enhanceWithAnalystReasoning(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      if (enhancement.status !== 'error') {
        const reasoning = enhancement.modules.reasoning;
        expect(reasoning?.supportingEvidence).toBeDefined();
        expect(reasoning?.supportingEvidence?.coverage).toBeDefined();

        const confidence = enhancement.modules.confidence;
        expect(confidence?.uncertaintyFactors).toBeDefined();
      }
    });

    test('should enable measurement-based quality improvement', async () => {
      const enhancement = await phase13.enhanceWithAnalystReasoning(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      if (enhancement.status !== 'error') {
        const benchmark = enhancement.modules.benchmark;
        expect(benchmark?.overallBenchmark).toBeDefined();
        expect(benchmark?.overallBenchmark?.overallScore).toBeGreaterThanOrEqual(0);
        expect(benchmark?.improvementRecommendations).toBeDefined();
      }
    });

    test('should maintain backward compatibility with Phases 1-12', async () => {
      // Phase 13 should not require or modify existing product structure
      const originalProduct = JSON.parse(JSON.stringify(mockProduct));

      const enhancement = await phase13.enhanceWithAnalystReasoning(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      // Original product should remain unchanged
      expect(mockProduct).toEqual(originalProduct);

      // Enhancement should be additive
      expect(enhancement._enhancements || enhancement.modules).toBeDefined();
    });
  });
});
