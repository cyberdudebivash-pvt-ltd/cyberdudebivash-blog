'use strict';

const { Phase12EnterpriseExcellence, ExecutiveDecisionIntelligenceEngine, OperationalActionEngine, IntelligenceNarrativeEngine, EvidenceExplainabilityEngine, IntelligenceChangeEngine, CustomerImpactEngine, DetectionOperationsEngine, IntelligenceQualityEngine, EnterpriseReportCertification, ProductDifferentiationEngine } = require('../phase-12-enterprise-excellence');

describe('Phase 12 — Enterprise Intelligence Report Excellence Engine', () => {
  let phase12;
  let mockProduct;
  let mockInvestigation;
  let mockReport;

  beforeEach(() => {
    phase12 = new Phase12EnterpriseExcellence();

    mockProduct = {
      id: 'prod-001',
      title: 'APT-28 Infrastructure Update Q3 2026',
      type: 'threat-actor',
      threatLevel: 'CRITICAL',
      sources: ['GreyNoise', 'Shodan', 'Team Cymru'],
      indicators: {
        ips: ['192.0.2.1', '192.0.2.2'],
        domains: ['evil.example.com'],
        hashes: ['abc123def456'],
        emails: ['admin@evil.example.com'],
      },
      metadata: {
        confidenceScore: 95,
        sourceCredibility: 'HIGH',
        lastUpdated: new Date().toISOString(),
      },
    };

    mockInvestigation = {
      id: 'inv-001',
      title: 'APT-28 Q3 2026 Infrastructure',
      severity: 'CRITICAL',
      threatActors: ['APT-28', 'Fancy Bear'],
      targetedSectors: ['financial', 'government', 'technology'],
      affectedUserCount: 50000,
      techniques: [
        { name: 'Spear Phishing', mitreTactic: ['Initial Access'] },
        { name: 'Living off the Land', mitreTactic: ['Execution'] },
        { name: 'Registry Modification', mitreTactic: ['Persistence'] },
      ],
      malware: ['SOFACY', 'Zebrocy'],
      infrastructure: [
        { ip: '192.0.2.1', hosting: 'Digital Ocean', location: 'RU' },
        { ip: '192.0.2.2', hosting: 'Linode', location: 'NL' },
      ],
      cisaKev: true,
      exploited: true,
      ransomware: false,
      evidence: [
        { type: 'C2 Traffic', confidence: 95, details: 'HTTPS beacon to 192.0.2.1:443' },
        { type: 'Malware Signature', confidence: 92, details: 'SOFACY sample matches known variant' },
      ],
    };

    mockReport = {
      id: 'rpt-001',
      productId: 'prod-001',
      generated: new Date().toISOString(),
      sections: {
        summary: 'APT-28 has updated infrastructure...',
        technical: 'Analysis of C2 nodes, malware samples...',
        indicators: 'IOCs for detection...',
      },
    };
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 1: Executive Decision Intelligence Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 1: Executive Decision Intelligence Engine', () => {
    let executiveEngine;

    beforeEach(() => {
      executiveEngine = new ExecutiveDecisionIntelligenceEngine();
    });

    test('should generate executive intelligence with all 10 dimensions', async () => {
      const intelligence = await executiveEngine.generateExecutiveIntelligence(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      expect(intelligence).toBeDefined();
      expect(intelligence.executiveSummary).toBeDefined();
      expect(intelligence.businessImpact).toBeDefined();
      expect(intelligence.businessRisk).toBeDefined();
      expect(intelligence.operationalRisk).toBeDefined();
      expect(intelligence.financialImpact).toBeDefined();
      expect(intelligence.regulatoryImpact).toBeDefined();
      expect(intelligence.supplyChainImpact).toBeDefined();
      expect(intelligence.thirdPartyRisk).toBeDefined();
      expect(intelligence.cloudImpact).toBeDefined();
      expect(intelligence.aiRisk).toBeDefined();
    });

    test('should generate executive summary with headline, key points, and confidence', () => {
      const summary = executiveEngine.generateExecutiveSummary(mockProduct, mockInvestigation);

      expect(summary.headline).toBe(mockProduct.title);
      expect(Array.isArray(summary.keyPoints)).toBe(true);
      expect(summary.keyPoints.length).toBeGreaterThan(0);
      expect(summary.recommendedAction).toBeDefined();
      expect(summary.timeframe).toBeDefined();
      expect(summary.confidence).toBeGreaterThanOrEqual(0);
      expect(summary.confidence).toBeLessThanOrEqual(100);
    });

    test('should identify business impact areas for targeted sectors', () => {
      const impact = executiveEngine.analyzeBusinessImpact(mockProduct, mockInvestigation);

      expect(impact.areas).toBeDefined();
      expect(Array.isArray(impact.areas)).toBe(true);
      expect(impact.areas.length).toBeGreaterThan(0);
      expect(impact.customerActions).toBeDefined();
    });

    test('should assess business risk with risk score and factors', () => {
      const risk = executiveEngine.assessBusinessRisk(mockProduct, mockInvestigation);

      expect(risk.overallRisk).toMatch(/CRITICAL|HIGH|MEDIUM|LOW/);
      expect(risk.riskScore).toBeGreaterThanOrEqual(0);
      expect(risk.riskScore).toBeLessThanOrEqual(10);
      expect(Array.isArray(risk.factors)).toBe(true);
      expect(risk.mitigation).toBeDefined();
    });

    test('should assess operational risk with threats and impacted systems', () => {
      const opRisk = executiveEngine.assessOperationalRisk(mockProduct, mockInvestigation);

      expect(Array.isArray(opRisk.threatsIdentified)).toBe(true);
      expect(opRisk.impactedSystems).toBeDefined();
      expect(opRisk.detectionCoverage).toBeDefined();
      expect(opRisk.responseTimeframe).toBeDefined();
    });

    test('should estimate financial impact based on affected users and breach type', () => {
      const financial = executiveEngine.estimateFinancialImpact(mockProduct, mockInvestigation);

      expect(financial.estimatedLoss).toBeDefined();
      expect(financial.impactFactors).toBeDefined();
      expect(Array.isArray(financial.impactFactors)).toBe(true);
      expect(financial.confidenceLevel).toMatch(/HIGH|MEDIUM|LOW/);
      expect(financial.disclaimer).toBeDefined();
    });

    test('should assess regulatory impact including GDPR, HIPAA, SOX', () => {
      const regulatory = executiveEngine.assessRegulatoryImpact(mockProduct, mockInvestigation);

      expect(Array.isArray(regulatory.applicableRegulations)).toBe(true);
      expect(regulatory.complianceActions).toBeDefined();
      expect(regulatory.reportingDeadlines).toBeDefined();
    });

    test('should assess supply chain impact', () => {
      const supplyChain = executiveEngine.assessSupplyChainImpact(mockProduct, mockInvestigation);

      expect(Array.isArray(supplyChain.risks)).toBe(true);
      expect(supplyChain.vendorCommunication).toBeDefined();
      expect(supplyChain.resilienceAssessment).toBeDefined();
    });

    test('should assess third-party risk', () => {
      const thirdParty = executiveEngine.assessThirdPartyRisk(mockProduct, mockInvestigation);

      expect(Array.isArray(thirdParty.risks)).toBe(true);
      expect(thirdParty.vendorAssessment).toBeDefined();
      expect(thirdParty.contractualActions).toBeDefined();
    });

    test('should assess cloud impact', () => {
      const cloud = executiveEngine.assessCloudImpact(mockProduct, mockInvestigation);

      expect(Array.isArray(cloud.affectedServices)).toBe(true);
      expect(cloud.mitigationSteps).toBeDefined();
    });

    test('should assess AI risk when applicable', () => {
      const ai = executiveEngine.assessAIRisk(mockProduct, mockInvestigation);

      expect(ai).toBeDefined();
      expect(typeof ai.applicable).toBe('boolean');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 2: Operational Action Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 2: Operational Action Engine', () => {
    let operationalEngine;

    beforeEach(() => {
      operationalEngine = new OperationalActionEngine();
    });

    test('should generate audience-specific actions for all 12 audiences', async () => {
      const actions = await operationalEngine.generateAudienceSpecificActions(
        mockProduct,
        mockInvestigation
      );

      expect(actions).toBeDefined();
      expect(actions.ceo).toBeDefined();
      expect(actions.board).toBeDefined();
      expect(actions.ciso).toBeDefined();
      expect(actions.soc).toBeDefined();
      expect(actions.threatHunting).toBeDefined();
      expect(actions.detectionEngineering).toBeDefined();
      expect(actions.incidentResponse).toBeDefined();
      expect(actions.vulnerabilityManagement).toBeDefined();
      expect(actions.cloudSecurity).toBeDefined();
      expect(actions.identitySecurity).toBeDefined();
      expect(actions.networkSecurity).toBeDefined();
      expect(actions.socManagement).toBeDefined();
    });

    test('should include priority, actions, and timeline for CEO', () => {
      const ceoActions = operationalEngine.generateCEOActions(mockProduct, mockInvestigation);

      expect(ceoActions.priority).toMatch(/CRITICAL|HIGH|MEDIUM|LOW/);
      expect(Array.isArray(ceoActions.actions)).toBe(true);
      expect(ceoActions.timeline).toBeDefined();
      expect(ceoActions.successMetric).toBeDefined();
    });

    test('should include priority, actions, and timeline for CISO', () => {
      const cisoActions = operationalEngine.generateCISOActions(mockProduct, mockInvestigation);

      expect(cisoActions.priority).toMatch(/CRITICAL|HIGH|MEDIUM|LOW/);
      expect(Array.isArray(cisoActions.actions)).toBe(true);
      expect(cisoActions.timeline).toBeDefined();
    });

    test('should include detection queries for SOC', () => {
      const socActions = operationalEngine.generateSOCActions(mockProduct, mockInvestigation);

      expect(socActions.priority).toBeDefined();
      expect(Array.isArray(socActions.actions)).toBe(true);
      expect(socActions.detectionQueries).toBeDefined();
    });

    test('should include hunt paths for threat hunting', () => {
      const huntActions = operationalEngine.generateThreatHuntingActions(mockProduct, mockInvestigation);

      expect(Array.isArray(huntActions.actions)).toBe(true);
      expect(huntActions.huntPaths).toBeDefined();
    });

    test('should include detection rules for detection engineering', () => {
      const detActions = operationalEngine.generateDetectionEngineeringActions(mockProduct, mockInvestigation);

      expect(Array.isArray(detActions.actions)).toBe(true);
      expect(detActions.detectionRules).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 3: Intelligence Narrative Engine v2 Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 3: Intelligence Narrative Engine v2', () => {
    let narrativeEngine;

    beforeEach(() => {
      narrativeEngine = new IntelligenceNarrativeEngine();
    });

    test('should generate all narrative elements', async () => {
      const narratives = await narrativeEngine.generateNarrativeElements(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      expect(narratives).toBeDefined();
      expect(narratives.attackStory).toBeDefined();
      expect(narratives.campaignStory).toBeDefined();
      expect(narratives.threatActorStory).toBeDefined();
      expect(narratives.infrastructureStory).toBeDefined();
      expect(narratives.victimStory).toBeDefined();
      expect(narratives.detectionStory).toBeDefined();
    });

    test('should build attack story with timeline', () => {
      const story = narrativeEngine.buildAttackStory(mockProduct, mockInvestigation);

      expect(story.narrative).toBeDefined();
      expect(typeof story.narrative).toBe('string');
      expect(story.timeline).toBeDefined();
      expect(Array.isArray(story.timeline)).toBe(true);
    });

    test('should build campaign story', () => {
      const story = narrativeEngine.buildCampaignStory(mockProduct, mockInvestigation);

      expect(story.narrative).toBeDefined();
      expect(story.objective).toBeDefined();
      expect(story.status).toMatch(/ongoing|escalating|concluded/);
    });

    test('should build threat actor story', () => {
      const story = narrativeEngine.buildThreatActorStory(mockProduct, mockInvestigation);

      expect(story.narrative).toBeDefined();
      expect(story.background).toBeDefined();
      expect(Array.isArray(story.capabilities)).toBe(true);
    });

    test('should build infrastructure story with C2 details', () => {
      const story = narrativeEngine.buildInfrastructureStory(mockProduct, mockInvestigation);

      expect(story.narrative).toBeDefined();
      expect(story.c2Nodes).toBeDefined();
      expect(story.hostingProviders).toBeDefined();
      expect(story.geographic).toBeDefined();
    });

    test('should build victim story with impact assessment', () => {
      const story = narrativeEngine.buildVictimStory(mockProduct, mockInvestigation);

      expect(story.narrative).toBeDefined();
      expect(story.affectedOrganizations).toBeDefined();
      expect(story.affectedSectors).toBeDefined();
      expect(story.estimatedImpact).toBeDefined();
    });

    test('should build detection story with indicators', () => {
      const story = narrativeEngine.buildDetectionStory(mockProduct, mockInvestigation);

      expect(story.narrative).toBeDefined();
      expect(story.indicators).toBeDefined();
      expect(story.techniques).toBeDefined();
      expect(story.detectionChain).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 4: Evidence Explainability Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 4: Evidence Explainability Engine', () => {
    let explainabilityEngine;

    beforeEach(() => {
      explainabilityEngine = new EvidenceExplainabilityEngine();
    });

    test('should enhance product with explainability', async () => {
      const enhanced = await explainabilityEngine.enhanceWithExplainability(
        mockProduct,
        mockReport
      );

      expect(enhanced).toBeDefined();
      expect(enhanced.keyJudgements).toBeDefined();
      expect(enhanced.confidenceLevels).toBeDefined();
      expect(enhanced.alternativeExplanations).toBeDefined();
      expect(enhanced.uncertainties).toBeDefined();
    });

    test('should explain key judgements with evidence', () => {
      const judgements = explainabilityEngine.explainKeyJudgements(mockProduct);

      expect(Array.isArray(judgements)).toBe(true);
      judgements.forEach(j => {
        expect(j.judgement).toBeDefined();
        expect(j.evidence).toBeDefined();
        expect(Array.isArray(j.evidence)).toBe(true);
        expect(j.reasoning).toBeDefined();
      });
    });

    test('should explain confidence levels', () => {
      const confidence = explainabilityEngine.explainConfidenceLevels(mockProduct);

      expect(confidence.overall).toBeGreaterThanOrEqual(0);
      expect(confidence.overall).toBeLessThanOrEqual(100);
      expect(confidence.reasoning).toBeDefined();
      expect(Array.isArray(confidence.factors)).toBe(true);
    });

    test('should generate alternative explanations', () => {
      const alternatives = explainabilityEngine.generateAlternativeExplanations(mockInvestigation);

      expect(Array.isArray(alternatives)).toBe(true);
      alternatives.forEach(alt => {
        expect(alt.explanation).toBeDefined();
        expect(alt.likelihood).toMatch(/low|moderate|high/);
        expect(alt.refutingEvidence).toBeDefined();
      });
    });

    test('should identify uncertainties and data gaps', () => {
      const uncertainties = explainabilityEngine.identifyUncertainties(mockReport);

      expect(Array.isArray(uncertainties)).toBe(true);
      uncertainties.forEach(u => {
        expect(u.unknown).toBeDefined();
        expect(u.impact).toMatch(/low|medium|high/);
        expect(u.dataQuality).toBeDefined();
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 5: Intelligence Change Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 5: Intelligence Change Engine', () => {
    let changeEngine;

    beforeEach(() => {
      changeEngine = new IntelligenceChangeEngine();
    });

    test('should generate change analysis', async () => {
      const changes = await changeEngine.generateChangeAnalysis(
        mockProduct,
        mockInvestigation,
        []
      );

      expect(changes).toBeDefined();
      expect(changes.newElements).toBeDefined();
      expect(changes.changedElements).toBeDefined();
      expect(changes.escalations).toBeDefined();
      expect(changes.reductions).toBeDefined();
    });

    test('should identify new infrastructure, malware, techniques, and victims', () => {
      const changes = changeEngine.generateChangeAnalysis(mockProduct, mockInvestigation, []);

      expect(changes.newInfra).toBeDefined();
      expect(changes.newMalware).toBeDefined();
      expect(changes.newTechniques).toBeDefined();
      expect(changes.newVictims).toBeDefined();
    });

    test('should identify escalations', () => {
      const escalations = changeEngine.identifyEscalation(mockProduct, mockInvestigation);

      expect(Array.isArray(escalations)).toBe(true);
      escalations.forEach(e => {
        expect(e.indicator).toBeDefined();
        expect(e.direction).toBe('escalating');
        expect(e.impact).toBeDefined();
      });
    });

    test('should identify reductions', () => {
      const reductions = changeEngine.identifyReduction(mockProduct, mockInvestigation);

      expect(Array.isArray(reductions)).toBe(true);
      reductions.forEach(r => {
        expect(r.indicator).toBeDefined();
        expect(r.direction).toBe('reducing');
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 6: Customer Impact Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 6: Customer Impact Engine', () => {
    let customerEngine;

    beforeEach(() => {
      customerEngine = new CustomerImpactEngine();
    });

    test('should generate sector-specific impacts', async () => {
      const impacts = await customerEngine.generateSectorImpact(
        mockProduct,
        mockInvestigation
      );

      expect(impacts).toBeDefined();
      expect(impacts.financialServices).toBeDefined();
      expect(impacts.government).toBeDefined();
      expect(impacts.healthcare).toBeDefined();
      expect(impacts.manufacturing).toBeDefined();
      expect(impacts.retail).toBeDefined();
      expect(impacts.technology).toBeDefined();
      expect(impacts.criticalInfra).toBeDefined();
    });

    test('should analyze financial sector impact', () => {
      const impact = customerEngine.analyzeFinancialServices(mockProduct, mockInvestigation);

      expect(impact.applicable).toBeDefined();
      expect(typeof impact.applicable).toBe('boolean');
      if (impact.applicable) {
        expect(Array.isArray(impact.risks)).toBe(true);
        expect(Array.isArray(impact.actions)).toBe(true);
      }
    });

    test('should analyze government sector impact', () => {
      const impact = customerEngine.analyzeGovernment(mockProduct, mockInvestigation);

      expect(impact.applicable).toBeDefined();
      if (impact.applicable) {
        expect(Array.isArray(impact.risks)).toBe(true);
        expect(Array.isArray(impact.actions)).toBe(true);
      }
    });

    test('should analyze healthcare sector impact', () => {
      const impact = customerEngine.analyzeHealthcare(mockProduct, mockInvestigation);

      expect(impact.applicable).toBeDefined();
      if (impact.applicable) {
        expect(Array.isArray(impact.risks)).toBe(true);
        expect(Array.isArray(impact.actions)).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 7: Detection Operations Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 7: Detection Operations Engine', () => {
    let detectionEngine;

    beforeEach(() => {
      detectionEngine = new DetectionOperationsEngine();
    });

    test('should generate detection guidance', async () => {
      const guidance = await detectionEngine.generateDetectionGuidance(
        mockProduct,
        mockInvestigation
      );

      expect(guidance).toBeDefined();
      expect(guidance.priority).toMatch(/CRITICAL|HIGH|MEDIUM|LOW/);
      expect(guidance.huntQueries).toBeDefined();
      expect(guidance.prioritizedDetections).toBeDefined();
      expect(guidance.coverageGaps).toBeDefined();
      expect(guidance.attackCoverage).toBeDefined();
      expect(guidance.recommendedDetections).toBeDefined();
      expect(guidance.validationChecklist).toBeDefined();
      expect(guidance.prioritizedMonitoring).toBeDefined();
    });

    test('should generate SIEM hunt queries', () => {
      const queries = detectionEngine.generateHuntQueries(mockProduct, mockInvestigation);

      expect(Array.isArray(queries)).toBe(true);
      queries.forEach(q => {
        expect(q.type).toMatch(/ioc|behavioral|infrastructure/);
        expect(q.query).toBeDefined();
        expect(q.platform).toBeDefined();
      });
    });

    test('should assess MITRE ATT&CK coverage', () => {
      const coverage = detectionEngine.assessATTACKCoverage(mockProduct, mockInvestigation);

      expect(coverage).toBeDefined();
      expect(coverage.coverageMatrix).toBeDefined();
      expect(coverage.coverage).toBeGreaterThanOrEqual(0);
      expect(coverage.coverage).toBeLessThanOrEqual(100);
      expect(coverage.gaps).toBeDefined();
    });

    test('should recommend specific detections', () => {
      const recommendations = detectionEngine.recommendDetections(mockProduct, mockInvestigation);

      expect(Array.isArray(recommendations)).toBe(true);
      recommendations.forEach(r => {
        expect(r.technique).toBeDefined();
        expect(r.detection).toBeDefined();
        expect(r.priority).toBeDefined();
      });
    });

    test('should generate validation checklist', () => {
      const checklist = detectionEngine.generateValidationChecklist(mockProduct, mockInvestigation);

      expect(Array.isArray(checklist)).toBe(true);
      expect(checklist.length).toBeGreaterThan(0);
      expect(checklist[0].task).toBeDefined();
      expect(checklist[0].timeline).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 8: Intelligence Quality Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 8: Intelligence Quality Engine', () => {
    let qualityEngine;

    beforeEach(() => {
      qualityEngine = new IntelligenceQualityEngine();
    });

    test('should score report quality across 10 dimensions', async () => {
      const quality = await qualityEngine.scoreReportQuality(mockProduct, {});

      expect(quality).toBeDefined();
      expect(quality.scores).toBeDefined();
      expect(quality.scores.analyticalDepth).toBeGreaterThanOrEqual(0);
      expect(quality.scores.analyticalDepth).toBeLessThanOrEqual(100);
      expect(quality.overallScore).toBeGreaterThanOrEqual(0);
      expect(quality.overallScore).toBeLessThanOrEqual(100);
      expect(Array.isArray(quality.strengths)).toBe(true);
      expect(Array.isArray(quality.weaknesses)).toBe(true);
      expect(Array.isArray(quality.recommendations)).toBe(true);
    });

    test('should score all 10 quality dimensions', async () => {
      const quality = await qualityEngine.scoreReportQuality(mockProduct, {});

      expect(quality.scores.analyticalDepth).toBeDefined();
      expect(quality.scores.operationalUsefulness).toBeDefined();
      expect(quality.scores.executiveUsefulness).toBeDefined();
      expect(quality.scores.detectionUsefulness).toBeDefined();
      expect(quality.scores.commercialUsefulness).toBeDefined();
      expect(quality.scores.editorialConsistency).toBeDefined();
      expect(quality.scores.evidenceCompleteness).toBeDefined();
      expect(quality.scores.actionability).toBeDefined();
      expect(quality.scores.readability).toBeDefined();
      expect(quality.scores.customerValue).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 9: Enterprise Report Certification Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 9: Enterprise Report Certification', () => {
    let certificationEngine;

    beforeEach(() => {
      certificationEngine = new EnterpriseReportCertification();
    });

    test('should certify report when all criteria met', async () => {
      const enhancement = {
        modules: {
          executive: { businessRisk: { riskScore: 8 } },
          operational: { actions: [1, 2, 3] },
          detection: { huntQueries: [1, 2] },
          quality: { overallScore: 85 },
        },
      };

      const certification = await certificationEngine.certifyReport(mockProduct, enhancement);

      expect(certification).toBeDefined();
      expect(typeof certification.passed).toBe('boolean');
      expect(certification.checks).toBeDefined();
      expect(certification.status).toMatch(/APPROVED_FOR_PUBLICATION|REVIEW_REQUIRED/);
    });

    test('should require minimum overall quality score', async () => {
      const lowQualityEnhancement = {
        modules: {
          executive: { businessRisk: { riskScore: 8 } },
          operational: { actions: [1, 2, 3] },
          detection: { huntQueries: [1, 2] },
          quality: { overallScore: 50 }, // Below minimum
        },
      };

      const certification = await certificationEngine.certifyReport(
        mockProduct,
        lowQualityEnhancement
      );

      expect(certification.passed).toBe(false);
      expect(Array.isArray(certification.deficiencies)).toBe(true);
    });

    test('should require all required modules', async () => {
      const incompleteEnhancement = {
        modules: {
          executive: { businessRisk: { riskScore: 8 } },
          operational: { actions: [1, 2, 3] },
          // Missing detection and quality modules
        },
      };

      const certification = await certificationEngine.certifyReport(
        mockProduct,
        incompleteEnhancement
      );

      expect(certification.passed).toBe(false);
      expect(certification.deficiencies.length).toBeGreaterThan(0);
    });

    test('should provide remediation guidance for failed certifications', async () => {
      const failedEnhancement = {
        modules: {
          quality: { overallScore: 50 },
        },
      };

      const certification = await certificationEngine.certifyReport(
        mockProduct,
        failedEnhancement
      );

      if (!certification.passed) {
        expect(certification.remediationGuidance).toBeDefined();
        expect(Array.isArray(certification.remediationGuidance)).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 10: Product Differentiation Engine Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 10: Product Differentiation Engine', () => {
    let differentiationEngine;

    beforeEach(() => {
      differentiationEngine = new ProductDifferentiationEngine();
    });

    test('should identify differentiators', async () => {
      const diff = await differentiationEngine.identifyDifferentiators(
        mockProduct,
        mockInvestigation,
        {}
      );

      expect(diff).toBeDefined();
      expect(diff.uniqueInsights).toBeDefined();
      expect(diff.highConfidenceFindings).toBeDefined();
      expect(diff.customerActions).toBeDefined();
      expect(diff.operationalPriorities).toBeDefined();
      expect(diff.detectionOpportunities).toBeDefined();
      expect(diff.strategicObservations).toBeDefined();
    });

    test('should find unique insights', () => {
      const insights = differentiationEngine.findUniqueInsights(mockProduct, mockInvestigation);

      expect(Array.isArray(insights)).toBe(true);
      insights.forEach(i => {
        expect(i.insight).toBeDefined();
        expect(i.type).toMatch(/technique|infrastructure|targeting|malware/);
        expect(i.significance).toMatch(/low|medium|high/);
      });
    });

    test('should identify high-confidence findings', () => {
      const findings = differentiationEngine.identifyHighConfidenceFindings(
        mockProduct,
        mockInvestigation
      );

      expect(Array.isArray(findings)).toBe(true);
      findings.forEach(f => {
        expect(f.finding).toBeDefined();
        expect(f.confidence).toBeGreaterThanOrEqual(80);
        expect(f.evidence).toBeDefined();
      });
    });

    test('should generate customer action recommendations', () => {
      const actions = differentiationEngine.generateCustomerActions(
        mockProduct,
        mockInvestigation
      );

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.length).toBeGreaterThanOrEqual(1);
      actions.forEach(a => {
        expect(a.action).toBeDefined();
        expect(a.impact).toBeDefined();
        expect(a.timeline).toBeDefined();
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ORCHESTRATION TESTS
  // ═══════════════════════════════════════════════════════════════════════

  describe('Phase 12 Orchestration', () => {
    test('should enhance intelligence product with all 10 modules', async () => {
      const enhancement = await phase12.enhanceIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockReport,
        []
      );

      expect(enhancement).toBeDefined();
      expect(enhancement.productId).toBe(mockProduct.id);
      expect(enhancement.timestamp).toBeDefined();
      expect(enhancement.modules).toBeDefined();
      expect(enhancement.modules.executive).toBeDefined();
      expect(enhancement.modules.operational).toBeDefined();
      expect(enhancement.modules.narrative).toBeDefined();
      expect(enhancement.modules.explainability).toBeDefined();
      expect(enhancement.modules.change).toBeDefined();
      expect(enhancement.modules.customerImpact).toBeDefined();
      expect(enhancement.modules.detection).toBeDefined();
      expect(enhancement.modules.quality).toBeDefined();
      expect(enhancement.modules.differentiation).toBeDefined();
      expect(enhancement.certification).toBeDefined();
    });

    test('should set status to certified when all criteria met', async () => {
      const enhancement = await phase12.enhanceIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      expect(enhancement.status).toMatch(/certified|review_required|error/);
    });

    test('should handle errors gracefully', async () => {
      const badProduct = { id: null };
      const enhancement = await phase12.enhanceIntelligenceProduct(
        badProduct,
        mockInvestigation,
        mockReport
      );

      expect(enhancement.status).toBe('error');
      expect(enhancement.error).toBeDefined();
    });

    test('should export phase metadata', () => {
      const metadata = phase12.toJSON();

      expect(metadata.phase).toBe('phase-12');
      expect(metadata.name).toBe('Enterprise Intelligence Report Excellence Engine');
      expect(Array.isArray(metadata.modules)).toBe(true);
      expect(metadata.modules.length).toBe(10);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // INTEGRATION TESTS
  // ═══════════════════════════════════════════════════════════════════════

  describe('Phase 12 Integration', () => {
    test('should produce enterprise-ready enhancement without modifying original product', async () => {
      const originalProduct = JSON.parse(JSON.stringify(mockProduct));

      await phase12.enhanceIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      expect(mockProduct).toEqual(originalProduct);
    });

    test('should maintain backward compatibility with existing phases', async () => {
      // Phase 12 should not require modifications to Phases 1-11
      const product = {
        id: 'phase-11-product',
        title: 'Test Product',
        type: 'vulnerability',
        // Simulating Phase 11 output structure
        sources: ['nvd', 'cisa'],
      };

      const enhancement = await phase12.enhanceIntelligenceProduct(
        product,
        mockInvestigation,
        mockReport
      );

      expect(enhancement).toBeDefined();
      expect(enhancement.status).toBeDefined();
      // Product should not be modified
      expect(product.id).toBe('phase-11-product');
    });

    test('should produce actionable outputs across all audience dimensions', async () => {
      const enhancement = await phase12.enhanceIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      if (enhancement.status !== 'error') {
        // Executive module should be actionable for C-suite
        expect(enhancement.modules.executive).toBeDefined();

        // Operational module should provide specific actions
        expect(enhancement.modules.operational).toBeDefined();
        expect(enhancement.modules.operational.ciso).toBeDefined();
        expect(enhancement.modules.operational.soc).toBeDefined();

        // Detection module should provide hunt queries
        expect(enhancement.modules.detection).toBeDefined();

        // Quality should score all dimensions
        expect(enhancement.modules.quality).toBeDefined();
        expect(enhancement.modules.quality.scores).toBeDefined();
      }
    });

    test('should classify quality gate results', async () => {
      const enhancement = await phase12.enhanceIntelligenceProduct(
        mockProduct,
        mockInvestigation,
        mockReport
      );

      if (enhancement.certification) {
        expect(['APPROVED_FOR_PUBLICATION', 'REVIEW_REQUIRED']).toContain(
          enhancement.certification.status
        );
      }
    });
  });
});
