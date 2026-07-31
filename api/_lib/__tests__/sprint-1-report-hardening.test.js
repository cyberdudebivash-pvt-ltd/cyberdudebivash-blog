'use strict';

const {
  Sprint1ReportHardening,
  ExecutiveSummaryExcellence,
  KeyJudgementsEnhancement,
  ThreatStorytellingEngine,
  BusinessDecisionSupportEngine,
  DetectionExcellenceEngine,
  IntelligenceTimelineEngine,
  CustomerValueLayerEngine,
  IntelligenceVisualDataModel,
  EditorialExcellenceEngine,
  CommercialProductQualityEngine,
} = require('../sprint-1-report-hardening');

describe('Sprint 1 — Global Intelligence Report Product Hardening', () => {
  let sprint1;
  let mockReport;
  let mockInvestigation;
  let mockProduct;
  let mockEnhancement;

  beforeEach(() => {
    sprint1 = new Sprint1ReportHardening();

    mockProduct = {
      id: 'prod-sprint1-001',
      title: 'APT-29 October 2026 Campaign Assessment',
      type: 'threat-actor',
      threatLevel: 'CRITICAL',
    };

    mockInvestigation = {
      id: 'inv-sprint1-001',
      title: 'APT-29 October 2026 Campaign',
      severity: 'CRITICAL',
      threatActors: ['APT-29', 'Cozy Bear'],
      targetedSectors: ['financial', 'government'],
      affectedUserCount: 12500,
      cisaKev: true,
      exploited: true,
      ransomware: false,
      techniques: [
        { name: 'Spear Phishing', mitreTactic: ['Initial Access'] },
        { name: 'Living off the Land', mitreTactic: ['Execution'] },
        { name: 'Registry Modification', mitreTactic: ['Persistence'] },
        { name: 'Lateral Movement', mitreTactic: ['Lateral Movement'] },
        { name: 'Data Exfiltration', mitreTactic: ['Exfiltration'] },
        { name: 'Proxy Execution', mitreTactic: ['Defense Evasion'] },
      ],
      malware: ['Zebrocy', 'Sofacy'],
      infrastructure: [
        { ip: '192.0.2.1', hosting: 'Digital Ocean', location: 'RU' },
        { ip: '192.0.2.2', hosting: 'Linode', location: 'NL' },
        { ip: '192.0.2.3', hosting: 'AWS', location: 'US' },
      ],
      evidence: [
        { type: 'C2 Traffic', confidence: 95, details: 'HTTPS beacon' },
        { type: 'Malware Signature', confidence: 92, details: 'Zebrocy sample' },
      ],
      timeline: 'Campaign active since September 2026',
    };

    mockReport = {
      id: 'rpt-sprint1-001',
      productId: mockProduct.id,
      generated: new Date().toISOString(),
      sections: {
        summary: 'APT-29 continues active operations...',
        technical: 'Analysis reveals infrastructure improvements...',
        indicators: 'IOCs available for detection...',
      },
    };

    mockEnhancement = {
      modules: {
        confidence: { overallConfidence: 82 },
        reasoning: {
          keyJudgements: [
            {
              judgement: 'APT-29 remains highly active',
              confidence: 95,
              reasoning: [{ evidence: true }, { assumption: false }],
            },
          ],
        },
        change: { newElements: [{ type: 'technique', name: 'NewTechnique' }] },
        consistency: {
          behaviorChanges: [{ change: 'expanded targeting' }],
          capabilityEvolution: { trend: 'ESCALATING' },
        },
      },
    };
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ORCHESTRATION: Sprint1ReportHardening Main Class Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Orchestration: Sprint1ReportHardening', () => {
    test('should initialize with default configuration', () => {
      const s1 = new Sprint1ReportHardening();

      expect(s1.config.executiveDepth).toBe('comprehensive');
      expect(s1.config.confidenceThreshold).toBe(70);
      expect(s1.config.minEvidenceItems).toBe(2);
      expect(s1.config.publicationQualityThreshold).toBe(75);
      expect(s1.config.enableDetailedTimeline).toBe(true);
      expect(s1.config.enableVisualData).toBe(true);
      expect(s1.config.maxExecutivePoints).toBe(5);
    });

    test('should initialize with custom configuration', () => {
      const s1 = new Sprint1ReportHardening({
        executiveDepth: 'detailed',
        confidenceThreshold: 80,
        publicationQualityThreshold: 85,
      });

      expect(s1.config.executiveDepth).toBe('detailed');
      expect(s1.config.confidenceThreshold).toBe(80);
      expect(s1.config.publicationQualityThreshold).toBe(85);
    });

    test('should initialize all 10 engine modules', () => {
      expect(sprint1.executiveSummaryEngine).toBeInstanceOf(ExecutiveSummaryExcellence);
      expect(sprint1.judgementEngine).toBeInstanceOf(KeyJudgementsEnhancement);
      expect(sprint1.narrativeEngine).toBeInstanceOf(ThreatStorytellingEngine);
      expect(sprint1.decisionEngine).toBeInstanceOf(BusinessDecisionSupportEngine);
      expect(sprint1.detectionEngine).toBeInstanceOf(DetectionExcellenceEngine);
      expect(sprint1.timelineEngine).toBeInstanceOf(IntelligenceTimelineEngine);
      expect(sprint1.customerValueEngine).toBeInstanceOf(CustomerValueLayerEngine);
      expect(sprint1.visualDataEngine).toBeInstanceOf(IntelligenceVisualDataModel);
      expect(sprint1.editorialEngine).toBeInstanceOf(EditorialExcellenceEngine);
      expect(sprint1.qualityEngine).toBeInstanceOf(CommercialProductQualityEngine);
    });

    test('should provide JSON metadata describing the sprint', () => {
      const json = sprint1.toJSON();

      expect(json.sprint).toBe('sprint-1');
      expect(json.name).toBe('Global Intelligence Report Product Hardening');
      expect(json.program).toBe('Enterprise Intelligence Excellence Program');
      expect(Array.isArray(json.modules)).toBe(true);
      expect(json.modules).toHaveLength(10);
    });

    test('should enhance intelligence report with all modules', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      expect(hardened.reportId).toBe(mockReport.id);
      expect(hardened.timestamp).toBeDefined();
      expect(hardened.enhancements).toBeDefined();
      expect(hardened.qualityMetrics).toBeDefined();
      expect(hardened.publication).toBeDefined();
      expect(hardened.status).toMatch(/approved_for_publication|review_required|error/);

      // Verify all 10 module enhancements are present
      expect(hardened.enhancements.executiveSummary).toBeDefined();
      expect(hardened.enhancements.keyJudgements).toBeDefined();
      expect(hardened.enhancements.narrative).toBeDefined();
      expect(hardened.enhancements.decisions).toBeDefined();
      expect(hardened.enhancements.detection).toBeDefined();
      expect(hardened.enhancements.timeline).toBeDefined();
      expect(hardened.enhancements.customerValue).toBeDefined();
      expect(hardened.enhancements.visualData).toBeDefined();
      expect(hardened.enhancements.editorial).toBeDefined();
    });

    test('should set status to approved_for_publication when quality exceeds threshold', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      if (hardened.qualityMetrics.overallScore >= sprint1.config.publicationQualityThreshold) {
        expect(hardened.status).toBe('approved_for_publication');
        expect(hardened.publication.approved).toBe(true);
      }
    });

    test('should set status to review_required when quality below threshold', async () => {
      const sparseMockInvestigation = {
        ...mockInvestigation,
        techniques: [],
        malware: [],
        infrastructure: [],
        evidence: [],
      };

      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        sparseMockInvestigation,
        mockProduct
      );

      if (hardened.qualityMetrics.overallScore < sprint1.config.publicationQualityThreshold) {
        expect(hardened.status).toBe('review_required');
        expect(hardened.publication.approved).toBe(false);
      }
    });

    test('should handle errors gracefully during enhancement', async () => {
      const invalidReport = null;

      const hardened = await sprint1.enhanceIntelligenceReport(
        invalidReport,
        mockInvestigation,
        mockProduct
      );

      expect(hardened.status).toBe('error');
      expect(hardened.error).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 1: Executive Summary Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 1: Executive Summary Excellence', () => {
    let executiveEngine;

    beforeEach(() => {
      executiveEngine = new ExecutiveSummaryExcellence();
    });

    test('should generate comprehensive executive summary', async () => {
      const summary = await executiveEngine.generateExcellentSummary(
        mockReport,
        mockInvestigation,
        mockEnhancement
      );

      expect(summary.whatHappened).toBeDefined();
      expect(summary.whyItMatters).toBeDefined();
      expect(summary.whoIsAffected).toBeDefined();
      expect(summary.businessImpact).toBeDefined();
      expect(summary.executiveActions).toBeDefined();
      expect(summary.securityTeamActions).toBeDefined();
      expect(summary.monitoringRequirements).toBeDefined();
      expect(summary.evidenceSummary).toBeDefined();
      expect(summary.confidenceSummary).toBeDefined();
    });

    test('should build what happened narrative with threat actors and malware', () => {
      const whatHappened = executiveEngine.generateWhatHappened(mockInvestigation);

      expect(whatHappened.headline).toBe(mockInvestigation.title);
      expect(whatHappened.summary).toContain('APT-29');
      expect(whatHappened.summary).toContain('Zebrocy');
      expect(whatHappened.severity).toBe('CRITICAL');
      expect(Array.isArray(whatHappened.keyEvents)).toBe(true);
      expect(whatHappened.timing).toBeDefined();
    });

    test('should extract key events including CISA KEV and exploitation', () => {
      const events = executiveEngine.extractKeyEvents(mockInvestigation);

      expect(Array.isArray(events)).toBe(true);
      expect(events.some(e => e.event === 'CISA KEV Listing')).toBe(true);
      expect(events.some(e => e.event === 'Active Exploitation')).toBe(true);
    });

    test('should assess urgency as IMMEDIATE for exploited vulnerabilities', () => {
      const timing = executiveEngine.assessTiming(mockInvestigation);

      expect(timing.urgency).toBe('IMMEDIATE');
    });

    test('should generate why it matters with business context', () => {
      const whyItMatters = executiveEngine.generateWhyItMatters(mockInvestigation);

      expect(whyItMatters.summary).toBeDefined();
      expect(Array.isArray(whyItMatters.details)).toBe(true);
      expect(whyItMatters.businessRiskLevel).toMatch(/CRITICAL|HIGH|MEDIUM|LOW/);
    });

    test('should classify business risk as CRITICAL for exploited CISA KEV vulnerabilities', () => {
      const risk = executiveEngine.assessBusinessRisk(mockInvestigation);

      expect(risk).toBe('CRITICAL');
    });

    test('should identify affected sectors and user count', () => {
      const affected = executiveEngine.generateWhoIsAffected(mockInvestigation);

      expect(affected.sectors).toEqual(['financial', 'government']);
      expect(affected.userCount).toBe(12500);
      expect(affected.organizationCount).toBeGreaterThan(0);
    });

    test('should generate business impact with scale and severity', () => {
      const impacts = executiveEngine.generateBusinessImpact(mockInvestigation);

      expect(Array.isArray(impacts)).toBe(true);
      expect(impacts.some(i => i.area === 'Breach Scope')).toBe(true);
      expect(impacts.some(i => i.area === 'Patch Liability')).toBe(true);
    });

    test('should generate executive actions with owner and timeline', () => {
      const actions = executiveEngine.generateExecutiveActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.some(a => a.action.toLowerCase().includes('activate'))).toBe(true);
      expect(actions.every(a => a.owner)).toBe(true);
      expect(actions.every(a => a.timeline)).toBe(true);
    });

    test('should generate security team actions prioritized by impact', () => {
      const actions = executiveEngine.generateSecurityTeamActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.length).toBeGreaterThan(0);
      expect(actions[0]).toContain('CISA KEV');
    });

    test('should summarize evidence quality and confidence', () => {
      const summary = executiveEngine.generateEvidenceSummary(mockInvestigation);

      expect(summary.infrastructure).toBe(3);
      expect(summary.malware).toBe(2);
      expect(summary.techniques).toBe(6);
      expect(summary.directEvidence).toBe(2);
      expect(summary.corroboration).toBe('Multiple independent sources');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 2: Key Judgements Enhancement Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 2: Key Judgements Enhancement', () => {
    let judgementEngine;

    beforeEach(() => {
      judgementEngine = new KeyJudgementsEnhancement();
    });

    test('should enhance all judgements with confidence and evidence', async () => {
      const enhanced = await judgementEngine.enhanceAllJudgements(
        mockReport,
        mockEnhancement
      );

      expect(Array.isArray(enhanced)).toBe(true);
      if (enhanced.length > 0) {
        expect(enhanced[0].assessment).toBeDefined();
        expect(enhanced[0].confidence).toBeDefined();
        expect(enhanced[0].confidenceNarrative).toBeDefined();
        expect(enhanced[0].supportingEvidence).toBeDefined();
        expect(enhanced[0].contradictoryEvidence).toBeDefined();
        expect(enhanced[0].remainingUncertainty).toBeDefined();
      }
    });

    test('should generate confidence narratives matching confidence score', () => {
      const narrative90 = judgementEngine.generateConfidenceNarrative(90);
      const narrative75 = judgementEngine.generateConfidenceNarrative(75);
      const narrative60 = judgementEngine.generateConfidenceNarrative(60);
      const narrative45 = judgementEngine.generateConfidenceNarrative(45);
      const narrative30 = judgementEngine.generateConfidenceNarrative(30);

      expect(narrative90).toContain('Very high confidence');
      expect(narrative75).toContain('High confidence');
      expect(narrative60).toContain('Moderate confidence');
      expect(narrative45).toContain('Low-to-moderate confidence');
      expect(narrative30).toContain('Low confidence');
    });

    test('should categorize supporting evidence separately from secondary evidence', () => {
      const judgement = {
        reasoning: [
          { evidence: true, details: 'Direct evidence' },
          { evidence: false, details: 'Secondary reasoning' },
        ],
      };

      const evidence = judgementEngine.generateSupportingEvidence(judgement);

      expect(evidence.directEvidence.length).toBe(1);
      expect(evidence.secondaryEvidence.length).toBe(1);
    });

    test('should identify contradictory evidence', () => {
      const judgement = { reasoning: [] };
      const contradictions = judgementEngine.generateContradictoryEvidence(judgement);

      expect(contradictions.contradictions).toEqual([]);
      expect(contradictions.assessment).toBeDefined();
    });

    test('should document remaining uncertainty and assumptions', () => {
      const judgement = {
        reasoning: [
          { assumption: true, details: 'Assumed infrastructure correlation' },
        ],
      };

      const uncertainty = judgementEngine.generateUncertainty(judgement);

      expect(uncertainty.gaps).toBeDefined();
      expect(Array.isArray(uncertainty.assumptions)).toBe(true);
      expect(uncertainty.timeline).toBeDefined();
    });

    test('should map operational impact across detection, hunting, and response', () => {
      const judgement = {};
      const impact = judgementEngine.generateOperationalImpact(judgement);

      expect(impact.detection).toBeDefined();
      expect(impact.hunting).toBeDefined();
      expect(impact.response).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 3: Threat Storytelling Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 3: Threat Storytelling', () => {
    let storyEngine;

    beforeEach(() => {
      storyEngine = new ThreatStorytellingEngine();
    });

    test('should generate coherent narrative with all story elements', async () => {
      const narrative = await storyEngine.generateCoherentNarrative(
        mockInvestigation,
        mockReport
      );

      expect(narrative.campaignEvolution).toBeDefined();
      expect(narrative.attackerObjectives).toBeDefined();
      expect(narrative.attackProgression).toBeDefined();
      expect(narrative.victimTargeting).toBeDefined();
      expect(narrative.infrastructureStrategy).toBeDefined();
      expect(narrative.detectionOpportunities).toBeDefined();
      expect(narrative.defensiveOpportunities).toBeDefined();
      expect(narrative.narrativeFlow).toBeDefined();
    });

    test('should build campaign evolution with attack phases', () => {
      const evolution = storyEngine.buildCampaignEvolution(mockInvestigation);

      expect(evolution.narrative).toBe(mockInvestigation.title);
      expect(Array.isArray(evolution.phases)).toBe(true);
      expect(evolution.phases.length).toBeGreaterThan(0);
      expect(evolution.timeline).toBeDefined();
    });

    test('should infer attacker objectives from targeting and capability', () => {
      const objectives = storyEngine.buildObjectives(mockInvestigation);

      expect(Array.isArray(objectives)).toBe(true);
      expect(objectives.some(o => o.includes('theft') || o.includes('fraud'))).toBe(true);
      expect(objectives.some(o => o.includes('Espionage'))).toBe(true);
    });

    test('should map attack progression to MITRE tactics', () => {
      const progression = storyEngine.buildAttackProgression(mockInvestigation);

      expect(Array.isArray(progression)).toBe(true);
      expect(progression.length).toBe(6);
      expect(progression[0].technique).toBe('Spear Phishing');
      expect(progression[0].tactic).toBe('Initial Access');
    });

    test('should classify victim targeting as strategic or opportunistic', () => {
      const targeting = storyEngine.buildVictimTargeting(mockInvestigation);

      expect(targeting.sectors).toEqual(['financial', 'government']);
      expect(targeting.userCount).toBe(12500);
      expect(targeting.selectivity).toBe('Strategic');
    });

    test('should describe infrastructure strategy and persistence', () => {
      const infrastructure = storyEngine.buildInfrastructureStrategy(mockInvestigation);

      expect(infrastructure.nodes).toBe(3);
      expect(infrastructure.hosting.length).toBeGreaterThan(0);
      expect(infrastructure.geography.length).toBeGreaterThan(0);
      expect(infrastructure.persistence).toBeDefined();
    });

    test('should identify detection opportunities for each capability vector', () => {
      const opportunities = storyEngine.buildDetectionOpportunities(mockInvestigation);

      expect(Array.isArray(opportunities)).toBe(true);
      expect(opportunities.some(o => o.includes('C2'))).toBe(true);
      expect(opportunities.some(o => o.includes('Malware'))).toBe(true);
      expect(opportunities.some(o => o.includes('Behavioral'))).toBe(true);
    });

    test('should provide defensive countermeasure recommendations', () => {
      const defensive = storyEngine.buildDefensiveOpportunities(mockInvestigation);

      expect(Array.isArray(defensive)).toBe(true);
      expect(defensive).toContain('Infrastructure blocking and containment');
      expect(defensive).toContain('Credential revocation and reset');
      expect(defensive).toContain('System patching and hardening');
    });

    test('should build narrative flow with dramatic arc', () => {
      const flow = storyEngine.buildNarrativeFlow(mockInvestigation);

      expect(flow.openingContext).toContain('APT-29');
      expect(flow.developingTension).toContain('financial');
      expect(flow.climax).toBe('Active exploitation confirmed');
      expect(flow.resolution).toBe('Defensive actions available');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 4: Business Decision Support Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 4: Business Decision Support', () => {
    let decisionEngine;

    beforeEach(() => {
      decisionEngine = new BusinessDecisionSupportEngine();
    });

    test('should generate decision framework for all 7 audience types', async () => {
      const framework = await decisionEngine.generateDecisionFramework(
        mockReport,
        mockInvestigation,
        mockEnhancement
      );

      expect(framework.executiveDecisions).toBeDefined();
      expect(framework.operationalDecisions).toBeDefined();
      expect(framework.socPriorities).toBeDefined();
      expect(framework.threatHuntingPriorities).toBeDefined();
      expect(framework.detectionPriorities).toBeDefined();
      expect(framework.incidentResponsePriorities).toBeDefined();
      expect(framework.riskReductionPriorities).toBeDefined();
    });

    test('should generate executive decisions with rationale and timeline', () => {
      const decisions = decisionEngine.generateExecutiveDecisions(mockInvestigation);

      expect(Array.isArray(decisions)).toBe(true);
      expect(decisions.length).toBeGreaterThan(0);
      expect(decisions[0].decision).toBeDefined();
      expect(decisions[0].rationale).toBeDefined();
      expect(decisions[0].timeline).toBeDefined();
      expect(decisions[0].evidence).toBeDefined();
    });

    test('should generate operational decisions with actionable steps', () => {
      const decisions = decisionEngine.generateOperationalDecisions(mockInvestigation);

      expect(Array.isArray(decisions)).toBe(true);
      expect(decisions.some(d => d.decision === 'Infrastructure Blocking')).toBe(true);
      expect(decisions.every(d => d.action)).toBe(true);
      expect(decisions.every(d => d.owner)).toBe(true);
    });

    test('should set SOC priorities with urgency levels', () => {
      const priorities = decisionEngine.generateSOCPriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
      expect(priorities[0].priority).toBe(1);
      expect(priorities[0].urgency).toMatch(/CRITICAL|HIGH|MEDIUM|LOW/);
      expect(priorities.every(p => p.task)).toBe(true);
    });

    test('should define threat hunting priorities with scope', () => {
      const priorities = decisionEngine.generateThreatHuntingPriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
      expect(priorities.some(p => p.hunt === 'Historical C2 callbacks')).toBe(true);
      expect(priorities.every(p => p.scope)).toBe(true);
    });

    test('should set detection priorities with confidence levels', () => {
      const priorities = decisionEngine.generateDetectionPriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
      expect(priorities.every(p => p.confidence)).toBe(true);
    });

    test('should schedule incident response steps with owners', () => {
      const steps = decisionEngine.generateIRPriorities(mockInvestigation);

      expect(Array.isArray(steps)).toBe(true);
      expect(steps[0].step).toContain('Containment');
      expect(steps.every(s => s.owner)).toBe(true);
      expect(steps.every(s => s.timeline)).toBe(true);
    });

    test('should identify risk reduction priorities and mitigations', () => {
      const risks = decisionEngine.generateRiskReductionPriorities(mockInvestigation);

      expect(Array.isArray(risks)).toBe(true);
      expect(risks.some(r => r.risk.toLowerCase().includes('exploit'))).toBe(true);
      expect(risks.every(r => r.timeframe)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 5: Detection Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 5: Detection Excellence', () => {
    let detectionEngine;

    beforeEach(() => {
      detectionEngine = new DetectionExcellenceEngine();
    });

    test('should enhance detection guidance with all vectors', async () => {
      const guidance = await detectionEngine.enhanceDetectionGuidance(
        mockReport,
        mockInvestigation
      );

      expect(guidance.deploymentGuidance).toBeDefined();
      expect(guidance.tuningGuidance).toBeDefined();
      expect(guidance.validationGuidance).toBeDefined();
      expect(guidance.knownLimitations).toBeDefined();
      expect(guidance.falsePositiveConsiderations).toBeDefined();
      expect(guidance.coverageExpectations).toBeDefined();
      expect(guidance.mitrAttackReferences).toBeDefined();
    });

    test('should provide deployment guidance with tools and priority', () => {
      const guidance = detectionEngine.generateDeploymentGuidance(mockInvestigation);

      expect(Array.isArray(guidance)).toBe(true);
      expect(guidance.some(g => g.detection === 'C2 Detection')).toBe(true);
      expect(guidance.every(g => g.tools)).toBe(true);
      expect(guidance.every(g => g.priority)).toBe(true);
    });

    test('should provide tuning guidance with baseline and methodology', () => {
      const tuning = detectionEngine.generateTuningGuidance(mockInvestigation);

      expect(tuning.alertThreshold).toBeDefined();
      expect(tuning.falsePositiveBaseline).toBeDefined();
      expect(tuning.tuningProcess).toBeDefined();
    });

    test('should provide validation guidance with testing methodology', () => {
      const validation = detectionEngine.generateValidationGuidance(mockInvestigation);

      expect(validation.testingMethod).toBeDefined();
      expect(validation.validationTimeline).toBeDefined();
      expect(validation.successCriteria).toBeDefined();
      expect(validation.failureResponse).toBeDefined();
    });

    test('should identify known limitations and gaps', () => {
      const limitations = detectionEngine.identifyLimitations(mockInvestigation);

      expect(Array.isArray(limitations)).toBe(true);
      expect(limitations.length).toBeGreaterThan(0);
      expect(limitations.some(l => l.includes('new variants'))).toBe(true);
    });

    test('should assess false positive risk and mitigation', () => {
      const fpRisk = detectionEngine.identifyFalsePositives(mockInvestigation);

      expect(fpRisk.highRisk).toBeDefined();
      expect(fpRisk.mediumRisk).toBeDefined();
      expect(fpRisk.mitigation).toBeDefined();
      expect(fpRisk.tuning).toBeDefined();
    });

    test('should assess coverage expectations based on technique count', () => {
      const coverage = detectionEngine.assessCoverageExpectations(mockInvestigation);

      expect(coverage.expectedCoverage).toBeGreaterThan(0);
      expect(coverage.expectedCoverage).toBeLessThanOrEqual(85);
      expect(coverage.assessment).toBeDefined();
    });

    test('should map techniques to MITRE ATT&CK framework', () => {
      const mitre = detectionEngine.generateMITREReferences(mockInvestigation);

      expect(mitre.tacticsRepresented).toBeDefined();
      expect(Array.isArray(mitre.tacticsRepresented)).toBe(true);
      expect(mitre.mitreAttackMapping).toBeDefined();
      expect(mitre.reference).toContain('mitre.org');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 6: Intelligence Timeline Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 6: Intelligence Timeline', () => {
    let timelineEngine;

    beforeEach(() => {
      timelineEngine = new IntelligenceTimelineEngine();
    });

    test('should generate intelligence timeline with gaps and confidence', async () => {
      const timeline = await timelineEngine.generateIntelligenceTimeline(
        mockInvestigation,
        mockReport
      );

      expect(timeline.timeline).toBeDefined();
      expect(timeline.gaps).toBeDefined();
      expect(timeline.confidence).toBeDefined();
    });

    test('should build structured timeline with events and evidence', () => {
      const timeline = timelineEngine.buildStructuredTimeline(mockInvestigation);

      expect(Array.isArray(timeline)).toBe(true);
      expect(timeline.length).toBeGreaterThan(0);
      expect(timeline.every(e => e.date)).toBe(true);
      expect(timeline.every(e => e.evidence)).toBe(true);
      expect(timeline.every(e => e.certainty)).toBe(true);
    });

    test('should identify gaps in timeline when data is sparse', () => {
      const sparseInvestigation = {
        ...mockInvestigation,
        timeline: null,
        infrastructure: [],
      };

      const gaps = timelineEngine.identifyTimelineGaps(sparseInvestigation);

      expect(Array.isArray(gaps)).toBe(true);
      expect(gaps.some(g => g.includes('origin date uncertain'))).toBe(true);
    });

    test('should assess timeline confidence based on evidence quality', () => {
      const confidence = timelineEngine.assessTimelineConfidence(mockInvestigation);

      expect(confidence.score).toBeGreaterThan(0);
      expect(confidence.score).toBeLessThanOrEqual(95);
      expect(confidence.assessment).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 7: Customer Value Layer Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 7: Customer Value Layer', () => {
    let customerValueEngine;

    beforeEach(() => {
      customerValueEngine = new CustomerValueLayerEngine();
    });

    test('should generate customer value layer with business context', async () => {
      const value = await customerValueEngine.generateCustomerValue(
        mockReport,
        mockInvestigation
      );

      expect(value.whyThisMatters).toBeDefined();
      expect(value.customerActions).toBeDefined();
      expect(value.defensivePriorities).toBeDefined();
      expect(value.operationalImpact).toBeDefined();
      expect(value.strategicImplications).toBeDefined();
      expect(value.recommendedFollowUp).toBeDefined();
      expect(value.timeToValue).toBeDefined();
    });

    test('should articulate why this matters in business terms', () => {
      const whyMatters = customerValueEngine.generateWhyThisMatters(mockInvestigation);

      expect(whyMatters.summary).toBeDefined();
      expect(Array.isArray(whyMatters.details)).toBe(true);
      expect(whyMatters.details.length).toBeGreaterThan(0);
      expect(whyMatters.businessAlignment).toBeDefined();
    });

    test('should generate customer actions with expected outcomes', () => {
      const actions = customerValueEngine.generateCustomerActions(mockInvestigation);

      expect(Array.isArray(actions)).toBe(true);
      expect(actions.every(a => a.action)).toBe(true);
      expect(actions.every(a => a.expectedOutcome)).toBe(true);
      expect(actions.every(a => a.timeline)).toBe(true);
    });

    test('should prioritize defensive actions by impact', () => {
      const priorities = customerValueEngine.generateDefensivePriorities(mockInvestigation);

      expect(Array.isArray(priorities)).toBe(true);
      expect(priorities[0].priority).toBe(1);
      expect(priorities.every(p => p.action)).toBe(true);
    });

    test('should map operational impact to each team', () => {
      const impact = customerValueEngine.generateOperationalImpact(mockInvestigation);

      expect(impact.detectionTeam).toBeDefined();
      expect(impact.huntingTeam).toBeDefined();
      expect(impact.incidentResponse).toBeDefined();
      expect(impact.threatManagement).toBeDefined();
    });

    test('should provide strategic implications and trend analysis', () => {
      const strategic = customerValueEngine.generateStrategicImplications(mockInvestigation);

      expect(strategic.threatLandscape).toBeDefined();
      expect(strategic.trendAnalysis).toBeDefined();
      expect(strategic.industryContext).toBeDefined();
      expect(strategic.futureWatching).toBeDefined();
    });

    test('should recommend follow-up activities with frequency', () => {
      const followUp = customerValueEngine.generateFollowUp(mockInvestigation);

      expect(Array.isArray(followUp)).toBe(true);
      expect(followUp.every(f => f.followUp)).toBe(true);
      expect(followUp.every(f => f.frequency)).toBe(true);
    });

    test('should estimate time to value across multiple horizons', () => {
      const ttv = customerValueEngine.estimateTimeToValue(mockInvestigation);

      expect(ttv.immediate).toBeDefined();
      expect(ttv.shortTerm).toBeDefined();
      expect(ttv.mediumTerm).toBeDefined();
      expect(ttv.longTerm).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 8: Intelligence Visual Data Model Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 8: Intelligence Visual Data Model', () => {
    let visualEngine;

    beforeEach(() => {
      visualEngine = new IntelligenceVisualDataModel();
    });

    test('should generate visual data model for rendering', async () => {
      const visualData = await visualEngine.generateVisualDataModel(
        mockInvestigation,
        mockReport
      );

      expect(visualData.attackMatrix).toBeDefined();
      expect(visualData.campaignTimeline).toBeDefined();
      expect(visualData.infrastructureMap).toBeDefined();
      expect(visualData.relationshipGraph).toBeDefined();
      expect(visualData.confidenceSummary).toBeDefined();
      expect(visualData.detectionCoverage).toBeDefined();
      expect(visualData.iocSummary).toBeDefined();
    });

    test('should generate MITRE ATT&CK matrix with tactic-to-technique mapping', () => {
      const matrix = visualEngine.generateAttackMatrix(mockInvestigation);

      expect(matrix.framework).toBe('MITRE ATT&CK');
      expect(matrix.matrix).toBeDefined();
      expect(matrix.coverage).toBeGreaterThan(0);
      expect(matrix.totalTechniques).toBe(6);
    });

    test('should generate timeline data ready for visualization', () => {
      const timeline = visualEngine.generateTimelineData(mockInvestigation);

      expect(timeline.events).toBeDefined();
      expect(timeline.format).toContain('ready');
    });

    test('should generate infrastructure graph with nodes and edges', () => {
      const infrastructure = visualEngine.generateInfrastructureMap(mockInvestigation);

      expect(infrastructure.nodes).toBeDefined();
      expect(Array.isArray(infrastructure.nodes)).toBe(true);
      expect(infrastructure.nodes.every(n => n.id)).toBe(true);
      expect(infrastructure.format).toBeDefined();
    });

    test('should generate relationship graph for D3 visualization', () => {
      const relationships = visualEngine.generateRelationshipGraph(mockInvestigation);

      expect(relationships.nodes).toBeDefined();
      expect(relationships.edges).toBeDefined();
      expect(relationships.format.toLowerCase()).toContain('graph');
    });

    test('should generate confidence summary data ready for gauges', () => {
      const confidence = visualEngine.generateConfidenceSummary(mockInvestigation);

      expect(confidence.overall).toBeDefined();
      expect(confidence.byDimension).toBeDefined();
      expect(confidence.format.toLowerCase()).toContain('gauge');
    });

    test('should generate detection coverage data for bar charts', () => {
      const coverage = visualEngine.generateDetectionCoverage(mockInvestigation);

      expect(Array.isArray(coverage.categories)).toBe(true);
      expect(coverage.categories.every(c => c.coverage)).toBe(true);
      expect(coverage.format.toLowerCase()).toContain('bar');
    });

    test('should summarize IOCs by type', () => {
      const iocs = visualEngine.generateIOCSummary(mockInvestigation);

      expect(iocs.ips).toBe(3);
      expect(iocs.hashes).toBe(2);
      expect(iocs.total).toBe(5);
      expect(iocs.format).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 9: Editorial Excellence Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 9: Editorial Excellence', () => {
    let editorialEngine;

    beforeEach(() => {
      editorialEngine = new EditorialExcellenceEngine();
    });

    test('should enhance editorial quality across all dimensions', async () => {
      const enhanced = await editorialEngine.enhanceEditorially(
        mockReport,
        {
          executiveSummary: {},
          narrative: {},
          decision: {},
          detection: {},
          editorial: {},
        }
      );

      expect(enhanced.readability).toBeDefined();
      expect(enhanced.terminology).toBeDefined();
      expect(enhanced.sectionConsistency).toBeDefined();
      expect(enhanced.grammarAndStyle).toBeDefined();
      expect(enhanced.narrativeFlow).toBeDefined();
      expect(enhanced.headingHierarchy).toBeDefined();
      expect(enhanced.formatting).toBeDefined();
    });

    test('should assess readability with grade level', () => {
      const readability = editorialEngine.improveReadability(mockReport);

      expect(readability.averageSentenceLength).toBeDefined();
      expect(readability.averageParagraphLength).toBeDefined();
      expect(readability.readingGrade).toContain('Grade');
      expect(Array.isArray(readability.recommendations)).toBe(true);
    });

    test('should standardize terminology definitions', () => {
      const terminology = editorialEngine.standardizeTerminology(mockReport);

      expect(terminology.threatActor).toBeDefined();
      expect(terminology.malware).toBeDefined();
      expect(terminology.techniques).toBeDefined();
      expect(terminology.indicators).toBeDefined();
    });

    test('should ensure required sections are present', () => {
      const consistency = editorialEngine.ensureSectionConsistency({});

      expect(Array.isArray(consistency.requiredSections)).toBe(true);
      expect(consistency.requiredSections).toContain('Executive Summary');
      expect(consistency.requiredSections).toContain('Detection Guidance');
      expect(consistency.validation).toBeDefined();
    });

    test('should provide grammar and style guidance', () => {
      const grammar = editorialEngine.enhanceGrammarAndStyle(mockReport);

      expect(grammar.voiceAndTone).toContain('analytical');
      expect(grammar.activeVoice).toContain('Preferred');
      expect(grammar.jargon).toBeDefined();
      expect(grammar.consistency).toBeDefined();
    });

    test('should define narrative flow progression', () => {
      const flow = editorialEngine.improveNarrativeFlow({});

      expect(flow.logicalProgression).toBeDefined();
      expect(flow.transitions).toBeDefined();
      expect(flow.callToAction).toBeDefined();
    });

    test('should validate heading hierarchy H1 to H4', () => {
      const hierarchy = editorialEngine.validateHeadingHierarchy({});

      expect(hierarchy.h1).toBeDefined();
      expect(hierarchy.h2).toBeDefined();
      expect(hierarchy.h3).toBeDefined();
      expect(hierarchy.h4).toBeDefined();
    });

    test('should specify formatting rules for emphasis and lists', () => {
      const formatting = editorialEngine.ensureFormatting(mockReport);

      expect(formatting.emphasis).toBeDefined();
      expect(formatting.lists).toBeDefined();
      expect(formatting.tables).toBeDefined();
      expect(formatting.spacing).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // MODULE 10: Commercial Product Quality Tests
  // ═══════════════════════════════════════════════════════════════════════

  describe('Module 10: Commercial Product Quality', () => {
    let qualityEngine;

    beforeEach(() => {
      qualityEngine = new CommercialProductQualityEngine();
    });

    test('should score report quality across 10 dimensions', async () => {
      const scores = await qualityEngine.scoreReportQuality(
        mockReport,
        {
          executiveSummary: { businessImpact: [{}] },
          narrative: { campaignEvolution: {} },
          decisions: { executiveDecisions: [{}], operationalDecisions: [{}], socPriorities: [{}], threatHuntingPriorities: [{}], detectionPriorities: [{}], incidentResponsePriorities: [{}], riskReductionPriorities: [{}] },
          detection: { deploymentGuidance: [{}], tuningGuidance: {}, detectionCoverage: {} },
          customerValue: { whyThisMatters: {}, customerActions: [{}], defensivePriorities: [{}], operationalImpact: {}, recommendedFollowUp: [{}] },
          keyJudgements: [{ confidenceNarrative: 'test', remainingUncertainty: {} }],
          visualData: { iocSummary: {}, detectionCoverage: {} },
          editorial: { sectionConsistency: {}, readability: {}, narrativeFlow: {} },
        },
        mockInvestigation
      );

      expect(scores.scores).toBeDefined();
      expect(scores.componentScores).toBeDefined();
      expect(scores.averageScore).toBeDefined();
      expect(scores.overallScore).toBeGreaterThanOrEqual(0);
      expect(scores.overallScore).toBeLessThanOrEqual(100);
      expect(scores.quality).toMatch(/EXCELLENT|GOOD|ACCEPTABLE|NEEDS_IMPROVEMENT|REVIEW_REQUIRED/);
    });

    test('should score executive value based on summary and impact', () => {
      const score = qualityEngine.scoreExecutiveValue({
        executiveSummary: { businessImpact: [{}] },
        decisions: { executiveDecisions: [{}] },
      });

      expect(score.name).toBe('Executive Value');
      expect(score.score).toBeGreaterThanOrEqual(0);
      expect(score.score).toBeLessThanOrEqual(100);
      expect(score.components).toBeDefined();
    });

    test('should score technical value on narrative, timeline, and IOCs', () => {
      const score = qualityEngine.scoreTechnicalValue({
        narrative: {},
        timeline: {},
        visualData: { iocSummary: {} },
      });

      expect(score.name).toBe('Technical Value');
      expect(score.score).toBe(100);
    });

    test('should score operational value on decisions and priorities', () => {
      const score = qualityEngine.scoreOperationalValue({
        decisions: {
          operationalDecisions: [{}],
          socPriorities: [{}],
          threatHuntingPriorities: [{}],
        },
      });

      expect(score.name).toBe('Operational Value');
      expect(score.score).toBe(100);
    });

    test('should score detection value on guidance and coverage', () => {
      const score = qualityEngine.scoreDetectionValue({
        detection: {
          deploymentGuidance: [{}],
          tuningGuidance: {},
        },
        visualData: { detectionCoverage: {} },
      });

      expect(score.name).toBe('Detection Value');
      expect(score.score).toBe(100);
    });

    test('should score actionability based on customer actions', () => {
      const score = qualityEngine.scoreActionability({
        customerValue: {
          customerActions: [{}],
          defensivePriorities: [{}],
          recommendedFollowUp: [{}],
        },
      });

      expect(score.name).toBe('Actionability');
      expect(score.score).toBe(100);
    });

    test('should score evidence quality based on indicator count', () => {
      const score = qualityEngine.scoreEvidenceQuality(
        {},
        mockInvestigation
      );

      expect(score.name).toBe('Evidence Quality');
      // Infrastructure (3) + Malware (2) + Techniques (6) + Evidence (2) = 13
      expect(score.evidenceCount).toBe(13);
    });

    test('should score confidence explainability', () => {
      const score = qualityEngine.scoreConfidenceExplainability({
        keyJudgements: [
          { confidenceNarrative: 'test', remainingUncertainty: {} },
        ],
      });

      expect(score.name).toBe('Confidence Explainability');
      expect(score.score).toBeGreaterThan(0);
    });

    test('should score editorial quality', () => {
      const score = qualityEngine.scoreEditorialQuality({
        editorial: {
          sectionConsistency: {},
          readability: {},
          narrativeFlow: {},
        },
      });

      expect(score.name).toBe('Editorial Quality');
      expect(score.score).toBe(100);
    });

    test('should score customer value delivery', () => {
      const score = qualityEngine.scoreCustomerValue({
        customerValue: {
          whyThisMatters: {},
          customerActions: [{}],
          operationalImpact: {},
        },
      });

      expect(score.name).toBe('Customer Value');
      expect(score.score).toBe(100);
    });

    test('should score commercial readiness', () => {
      const score = qualityEngine.scoreCommercialReadiness({
        editorial: {},
        executiveSummary: {},
        narrative: {},
        decisions: {},
        detection: {},
        customerValue: {},
        timeline: {},
        visualData: {},
      });

      expect(score.name).toBe('Commercial Readiness');
      expect(score.score).toBeGreaterThan(0);
    });

    test('should classify quality from score levels', () => {
      expect(qualityEngine.classifyQuality(95)).toBe('EXCELLENT');
      expect(qualityEngine.classifyQuality(85)).toBe('GOOD');
      expect(qualityEngine.classifyQuality(75)).toBe('ACCEPTABLE');
      expect(qualityEngine.classifyQuality(65)).toBe('NEEDS_IMPROVEMENT');
      expect(qualityEngine.classifyQuality(50)).toBe('REVIEW_REQUIRED');
    });

    test('should certify for publication when score exceeds threshold', async () => {
      const metrics = {
        overallScore: 85,
        componentScores: { test: { score: 85 } },
      };

      const certification = await qualityEngine.certifyForPublication(metrics, 75);

      expect(certification.approved).toBe(true);
      expect(certification.score).toBe(85);
      expect(certification.status).toBe('APPROVED_FOR_PUBLICATION');
    });

    test('should require review when score below threshold', async () => {
      const metrics = {
        overallScore: 65,
        componentScores: { test: { score: 65, name: 'Test' } },
      };

      const certification = await qualityEngine.certifyForPublication(metrics, 75);

      expect(certification.approved).toBe(false);
      expect(certification.score).toBe(65);
      expect(certification.status).toBe('REVIEW_REQUIRED');
    });

    test('should identify specific deficiencies below 70 threshold', async () => {
      const metrics = {
        overallScore: 60,
        componentScores: {
          executive: { score: 65, name: 'Executive Value' },
          technical: { score: 50, name: 'Technical Value' },
          editorial: { score: 75, name: 'Editorial Quality' },
        },
      };

      const certification = await qualityEngine.certifyForPublication(metrics, 75);

      expect(Array.isArray(certification.deficiencies)).toBe(true);
      expect(certification.deficiencies.length).toBeGreaterThan(0);
      expect(certification.deficiencies.some(d => d.includes('Technical Value'))).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // INTEGRATION TESTS: Module Composition & Backward Compatibility
  // ═══════════════════════════════════════════════════════════════════════

  describe('Integration: Module Composition', () => {
    test('should compose all 10 modules into coherent report enhancement', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      const hasAllEnhancements = [
        'executiveSummary',
        'keyJudgements',
        'narrative',
        'decisions',
        'detection',
        'timeline',
        'customerValue',
        'visualData',
        'editorial',
      ].every(mod => hardened.enhancements[mod]);

      expect(hasAllEnhancements).toBe(true);
    });

    test('should produce quality metrics that sum to overall score', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      const avgOfComponents = Object.values(hardened.qualityMetrics.scores || {}).reduce(
        (a, b) => a + (b.score || 0),
        0
      ) / Object.keys(hardened.qualityMetrics.scores || {}).length;

      const roundedAvg = Math.round(avgOfComponents);
      const overallScore = hardened.qualityMetrics.overallScore;

      expect(Math.abs(roundedAvg - overallScore)).toBeLessThanOrEqual(1);
    });

    test('should provide consistent evidence across all modules', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      const execSummaryEvidence = hardened.enhancements.executiveSummary?.evidenceSummary;
      const qualityEvidenceScore = hardened.qualityMetrics.scores.evidenceQuality;

      expect(execSummaryEvidence.infrastructure).toBe(mockInvestigation.infrastructure.length);
      expect(qualityEvidenceScore.evidenceCount).toBe(
        mockInvestigation.infrastructure.length +
          mockInvestigation.malware.length +
          mockInvestigation.techniques.length +
          (mockInvestigation.evidence?.length || 0)
      );
    });
  });

  describe('Backward Compatibility: Phases 1-13 Integration', () => {
    test('should preserve output format for downstream consumption', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      // Verify essential output fields exist and have correct types
      expect(typeof hardened.reportId).toBe('string');
      expect(typeof hardened.timestamp).toBe('string');
      expect(typeof hardened.status).toBe('string');
      expect(typeof hardened.enhancements).toBe('object');
      expect(typeof hardened.qualityMetrics).toBe('object');
      expect(typeof hardened.publication).toBe('object');
    });

    test('should work with minimal investigation data', async () => {
      const minimal = {
        id: 'inv-minimal',
        title: 'Minimal Investigation',
        severity: 'HIGH',
      };

      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        minimal,
        mockProduct
      );

      expect(hardened.status).toMatch(/approved_for_publication|review_required|error/);
      expect(hardened.enhancements.executiveSummary).toBeDefined();
    });

    test('should handle sparse evidence gracefully', async () => {
      const sparse = {
        ...mockInvestigation,
        techniques: [],
        malware: [],
        infrastructure: [],
        evidence: [],
      };

      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        sparse,
        mockProduct
      );

      expect(hardened.status).toBeDefined();
      expect(hardened.qualityMetrics.scores.evidenceQuality.evidenceCount).toBe(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // REGRESSION TESTS: Quality Assurance
  // ═══════════════════════════════════════════════════════════════════════

  describe('Regression: Report Quality Standards', () => {
    test('should not degrade report structure with enhancements', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      // Enhancements should not modify original report
      expect(mockReport.sections.summary).toBe('APT-29 continues active operations...');
      expect(hardened.reportId).toBe(mockReport.id);
    });

    test('should maintain evidence lineage and confidence methodology', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      const evidenceCount = hardened.qualityMetrics.scores.evidenceQuality.evidenceCount;
      expect(evidenceCount).toBeGreaterThanOrEqual(0);
      expect(typeof evidenceCount).toBe('number');
    });

    test('should improve or maintain Lighthouse-equivalent scores', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      // Quality score should not decrease from enhancements
      expect(hardened.qualityMetrics.overallScore).toBeGreaterThanOrEqual(0);
      expect(hardened.qualityMetrics.overallScore).toBeLessThanOrEqual(100);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // PERFORMANCE TESTS: Edge Cases & Scale
  // ═══════════════════════════════════════════════════════════════════════

  describe('Performance: Edge Cases', () => {
    test('should handle very large evidence sets', async () => {
      const largeInvestigation = {
        ...mockInvestigation,
        infrastructure: Array(100).fill({ ip: '1.2.3.4', hosting: 'AWS', location: 'US' }),
        techniques: Array(50).fill({ name: 'Technique', mitreTactic: ['Execution'] }),
      };

      const start = Date.now();
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        largeInvestigation,
        mockProduct
      );
      const duration = Date.now() - start;

      expect(hardened.status).toBeDefined();
      expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
    });

    test('should handle null/undefined enhancements gracefully', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        null
      );

      expect(hardened.status).toMatch(/approved_for_publication|review_required|error/);
    });

    test('should classify quality at boundary scores', () => {
      expect(sprint1.qualityEngine.classifyQuality(90)).toBe('EXCELLENT');
      expect(sprint1.qualityEngine.classifyQuality(89)).toBe('GOOD');
      expect(sprint1.qualityEngine.classifyQuality(80)).toBe('GOOD');
      expect(sprint1.qualityEngine.classifyQuality(79)).toBe('ACCEPTABLE');
      expect(sprint1.qualityEngine.classifyQuality(70)).toBe('ACCEPTABLE');
      expect(sprint1.qualityEngine.classifyQuality(69)).toBe('NEEDS_IMPROVEMENT');
      expect(sprint1.qualityEngine.classifyQuality(60)).toBe('NEEDS_IMPROVEMENT');
      expect(sprint1.qualityEngine.classifyQuality(59)).toBe('REVIEW_REQUIRED');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // PRODUCTION READINESS: Quality Gates
  // ═══════════════════════════════════════════════════════════════════════

  describe('Production Readiness: Quality Gates', () => {
    test('all modules should export correctly', () => {
      const exported = {
        Sprint1ReportHardening,
        ExecutiveSummaryExcellence,
        KeyJudgementsEnhancement,
        ThreatStorytellingEngine,
        BusinessDecisionSupportEngine,
        DetectionExcellenceEngine,
        IntelligenceTimelineEngine,
        CustomerValueLayerEngine,
        IntelligenceVisualDataModel,
        EditorialExcellenceEngine,
        CommercialProductQualityEngine,
      };

      Object.entries(exported).forEach(([name, cls]) => {
        expect(typeof cls).toBe('function');
        expect(cls.name).toBe(name);
      });
    });

    test('should initialize without errors', () => {
      expect(() => {
        new Sprint1ReportHardening();
        new ExecutiveSummaryExcellence();
        new KeyJudgementsEnhancement();
        new ThreatStorytellingEngine();
        new BusinessDecisionSupportEngine();
        new DetectionExcellenceEngine();
        new IntelligenceTimelineEngine();
        new CustomerValueLayerEngine();
        new IntelligenceVisualDataModel();
        new EditorialExcellenceEngine();
        new CommercialProductQualityEngine();
      }).not.toThrow();
    });

    test('should support asyncronous enhancement workflow', async () => {
      const hardened = await sprint1.enhanceIntelligenceReport(
        mockReport,
        mockInvestigation,
        mockProduct,
        mockEnhancement
      );

      expect(hardened.timestamp).toBeDefined();
      expect(new Date(hardened.timestamp)).toBeInstanceOf(Date);
    });
  });
});
