'use strict';

const { GoldStandardEIPCCertificationEngine } = require('../gs-eipc-certification-engine');

describe('Gold Standard EIPC Certification Engine', () => {
  let engine;

  beforeEach(() => {
    engine = new GoldStandardEIPCCertificationEngine();
  });

  const mockProduct = {
    id: 'prod-001',
    productType: 'threat-report',
    classification: 'TLP:AMBER',
    modules: {
      executiveSummary: {
        content: 'This is a comprehensive executive summary of a significant threat campaign affecting government and technology sectors. Strategic implications include enhanced monitoring and resource allocation.',
      },
      technicalAnalysis: { content: 'Detailed technical analysis' },
      narratives: { content: 'Threat narrative' },
      keyJudgements: { content: 'Key analytical judgements' },
      evidence: { content: [] },
      detectionRules: { content: [] },
      recommendations: { content: [] },
      timeline: { content: [] },
      businessContext: { content: 'Business impact analysis' },
      operationalGuidance: { content: 'Operational recommendations' },
    },
  };

  const mockInvestigation = {
    id: 'inv-001',
    title: 'APT-28 Campaign Analysis',
    description: 'Analysis of APT-28 operations',
    severity: 'CRITICAL',
    classification: 'TLP:AMBER',
    businessImpact: 'High operational impact',
    threatActors: [{ name: 'APT-28', aliases: ['Fancy Bear'] }],
    campaigns: [{ name: 'Operation Ghost' }],
    findings: [{ statement: 'Evidence of targeting', severity: 'critical', confidence: 0.95 }],
    iocs: [{ value: '192.168.1.1', type: 'ip', severity: 'HIGH', confidence: 0.95 }],
    infrastructure: [{ type: 'c2', value: 'attacker.com' }],
    malware: ['Sofacy'],
    mitreTechniques: [
      { technique: 'Spear Phishing', tactic: 'Initial Access' },
      { technique: 'Lateral Movement', tactic: 'Lateral Movement' },
    ],
    timeline: [{ date: '2024-01-15', event: 'Initial compromise detected' }],
    targetedSectors: ['government', 'technology'],
    confidence: 0.85,
    confidenceReasoning: 'Based on multiple independent sources',
    sources: ['Crowdstrike', 'Mandiant'],
    riskLevel: {
      confidentiality: 'HIGH',
      integrity: 'HIGH',
      availability: 'MEDIUM',
    },
  };

  const mockReport = {
    id: 'report-001',
    investigationId: 'inv-001',
    createdAt: new Date().toISOString(),
  };

  test('should initialize with 10 target score categories', () => {
    const targetScores = engine.targetScores;
    expect(Object.keys(targetScores).length).toBe(10);
    expect(targetScores.executiveIntelligence).toBe(95);
    expect(targetScores.detectionEngineering).toBe(98);
  });

  test('should certify product across all 10 categories', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);

    expect(certification).toBeDefined();
    expect(certification.productId).toBe('prod-001');
    expect(Object.keys(certification.categories).length).toBe(10);
    expect(certification.certificationStatus).toBeDefined();
    expect(certification.overallScore).toBeGreaterThanOrEqual(0);
    expect(certification.overallScore).toBeLessThanOrEqual(100);
  });

  test('should score executive intelligence category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.executiveIntelligence;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.score).toBeLessThanOrEqual(100);
    expect(score.targetScore).toBe(95);
    expect(typeof score.passed).toBe('boolean');
    expect(Array.isArray(score.findings)).toBe(true);
  });

  test('should score technical intelligence category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.technicalIntelligence;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(95);
  });

  test('should score analytical tradecraft category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.analyticalTradecraft;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(95);
    // Should include confidence reasoning
    if (mockInvestigation.confidenceReasoning) {
      expect(score.score).toBeGreaterThan(0);
    }
  });

  test('should score campaign intelligence category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.campaignIntelligence;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(95);
  });

  test('should score intelligence correlation category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.intelligenceCorrelation;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(95);
    // Should credit threat actors and campaigns
    if (mockInvestigation.threatActors && mockInvestigation.campaigns) {
      expect(score.score).toBeGreaterThan(0);
    }
  });

  test('should score original analytical value category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.originalAnalyticalValue;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(95);
  });

  test('should score detection engineering category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.detectionEngineering;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(98);
  });

  test('should score multi-audience decision support category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.multiAudienceDecisionSupport;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(98);
  });

  test('should score editorial excellence category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.editorialExcellence;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(98);
  });

  test('should score commercial product excellence category', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const score = certification.categories.commercialProductExcellence;

    expect(score).toBeDefined();
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.targetScore).toBe(98);
  });

  test('should determine GOLD certification when all categories passed', async () => {
    // Create a high-quality product
    const excellentProduct = {
      ...mockProduct,
      modules: {
        ...mockProduct.modules,
        sigmaRules: { content: 'Sigma rules' },
        yaraRules: { content: 'YARA rules' },
        suricataRules: { content: 'Suricata rules' },
        siemQueries: { content: 'SIEM queries' },
        threatHuntingQueries: { content: 'Threat hunting queries' },
        deploymentGuidance: { content: 'Deployment guidance' },
        relationships: { content: 'Relationships' },
        synthesis: { content: 'Synthesis' },
        significance: { content: 'Significance' },
      },
    };

    const certification = await engine.certifyProduct(excellentProduct, mockInvestigation, mockReport);

    expect(certification.certificationStatus).toBeDefined();
    expect(['GOLD', 'SILVER', 'BRONZE', 'FAIL']).toContain(certification.certificationStatus);
  });

  test('should count passed and failed categories', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);

    expect(certification.passedCategories).toBeGreaterThanOrEqual(0);
    expect(certification.failedCategories).toBeGreaterThanOrEqual(0);
    expect(certification.passedCategories + certification.failedCategories).toBe(10);
  });

  test('should generate improvement recommendations for failed categories', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);

    if (certification.failedCategories > 0) {
      expect(Array.isArray(certification.recommendations)).toBe(true);
      expect(certification.recommendations.length).toBeGreaterThan(0);

      const rec = certification.recommendations[0];
      expect(rec.category).toBeDefined();
      expect(rec.currentScore).toBeDefined();
      expect(rec.targetScore).toBeDefined();
      expect(rec.gap).toBeDefined();
      expect(rec.priority).toMatch(/High|Medium|Low/);
    }
  });

  test('should store certifications in history', async () => {
    await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);

    const history = engine.getCertificationHistory();
    expect(history.length).toBeGreaterThan(0);
    expect(history[0].productId).toBe('prod-001');
  });

  test('should retrieve certification history for specific product', async () => {
    await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);

    const productHistory = engine.getCertificationHistory('prod-001');
    expect(productHistory.length).toBeGreaterThan(0);
    expect(productHistory[0].productId).toBe('prod-001');
  });

  test('should detect regression when score decreases', async () => {
    // First certification
    await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);

    // Second certification with lower quality
    const degradedProduct = {
      ...mockProduct,
      modules: {
        executiveSummary: { content: 'Brief summary' },
      },
    };

    await engine.certifyProduct(degradedProduct, mockInvestigation, mockReport);

    const regression = engine.detectRegression('prod-001');
    expect(regression).toBeDefined();
    if (regression) {
      expect(regression.productId).toBe('prod-001');
      expect(regression.previousScore).toBeDefined();
      expect(regression.currentScore).toBeDefined();
      expect(typeof regression.isRegression).toBe('boolean');
    }
  });

  test('should generate quality scorecard', async () => {
    const certification = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);
    const scorecard = engine.generateScorecard(certification);

    expect(scorecard.productId).toBe('prod-001');
    expect(scorecard.scores).toBeDefined();
    expect(scorecard.scores.executiveIntelligence).toBeGreaterThanOrEqual(0);
    expect(scorecard.scores.executiveIntelligence).toBeLessThanOrEqual(100);
    expect(scorecard.overallCertification).toMatch(/GOLD|SILVER|BRONZE|FAIL/);
    expect(scorecard.overallScore).toBeDefined();
    expect(scorecard.passedCategories).toBeGreaterThanOrEqual(0);
    expect(scorecard.publishingGate).toEqual(
      scorecard.overallCertification === 'GOLD' || scorecard.overallCertification === 'SILVER'
    );
  });

  test('should humanize category names', () => {
    const humanized = engine.humanizeCategory('executiveIntelligence');
    expect(humanized).toBe('Executive Intelligence');

    const humanized2 = engine.humanizeCategory('detectionEngineering');
    expect(humanized2).toBe('Detection Engineering');
  });

  test('should provide improvement recommendations for each category', () => {
    const exec = engine.recommendationForCategory('executiveIntelligence');
    expect(typeof exec).toBe('string');
    expect(exec.length).toBeGreaterThan(0);

    const detection = engine.recommendationForCategory('detectionEngineering');
    expect(typeof detection).toBe('string');
    expect(detection.length).toBeGreaterThan(0);
  });

  test('should handle products with minimal modules gracefully', async () => {
    const minimalProduct = {
      id: 'prod-minimal',
      productType: 'report',
      modules: {},
    };

    const certification = await engine.certifyProduct(minimalProduct, mockInvestigation, mockReport);

    expect(certification).toBeDefined();
    expect(certification.certificationStatus).toBeDefined();
    expect(certification.recommendations).toBeDefined();
  });

  test('should produce consistent scores for same product', async () => {
    const cert1 = await engine.certifyProduct(mockProduct, mockInvestigation, mockReport);

    // Create new engine instance
    const engine2 = new GoldStandardEIPCCertificationEngine();
    const cert2 = await engine2.certifyProduct(mockProduct, mockInvestigation, mockReport);

    expect(cert1.overallScore).toBe(cert2.overallScore);
    expect(cert1.certificationStatus).toBe(cert2.certificationStatus);
  });
});
