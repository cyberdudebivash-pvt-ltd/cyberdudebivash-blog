'use strict';

const { GoldStandardPublicationGate } = require('../gs-publication-gate');

describe('Gold Standard Publication Gate', () => {
  let gate;

  beforeEach(() => {
    gate = new GoldStandardPublicationGate();
  });

  const mockProduct = {
    id: 'prod-001',
    productType: 'threat-report',
    classification: 'TLP:AMBER',
    modules: {
      executiveSummary: {
        content: 'This is a comprehensive executive summary of a significant threat campaign.',
      },
      technicalAnalysis: { content: 'Detailed technical analysis' },
      narratives: { content: 'Threat narrative' },
      keyJudgements: { content: 'Key analytical judgements' },
      evidence: { content: [] },
      recommendations: { content: [] },
      detectionRules: { content: [] },
      immediateActions: { content: [] },
    },
  };

  const mockInvestigation = {
    id: 'inv-001',
    title: 'APT-28 Campaign Analysis',
    severity: 'CRITICAL',
    classification: 'TLP:AMBER',
    businessImpact: 'High operational impact',
    threatActors: [{ name: 'APT-28' }],
    campaigns: [{ name: 'Operation Ghost' }],
    findings: [
      { statement: 'Evidence of targeting', severity: 'critical', confidence: 0.95 },
      { statement: 'Malware detected', severity: 'critical', confidence: 0.90 },
      { statement: 'Network compromise', severity: 'high', confidence: 0.85 },
    ],
    iocs: [
      { value: '192.168.1.1', type: 'ip', severity: 'HIGH', confidence: 0.95 },
      { value: 'attacker.com', type: 'domain', severity: 'HIGH', confidence: 0.90 },
    ],
    infrastructure: [{ type: 'c2', value: 'attacker.com' }],
    malware: ['Sofacy'],
    mitreTechniques: [
      { technique: 'Spear Phishing', tactic: 'Initial Access' },
      { technique: 'Lateral Movement', tactic: 'Lateral Movement' },
    ],
    timeline: [{ date: '2024-01-15', event: 'Initial compromise detected' }],
    targetedSectors: ['government', 'technology'],
    confidence: 0.85,
    confidenceReasoning: 'Based on multiple independent sources and corroborating evidence',
    sources: ['Crowdstrike', 'Mandiant'],
    assumptionsDocumented: true,
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

  test('should initialize publication gate with certification engine and metrics tracker', () => {
    expect(gate.certificationEngine).toBeDefined();
    expect(gate.metricsTracker).toBeDefined();
  });

  test('should evaluate product for publication', async () => {
    const evaluation = await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    expect(evaluation).toBeDefined();
    expect(evaluation.productId).toBe('prod-001');
    expect(evaluation.timestamp).toBeDefined();
    expect(evaluation.certified).toEqual(expect.any(Boolean));
    expect(evaluation.approved).toEqual(expect.any(Boolean));
    expect(evaluation.certification).toBeDefined();
    expect(Array.isArray(evaluation.gateResults)).toBe(true);
    expect(Array.isArray(evaluation.blockers)).toBe(true);
  });

  test('should validate certification status', async () => {
    const evaluation = await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const certGate = evaluation.gateResults.find(g => g.gate === 'gold-standard-certification');
    expect(certGate).toBeDefined();
    expect(certGate.passed).toEqual(expect.any(Boolean));
    expect(certGate.details).toBeDefined();
  });

  test('should validate evidence integrity', async () => {
    const evaluation = await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const evidenceGate = evaluation.gateResults.find(g => g.gate === 'evidence-integrity');
    expect(evidenceGate).toBeDefined();
    expect(evidenceGate.passed).toEqual(expect.any(Boolean));
    expect(evidenceGate.details).toBeDefined();
    expect(evidenceGate.details.total).toBeGreaterThanOrEqual(0);
  });

  test('should validate confidence preservation', async () => {
    const evaluation = await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const confidenceGate = evaluation.gateResults.find(g => g.gate === 'confidence-preservation');
    expect(confidenceGate).toBeDefined();
    expect(confidenceGate.passed).toEqual(expect.any(Boolean));
  });

  test('should validate analytical rigor', async () => {
    const evaluation = await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const analyticalGate = evaluation.gateResults.find(g => g.gate === 'analytical-rigor');
    expect(analyticalGate).toBeDefined();
    expect(analyticalGate.passed).toEqual(expect.any(Boolean));
  });

  test('should validate commercial readiness', async () => {
    const evaluation = await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const commercialGate = evaluation.gateResults.find(g => g.gate === 'commercial-readiness');
    expect(commercialGate).toBeDefined();
    expect(commercialGate.passed).toEqual(expect.any(Boolean));
  });

  test('should reject product with insufficient evidence', async () => {
    const poorInvestigation = {
      ...mockInvestigation,
      findings: [],
      iocs: [],
      infrastructure: [],
    };

    const evaluation = await gate.evaluateProductForPublication(mockProduct, poorInvestigation, mockReport);

    const evidenceGate = evaluation.gateResults.find(g => g.gate === 'evidence-integrity');
    expect(evidenceGate.passed).toBe(false);
    expect(evaluation.blockers.some(b => b.includes('evidence'))).toBe(true);
  });

  test('should reject product with missing confidence reasoning', async () => {
    const poorInvestigation = {
      ...mockInvestigation,
      confidence: 0.85,
      confidenceReasoning: null,
    };

    const evaluation = await gate.evaluateProductForPublication(mockProduct, poorInvestigation, mockReport);

    const confidenceGate = evaluation.gateResults.find(g => g.gate === 'confidence-preservation');
    expect(confidenceGate.passed).toBe(false);
  });

  test('should generate improvement recommendations for blocked products', async () => {
    const poorInvestigation = {
      id: 'inv-002',
      title: 'Poor Quality Report',
      findings: [],
      iocs: [],
      infrastructure: [],
      confidence: 0,
    };

    const evaluation = await gate.evaluateProductForPublication(mockProduct, poorInvestigation, mockReport);

    if (!evaluation.approved) {
      expect(Array.isArray(evaluation.recommendations)).toBe(true);
    }
  });

  test('should track published products', async () => {
    await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const metrics = gate.getPublicationMetrics();
    expect(metrics).toBeDefined();
    expect(typeof metrics.publishedProducts).toBe('number');
    expect(typeof metrics.blockedProducts).toBe('number');
  });

  test('should track blocked products with reasons', async () => {
    const poorInvestigation = {
      ...mockInvestigation,
      findings: [],
      iocs: [],
    };

    await gate.evaluateProductForPublication(mockProduct, poorInvestigation, mockReport);

    const metrics = gate.getPublicationMetrics();
    if (metrics.blockedProducts > 0) {
      expect(metrics.recentBlockages.length).toBeGreaterThan(0);
    }
  });

  test('should provide gate metrics', async () => {
    await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const metrics = gate.getGateMetrics();
    expect(metrics).toBeDefined();
    expect(metrics.metricsSnapshot).toBeDefined();
    expect(metrics.publishingGateStatus).toBeDefined();
    expect(metrics.executiveSummary).toBeDefined();
  });

  test('should calculate publishing rate', async () => {
    // Publish one approved product
    await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const metrics = gate.getPublicationMetrics();
    expect(typeof metrics.publishingRate).toBe('number');
    expect(metrics.publishingRate).toBeGreaterThanOrEqual(0);
    expect(metrics.publishingRate).toBeLessThanOrEqual(100);
  });

  test('should integrate with metrics tracker', async () => {
    await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const metrics = gate.metricsTracker.getAggregateMetrics();
    expect(metrics.productCount).toBeGreaterThan(0);
  });

  test('should provide regression detection via metrics tracker', async () => {
    // First certification
    await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const regressionReport = gate.metricsTracker.getRegressionReport();
    expect(regressionReport).toBeDefined();
    expect(typeof regressionReport.totalRegressions).toBe('number');
  });

  test('should provide improvement opportunities', async () => {
    await gate.evaluateProductForPublication(mockProduct, mockInvestigation, mockReport);

    const improvementReport = gate.metricsTracker.getImprovementReport();
    expect(improvementReport).toBeDefined();
    expect(Array.isArray(improvementReport.categoryImprovements)).toBe(true);
  });

  test('should handle products with minimal modules', async () => {
    const minimalProduct = {
      id: 'prod-minimal',
      productType: 'report',
      modules: {},
    };

    const evaluation = await gate.evaluateProductForPublication(minimalProduct, mockInvestigation, mockReport);

    expect(evaluation).toBeDefined();
    expect(evaluation.approved).toEqual(expect.any(Boolean));
  });
});
