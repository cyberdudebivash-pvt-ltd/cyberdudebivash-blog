'use strict';

const { SentinelApexEIXPresentationEngine } = require('../sa-eix-presentation-engine');

describe('Sentinel APEX Enterprise Intelligence Experience (SA-EIX) Presentation Engine', () => {
  let engine;

  beforeEach(() => {
    engine = new SentinelApexEIXPresentationEngine();
  });

  const mockProduct = {
    id: 'prod-apt28-2026-07-31',
    productType: 'threat-report',
    classification: 'TLP:AMBER',
    modules: {
      executiveSummary: {
        content: 'Comprehensive executive summary of APT-28 campaign',
        threatLevel: 'CRITICAL',
      },
      technicalAnalysis: {
        content: 'Detailed technical analysis',
        depth: 'Advanced',
      },
      narratives: { content: 'Threat narrative' },
      keyJudgements: { content: 'Key analytical judgements' },
      evidence: { items: [] },
      recommendations: { items: [] },
      detectionRules: { items: [] },
      immediateActions: { items: [] },
    },
  };

  const mockInvestigation = {
    id: 'inv-apt28-2026-07-31',
    title: 'APT-28 Campaign Analysis',
    severity: 'CRITICAL',
    classification: 'TLP:AMBER',
    businessImpact: 'High operational impact',
    threatActors: [{ name: 'APT-28', confidence: 0.95 }],
    campaigns: [
      { name: 'Operation Ghost', startDate: '2026-01-15', endDate: '2026-07-31' },
    ],
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
    timeline: [
      { date: '2026-01-15', event: 'Initial compromise detected' },
      { date: '2026-07-31', event: 'Campaign ongoing' },
    ],
    targetedSectors: ['government', 'technology'],
    targetedRegions: ['US', 'EU', 'NATO'],
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
    id: 'report-apt28-2026-07-31',
    investigationId: 'inv-apt28-2026-07-31',
    createdAt: new Date().toISOString(),
  };

  // ==================== INITIALIZATION TESTS ====================

  test('should initialize with branding configuration', () => {
    expect(engine.brandingConfig).toBeDefined();
    expect(engine.brandingConfig.name).toBe('Sentinel APEX');
    expect(engine.brandingConfig.colors).toBeDefined();
    expect(engine.brandingConfig.colors.primary).toBe('#0A3A5C');
    expect(engine.brandingConfig.typography).toBeDefined();
  });

  test('should initialize with layout configuration', () => {
    expect(engine.layoutConfig).toBeDefined();
    expect(engine.layoutConfig.coverPage).toBe(true);
    expect(engine.layoutConfig.dashboardHeader).toBe(true);
    expect(engine.layoutConfig.decisionCenter).toBe(true);
  });

  test('should initialize with empty presentation cache', () => {
    expect(engine.presentationCache).toBeDefined();
    expect(engine.presentationCache.size).toBe(0);
  });

  // ==================== PRESENTATION ENHANCEMENT TESTS ====================

  test('should enhance intelligence product with all presentation layers', async () => {
    const enhancement = await engine.enhanceIntelligenceProduct(mockProduct, mockInvestigation, mockReport);

    expect(enhancement).toBeDefined();
    expect(enhancement.productId).toBe('prod-apt28-2026-07-31');
    expect(enhancement.originalProduct).toEqual(mockProduct);
    expect(enhancement.presentationEnhancements).toBeDefined();
    expect(enhancement.metadata).toBeDefined();
    expect(enhancement.metadata.presentationVersion).toBe('1.0');
  });

  test('should generate enterprise cover page', async () => {
    const coverPage = await engine.generateEnterpriseCoverPage(mockProduct, mockInvestigation, mockReport);

    expect(coverPage).toBeDefined();
    expect(coverPage.type).toBe('enterprise-cover');
    expect(coverPage.sections).toBeDefined();
    expect(coverPage.sections.header).toBeDefined();
    expect(coverPage.sections.header.threatScore).toBeGreaterThanOrEqual(0);
    expect(coverPage.sections.header.threatScore).toBeLessThanOrEqual(100);
    expect(coverPage.sections.header.classification).toBe('TLP:AMBER');
  });

  test('should generate SOC dashboard header with operational widgets', async () => {
    const dashboard = await engine.generateSOCDashboardHeader(mockProduct, mockInvestigation);

    expect(dashboard).toBeDefined();
    expect(dashboard.type).toBe('soc-dashboard-header');
    expect(dashboard.widgets).toBeDefined();
    expect(Array.isArray(dashboard.widgets)).toBe(true);
    expect(dashboard.widgets.length).toBe(8);

    const widgetNames = dashboard.widgets.map(w => w.name);
    expect(widgetNames).toContain('Threat Level');
    expect(widgetNames).toContain('Confidence');
    expect(widgetNames).toContain('Business Risk');
  });

  test('should generate executive intelligence cards', async () => {
    const cards = await engine.generateExecutiveIntelligenceCards(mockProduct, mockInvestigation);

    expect(cards).toBeDefined();
    expect(Array.isArray(cards)).toBe(true);
    expect(cards.length).toBeGreaterThan(0);

    const cardCategories = cards.map(c => c.category);
    expect(cardCategories).toContain('threat-summary');
    expect(cardCategories).toContain('business-impact');
  });

  test('should generate evidence gallery with categorized findings', async () => {
    const gallery = await engine.generateEvidenceGallery(mockProduct, mockInvestigation);

    expect(gallery).toBeDefined();
    expect(gallery.type).toBe('evidence-gallery');
    expect(gallery.sections).toBeDefined();
    expect(Array.isArray(gallery.sections)).toBe(true);

    const sectionTitles = gallery.sections.map(s => s.title);
    expect(sectionTitles).toContain('Key Findings');
    expect(sectionTitles).toContain('Indicators of Compromise');
  });

  test('should generate interactive diagrams with attack flow data', async () => {
    const diagrams = await engine.generateInteractiveDiagrams(mockProduct, mockInvestigation);

    expect(diagrams).toBeDefined();
    expect(diagrams.type).toBe('interactive-diagrams');
    expect(Array.isArray(diagrams.diagrams)).toBe(true);
    expect(diagrams.diagrams.length).toBeGreaterThan(0);

    const diagramTypes = diagrams.diagrams.map(d => d.type);
    expect(diagramTypes).toContain('kill-chain');
  });

  test('should generate executive decision center for multiple audiences', async () => {
    const decisionCenter = await engine.generateExecutiveDecisionCenter(mockProduct, mockInvestigation);

    expect(decisionCenter).toBeDefined();
    expect(decisionCenter.audiences).toBeDefined();
    expect(Object.keys(decisionCenter.audiences).length).toBeGreaterThan(0);
  });

  test('should generate responsive layout configuration', () => {
    const enhancement = {
      presentationEnhancements: {},
    };
    const layout = engine.generateResponsiveLayout(enhancement);

    expect(layout).toBeDefined();
    expect(layout.type).toBe('responsive-layout');
    expect(layout.breakpoints).toBeDefined();
    expect(layout.themes).toBeDefined();
    expect(layout.printStyles).toBeDefined();
  });

  // ==================== THREAT SCORING TESTS ====================

  test('should calculate threat score from investigation data', () => {
    const score = engine.calculateThreatScore(mockInvestigation);

    expect(typeof score).toBe('number');
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  test('should assign threat level based on score', () => {
    const level = engine.getThreatLevel(85);

    expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).toContain(level);
  });

  test('should calculate business risk score', () => {
    const riskScore = engine.calculateBusinessRiskScore(mockInvestigation);

    expect(typeof riskScore).toBe('number');
    expect(riskScore).toBeGreaterThanOrEqual(0);
    expect(riskScore).toBeLessThanOrEqual(100);
  });

  // ==================== COLOR AND STYLING TESTS ====================

  test('should return appropriate color for threat level', () => {
    const colorCritical = engine.getThreatLevelColor('CRITICAL');
    const colorLow = engine.getThreatLevelColor('LOW');

    expect(typeof colorCritical).toBe('string');
    expect(typeof colorLow).toBe('string');
    expect(colorCritical).not.toEqual(colorLow);
  });

  test('should return appropriate color for risk level', () => {
    const colorHigh = engine.getRiskColor('HIGH');

    expect(typeof colorHigh).toBe('string');
    expect(colorHigh).toBeDefined();
  });

  // ==================== EVIDENCE ANALYSIS TESTS ====================

  test('should analyze evidence coverage from investigation', () => {
    const coverage = engine.analyzeEvidenceCoverage(mockInvestigation);

    expect(coverage).toBeDefined();
    expect(typeof coverage.findingsCount).toBe('number');
    expect(typeof coverage.iocsCount).toBe('number');
    expect(typeof coverage.infrastructureCount).toBe('number');
    expect(coverage.totalEvidence).toBeGreaterThan(0);
  });

  test('should calculate detection coverage from MITRE techniques', () => {
    const coverage = engine.calculateDetectionCoverage(mockInvestigation);

    expect(typeof coverage).toBe('number');
    expect(coverage).toBeGreaterThanOrEqual(0);
    expect(coverage).toBeLessThanOrEqual(100);
  });

  // ==================== TIMELINE TESTS ====================

  test('should format timeline from investigation data', () => {
    const timeline = engine.formatTimelineData(mockInvestigation);

    expect(Array.isArray(timeline)).toBe(true);
    expect(timeline.length).toBeGreaterThan(0);

    const firstEvent = timeline[0];
    expect(firstEvent.date).toBeDefined();
    expect(firstEvent.event).toBeDefined();
  });

  test('should calculate timeline span', () => {
    const span = engine.calculateTimelineSpan(mockInvestigation);

    expect(typeof span).toBe('string');
  });

  // ==================== AUDIENCE-SPECIFIC TESTS ====================

  test('should generate CEO-focused decision guidance', () => {
    const guidance = engine.generateAudienceGuidance('ceo', mockInvestigation);

    expect(guidance).toBeDefined();
    expect(Array.isArray(guidance.decisions)).toBe(true);
    expect(Array.isArray(guidance.metrics)).toBe(true);
  });

  test('should generate CISO-focused decision guidance', () => {
    const guidance = engine.generateAudienceGuidance('ciso', mockInvestigation);

    expect(guidance).toBeDefined();
    expect(Array.isArray(guidance.decisions)).toBe(true);
  });

  test('should generate SOC-Director-focused decision guidance', () => {
    const guidance = engine.generateAudienceGuidance('soc-director', mockInvestigation);

    expect(guidance).toBeDefined();
    expect(Array.isArray(guidance.decisions)).toBe(true);
  });

  test('should generate Threat-Hunter-focused decision guidance', () => {
    const guidance = engine.generateAudienceGuidance('threat-hunter', mockInvestigation);

    expect(guidance).toBeDefined();
    expect(Array.isArray(guidance.decisions)).toBe(true);
  });

  // ==================== SECTOR AND REGION ANALYSIS TESTS ====================

  test('should format affected sectors', () => {
    const sectors = engine.formatAffectedSectors(mockInvestigation.targetedSectors);

    expect(Array.isArray(sectors)).toBe(true);
    expect(sectors.length).toBeGreaterThan(0);
  });

  test('should format affected regions', () => {
    const regions = engine.formatAffectedRegions(mockInvestigation.targetedRegions);

    expect(Array.isArray(regions)).toBe(true);
    expect(regions.length).toBeGreaterThan(0);
  });

  // ==================== CACHING TESTS ====================

  test('should cache presentation after generation', async () => {
    const enhancement = await engine.enhanceIntelligenceProduct(mockProduct, mockInvestigation, mockReport);
    engine.presentationCache.set(enhancement.productId, enhancement);

    const cached = engine.getProductPresentation(enhancement.productId);
    expect(cached).toBeDefined();
    expect(cached.productId).toBe('prod-apt28-2026-07-31');
  });

  test('should retrieve all presentations from cache', async () => {
    const enhancement = await engine.enhanceIntelligenceProduct(mockProduct, mockInvestigation, mockReport);
    engine.presentationCache.set(enhancement.productId, enhancement);

    const allPresentations = engine.getAllPresentations();
    expect(Array.isArray(allPresentations)).toBe(true);
    expect(allPresentations.length).toBeGreaterThan(0);
  });

  // ==================== STYLING TESTS ====================

  test('should return theme styling configuration', () => {
    const styling = engine.getThemeStyling('cover-page');

    expect(styling).toBeDefined();
    expect(styling.primary).toBeDefined();
    expect(styling.typography).toBeDefined();
    expect(styling.spacing).toBeDefined();
  });

  // ==================== LAYOUT CONFIGURATION TESTS ====================

  test('should respect layout configuration toggles', async () => {
    engine.layoutConfig.coverPage = false;
    engine.layoutConfig.dashboardHeader = false;

    const enhancement = await engine.enhanceIntelligenceProduct(mockProduct, mockInvestigation, mockReport);

    expect(enhancement.presentationEnhancements.coverPage).toBeUndefined();
    expect(enhancement.presentationEnhancements.dashboardHeader).toBeUndefined();
  });

  // ==================== INTEGRATION TESTS ====================

  test('should handle minimal investigation data gracefully', async () => {
    const minimalInvestigation = {
      id: 'minimal-inv',
      title: 'Minimal Investigation',
      findings: [],
      iocs: [],
      infrastructure: [],
    };

    const enhancement = await engine.enhanceIntelligenceProduct(mockProduct, minimalInvestigation, mockReport);

    expect(enhancement).toBeDefined();
    expect(enhancement.presentationEnhancements).toBeDefined();
  });

  test('should handle missing optional fields', async () => {
    const incompleteProduct = {
      id: 'incomplete-prod',
      productType: 'report',
    };

    const enhancement = await engine.enhanceIntelligenceProduct(incompleteProduct, mockInvestigation, mockReport);

    expect(enhancement).toBeDefined();
    expect(enhancement.productId).toBe('incomplete-prod');
  });

  test('should generate consistent presentations for same input', async () => {
    const enhancement1 = await engine.enhanceIntelligenceProduct(mockProduct, mockInvestigation, mockReport);
    const enhancement2 = await engine.enhanceIntelligenceProduct(mockProduct, mockInvestigation, mockReport);

    expect(enhancement1.metadata.enhancedAt).toBeDefined();
    expect(enhancement2.metadata.enhancedAt).toBeDefined();
    expect(enhancement1.presentationEnhancements.coverPage).toBeDefined();
    expect(enhancement2.presentationEnhancements.coverPage).toBeDefined();
  });
});
