'use strict';

const { Phase11Orchestrator } = require('../phase-11-orchestrator');

describe('Phase 11 Orchestrator', () => {
  let orchestrator;

  beforeEach(() => {
    orchestrator = new Phase11Orchestrator();
  });

  const mockInvestigation = {
    id: 'inv-001',
    title: 'APT-28 Campaign Analysis',
    description: 'Comprehensive analysis of APT-28 operations',
    severity: 'CRITICAL',
    classification: 'TLP:AMBER',
    threatActors: [
      {
        name: 'APT-28',
        aliases: ['Fancy Bear'],
        description: 'Russian-attributed threat actor',
        firstSeen: '2007-01-01',
        lastSeen: '2024-07-01',
        origin: 'Russia',
      },
    ],
    campaigns: [
      {
        name: 'Operation Ghost',
        description: 'Political targeting campaign',
        status: 'ONGOING',
        startDate: '2024-01-01',
        objectives: ['Espionage', 'Disruption'],
      },
    ],
    targetedSectors: ['government', 'technology'],
    targetedRegions: ['north-america', 'europe'],
    targetedOrganizations: ['NATO', 'US State Dept'],
    affectedUserCount: 5000,
    techniques: [
      {
        name: 'Spear Phishing',
        mitreTactic: 'Initial Access',
        type: 'attack',
      },
    ],
    iocs: [
      {
        value: '192.168.1.1',
        type: 'ip',
        severity: 'HIGH',
        confidence: 0.95,
      },
    ],
    findings: [
      {
        id: 'f-001',
        statement: 'Evidence of government sector targeting',
        severity: 'critical',
      },
    ],
    infrastructure: [
      {
        type: 'c2',
        value: 'attacker.com',
        location: 'Russia',
      },
    ],
    malware: ['Sofacy', 'CHOPSTICK'],
    toolsUsed: ['PuTTY', 'WinRAR'],
    timeline: [
      {
        date: '2024-01-15',
        event: 'Initial compromise detected',
      },
    ],
    sources: ['Crowdstrike', 'Mandiant'],
    references: ['https://example.com/report'],
  };

  const mockReport = {
    id: 'report-001',
    investigationId: 'inv-001',
    createdAt: new Date().toISOString(),
  };

  test('should initialize orchestrator with all engines', () => {
    expect(orchestrator.catalog).toBeDefined();
    expect(orchestrator.executive).toBeDefined();
    expect(orchestrator.technical).toBeDefined();
    expect(orchestrator.threatActor).toBeDefined();
    expect(orchestrator.sectorRegional).toBeDefined();
    expect(orchestrator.vulnerabilityDetection).toBeDefined();
    expect(orchestrator.collectionsPackages).toBeDefined();
  });

  test('should generate global intelligence portfolio', async () => {
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(mockInvestigation, mockReport);

    expect(portfolio).toBeDefined();
    expect(portfolio.investigationId).toBe('inv-001');
    expect(portfolio.reportId).toBe('report-001');
    expect(portfolio.products).toBeDefined();
    expect(portfolio.products.executive).toBeDefined();
    expect(portfolio.products.technical).toBeDefined();
    expect(portfolio.metadata).toBeDefined();
    expect(portfolio.metadata.status).toBe('complete');
  });

  test('should compose executive products', async () => {
    const products = await orchestrator.composeExecutiveProducts(mockInvestigation, mockReport);

    expect(Array.isArray(products)).toBe(true);
    expect(products.length).toBeGreaterThan(0);

    const briefTypes = products.map(p => p.type || p.productId);
    expect(briefTypes.some(t => t.includes('executive'))).toBe(true);
  });

  test('should compose technical products', async () => {
    const products = await orchestrator.composeTechnicalProducts(mockInvestigation, mockReport);

    expect(Array.isArray(products)).toBe(true);
    expect(products.length).toBeGreaterThan(0);

    const technicalTypes = products.map(p => p.type || p.productId);
    expect(technicalTypes.some(t => t.includes('technical'))).toBe(true);
  });

  test('should compose threat actor products when threat actors present', async () => {
    const products = await orchestrator.composeThreatActorProducts(mockInvestigation, mockReport);

    expect(Array.isArray(products)).toBe(true);
    expect(products.length).toBeGreaterThan(0);
  });

  test('should skip threat actor products when no threat actors', async () => {
    const investigationNoActors = { ...mockInvestigation, threatActors: [] };
    const products = await orchestrator.composeThreatActorProducts(investigationNoActors, mockReport);

    expect(Array.isArray(products)).toBe(true);
    expect(orchestrator.compositionStats.skipped).toBeGreaterThan(0);
  });

  test('should compose sector and regional products', async () => {
    const products = await orchestrator.composeSectorRegionalProducts(mockInvestigation, mockReport);

    expect(Array.isArray(products)).toBe(true);
  });

  test('should record composition statistics', () => {
    orchestrator.recordComposition(true);
    expect(orchestrator.compositionStats.attempted).toBe(1);
    expect(orchestrator.compositionStats.succeeded).toBe(1);

    orchestrator.recordComposition(false);
    expect(orchestrator.compositionStats.attempted).toBe(2);
    expect(orchestrator.compositionStats.failed).toBe(1);

    orchestrator.recordComposition(false, true);
    expect(orchestrator.compositionStats.skipped).toBe(1);
  });

  test('should calculate success rate', async () => {
    orchestrator.recordComposition(true);
    orchestrator.recordComposition(true);
    orchestrator.recordComposition(false);

    const stats = await orchestrator.getCompositionStats();
    expect(stats.successRate).toBe('66.67%');
  });

  test('should validate phase 11 integration', async () => {
    const validation = await orchestrator.validatePhase11Integration(mockInvestigation, mockReport);

    expect(validation).toBeDefined();
    expect(validation.phase11Orchestrator).toBe('operational');
    expect(validation.enginesReady).toBeDefined();
    expect(validation.status).toBe('ready');
  });

  test('should enhance product with phase 11 context', async () => {
    const mockProduct = {
      id: 'prod-001',
      productId: 'executive-brief',
      type: 'executive',
    };

    const result = await orchestrator.enhanceProductWithPhase11Context(mockProduct, mockInvestigation, mockReport);

    expect(result).toBeDefined();
    expect(result.product).toBeDefined();
    expect(result.product.phase11Enhancements).toBeDefined();
    expect(result.status).toBe('enhanced');
  });

  test('should handle graceful degradation on composition failure', async () => {
    const invalidInvestigation = { id: 'inv-invalid' };
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(invalidInvestigation, mockReport);

    expect(portfolio).toBeDefined();
    expect(portfolio.metadata).toBeDefined();
  });
});
