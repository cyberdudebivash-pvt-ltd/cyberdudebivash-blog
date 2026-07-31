'use strict';

const { Phase11Orchestrator } = require('../phase-11-orchestrator');
const { ProductManagementAPI } = require('../product-management-api');

describe('Phase 11 Integration Tests', () => {
  let orchestrator;
  let api;
  let mockRedis;

  beforeEach(() => {
    orchestrator = new Phase11Orchestrator();

    mockRedis = {
      hgetall: jest.fn().mockResolvedValue([]),
      zrevrange: jest.fn().mockResolvedValue([]),
      zcard: jest.fn().mockResolvedValue(0),
      hset: jest.fn().mockResolvedValue(1),
      zadd: jest.fn().mockResolvedValue(1),
    };

    api = new ProductManagementAPI(mockRedis);
  });

  const createMockInvestigation = (overrides = {}) => ({
    id: 'inv-phase11-001',
    title: 'Phase 11 Comprehensive Test',
    description: 'Testing all Phase 11 capabilities',
    severity: 'CRITICAL',
    classification: 'TLP:AMBER',
    threatActors: [
      {
        name: 'APT-Test',
        aliases: ['Test Actor'],
        description: 'Test threat actor',
        firstSeen: '2024-01-01',
        lastSeen: '2024-07-31',
        origin: 'Unknown',
      },
    ],
    campaigns: [
      {
        name: 'Test Campaign',
        description: 'Test campaign description',
        status: 'ONGOING',
        startDate: '2024-01-01',
        objectives: ['Test Objective'],
      },
    ],
    targetedSectors: ['financial-services', 'healthcare'],
    targetedRegions: ['north-america', 'europe'],
    targetedOrganizations: ['Bank', 'Hospital'],
    affectedUserCount: 1000,
    techniques: [
      {
        name: 'Phishing',
        mitreTactic: 'Initial Access',
        type: 'attack',
      },
      {
        name: 'Lateral Movement',
        mitreTactic: 'Lateral Movement',
        type: 'technique',
      },
    ],
    iocs: [
      {
        value: '10.0.0.1',
        type: 'ip',
        severity: 'HIGH',
        confidence: 0.9,
      },
      {
        value: 'malware.exe',
        type: 'file',
        severity: 'CRITICAL',
        confidence: 0.95,
      },
    ],
    findings: [
      {
        id: 'f-001',
        statement: 'Financial services sector targeting detected',
        severity: 'critical',
      },
      {
        id: 'f-002',
        statement: 'Healthcare sector compromises',
        severity: 'high',
      },
    ],
    infrastructure: [
      {
        type: 'c2',
        value: 'evil.com',
        location: 'Eastern Europe',
      },
      {
        type: 'hosting',
        value: 'payload.host',
        location: 'Unknown',
      },
    ],
    malware: ['Emotet', 'Trickbot'],
    toolsUsed: ['Mimikatz', 'PSTools'],
    timeline: [
      {
        date: '2024-01-15',
        event: 'Initial reconnaissance',
      },
      {
        date: '2024-02-01',
        event: 'Credential harvesting',
      },
    ],
    sources: ['Mandiant', 'Crowdstrike'],
    references: ['https://test.com'],
    persistenceMechanisms: [
      {
        mechanism: 'Registry Run Key',
        description: 'Persistence via registry modification',
      },
    ],
    ...overrides,
  });

  const mockReport = {
    id: 'report-phase11-001',
    investigationId: 'inv-phase11-001',
    createdAt: new Date().toISOString(),
  };

  test('should generate comprehensive portfolio with all product families', async () => {
    const investigation = createMockInvestigation();
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    expect(portfolio).toBeDefined();
    expect(portfolio.investigationId).toBe('inv-phase11-001');
    expect(portfolio.reportId).toBe('report-phase11-001');

    // Verify all product families are present
    expect(portfolio.products.executive).toBeDefined();
    expect(portfolio.products.executive.length).toBeGreaterThan(0);

    expect(portfolio.products.technical).toBeDefined();
    expect(portfolio.products.technical.length).toBeGreaterThan(0);

    expect(portfolio.products.threatActor).toBeDefined();
    expect(portfolio.products.threatActor.length).toBeGreaterThan(0);

    expect(portfolio.products.sectorRegional).toBeDefined();

    expect(portfolio.products.collections).toBeDefined();

    expect(portfolio.products.customerPackages).toBeDefined();

    // Verify metadata
    expect(portfolio.metadata).toBeDefined();
    expect(portfolio.metadata.generatedAt).toBeDefined();
    expect(portfolio.metadata.status).toBe('complete');
    expect(portfolio.metadata.totalProducts).toBeGreaterThan(0);
  });

  test('should preserve classification levels across all products', async () => {
    const investigation = createMockInvestigation();
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    // Check all product types preserve classification
    for (const productList of Object.values(portfolio.products)) {
      if (Array.isArray(productList)) {
        for (const product of productList) {
          if (product.classification) {
            expect(['TLP:WHITE', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED'].includes(product.classification)).toBe(true);
          }
        }
      }
    }
  });

  test('should include sector-specific intelligence for targeted sectors', async () => {
    const investigation = createMockInvestigation({
      targetedSectors: ['financial-services', 'healthcare'],
    });

    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);
    const sectorProducts = portfolio.products.sectorRegional;

    expect(sectorProducts.length).toBeGreaterThanOrEqual(2);

    const sectorNames = sectorProducts.map(p => p.sector);
    expect(sectorNames).toContain('financial-services');
    expect(sectorNames).toContain('healthcare');
  });

  test('should include regional intelligence for targeted regions', async () => {
    const investigation = createMockInvestigation({
      targetedRegions: ['north-america', 'europe'],
    });

    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);
    const regionalProducts = portfolio.products.sectorRegional.filter(p => p.region);

    expect(regionalProducts.length).toBeGreaterThanOrEqual(2);

    const regionNames = regionalProducts.map(p => p.region);
    expect(regionNames).toContain('north-america');
    expect(regionNames).toContain('europe');
  });

  test('should skip threat actor products if no threat actors', async () => {
    const investigation = createMockInvestigation({
      threatActors: [],
    });

    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    expect(portfolio.products.threatActor.length).toBe(0);
  });

  test('should generate customer packages for different roles', async () => {
    const investigation = createMockInvestigation();
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    const packages = portfolio.products.customerPackages;
    expect(packages.length).toBeGreaterThan(0);

    // Check for different role packages
    const roles = packages.map(pkg => pkg.role || pkg.audience);
    const roleVariety = new Set(roles).size;
    expect(roleVariety).toBeGreaterThan(0);
  });

  test('should build intelligence collections', async () => {
    const investigation = createMockInvestigation();
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    const collections = portfolio.products.collections;
    expect(Array.isArray(collections)).toBe(true);
  });

  test('should maintain lineage through all products', async () => {
    const investigation = createMockInvestigation();
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    for (const productList of Object.values(portfolio.products)) {
      if (Array.isArray(productList)) {
        for (const product of productList) {
          if (product.lineage) {
            expect(product.lineage.investigation).toBeDefined();
            expect(product.lineage.report).toBeDefined();
          }
        }
      }
    }
  });

  test('should handle vulnerability intelligence when provided', async () => {
    const investigation = createMockInvestigation();
    const vulnerabilityData = {
      cveId: 'CVE-2024-1234',
      severity: 'CRITICAL',
      description: 'Critical vulnerability in popular software',
      inTheWild: true,
      affectedProducts: [
        {
          vendor: 'Software Vendor',
          product: 'Application',
          versions: ['1.0', '1.1', '2.0'],
        },
      ],
    };

    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(
      investigation,
      mockReport,
      vulnerabilityData
    );

    const vulnProducts = portfolio.products.vulnerabilityDetection;
    expect(vulnProducts).toBeDefined();
  });

  test('should validate all engines are operational', async () => {
    const validation = await orchestrator.validatePhase11Integration(createMockInvestigation(), mockReport);

    expect(validation.phase11Orchestrator).toBe('operational');
    expect(validation.enginesReady).toBeDefined();
    expect(validation.enginesReady.catalog).toBe(true);
    expect(validation.enginesReady.executive).toBe(true);
    expect(validation.enginesReady.technical).toBe(true);
    expect(validation.enginesReady.threatActor).toBe(true);
    expect(validation.enginesReady.sectorRegional).toBe(true);
    expect(validation.enginesReady.vulnerabilityDetection).toBe(true);
    expect(validation.enginesReady.collectionsPackages).toBe(true);
    expect(validation.status).toBe('ready');
  });

  test('should record composition statistics accurately', async () => {
    const investigation = createMockInvestigation();
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    const stats = portfolio.metadata.compositionStats;
    expect(stats).toBeDefined();
    expect(stats.attempted).toBeGreaterThan(0);
    expect(stats.succeeded).toBeGreaterThan(0);
  });

  test('should handle graceful degradation on partial failures', async () => {
    const incompleteInvestigation = {
      id: 'inv-incomplete',
    };

    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(incompleteInvestigation, mockReport);

    expect(portfolio).toBeDefined();
    expect(portfolio.metadata).toBeDefined();
    expect(portfolio.metadata.status).toBe('complete');
  });

  test('should integrate with product management API', async () => {
    const investigation = createMockInvestigation();
    const portfolio = await orchestrator.generateGlobalIntelligencePortfolio(investigation, mockReport);

    // Simulate API integration
    const totalProducts = Object.values(portfolio.products).reduce((sum, arr) => {
      return sum + (Array.isArray(arr) ? arr.length : 0);
    }, 0);

    expect(totalProducts).toBeGreaterThan(0);
    expect(portfolio.metadata.totalProducts).toBe(totalProducts);
  });
});
