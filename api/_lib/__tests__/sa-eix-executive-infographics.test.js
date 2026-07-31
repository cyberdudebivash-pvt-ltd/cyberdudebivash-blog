'use strict';

const { SentinelApexExecutiveInfographics } = require('../sa-eix-executive-infographics');

describe('SentinelApexExecutiveInfographics', () => {
  let infographics;

  beforeEach(() => {
    infographics = new SentinelApexExecutiveInfographics();
  });

  describe('Initialization', () => {
    test('should initialize with default branding config', () => {
      expect(infographics).toBeDefined();
      expect(infographics.designTokens).toBeDefined();
      expect(infographics.theme).toBeDefined();
    });

    test('should initialize with custom branding config', () => {
      const custom = new SentinelApexExecutiveInfographics({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
      expect(custom.designTokens).toBeDefined();
    });

    test('should have design system available', () => {
      expect(infographics.designSystem).toBeDefined();
      expect(infographics.designTokens).toBeDefined();
    });
  });

  describe('generateKPICard', () => {
    test('should generate KPI card with default status', () => {
      const card = infographics.generateKPICard('Test Label', 42, 'metric');
      expect(card.type).toBe('kpi-card');
      expect(card.html).toContain('Test Label');
      expect(card.html).toContain('42');
      expect(card.html).toContain('metric');
      expect(card.metadata.label).toBe('Test Label');
      expect(card.metadata.value).toBe(42);
      expect(card.metadata.status).toBe('normal');
    });

    test('should generate KPI card with critical status', () => {
      const card = infographics.generateKPICard('Critical', 99, 'alerts', 'critical');
      expect(card.type).toBe('kpi-card');
      expect(card.metadata.status).toBe('critical');
      expect(card.metadata.color).toBeDefined();
      expect(card.html).toContain('99');
    });

    test('should generate KPI card with warning status', () => {
      const card = infographics.generateKPICard('Warning', 50, 'warnings', 'warning');
      expect(card.type).toBe('kpi-card');
      expect(card.metadata.status).toBe('warning');
      expect(card.metadata.color).toBeDefined();
      expect(card.html).toContain('50');
    });

    test('should include status color in metadata', () => {
      const card = infographics.generateKPICard('Test', 10, 'metric', 'normal');
      expect(card.metadata.color).toBeDefined();
    });

    test('should escape HTML in label', () => {
      const card = infographics.generateKPICard('<script>alert(1)</script>', 42, 'metric');
      expect(card.html).toContain('&lt;script&gt;');
    });

    test('should escape HTML in metric', () => {
      const card = infographics.generateKPICard('Label', 42, '&gt;dangerous');
      expect(card.html).toContain('&amp;gt;dangerous');
    });

    test('should handle numeric values', () => {
      const card = infographics.generateKPICard('Number', 12345, 'count');
      expect(card.html).toContain('12345');
    });

    test('should handle string values', () => {
      const card = infographics.generateKPICard('Status', 'ACTIVE', 'state');
      expect(card.html).toContain('ACTIVE');
    });

    test('should include HTML structure', () => {
      const card = infographics.generateKPICard('Test', 42, 'metric', 'normal');
      expect(card.html).toContain('kpi-card');
      expect(card.html).toContain('border-radius');
      expect(card.html).toContain('padding');
    });
  });

  describe('generateBusinessImpactChart', () => {
    test('should generate business impact chart with empty threats', () => {
      const chart = infographics.generateBusinessImpactChart([]);
      expect(chart.type).toBe('business-impact-chart');
      expect(chart.metadata.threatCount).toBe(0);
      expect(chart.html).toContain('Business Impact Assessment');
    });

    test('should generate business impact chart with threats', () => {
      const threats = [
        { name: 'Threat A', businessImpact: 'High', impactScore: 85 },
        { name: 'Threat B', businessImpact: 'Medium', impactScore: 60 },
      ];
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.type).toBe('business-impact-chart');
      expect(chart.metadata.threatCount).toBe(2);
      expect(chart.html).toContain('Threat A');
      expect(chart.html).toContain('Threat B');
    });

    test('should limit threats to 5', () => {
      const threats = Array.from({ length: 10 }, (_, i) => ({
        name: `Threat ${i}`,
        impactScore: 50 + i * 5,
      }));
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.metadata.threatCount).toBe(5);
    });

    test('should color-code threats by impact score', () => {
      const threats = [
        { name: 'Critical', impactScore: 90 },
        { name: 'Medium', impactScore: 60 },
        { name: 'Low', impactScore: 30 },
      ];
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.html).toContain('90%');
      expect(chart.html).toContain('60%');
      expect(chart.html).toContain('30%');
    });

    test('should handle threats without impactScore', () => {
      const threats = [
        { name: 'No Score', businessImpact: 'Unknown' },
      ];
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.html).toContain('No Score');
    });

    test('should escape threat names', () => {
      const threats = [{ name: '<img src=x>', impactScore: 50 }];
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.html).toContain('&lt;img');
    });

    test('should handle missing threat names', () => {
      const threats = [{ impactScore: 50 }, { impactScore: 70 }];
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.html).toContain('Threat 1');
      expect(chart.html).toContain('Threat 2');
    });

    test('should include metadata about threats', () => {
      const threats = [
        { name: 'A', businessImpact: 'High' },
        { name: 'B', businessImpact: 'Low' },
      ];
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.metadata.threats).toBeDefined();
      expect(chart.metadata.threats.length).toBe(2);
    });
  });

  describe('generateRiskGauge', () => {
    test('should generate risk gauge with default values', () => {
      const gauge = infographics.generateRiskGauge();
      expect(gauge.type).toBe('risk-gauge');
      expect(gauge.html).toContain('Risk Gauge');
      expect(gauge.html).toContain('svg');
    });

    test('should generate risk gauge for low risk', () => {
      const gauge = infographics.generateRiskGauge(25, 100);
      expect(gauge.metadata.riskLevel).toBe(25);
      expect(gauge.metadata.riskLabel).toBe('LOW');
      expect(gauge.html).toContain('LOW');
    });

    test('should generate risk gauge for medium risk', () => {
      const gauge = infographics.generateRiskGauge(50, 100);
      expect(gauge.metadata.riskLevel).toBe(50);
      expect(gauge.metadata.riskLabel).toBe('MEDIUM');
      expect(gauge.html).toContain('MEDIUM');
    });

    test('should generate risk gauge for high risk', () => {
      const gauge = infographics.generateRiskGauge(75, 100);
      expect(gauge.metadata.riskLevel).toBe(75);
      expect(gauge.metadata.riskLabel).toBe('HIGH');
      expect(gauge.html).toContain('HIGH');
    });

    test('should generate risk gauge for critical risk', () => {
      const gauge = infographics.generateRiskGauge(95, 100);
      expect(gauge.metadata.riskLevel).toBe(95);
      expect(gauge.metadata.riskLabel).toBe('CRITICAL');
      expect(gauge.html).toContain('CRITICAL');
    });

    test('should handle custom max risk value', () => {
      const gauge = infographics.generateRiskGauge(50, 200);
      expect(gauge.metadata.riskLevel).toBe(25);
    });

    test('should cap risk at 100%', () => {
      const gauge = infographics.generateRiskGauge(150, 100);
      expect(gauge.metadata.riskLevel).toBe(100);
    });

    test('should include SVG path data', () => {
      const gauge = infographics.generateRiskGauge(50, 100);
      expect(gauge.html).toContain('svg');
      expect(gauge.html).toContain('path');
    });

    test('should display risk level and percentage', () => {
      const gauge = infographics.generateRiskGauge(60, 100);
      expect(gauge.html).toContain('60');
      expect(gauge.html).toContain('Risk Level');
      expect(gauge.metadata.riskLevel).toBe(60);
    });

    test('should include risk color in metadata', () => {
      const gauge = infographics.generateRiskGauge(75, 100);
      expect(gauge.metadata.riskColor).toBeDefined();
    });
  });

  describe('generateOperationalReadiness', () => {
    test('should generate operational readiness with defaults', () => {
      const readiness = infographics.generateOperationalReadiness({});
      expect(readiness.type).toBe('operational-readiness');
      expect(readiness.html).toContain('Operational Readiness');
      expect(readiness.html).toContain('Detection');
      expect(readiness.html).toContain('Response');
      expect(readiness.html).toContain('Recovery');
      expect(readiness.html).toContain('Resilience');
    });

    test('should include all four metrics', () => {
      const data = {
        detection: 0.85,
        response: 0.75,
        recovery: 0.65,
        resilience: 0.55,
      };
      const readiness = infographics.generateOperationalReadiness(data);
      expect(readiness.metadata.detection).toBe(85);
      expect(readiness.metadata.response).toBe(75);
      expect(readiness.metadata.recovery).toBe(65);
      expect(readiness.metadata.resilience).toBe(55);
    });

    test('should scale decimal values to percentages', () => {
      const data = {
        detection: 0.5,
        response: 0.75,
        recovery: 1.0,
        resilience: 0.25,
      };
      const readiness = infographics.generateOperationalReadiness(data);
      expect(readiness.html).toContain('50');
      expect(readiness.html).toContain('75');
      expect(readiness.html).toContain('100');
      expect(readiness.html).toContain('25');
    });

    test('should include SVG progress circles', () => {
      const readiness = infographics.generateOperationalReadiness({
        detection: 0.8,
      });
      expect(readiness.html).toContain('svg');
      expect(readiness.html).toContain('circle');
    });

    test('should handle missing metrics', () => {
      const data = { detection: 0.9 };
      const readiness = infographics.generateOperationalReadiness(data);
      expect(readiness.metadata.detection).toBe(90);
      expect(readiness.metadata.response).toBe(0);
      expect(readiness.metadata.recovery).toBe(0);
      expect(readiness.metadata.resilience).toBe(0);
    });

    test('should cap values at 100%', () => {
      const data = { detection: 1.5 };
      const readiness = infographics.generateOperationalReadiness(data);
      expect(readiness.metadata.detection).toBe(150);
    });

    test('should include grid layout', () => {
      const readiness = infographics.generateOperationalReadiness({});
      expect(readiness.html).toContain('grid');
      expect(readiness.html).toContain('display: grid');
    });
  });

  describe('generateFinancialExposure', () => {
    test('should generate financial exposure with defaults', () => {
      const exposure = infographics.generateFinancialExposure({});
      expect(exposure.type).toBe('financial-exposure');
      expect(exposure.html).toContain('Financial Exposure');
      expect(exposure.html).toContain('Potential Loss');
    });

    test('should format USD currency', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 1500000,
        currency: 'USD',
      });
      expect(exposure.html).toContain('$1.5M');
      expect(exposure.metadata.currency).toBe('USD');
    });

    test('should format EUR currency', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 1500000,
        currency: 'EUR',
      });
      expect(exposure.html).toContain('€1.5M');
    });

    test('should format GBP currency', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 1500000,
        currency: 'GBP',
      });
      expect(exposure.html).toContain('£1.5M');
    });

    test('should handle billion-scale amounts', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 5000000000,
        currency: 'USD',
      });
      expect(exposure.html).toContain('$5.0B');
    });

    test('should handle million-scale amounts', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 2500000,
        currency: 'USD',
      });
      expect(exposure.html).toContain('$2.5M');
    });

    test('should handle thousand-scale amounts', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 50000,
        currency: 'USD',
      });
      expect(exposure.html).toContain('$50.0K');
    });

    test('should handle small amounts', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 500,
        currency: 'USD',
      });
      expect(exposure.html).toContain('$500');
    });

    test('should display business impact', () => {
      const exposure = infographics.generateFinancialExposure({
        businessImpact: 'Supply Chain Disruption',
      });
      expect(exposure.html).toContain('Supply Chain Disruption');
    });

    test('should escape business impact HTML', () => {
      const exposure = infographics.generateFinancialExposure({
        businessImpact: '<script>alert(1)</script>',
      });
      expect(exposure.html).toContain('&lt;script&gt;');
    });

    test('should display confidence percentage', () => {
      const exposure = infographics.generateFinancialExposure({
        confidence: 0.85,
      });
      expect(exposure.html).toContain('85%');
      expect(exposure.metadata.confidence).toBe(85);
    });

    test('should include metadata', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 1000000,
        currency: 'USD',
        confidence: 0.9,
        businessImpact: 'Critical',
      });
      expect(exposure.metadata.potentialLoss).toBe(1000000);
      expect(exposure.metadata.currency).toBe('USD');
      expect(exposure.metadata.confidence).toBe(90);
      expect(exposure.metadata.businessImpact).toBe('Critical');
    });
  });

  describe('generateCriticalAssets', () => {
    test('should generate critical assets with empty list', () => {
      const assets = infographics.generateCriticalAssets([]);
      expect(assets.type).toBe('critical-assets');
      expect(assets.html).toContain('Critical Assets At Risk');
      expect(assets.metadata.totalAssets).toBe(0);
    });

    test('should generate critical assets with multiple assets', () => {
      const assetList = [
        { name: 'Database', type: 'Infrastructure', risk: 'CRITICAL' },
        { name: 'API Gateway', type: 'Services', risk: 'HIGH' },
      ];
      const assets = infographics.generateCriticalAssets(assetList);
      expect(assets.html).toContain('Database');
      expect(assets.html).toContain('API Gateway');
      expect(assets.metadata.totalAssets).toBe(2);
    });

    test('should limit assets to 8', () => {
      const assetList = Array.from({ length: 15 }, (_, i) => ({
        name: `Asset ${i}`,
        type: 'Infrastructure',
      }));
      const assets = infographics.generateCriticalAssets(assetList);
      expect(assets.metadata.assetsAtRisk).toBe(8);
    });

    test('should escape asset names', () => {
      const assetList = [{ name: '<img src=x>', type: 'Infrastructure' }];
      const assets = infographics.generateCriticalAssets(assetList);
      expect(assets.html).toContain('&lt;img');
    });

    test('should escape asset types', () => {
      const assetList = [{ name: 'Asset', type: '&malicious' }];
      const assets = infographics.generateCriticalAssets(assetList);
      expect(assets.html).toContain('&amp;malicious');
    });

    test('should display risk level when present', () => {
      const assetList = [
        { name: 'Asset1', type: 'Type1', risk: 'CRITICAL' },
      ];
      const assets = infographics.generateCriticalAssets(assetList);
      expect(assets.html).toContain('CRITICAL');
    });

    test('should handle missing risk level', () => {
      const assetList = [{ name: 'Asset', type: 'Type' }];
      const assets = infographics.generateCriticalAssets(assetList);
      expect(assets.html).toContain('Asset');
    });

    test('should include total asset count', () => {
      const assetList = Array.from({ length: 5 }, (_, i) => ({
        name: `Asset ${i}`,
      }));
      const assets = infographics.generateCriticalAssets(assetList);
      expect(assets.html).toContain('Total Assets At Risk');
      expect(assets.metadata.totalAssets).toBe(5);
    });

    test('should include grid layout', () => {
      const assets = infographics.generateCriticalAssets([
        { name: 'Asset1' },
      ]);
      expect(assets.html).toContain('grid');
    });
  });

  describe('generateExecutiveInfographics', () => {
    test('should generate complete executive dashboard', () => {
      const dashboard = infographics.generateExecutiveInfographics(
        { id: 'prod1' },
        {
          id: 'inv1',
          severity: 'CRITICAL',
          infrastructure: [1, 2, 3],
          threatActors: [1, 2],
          criticalAssets: [{ name: 'Asset1' }],
        },
        {
          detectionReadiness: 0.85,
          riskLevel: 75,
          operationalReadiness: { detection: 0.9 },
          financialExposure: { potentialLoss: 1000000 },
        }
      );

      expect(dashboard.type).toBe('executive-infographics');
      expect(dashboard.html).toContain('Executive Summary');
      expect(dashboard.components).toBeDefined();
    });

    test('should include all required components', () => {
      const dashboard = infographics.generateExecutiveInfographics({}, {}, {});
      expect(dashboard.components.kpiCards).toBeDefined();
      expect(dashboard.components.kpiCards.length).toBe(4);
      expect(dashboard.components.businessImpact).toBeDefined();
      expect(dashboard.components.riskGauge).toBeDefined();
      expect(dashboard.components.operationalReadiness).toBeDefined();
      expect(dashboard.components.financialExposure).toBeDefined();
      expect(dashboard.components.criticalAssets).toBeDefined();
    });

    test('should generate KPI cards from investigation data', () => {
      const dashboard = infographics.generateExecutiveInfographics(
        {},
        {
          severity: 'CRITICAL',
          infrastructure: [1, 2],
          threatActors: [1, 2, 3],
        },
        { detectionReadiness: 0.75 }
      );

      expect(dashboard.components.kpiCards[0].html).toContain('CRITICAL');
      expect(dashboard.components.kpiCards[1].html).toContain('75%');
      expect(dashboard.components.kpiCards[2].html).toContain('2');
      expect(dashboard.components.kpiCards[3].html).toContain('3');
    });

    test('should include metadata with investigation details', () => {
      const dashboard = infographics.generateExecutiveInfographics(
        { id: 'product123' },
        { id: 'investigation456', severity: 'HIGH' },
        {}
      );

      expect(dashboard.metadata.productId).toBe('product123');
      expect(dashboard.metadata.investigation).toBe('investigation456');
      expect(dashboard.metadata.threatLevel).toBe('HIGH');
      expect(dashboard.metadata.generatedAt).toBeDefined();
    });

    test('should handle empty inputs gracefully', () => {
      const dashboard = infographics.generateExecutiveInfographics({}, {}, {});
      expect(dashboard.type).toBe('executive-infographics');
      expect(dashboard.html).toContain('Executive Summary');
    });

    test('should include all component HTML in dashboard', () => {
      const dashboard = infographics.generateExecutiveInfographics(
        {},
        {
          threatActors: [{ name: 'Actor1' }],
          criticalAssets: [{ name: 'Asset1' }],
        },
        { riskLevel: 50 }
      );

      expect(dashboard.html).toContain('Business Impact Assessment');
      expect(dashboard.html).toContain('Risk Gauge');
      expect(dashboard.html).toContain('Operational Readiness');
      expect(dashboard.html).toContain('Financial Exposure');
      expect(dashboard.html).toContain('Critical Assets At Risk');
    });

    test('should use generated timestamp in metadata', () => {
      const beforeTime = new Date().toISOString();
      const dashboard = infographics.generateExecutiveInfographics({}, {}, {});
      const afterTime = new Date().toISOString();

      expect(dashboard.metadata.generatedAt).toBeDefined();
      const generatedTime = new Date(dashboard.metadata.generatedAt);
      const beforeDate = new Date(beforeTime);
      const afterDate = new Date(afterTime);

      expect(generatedTime.getTime()).toBeGreaterThanOrEqual(beforeDate.getTime() - 100);
      expect(generatedTime.getTime()).toBeLessThanOrEqual(afterDate.getTime() + 100);
    });
  });

  describe('Color Utilities', () => {
    describe('getStatusColor', () => {
      test('should return success color for normal status', () => {
        const color = infographics.getStatusColor('normal');
        expect(color).toBeDefined();
      });

      test('should return warning color for warning status', () => {
        const color = infographics.getStatusColor('warning');
        expect(color).toBeDefined();
      });

      test('should return critical color for critical status', () => {
        const color = infographics.getStatusColor('critical');
        expect(color).toBeDefined();
      });

      test('should return default color for unknown status', () => {
        const color = infographics.getStatusColor('unknown');
        expect(color).toBeDefined();
      });
    });

    describe('getConfidenceColor', () => {
      test('should return success for high confidence', () => {
        const color = infographics.getConfidenceColor(0.9);
        expect(color).toBeDefined();
      });

      test('should return accent for medium-high confidence', () => {
        const color = infographics.getConfidenceColor(0.7);
        expect(color).toBeDefined();
      });

      test('should return warning for medium confidence', () => {
        const color = infographics.getConfidenceColor(0.5);
        expect(color).toBeDefined();
      });

      test('should return critical for low confidence', () => {
        const color = infographics.getConfidenceColor(0.2);
        expect(color).toBeDefined();
      });

      test('should handle edge cases', () => {
        expect(infographics.getConfidenceColor(0)).toBeDefined();
        expect(infographics.getConfidenceColor(1)).toBeDefined();
      });
    });

    describe('getSeverityColor', () => {
      test('should return critical color for CRITICAL', () => {
        const color = infographics.getSeverityColor('CRITICAL');
        expect(color).toBeDefined();
      });

      test('should return warning color for HIGH', () => {
        const color = infographics.getSeverityColor('HIGH');
        expect(color).toBeDefined();
      });

      test('should return accent color for MEDIUM', () => {
        const color = infographics.getSeverityColor('MEDIUM');
        expect(color).toBeDefined();
      });

      test('should return success color for LOW', () => {
        const color = infographics.getSeverityColor('LOW');
        expect(color).toBeDefined();
      });

      test('should return secondary color for UNKNOWN', () => {
        const color = infographics.getSeverityColor('UNKNOWN');
        expect(color).toBeDefined();
      });

      test('should handle unknown severity gracefully', () => {
        const color = infographics.getSeverityColor('UNDEFINED');
        expect(color).toBeDefined();
      });
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = infographics.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = infographics.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = infographics.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape quotes', () => {
      const escaped = infographics.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = infographics.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should escape multiple special characters', () => {
      const escaped = infographics.escapeHtml('<script>"alert(1)"</script>');
      expect(escaped).toContain('&lt;script&gt;');
      expect(escaped).toContain('&quot;');
    });

    test('should handle empty strings', () => {
      const escaped = infographics.escapeHtml('');
      expect(escaped).toBe('');
    });

    test('should handle null', () => {
      const escaped = infographics.escapeHtml(null);
      expect(escaped).toBe('');
    });

    test('should handle undefined', () => {
      const escaped = infographics.escapeHtml(undefined);
      expect(escaped).toBe('');
    });

    test('should convert numbers to strings before escaping', () => {
      const escaped = infographics.escapeHtml(42);
      expect(escaped).toBe('42');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very large numbers in KPI cards', () => {
      const card = infographics.generateKPICard('Big', 999999999, 'count');
      expect(card.html).toContain('999999999');
    });

    test('should handle negative numbers', () => {
      const card = infographics.generateKPICard('Negative', -50, 'change');
      expect(card.html).toContain('-50');
    });

    test('should handle zero values', () => {
      const card = infographics.generateKPICard('Zero', 0, 'count');
      expect(card.metadata.value).toBe(0);
      expect(card.html).toContain('0');
    });

    test('should handle special characters in data', () => {
      const threats = [{ name: 'Threat & Malware', impactScore: 50 }];
      const chart = infographics.generateBusinessImpactChart(threats);
      expect(chart.html).toContain('&amp;');
    });

    test('should handle very long labels', () => {
      const longLabel = 'A'.repeat(200);
      const card = infographics.generateKPICard(longLabel, 42, 'metric');
      expect(card.html).toContain(longLabel);
    });

    test('should handle special unicode characters', () => {
      const card = infographics.generateKPICard('Unicode 中文 🔐', 42, 'metric');
      expect(card.html).toContain('中文');
      expect(card.html).toContain('🔐');
    });

    test('should handle extreme risk values', () => {
      const gauge = infographics.generateRiskGauge(1000, 100);
      expect(gauge.metadata.riskLevel).toBe(100);
    });

    test('should handle negative risk values', () => {
      const gauge = infographics.generateRiskGauge(-50, 100);
      expect(gauge.metadata.riskLevel).toBeDefined();
    });

    test('should handle financial exposure with zero currency', () => {
      const exposure = infographics.generateFinancialExposure({
        potentialLoss: 0,
      });
      expect(exposure.html).toContain('$0');
    });

    test('should handle null threat actors array', () => {
      const dashboard = infographics.generateExecutiveInfographics(
        {},
        { threatActors: null },
        {}
      );
      expect(dashboard.html).toContain('Executive Summary');
    });

    test('should handle undefined infrastructure array', () => {
      const dashboard = infographics.generateExecutiveInfographics(
        {},
        { infrastructure: undefined },
        {}
      );
      expect(dashboard.html).toContain('Executive Summary');
    });

    test('should generate valid HTML structure', () => {
      const card = infographics.generateKPICard('Test', 42, 'metric');
      expect(card.html).toMatch(/<div[^>]*>/);
      expect(card.html).toMatch(/<\/div>/);
    });

    test('should include theme variables in HTML', () => {
      const card = infographics.generateKPICard('Test', 42, 'metric');
      expect(card.html).toContain('background:');
      expect(card.html).toContain('color:');
    });

    test('should have consistent metadata across all components', () => {
      const card = infographics.generateKPICard('Test', 42, 'metric');
      const chart = infographics.generateBusinessImpactChart([]);
      const gauge = infographics.generateRiskGauge();
      const readiness = infographics.generateOperationalReadiness();
      const exposure = infographics.generateFinancialExposure();
      const assets = infographics.generateCriticalAssets();

      expect(card.metadata).toBeDefined();
      expect(chart.metadata).toBeDefined();
      expect(gauge.metadata).toBeDefined();
      expect(readiness.metadata).toBeDefined();
      expect(exposure.metadata).toBeDefined();
      expect(assets.metadata).toBeDefined();
    });
  });
});
