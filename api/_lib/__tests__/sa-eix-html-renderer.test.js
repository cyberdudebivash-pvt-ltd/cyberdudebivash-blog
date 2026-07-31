'use strict';

const { SentinelApexEIXHTMLRenderer } = require('../sa-eix-html-renderer');

describe('Sentinel APEX Enterprise Intelligence Experience HTML Renderer', () => {
  let renderer;

  beforeEach(() => {
    renderer = new SentinelApexEIXHTMLRenderer();
  });

  const mockEnhancement = {
    productId: 'prod-apt28-2026-07-31',
    presentationEnhancements: {
      coverPage: {
        type: 'enterprise-cover',
        sections: {
          header: {
            title: 'APT-28 Campaign Analysis',
            subtitle: 'Strategic threat intelligence briefing',
            threatLevel: 'CRITICAL',
            threatScore: 85,
            classification: 'TLP:AMBER',
          },
          threatInformation: {
            severity: 'CRITICAL',
            confidence: 0.85,
            businessImpact: 'High operational impact',
            operationalRisk: 'HIGH',
            detectionCoverage: 75,
          },
          threatActors: [
            { name: 'APT-28' },
            { name: 'Fancy Bear' },
          ],
          campaigns: [
            { name: 'Operation Ghost' },
          ],
          affectedIndustries: ['government', 'technology'],
          affectedRegions: ['US', 'EU'],
          keyMetrics: {
            findingsCount: 15,
            iocsCount: 25,
            infrastructureCount: 8,
            techniquesCount: 12,
          },
        },
      },
      dashboardHeader: {
        type: 'soc-dashboard-header',
        widgets: [
          { name: 'Threat Level', value: 'CRITICAL', icon: 'alert', color: '#E74C3C' },
          { name: 'Confidence', value: '85%', icon: 'check-circle', color: '#2ECC71' },
          { name: 'Business Risk', value: 'HIGH', icon: 'trending-up', color: '#E67E22' },
        ],
      },
      executiveCards: [
        {
          type: 'card',
          category: 'threat-summary',
          title: 'Threat Overview',
          content: {
            headline: 'APT-28 Campaign Analysis',
            severity: 'CRITICAL',
            threatActors: 'APT-28',
          },
          icon: 'alert-triangle',
        },
        {
          type: 'card',
          category: 'business-impact',
          title: 'Business Impact',
          content: {
            impact: 'High operational impact',
            affectedSystems: ['Mail servers', 'VPN'],
          },
          icon: 'bar-chart-2',
        },
      ],
      evidenceGallery: {
        type: 'evidence-gallery',
        sections: [
          {
            title: 'Key Findings',
            count: 3,
            items: [
              {
                id: 'f1',
                statement: 'Evidence of targeting',
                severity: 'critical',
                confidence: 0.95,
              },
              {
                id: 'f2',
                statement: 'Malware detected',
                severity: 'critical',
                confidence: 0.90,
              },
            ],
          },
          {
            title: 'Indicators of Compromise',
            count: 2,
            items: [
              {
                id: 'i1',
                value: '192.168.1.1',
                type: 'ip',
                severity: 'HIGH',
                confidence: 0.95,
              },
              {
                id: 'i2',
                value: 'attacker.com',
                type: 'domain',
                severity: 'HIGH',
                confidence: 0.90,
              },
            ],
          },
        ],
      },
      interactiveDiagrams: {
        type: 'interactive-diagrams',
        diagrams: [
          {
            type: 'kill-chain',
            title: 'Kill Chain Analysis',
            stages: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation'],
          },
          {
            type: 'mitre-matrix',
            title: 'MITRE ATT&CK Coverage',
            tactics: {
              'Initial Access': ['Spear Phishing'],
              'Execution': ['PowerShell'],
            },
          },
        ],
      },
      decisionCenter: {
        type: 'executive-decision-center',
        audiences: {
          ceo: {
            title: 'CEO',
            decisions: ['Business Continuity', 'Insurance Review'],
            metrics: [
              { label: 'Revenue Impact', value: 'High' },
              { label: 'Operational Impact', value: 'Medium' },
            ],
          },
          ciso: {
            title: 'CISO',
            decisions: ['Incident Response', 'Detection Deployment'],
            metrics: [
              { label: 'Threat Level', value: 'CRITICAL' },
              { label: 'Detection Coverage', value: '75%' },
            ],
          },
        },
      },
    },
  };

  // ==================== INITIALIZATION TESTS ====================

  test('should initialize with default branding config', () => {
    expect(renderer.brandingConfig).toBeDefined();
    expect(renderer.brandingConfig.name).toBe('Sentinel APEX');
    expect(renderer.brandingConfig.colors).toBeDefined();
    expect(renderer.brandingConfig.typography).toBeDefined();
  });

  test('should initialize with custom branding config', () => {
    const customBranding = {
      name: 'Custom SIEM',
      colors: { primary: '#FF0000' },
    };
    const customRenderer = new SentinelApexEIXHTMLRenderer(customBranding);

    expect(customRenderer.brandingConfig.name).toBe('Custom SIEM');
    expect(customRenderer.brandingConfig.colors.primary).toBe('#FF0000');
  });

  // ==================== FULL REPORT RENDERING TESTS ====================

  test('should render complete enhanced report', () => {
    const html = renderer.renderEnhancedReport(mockEnhancement, { theme: 'dark' });

    expect(html).toBeDefined();
    expect(typeof html).toBe('string');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
    expect(html).toContain('APT-28 Campaign Analysis');
  });

  test('should render report with light theme', () => {
    const html = renderer.renderEnhancedReport(mockEnhancement, { theme: 'light' });

    expect(html).toBeDefined();
    expect(html).toContain('data-theme="light"');
  });

  test('should render report with dark theme', () => {
    const html = renderer.renderEnhancedReport(mockEnhancement, { theme: 'dark' });

    expect(html).toBeDefined();
    expect(html).toContain('data-theme="dark"');
  });

  test('should render responsive report', () => {
    const html = renderer.renderEnhancedReport(mockEnhancement, { responsive: true });

    expect(html).toContain('@media');
    expect(html).toContain('max-width');
  });

  // ==================== COVER PAGE TESTS ====================

  test('should render cover page', () => {
    const html = renderer.renderCoverPage(mockEnhancement.presentationEnhancements.coverPage);

    expect(html).toContain('cover-page');
    expect(html).toContain('APT-28 Campaign Analysis');
    expect(html).toContain('TLP:AMBER');
    expect(html).toContain('85');
    expect(html).toContain('CRITICAL');
  });

  test('should render threat score on cover page', () => {
    const html = renderer.renderCoverPage(mockEnhancement.presentationEnhancements.coverPage);

    expect(html).toContain('threat-score-box');
    expect(html).toContain('Threat Score');
  });

  test('should render threat actors on cover page', () => {
    const html = renderer.renderCoverPage(mockEnhancement.presentationEnhancements.coverPage);

    expect(html).toContain('APT-28');
  });

  test('should render affected industries on cover page', () => {
    const html = renderer.renderCoverPage(mockEnhancement.presentationEnhancements.coverPage);

    expect(html).toContain('government');
    expect(html).toContain('technology');
  });

  // ==================== DASHBOARD HEADER TESTS ====================

  test('should render dashboard header', () => {
    const html = renderer.renderDashboardHeader(mockEnhancement.presentationEnhancements.dashboardHeader);

    expect(html).toContain('dashboard-header');
    expect(html).toContain('Operational Intelligence Dashboard');
    expect(html).toContain('widgets-grid');
  });

  test('should render all dashboard widgets', () => {
    const html = renderer.renderDashboardHeader(mockEnhancement.presentationEnhancements.dashboardHeader);

    expect(html).toContain('Threat Level');
    expect(html).toContain('Confidence');
    expect(html).toContain('Business Risk');
  });

  test('should render widget values', () => {
    const html = renderer.renderDashboardHeader(mockEnhancement.presentationEnhancements.dashboardHeader);

    expect(html).toContain('CRITICAL');
    expect(html).toContain('85%');
    expect(html).toContain('HIGH');
  });

  // ==================== EXECUTIVE CARDS TESTS ====================

  test('should render executive cards', () => {
    const html = renderer.renderExecutiveCards(mockEnhancement.presentationEnhancements.executiveCards);

    expect(html).toContain('executive-cards');
    expect(html).toContain('cards-grid');
  });

  test('should render card categories', () => {
    const html = renderer.renderExecutiveCards(mockEnhancement.presentationEnhancements.executiveCards);

    expect(html).toContain('threat-summary');
    expect(html).toContain('business-impact');
  });

  test('should render card content', () => {
    const html = renderer.renderExecutiveCards(mockEnhancement.presentationEnhancements.executiveCards);

    expect(html).toContain('Threat Overview');
    expect(html).toContain('Business Impact');
    expect(html).toContain('APT-28 Campaign Analysis');
  });

  test('should handle empty card list', () => {
    const html = renderer.renderExecutiveCards([]);

    expect(html).toBe('');
  });

  // ==================== EVIDENCE GALLERY TESTS ====================

  test('should render evidence gallery', () => {
    const html = renderer.renderEvidenceGallery(mockEnhancement.presentationEnhancements.evidenceGallery);

    expect(html).toContain('evidence-gallery');
    expect(html).toContain('Evidence Gallery');
  });

  test('should render gallery sections', () => {
    const html = renderer.renderEvidenceGallery(mockEnhancement.presentationEnhancements.evidenceGallery);

    expect(html).toContain('Key Findings');
    expect(html).toContain('Indicators of Compromise');
  });

  test('should render gallery section counts', () => {
    const html = renderer.renderEvidenceGallery(mockEnhancement.presentationEnhancements.evidenceGallery);

    expect(html).toContain('3 items');
    expect(html).toContain('2 items');
  });

  test('should render gallery items', () => {
    const html = renderer.renderEvidenceGallery(mockEnhancement.presentationEnhancements.evidenceGallery);

    expect(html).toContain('Evidence of targeting');
    expect(html).toContain('192.168.1.1');
  });

  // ==================== DIAGRAMS TESTS ====================

  test('should render diagrams section', () => {
    const html = renderer.renderDiagrams(mockEnhancement.presentationEnhancements.interactiveDiagrams);

    expect(html).toContain('diagrams-section');
    expect(html).toContain('Intelligence Visualizations');
  });

  test('should render diagram types', () => {
    const html = renderer.renderDiagrams(mockEnhancement.presentationEnhancements.interactiveDiagrams);

    expect(html).toContain('kill-chain');
    expect(html).toContain('mitre-matrix');
  });

  test('should render diagram titles', () => {
    const html = renderer.renderDiagrams(mockEnhancement.presentationEnhancements.interactiveDiagrams);

    expect(html).toContain('Kill Chain Analysis');
    expect(html).toContain('MITRE ATT');
  });

  // ==================== DECISION CENTER TESTS ====================

  test('should render decision center', () => {
    const html = renderer.renderDecisionCenter(mockEnhancement.presentationEnhancements.decisionCenter);

    expect(html).toContain('decision-center');
    expect(html).toContain('Executive Decision Center');
  });

  test('should render audience panels', () => {
    const html = renderer.renderDecisionCenter(mockEnhancement.presentationEnhancements.decisionCenter);

    expect(html).toContain('CEO Decisions');
    expect(html).toContain('CISO Decisions');
  });

  test('should render audience decisions', () => {
    const html = renderer.renderDecisionCenter(mockEnhancement.presentationEnhancements.decisionCenter);

    expect(html).toContain('Business Continuity');
    expect(html).toContain('Incident Response');
  });

  test('should render audience metrics', () => {
    const html = renderer.renderDecisionCenter(mockEnhancement.presentationEnhancements.decisionCenter);

    expect(html).toContain('Revenue Impact');
    expect(html).toContain('Threat Level');
  });

  // ==================== CSS GENERATION TESTS ====================

  test('should generate CSS for dark theme', () => {
    const css = renderer.generateCSS('dark');

    expect(css).toBeDefined();
    expect(typeof css).toBe('string');
    expect(css).toContain('--bg-color:');
    expect(css).toContain('--fg-color:');
  });

  test('should generate CSS for light theme', () => {
    const css = renderer.generateCSS('light');

    expect(css).toBeDefined();
    expect(css).toContain('--bg-color:');
  });

  test('should include responsive styles', () => {
    const css = renderer.generateCSS('dark', true);

    expect(css).toContain('@media');
    expect(css).toContain('max-width: 1024px');
    expect(css).toContain('max-width: 640px');
  });

  test('should cache CSS', () => {
    const css1 = renderer.generateCSS('dark', true);
    const css2 = renderer.generateCSS('dark', true);

    expect(css1).toBe(css2);
    expect(renderer.cssCache.size).toBeGreaterThan(0);
  });

  // ==================== HTML ESCAPING TESTS ====================

  test('should escape HTML entities', () => {
    const escaped = renderer.escapeHtml('<script>alert("xss")</script>');

    expect(escaped).toContain('&lt;');
    expect(escaped).toContain('&gt;');
    expect(escaped).not.toContain('<script>');
  });

  test('should handle null input for escaping', () => {
    const escaped = renderer.escapeHtml(null);

    expect(escaped).toBe('');
  });

  // ==================== COLOR UTILITY TESTS ====================

  test('should return correct threat color for score', () => {
    expect(renderer.getThreatColor(85)).toBe('#E74C3C');
    expect(renderer.getThreatColor(65)).toBe('#E67E22');
    expect(renderer.getThreatColor(45)).toBe('#F39C12');
    expect(renderer.getThreatColor(15)).toBe('#2ECC71');
  });

  test('should return correct threat level color', () => {
    expect(renderer.getThreatLevelColor('CRITICAL')).toBe('#E74C3C');
    expect(renderer.getThreatLevelColor('HIGH')).toBe('#E67E22');
    expect(renderer.getThreatLevelColor('MEDIUM')).toBe('#F39C12');
    expect(renderer.getThreatLevelColor('LOW')).toBe('#2ECC71');
  });

  test('should return correct severity color', () => {
    expect(renderer.getSeverityColor('critical')).toBe('#E74C3C');
    expect(renderer.getSeverityColor('high')).toBe('#E67E22');
    expect(renderer.getSeverityColor('medium')).toBe('#F39C12');
  });

  // ==================== ICON UTILITY TESTS ====================

  test('should provide widget icons', () => {
    expect(renderer.getWidgetIcon('alert')).toBe('⚠️');
    expect(renderer.getWidgetIcon('check-circle')).toBe('✓');
    expect(renderer.getWidgetIcon('shield')).toBe('🛡️');
  });

  test('should provide card icons', () => {
    expect(renderer.getCardIcon('alert-triangle')).toBe('⚠️');
    expect(renderer.getCardIcon('bar-chart-2')).toBe('📊');
  });

  // ==================== HUMANIZATION TESTS ====================

  test('should humanize camelCase keys', () => {
    expect(renderer.humanizeKey('threatLevel')).toBe('Threat Level');
    expect(renderer.humanizeKey('businessImpact')).toBe('Business Impact');
    expect(renderer.humanizeKey('affectedSectors')).toBe('Affected Sectors');
  });

  // ==================== DOCUMENT WRAPPING TESTS ====================

  test('should wrap HTML in complete document', () => {
    const html = '<p>Test</p>';
    const css = 'body { color: red; }';
    const document = renderer.wrapInDocument(html, css, 'dark');

    expect(document).toContain('<!DOCTYPE html>');
    expect(document).toContain('<html');
    expect(document).toContain('<head>');
    expect(document).toContain('<style>');
    expect(document).toContain(css);
    expect(document).toContain('<body>');
    expect(document).toContain(html);
    expect(document).toContain('</html>');
  });

  // ==================== INTEGRATION TESTS ====================

  test('should render complete report without errors', () => {
    const html = renderer.renderEnhancedReport(mockEnhancement);

    expect(html).toBeDefined();
    expect(html.length).toBeGreaterThan(1000);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('report-container');
  });

  test('should handle enhancement with minimal sections', () => {
    const minimalEnhancement = {
      productId: 'minimal',
      presentationEnhancements: {},
    };

    const html = renderer.renderEnhancedReport(minimalEnhancement);

    expect(html).toBeDefined();
    expect(html).toContain('<!DOCTYPE html>');
  });
});
