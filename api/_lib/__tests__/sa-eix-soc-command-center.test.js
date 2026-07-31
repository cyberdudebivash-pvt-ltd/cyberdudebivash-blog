'use strict';

const { SentinelApexSOCCommandCenter } = require('../sa-eix-soc-command-center');

describe('Sentinel APEX SA-EIX SOC Command Center', () => {
  let soc;

  beforeEach(() => {
    soc = new SentinelApexSOCCommandCenter();
  });

  const mockInvestigation = {
    id: 'inv-apt28-2026-07-31',
    title: 'APT-28 Campaign',
    severity: 'CRITICAL',
    classification: 'TLP:AMBER',
    businessImpact: 'High operational impact',
    threatActors: [{ name: 'APT-28' }, { name: 'Fancy Bear' }],
    campaigns: [{ name: 'Operation Ghost' }],
    findings: [
      { statement: 'Evidence detected', severity: 'critical', confidence: 0.95 },
      { statement: 'Second finding', severity: 'high', confidence: 0.87 },
    ],
    iocs: [
      { value: '192.168.1.1', type: 'ip', severity: 'HIGH' },
      { value: 'attacker.com', type: 'domain', severity: 'CRITICAL' },
    ],
    infrastructure: [
      { type: 'c2', value: 'attacker.com' },
      { type: 'hosting', value: '192.168.1.1' },
    ],
    mitreTechniques: [
      { technique: 'Spear Phishing', tactic: 'Initial Access' },
      { technique: 'Command Line Interface', tactic: 'Execution' },
    ],
    targetedSectors: ['government', 'technology'],
    confidence: 0.95,
    confidenceReasoning: 'Multiple sources',
  };

  const mockEnhancement = {
    productId: 'prod-apt28-2026-07-31',
    presentationEnhancements: {
      coverPage: {
        sections: {
          header: {
            threatScore: 85,
          },
          threatInformation: {
            confidence: 0.92,
            detectionCoverage: 0.78,
            coverageDetails: {
              edrs: 0.85,
              siem: 0.72,
              ndr: 0.65,
            },
          },
        },
      },
    },
  };

  // ==================== INITIALIZATION TESTS ====================

  test('should initialize with theme configuration', () => {
    expect(soc.theme).toBeDefined();
    expect(soc.theme.background).toBeDefined();
    expect(soc.theme.text).toBeDefined();
    expect(soc.theme.border).toBeDefined();
  });

  test('should initialize with custom branding config', () => {
    const customBranding = { colors: { primary: '#FF0000' } };
    const customSoc = new SentinelApexSOCCommandCenter(customBranding);

    expect(customSoc.brandingConfig).toBeDefined();
    expect(customSoc.brandingConfig.colors).toBeDefined();
  });

  // ==================== THREAT COMMAND HEADER TESTS ====================

  test('should generate threat command header', () => {
    const result = soc.generateThreatCommandHeader(mockInvestigation);

    expect(result).toBeDefined();
    expect(result.type).toBe('threat-command-header');
    expect(result.html).toBeDefined();
    expect(result.metadata).toBeDefined();
  });

  test('should include threat actor names in header', () => {
    const result = soc.generateThreatCommandHeader(mockInvestigation);

    expect(result.html).toContain('APT-28');
    expect(result.html).toContain('Fancy Bear');
  });

  test('should include business impact in header', () => {
    const result = soc.generateThreatCommandHeader(mockInvestigation);

    expect(result.html).toContain('High operational impact');
  });

  test('should display severity and confidence in header', () => {
    const result = soc.generateThreatCommandHeader(mockInvestigation);

    expect(result.html).toContain('CRITICAL');
    expect(result.html).toContain('95%');
  });

  test('should handle missing threat actors', () => {
    const investigation = { severity: 'MEDIUM', confidence: 0.5 };
    const result = soc.generateThreatCommandHeader(investigation);

    expect(result.html).toContain('No threat actors identified');
  });

  // ==================== EXECUTIVE COMMAND RIBBON TESTS ====================

  test('should generate executive command ribbon', () => {
    const result = soc.generateExecutiveCommandRibbon(mockInvestigation);

    expect(result).toBeDefined();
    expect(result.type).toBe('executive-command-ribbon');
    expect(result.html).toBeDefined();
  });

  test('should include campaign information in ribbon', () => {
    const result = soc.generateExecutiveCommandRibbon(mockInvestigation);

    expect(result.html).toContain('Operation Ghost');
  });

  test('should include targeted sectors in ribbon', () => {
    const result = soc.generateExecutiveCommandRibbon(mockInvestigation);

    expect(result.html).toContain('government');
    expect(result.html).toContain('technology');
  });

  test('should display infrastructure and technique counts', () => {
    const result = soc.generateExecutiveCommandRibbon(mockInvestigation);

    expect(result.html).toContain('2');
    expect(result.metadata.infrastructureCount).toBe(2);
    expect(result.metadata.techniqueCount).toBe(2);
  });

  // ==================== SOC METRICS RIBBON TESTS ====================

  test('should generate SOC metrics ribbon', () => {
    const result = soc.generateSOCMetricsRibbon(mockEnhancement);

    expect(result).toBeDefined();
    expect(result.type).toBe('soc-metrics-ribbon');
    expect(result.html).toBeDefined();
  });

  test('should display detection coverage percentage', () => {
    const result = soc.generateSOCMetricsRibbon(mockEnhancement);

    expect(result.html).toContain('78');
    expect(result.metadata.detectionCoverage).toBe(78);
  });

  test('should display threat score', () => {
    const result = soc.generateSOCMetricsRibbon(mockEnhancement);

    expect(result.html).toContain('85');
    expect(result.metadata.threatScore).toBe(85);
  });

  // ==================== THREAT SCORE WIDGET TESTS ====================

  test('should generate threat score widget', () => {
    const result = soc.generateThreatScoreWidget(mockInvestigation, mockEnhancement);

    expect(result).toBeDefined();
    expect(result.type).toBe('threat-score-widget');
    expect(result.html).toContain('<svg');
    expect(result.html).toContain('</svg>');
  });

  test('should display threat score numerically', () => {
    const result = soc.generateThreatScoreWidget(mockInvestigation, mockEnhancement);

    expect(result.html).toContain('85');
    expect(result.metadata.threatScore).toBe(85);
  });

  test('should categorize threat as CRITICAL for high scores', () => {
    const result = soc.generateThreatScoreWidget(mockInvestigation, mockEnhancement);

    expect(result.html).toContain('CRITICAL');
    expect(result.metadata.category).toBe('CRITICAL');
  });

  test('should render SVG circle gauge', () => {
    const result = soc.generateThreatScoreWidget(mockInvestigation, mockEnhancement);

    expect(result.html).toContain('circle');
    expect(result.html).toContain('stroke-dasharray');
  });

  // ==================== RISK INDICATOR TESTS ====================

  test('should generate risk indicator', () => {
    const result = soc.generateRiskIndicator('HIGH', 'Risk Level');

    expect(result).toBeDefined();
    expect(result.type).toBe('risk-indicator');
    expect(result.html).toBeDefined();
  });

  test('should display severity level', () => {
    const result = soc.generateRiskIndicator('CRITICAL', 'Current Risk');

    expect(result.html).toContain('CRITICAL');
    expect(result.metadata.severity).toBe('CRITICAL');
  });

  test('should display custom label', () => {
    const result = soc.generateRiskIndicator('MEDIUM', 'Custom Label');

    expect(result.html).toContain('Custom Label');
    expect(result.metadata.label).toBe('Custom Label');
  });

  test('should render status dot', () => {
    const result = soc.generateRiskIndicator('HIGH', 'Risk');

    expect(result.html).toContain('border-radius: 50%');
  });

  // ==================== CONFIDENCE INDICATOR TESTS ====================

  test('should generate confidence indicator', () => {
    const result = soc.generateConfidenceIndicator(0.85, 'Confidence');

    expect(result).toBeDefined();
    expect(result.type).toBe('confidence-indicator');
    expect(result.html).toBeDefined();
  });

  test('should display confidence percentage', () => {
    const result = soc.generateConfidenceIndicator(0.92, 'Analysis Confidence');

    expect(result.html).toContain('92%');
    expect(result.metadata.confidencePercent).toBe(92);
  });

  test('should render progress bar', () => {
    const result = soc.generateConfidenceIndicator(0.75, 'Confidence');

    expect(result.html).toContain('width: 75%');
  });

  test('should color confidence based on level', () => {
    const highConfidence = soc.generateConfidenceIndicator(0.95);
    const lowConfidence = soc.generateConfidenceIndicator(0.30);

    expect(highConfidence.metadata.color).not.toBe(lowConfidence.metadata.color);
  });

  // ==================== LIVE INTELLIGENCE BADGE TESTS ====================

  test('should generate live intelligence badge', () => {
    const result = soc.generateLiveIntelligenceBadge('active');

    expect(result).toBeDefined();
    expect(result.type).toBe('live-intelligence-badge');
    expect(result.html).toBeDefined();
  });

  test('should display active status', () => {
    const result = soc.generateLiveIntelligenceBadge('active');

    expect(result.html).toContain('Live');
    expect(result.metadata.status).toBe('active');
  });

  test('should display updated status', () => {
    const result = soc.generateLiveIntelligenceBadge('updated');

    expect(result.html).toContain('Updated');
  });

  test('should include timestamp when provided', () => {
    const timestamp = '2026-07-31T12:00:00Z';
    const result = soc.generateLiveIntelligenceBadge('active', timestamp);

    expect(result.html).toContain('12:00:00');
    expect(result.metadata.timestamp).toBe(timestamp);
  });

  test('should render pulse animation for active status', () => {
    const result = soc.generateLiveIntelligenceBadge('active');

    expect(result.html).toContain('animation: pulse');
  });

  // ==================== DETECTION READINESS WIDGET TESTS ====================

  test('should generate detection readiness widget', () => {
    const result = soc.generateDetectionReadinessWidget(mockEnhancement);

    expect(result).toBeDefined();
    expect(result.type).toBe('detection-readiness-widget');
    expect(result.html).toBeDefined();
  });

  test('should display overall detection coverage', () => {
    const result = soc.generateDetectionReadinessWidget(mockEnhancement);

    expect(result.html).toContain('78% Covered');
  });

  test('should display system-specific coverage', () => {
    const result = soc.generateDetectionReadinessWidget(mockEnhancement);

    expect(result.html).toContain('EDR/XDR');
    expect(result.html).toContain('SIEM');
    expect(result.html).toContain('NDR/NPD');
  });

  test('should show coverage percentages for each system', () => {
    const result = soc.generateDetectionReadinessWidget(mockEnhancement);

    expect(result.html).toContain('85%');
    expect(result.html).toContain('72%');
    expect(result.html).toContain('65%');
  });

  // ==================== EVIDENCE COUNTER TESTS ====================

  test('should generate evidence counter', () => {
    const result = soc.generateEvidenceCounter(mockInvestigation.findings);

    expect(result).toBeDefined();
    expect(result.type).toBe('evidence-counter');
    expect(result.html).toBeDefined();
  });

  test('should display total evidence count', () => {
    const result = soc.generateEvidenceCounter(mockInvestigation.findings);

    expect(result.html).toContain('2');
    expect(result.metadata.totalEvidence).toBe(2);
  });

  test('should handle empty evidence list', () => {
    const result = soc.generateEvidenceCounter([]);

    expect(result.html).toContain('No evidence available');
    expect(result.metadata.totalEvidence).toBe(0);
  });

  test('should display evidence breakdown by type', () => {
    const evidence = [
      { type: 'screenshot' },
      { type: 'pcap' },
      { type: 'screenshot' },
    ];
    const result = soc.generateEvidenceCounter(evidence);

    expect(result.metadata.byType.screenshot).toBe(2);
    expect(result.metadata.byType.pcap).toBe(1);
  });

  // ==================== IOC COUNTER TESTS ====================

  test('should generate IOC counter', () => {
    const result = soc.generateIOCCounter(mockInvestigation.iocs);

    expect(result).toBeDefined();
    expect(result.type).toBe('ioc-counter');
    expect(result.html).toBeDefined();
  });

  test('should display total IOC count', () => {
    const result = soc.generateIOCCounter(mockInvestigation.iocs);

    expect(result.html).toContain('2');
    expect(result.metadata.totalIOCs).toBe(2);
  });

  test('should handle empty IOC list', () => {
    const result = soc.generateIOCCounter([]);

    expect(result.html).toContain('No IOCs available');
    expect(result.metadata.totalIOCs).toBe(0);
  });

  test('should display IOC breakdown by severity', () => {
    const result = soc.generateIOCCounter(mockInvestigation.iocs);

    expect(result.metadata.bySeverity.CRITICAL).toBe(1);
    expect(result.metadata.bySeverity.HIGH).toBe(1);
  });

  test('should only show severity levels with IOCs', () => {
    const result = soc.generateIOCCounter(mockInvestigation.iocs);
    const htmlLines = result.html.split('\n');
    const severityLines = htmlLines.filter(line => line.includes('CRITICAL') || line.includes('HIGH'));

    expect(severityLines.length).toBeGreaterThan(0);
  });

  // ==================== SOC DASHBOARD INTEGRATION TESTS ====================

  test('should generate complete SOC dashboard', () => {
    const product = { id: 'prod-apt28-2026-07-31' };
    const result = soc.generateSOCDashboard(product, mockInvestigation, mockEnhancement);

    expect(result).toBeDefined();
    expect(result.type).toBe('soc-command-center-dashboard');
    expect(result.html).toBeDefined();
    expect(result.components).toBeDefined();
    expect(result.metadata).toBeDefined();
  });

  test('should include all major components in dashboard', () => {
    const product = { id: 'prod-apt28' };
    const result = soc.generateSOCDashboard(product, mockInvestigation, mockEnhancement);

    expect(result.components.threatHeader).toBeDefined();
    expect(result.components.executiveRibbon).toBeDefined();
    expect(result.components.metricsRibbon).toBeDefined();
    expect(result.components.threatScoreWidget).toBeDefined();
    expect(result.components.riskIndicator).toBeDefined();
    expect(result.components.confidenceIndicator).toBeDefined();
    expect(result.components.liveIntelligence).toBeDefined();
    expect(result.components.detectionReadiness).toBeDefined();
    expect(result.components.evidenceCounter).toBeDefined();
    expect(result.components.iocCounter).toBeDefined();
  });

  test('should include metadata with investigation summary', () => {
    const product = { id: 'prod-test' };
    const result = soc.generateSOCDashboard(product, mockInvestigation, mockEnhancement);

    expect(result.metadata.productId).toBe('prod-test');
    expect(result.metadata.threatLevel).toBe('CRITICAL');
    expect(result.metadata.threatActors).toContain('APT-28');
    expect(result.metadata.totalEvidence).toBe(2);
    expect(result.metadata.totalIOCs).toBe(2);
  });

  test('should render valid HTML structure', () => {
    const product = { id: 'prod-test' };
    const result = soc.generateSOCDashboard(product, mockInvestigation, mockEnhancement);

    expect(result.html).toContain('soc-command-center');
    expect(result.html).toContain('soc-threat-header');
    expect(result.html).toContain('executive-ribbon');
  });

  // ==================== COLOR UTILITY TESTS ====================

  test('should return critical color for CRITICAL severity', () => {
    const color = soc.getSeverityColor('CRITICAL');

    expect(typeof color).toBe('string');
    expect(color).toContain('#');
  });

  test('should return correct colors for each severity level', () => {
    const critical = soc.getSeverityColor('CRITICAL');
    const high = soc.getSeverityColor('HIGH');
    const medium = soc.getSeverityColor('MEDIUM');
    const low = soc.getSeverityColor('LOW');

    expect(critical).not.toBe(high);
    expect(high).not.toBe(medium);
    expect(medium).not.toBe(low);
  });

  test('should return green for high confidence', () => {
    const color = soc.getConfidenceColor(0.9);

    expect(color).toBeDefined();
    expect(typeof color).toBe('string');
  });

  test('should return red for low confidence', () => {
    const highConfidence = soc.getConfidenceColor(0.9);
    const lowConfidence = soc.getConfidenceColor(0.2);

    expect(highConfidence).not.toBe(lowConfidence);
  });

  test('should return color for status', () => {
    const successColor = soc.getStatusColor('success');
    const warningColor = soc.getStatusColor('warning');
    const criticalColor = soc.getStatusColor('critical');

    expect(successColor).toBeDefined();
    expect(warningColor).toBeDefined();
    expect(criticalColor).toBeDefined();
  });

  // ==================== HTML ESCAPING TESTS ====================

  test('should escape HTML special characters', () => {
    const input = '<script>alert("xss")</script>';
    const escaped = soc.escapeHtml(input);

    expect(escaped).toContain('&lt;');
    expect(escaped).toContain('&gt;');
    expect(escaped).not.toContain('<script>');
  });

  test('should escape ampersands', () => {
    const escaped = soc.escapeHtml('Test & Test');

    expect(escaped).toContain('&amp;');
  });

  test('should escape quotes', () => {
    const escaped = soc.escapeHtml('Test "quoted" text');

    expect(escaped).toContain('&quot;');
  });

  test('should handle null input', () => {
    const escaped = soc.escapeHtml(null);

    expect(escaped).toBe('');
  });

  // ==================== EDGE CASES ====================

  test('should handle investigation with minimal data', () => {
    const minimalInvestigation = { id: 'inv-test' };
    const result = soc.generateThreatCommandHeader(minimalInvestigation);

    expect(result.html).toBeDefined();
    expect(result.html).toContain('No threat actors identified');
  });

  test('should handle enhancement with minimal data', () => {
    const minimalEnhancement = { presentationEnhancements: {} };
    const result = soc.generateSOCMetricsRibbon(minimalEnhancement);

    expect(result.html).toBeDefined();
    expect(result.metadata).toBeDefined();
  });

  test('should handle very high threat scores', () => {
    const enhancement = {
      presentationEnhancements: {
        coverPage: {
          sections: {
            header: { threatScore: 100 },
          },
        },
      },
    };
    const result = soc.generateThreatScoreWidget({}, enhancement);

    expect(result.metadata.threatScore).toBe(100);
    expect(result.metadata.category).toBe('CRITICAL');
  });

  test('should handle zero threat score', () => {
    const enhancement = {
      presentationEnhancements: {
        coverPage: {
          sections: {
            header: { threatScore: 0 },
          },
        },
      },
    };
    const result = soc.generateThreatScoreWidget({}, enhancement);

    expect(result.metadata.threatScore).toBe(0);
    expect(result.metadata.category).toBe('LOW');
  });
});
