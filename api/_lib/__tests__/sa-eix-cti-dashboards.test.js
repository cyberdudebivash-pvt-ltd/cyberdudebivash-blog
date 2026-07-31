'use strict';

const { SentinelApexCTIDashboards } = require('../sa-eix-cti-dashboards');

describe('Sentinel APEX SA-EIX Enterprise CTI Dashboards', () => {
  let cti;

  beforeEach(() => {
    cti = new SentinelApexCTIDashboards();
  });

  const mockInvestigation = {
    id: 'inv-apt28-2026-07-31',
    severity: 'CRITICAL',
    threatActors: [
      { name: 'APT-28', aliases: ['Fancy Bear'], confidence: 0.95, active: true, origin: 'Russia', targetSectors: ['government', 'defense'] },
      { name: 'APT-29', aliases: ['Cozy Bear'], confidence: 0.90, active: true, origin: 'Russia', targetSectors: ['government', 'technology'] },
    ],
    campaigns: [
      { name: 'Operation Ghost', startDate: '2026-01-15', status: 'Active', description: 'Large-scale phishing campaign' },
      { name: 'Campaign Scorpion', startDate: '2026-03-10', status: 'Ongoing' },
    ],
    targetedSectors: ['government', 'technology', 'defense', 'finance'],
    targetedCountries: ['US', 'UK', 'Canada', 'Australia'],
    infrastructure: [
      { type: 'c2', value: 'attacker.com' },
      { type: 'c2', value: 'c2.evil.com' },
      { type: 'hosting', value: '192.168.1.1' },
      { type: 'domain', value: 'phishing.xyz' },
    ],
    malware: [
      { name: 'NotPetya', type: 'ransomware', family: 'Petya' },
      { name: 'Mirai', type: 'botnet', family: 'IoT' },
      { name: 'Emotet', type: 'trojan', family: 'Banking' },
    ],
    mitreTechniques: [
      { tactic: 'Initial Access', technique: 'Spear Phishing' },
      { tactic: 'Initial Access', technique: 'Supply Chain Compromise' },
      { tactic: 'Execution', technique: 'PowerShell' },
      { tactic: 'Persistence', technique: 'Registry Run Keys' },
    ],
    findings: [
      { type: 'screenshot', status: 'verified', severity: 'critical', confidence: 0.95 },
      { type: 'pcap', status: 'verified', severity: 'high', confidence: 0.92 },
      { type: 'log', status: 'suspected', severity: 'medium', confidence: 0.75 },
      { type: 'report', status: 'unconfirmed', severity: 'low', confidence: 0.60 },
    ],
    metadata: {
      quality: 'high',
      lastUpdated: '2026-07-31T12:00:00Z',
      sources: 15,
      verifiedClaims: 8,
    },
  };

  const mockProduct = {
    id: 'prod-apt28-2026-07-31',
  };

  // ==================== INITIALIZATION TESTS ====================

  test('should initialize with theme configuration', () => {
    expect(cti.theme).toBeDefined();
    expect(cti.designTokens).toBeDefined();
  });

  // ==================== THREAT LANDSCAPE TESTS ====================

  test('should generate threat landscape', () => {
    const result = cti.generateThreatLandscape(mockInvestigation);

    expect(result).toBeDefined();
    expect(result.type).toBe('threat-landscape');
    expect(result.html).toBeDefined();
    expect(result.metadata).toBeDefined();
  });

  test('should display overall severity', () => {
    const result = cti.generateThreatLandscape(mockInvestigation);

    expect(result.html).toContain('CRITICAL');
    expect(result.metadata.severity).toBe('CRITICAL');
  });

  test('should display threat actor count', () => {
    const result = cti.generateThreatLandscape(mockInvestigation);

    expect(result.metadata.threatActorCount).toBe(2);
    expect(result.html).toContain('2');
  });

  test('should display target sectors', () => {
    const result = cti.generateThreatLandscape(mockInvestigation);

    expect(result.html).toContain('government');
    expect(result.html).toContain('technology');
  });

  test('should handle missing investigation data', () => {
    const result = cti.generateThreatLandscape({});

    expect(result.html).toBeDefined();
    expect(result.metadata.threatActorCount).toBe(0);
  });

  // ==================== CAMPAIGN STATUS TESTS ====================

  test('should generate campaign status', () => {
    const result = cti.generateCampaignStatus(mockInvestigation.campaigns);

    expect(result).toBeDefined();
    expect(result.type).toBe('campaign-status');
    expect(result.html).toBeDefined();
  });

  test('should display campaign names', () => {
    const result = cti.generateCampaignStatus(mockInvestigation.campaigns);

    expect(result.html).toContain('Operation Ghost');
    expect(result.html).toContain('Campaign Scorpion');
  });

  test('should display campaign status badges', () => {
    const result = cti.generateCampaignStatus(mockInvestigation.campaigns);

    expect(result.html).toContain('Active');
    expect(result.html).toContain('Ongoing');
  });

  test('should display campaign start dates', () => {
    const result = cti.generateCampaignStatus(mockInvestigation.campaigns);

    expect(result.html).toContain('2026-01-15');
    expect(result.html).toContain('2026-03-10');
  });

  test('should handle empty campaign list', () => {
    const result = cti.generateCampaignStatus([]);

    expect(result.html).toContain('No campaigns identified');
  });

  // ==================== THREAT ACTOR ACTIVITY TESTS ====================

  test('should generate threat actor activity', () => {
    const result = cti.generateThreatActorActivity(mockInvestigation.threatActors);

    expect(result).toBeDefined();
    expect(result.type).toBe('threat-actor-activity');
    expect(result.html).toBeDefined();
  });

  test('should display threat actor names', () => {
    const result = cti.generateThreatActorActivity(mockInvestigation.threatActors);

    expect(result.html).toContain('APT-28');
    expect(result.html).toContain('APT-29');
  });

  test('should display aliases', () => {
    const result = cti.generateThreatActorActivity(mockInvestigation.threatActors);

    expect(result.html).toContain('Fancy Bear');
    expect(result.html).toContain('Cozy Bear');
  });

  test('should display confidence levels', () => {
    const result = cti.generateThreatActorActivity(mockInvestigation.threatActors);

    expect(result.html).toContain('95%');
    expect(result.html).toContain('90%');
  });

  test('should display active status', () => {
    const result = cti.generateThreatActorActivity(mockInvestigation.threatActors);

    expect(result.html).toContain('Active');
    expect(result.metadata.activeActors).toBe(2);
  });

  test('should handle empty actor list', () => {
    const result = cti.generateThreatActorActivity([]);

    expect(result.html).toContain('No threat actors identified');
  });

  // ==================== VICTIM DISTRIBUTION TESTS ====================

  test('should generate victim distribution', () => {
    const result = cti.generateVictimDistribution(mockInvestigation);

    expect(result).toBeDefined();
    expect(result.type).toBe('victim-distribution');
    expect(result.html).toBeDefined();
  });

  test('should display sector counts', () => {
    const result = cti.generateVictimDistribution(mockInvestigation);

    expect(result.html).toContain('4');
    expect(result.metadata.targetSectorCount).toBe(4);
  });

  test('should display country count', () => {
    const result = cti.generateVictimDistribution(mockInvestigation);

    expect(result.html).toContain('4');
    expect(result.metadata.targetCountryCount).toBe(4);
  });

  test('should display target sectors', () => {
    const result = cti.generateVictimDistribution(mockInvestigation);

    expect(result.html).toContain('government');
    expect(result.html).toContain('technology');
  });

  // ==================== INFRASTRUCTURE SUMMARY TESTS ====================

  test('should generate infrastructure summary', () => {
    const result = cti.generateInfrastructureSummary(mockInvestigation.infrastructure);

    expect(result).toBeDefined();
    expect(result.type).toBe('infrastructure-summary');
    expect(result.html).toBeDefined();
  });

  test('should display total infrastructure nodes', () => {
    const result = cti.generateInfrastructureSummary(mockInvestigation.infrastructure);

    expect(result.html).toContain('4');
    expect(result.metadata.totalNodes).toBe(4);
  });

  test('should display infrastructure type counts', () => {
    const result = cti.generateInfrastructureSummary(mockInvestigation.infrastructure);

    expect(result.metadata.byType.c2).toBe(2);
    expect(result.metadata.byType.hosting).toBe(1);
  });

  test('should handle empty infrastructure list', () => {
    const result = cti.generateInfrastructureSummary([]);

    expect(result.html).toContain('No infrastructure nodes identified');
  });

  // ==================== MALWARE SUMMARY TESTS ====================

  test('should generate malware summary', () => {
    const result = cti.generateMalwareSummary(mockInvestigation.malware);

    expect(result).toBeDefined();
    expect(result.type).toBe('malware-summary');
    expect(result.html).toBeDefined();
  });

  test('should display malware count', () => {
    const result = cti.generateMalwareSummary(mockInvestigation.malware);

    expect(result.html).toContain('3');
    expect(result.metadata.totalMalware).toBe(3);
  });

  test('should display malware names', () => {
    const result = cti.generateMalwareSummary(mockInvestigation.malware);

    expect(result.html).toContain('NotPetya');
    expect(result.html).toContain('Mirai');
    expect(result.html).toContain('Emotet');
  });

  test('should display malware types', () => {
    const result = cti.generateMalwareSummary(mockInvestigation.malware);

    expect(result.html).toContain('ransomware');
    expect(result.html).toContain('botnet');
    expect(result.html).toContain('trojan');
  });

  test('should handle empty malware list', () => {
    const result = cti.generateMalwareSummary([]);

    expect(result.html).toContain('No malware identified');
  });

  // ==================== MITRE COVERAGE TESTS ====================

  test('should generate MITRE coverage', () => {
    const result = cti.generateMITRECoverage(mockInvestigation.mitreTechniques);

    expect(result).toBeDefined();
    expect(result.type).toBe('mitre-coverage');
    expect(result.html).toBeDefined();
  });

  test('should display tactic count', () => {
    const result = cti.generateMITRECoverage(mockInvestigation.mitreTechniques);

    expect(result.metadata.tacticCount).toBe(3);
  });

  test('should display tactics', () => {
    const result = cti.generateMITRECoverage(mockInvestigation.mitreTechniques);

    expect(result.html).toContain('Initial Access');
    expect(result.html).toContain('Execution');
    expect(result.html).toContain('Persistence');
  });

  test('should display techniques under tactics', () => {
    const result = cti.generateMITRECoverage(mockInvestigation.mitreTechniques);

    expect(result.html).toContain('Spear Phishing');
    expect(result.html).toContain('PowerShell');
  });

  test('should handle empty techniques list', () => {
    const result = cti.generateMITRECoverage([]);

    expect(result.html).toContain('No MITRE techniques identified');
  });

  // ==================== EVIDENCE STATUS TESTS ====================

  test('should generate evidence status', () => {
    const result = cti.generateEvidenceStatus(mockInvestigation.findings);

    expect(result).toBeDefined();
    expect(result.type).toBe('evidence-status');
    expect(result.html).toBeDefined();
  });

  test('should display evidence count by status', () => {
    const result = cti.generateEvidenceStatus(mockInvestigation.findings);

    expect(result.metadata.byStatus.verified).toBe(2);
    expect(result.metadata.byStatus.suspected).toBe(1);
    expect(result.metadata.byStatus.unconfirmed).toBe(1);
  });

  test('should display total evidence count', () => {
    const result = cti.generateEvidenceStatus(mockInvestigation.findings);

    expect(result.metadata.totalEvidence).toBe(4);
  });

  test('should handle empty evidence list', () => {
    const result = cti.generateEvidenceStatus([]);

    expect(result.metadata.totalEvidence).toBe(0);
  });

  // ==================== PUBLICATION QUALITY TESTS ====================

  test('should generate publication quality', () => {
    const result = cti.generatePublicationQuality(mockInvestigation.metadata);

    expect(result).toBeDefined();
    expect(result.type).toBe('publication-quality');
    expect(result.html).toBeDefined();
  });

  test('should display quality rating', () => {
    const result = cti.generatePublicationQuality(mockInvestigation.metadata);

    expect(result.html).toContain('high');
    expect(result.metadata.quality).toBe('high');
  });

  test('should display source and claim counts', () => {
    const result = cti.generatePublicationQuality(mockInvestigation.metadata);

    expect(result.html).toContain('15');
    expect(result.html).toContain('8');
  });

  test('should display last updated date', () => {
    const result = cti.generatePublicationQuality(mockInvestigation.metadata);

    expect(result.html).toContain('2026-07-31');
  });

  test('should handle missing metadata', () => {
    const result = cti.generatePublicationQuality({});

    expect(result.html).toBeDefined();
    expect(result.metadata.quality).toBe('high');
  });

  // ==================== ENTERPRISE CTI DASHBOARD INTEGRATION TESTS ====================

  test('should generate complete enterprise CTI dashboard', () => {
    const result = cti.generateEnterpriseCTIDashboard(mockProduct, mockInvestigation);

    expect(result).toBeDefined();
    expect(result.type).toBe('enterprise-cti-dashboard');
    expect(result.html).toBeDefined();
    expect(result.components).toBeDefined();
    expect(result.metadata).toBeDefined();
  });

  test('should include all major dashboard components', () => {
    const result = cti.generateEnterpriseCTIDashboard(mockProduct, mockInvestigation);

    expect(result.components.threatLandscape).toBeDefined();
    expect(result.components.campaignStatus).toBeDefined();
    expect(result.components.threatActorActivity).toBeDefined();
    expect(result.components.victimDistribution).toBeDefined();
    expect(result.components.infrastructureSummary).toBeDefined();
    expect(result.components.malwareSummary).toBeDefined();
    expect(result.components.mitreCoverage).toBeDefined();
    expect(result.components.evidenceStatus).toBeDefined();
    expect(result.components.publicationQuality).toBeDefined();
  });

  test('should include proper metadata', () => {
    const result = cti.generateEnterpriseCTIDashboard(mockProduct, mockInvestigation);

    expect(result.metadata.productId).toBe('prod-apt28-2026-07-31');
    expect(result.metadata.investigation).toBe('inv-apt28-2026-07-31');
    expect(result.metadata.generatedAt).toBeDefined();
  });

  test('should render valid HTML structure', () => {
    const result = cti.generateEnterpriseCTIDashboard(mockProduct, mockInvestigation);

    expect(result.html).toContain('enterprise-cti-dashboard');
    expect(result.html).toContain('threat-landscape');
    expect(result.html).toContain('campaign-status');
  });

  // ==================== COLOR UTILITY TESTS ====================

  test('should return correct severity color', () => {
    const criticalColor = cti.getSeverityColor('CRITICAL');
    const highColor = cti.getSeverityColor('HIGH');

    expect(criticalColor).toBeDefined();
    expect(criticalColor).not.toBe(highColor);
  });

  test('should return confidence colors', () => {
    const highConfidence = cti.getConfidenceColor(0.9);
    const lowConfidence = cti.getConfidenceColor(0.2);

    expect(highConfidence).toBeDefined();
    expect(highConfidence).not.toBe(lowConfidence);
  });

  // ==================== HTML ESCAPING TESTS ====================

  test('should escape HTML special characters', () => {
    const escaped = cti.escapeHtml('<script>alert("xss")</script>');

    expect(escaped).toContain('&lt;');
    expect(escaped).toContain('&gt;');
    expect(escaped).not.toContain('<script>');
  });

  test('should handle null input', () => {
    const escaped = cti.escapeHtml(null);

    expect(escaped).toBe('');
  });

  // ==================== EDGE CASES ====================

  test('should handle investigation with minimal data', () => {
    const minimal = { id: 'test' };
    const result = cti.generateEnterpriseCTIDashboard({}, minimal);

    expect(result.html).toBeDefined();
  });

  test('should handle large numbers of actors and campaigns', () => {
    const largeLists = {
      threatActors: Array.from({ length: 50 }, (_, i) => ({ name: `Actor-${i}`, confidence: 0.9 })),
      campaigns: Array.from({ length: 50 }, (_, i) => ({ name: `Campaign-${i}` })),
    };

    const result = cti.generateEnterpriseCTIDashboard({}, largeLists);

    expect(result.components.threatActorActivity).toBeDefined();
    expect(result.components.campaignStatus).toBeDefined();
  });
});
