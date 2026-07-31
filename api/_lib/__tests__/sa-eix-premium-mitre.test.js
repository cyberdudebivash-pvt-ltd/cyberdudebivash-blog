'use strict';

const { SentinelApexPremiumMITRE } = require('../sa-eix-premium-mitre');

describe('SentinelApexPremiumMITRE', () => {
  let mitre;

  beforeEach(() => {
    mitre = new SentinelApexPremiumMITRE();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(mitre).toBeDefined();
      expect(mitre.designTokens).toBeDefined();
      expect(mitre.theme).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexPremiumMITRE({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generateTacticCoverage', () => {
    test('should generate tactic coverage with empty tactics', () => {
      const coverage = mitre.generateTacticCoverage([]);
      expect(coverage.type).toBe('tactic-coverage');
      expect(coverage.html).toContain('Tactic Coverage');
      expect(coverage.metadata.totalTactics).toBe(0);
    });

    test('should generate tactic coverage with tactics', () => {
      const tactics = [
        { name: 'Initial Access', coverage: 0.8, techniques: [{ id: 'T1566' }] },
        { name: 'Execution', coverage: 0.6, techniques: [{ id: 'T1059' }] },
      ];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.metadata.totalTactics).toBe(2);
      expect(coverage.html).toContain('Initial Access');
      expect(coverage.html).toContain('Execution');
    });

    test('should calculate average coverage', () => {
      const tactics = [
        { name: 'Tactic1', coverage: 0.8 },
        { name: 'Tactic2', coverage: 0.6 },
        { name: 'Tactic3', coverage: 0.4 },
      ];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.metadata.averageCoverage).toBe(60);
    });

    test('should display coverage percentages', () => {
      const tactics = [
        { name: 'Test', coverage: 0.95, techniques: [] },
      ];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.html).toContain('95%');
    });

    test('should count techniques per tactic', () => {
      const tactics = [
        { name: 'Test', coverage: 0.5, techniques: Array.from({ length: 5 }, (_, i) => ({ id: `T${i}` })) },
      ];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.metadata.tactics[0].techniques).toBe(5);
    });

    test('should escape tactic names', () => {
      const tactics = [
        { name: '<img src=x>', coverage: 0.5 },
      ];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.html).toContain('&lt;img');
    });

    test('should handle null tactics', () => {
      const coverage = mitre.generateTacticCoverage(null);
      expect(coverage.metadata.totalTactics).toBe(0);
    });

    test('should handle zero coverage', () => {
      const tactics = [{ name: 'Uncovered', coverage: 0 }];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.html).toContain('0%');
    });

    test('should handle full coverage', () => {
      const tactics = [{ name: 'Covered', coverage: 1.0 }];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.html).toContain('100%');
    });
  });

  describe('generateTechniqueHeatmap', () => {
    test('should generate technique heatmap with empty techniques', () => {
      const heatmap = mitre.generateTechniqueHeatmap([]);
      expect(heatmap.type).toBe('technique-heatmap');
      expect(heatmap.html).toContain('Technique Coverage Heatmap');
      expect(heatmap.metadata.totalTechniques).toBe(0);
    });

    test('should generate technique heatmap with techniques', () => {
      const techniques = [
        { id: 'T1566', name: 'Phishing', coverage: 0.9 },
        { id: 'T1059', name: 'Command Line', coverage: 0.7 },
      ];
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.metadata.totalTechniques).toBe(2);
      expect(heatmap.metadata.coveredTechniques).toBe(2);
    });

    test('should count covered techniques', () => {
      const techniques = [
        { id: 'T1', name: 'Covered', coverage: 0.5 },
        { id: 'T2', name: 'Uncovered', coverage: 0 },
        { id: 'T3', name: 'Covered', coverage: 0.8 },
      ];
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.metadata.coveredTechniques).toBe(2);
      expect(heatmap.metadata.coveragePercent).toBe(67);
    });

    test('should limit displayed techniques to 12', () => {
      const techniques = Array.from({ length: 20 }, (_, i) => ({
        id: `T${i}`,
        name: `Technique ${i}`,
        coverage: 0.5,
      }));
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.metadata.displayedTechniques).toBe(12);
      expect(heatmap.metadata.totalTechniques).toBe(20);
    });

    test('should display technique IDs and names', () => {
      const techniques = [
        { id: 'T1566', name: 'Phishing' },
      ];
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.html).toContain('T1566');
      expect(heatmap.html).toContain('Phishing');
    });

    test('should escape technique names', () => {
      const techniques = [
        { id: 'T1', name: '<img src=x>', coverage: 0.5 },
      ];
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.html).toContain('&lt;img');
    });

    test('should handle null techniques', () => {
      const heatmap = mitre.generateTechniqueHeatmap(null);
      expect(heatmap.metadata.totalTechniques).toBe(0);
    });

    test('should handle zero coverage techniques', () => {
      const techniques = [
        { id: 'T1', name: 'Uncovered', coverage: 0 },
      ];
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.metadata.coveredTechniques).toBe(0);
      expect(heatmap.metadata.coveragePercent).toBe(0);
    });
  });

  describe('generateDetectionMapping', () => {
    test('should generate detection mapping with empty detections', () => {
      const mapping = mitre.generateDetectionMapping([]);
      expect(mapping.type).toBe('detection-mapping');
      expect(mapping.html).toContain('Detection Mapping');
      expect(mapping.metadata.total).toBe(0);
    });

    test('should generate detection mapping with detections', () => {
      const detections = [
        { status: 'detected' },
        { status: 'partial' },
        { status: 'undetected' },
      ];
      const mapping = mitre.generateDetectionMapping(detections);
      expect(mapping.metadata.total).toBe(3);
      expect(mapping.metadata.detected).toBe(1);
      expect(mapping.metadata.partial).toBe(1);
      expect(mapping.metadata.undetected).toBe(1);
    });

    test('should calculate detection rate', () => {
      const detections = [
        { status: 'detected' },
        { status: 'detected' },
        { status: 'partial' },
        { status: 'undetected' },
      ];
      const mapping = mitre.generateDetectionMapping(detections);
      expect(mapping.metadata.detectionRate).toBe(50);
    });

    test('should display detection status breakdown', () => {
      const detections = [
        { status: 'detected' },
      ];
      const mapping = mitre.generateDetectionMapping(detections);
      expect(mapping.html).toContain('Detected');
      expect(mapping.html).toContain('Partial');
      expect(mapping.html).toContain('Undetected');
    });

    test('should handle zero detections', () => {
      const mapping = mitre.generateDetectionMapping([]);
      expect(mapping.metadata.detectionRate).toBe(0);
    });

    test('should handle 100% detection rate', () => {
      const detections = [
        { status: 'detected' },
        { status: 'detected' },
        { status: 'detected' },
      ];
      const mapping = mitre.generateDetectionMapping(detections);
      expect(mapping.metadata.detectionRate).toBe(100);
    });

    test('should handle null detections', () => {
      const mapping = mitre.generateDetectionMapping(null);
      expect(mapping.metadata.total).toBe(0);
    });
  });

  describe('generateAdversaryTactics', () => {
    test('should generate adversary tactics with empty adversaries', () => {
      const tactics = mitre.generateAdversaryTactics([]);
      expect(tactics.type).toBe('adversary-tactics');
      expect(tactics.html).toContain('Adversary Tactic Frequency');
      expect(tactics.metadata.totalAdversaries).toBe(0);
    });

    test('should generate adversary tactics with adversaries', () => {
      const adversaries = [
        { name: 'APT1', tactics: ['initial-access', 'execution'] },
        { name: 'APT2', tactics: ['execution', 'persistence'] },
      ];
      const tactics = mitre.generateAdversaryTactics(adversaries);
      expect(tactics.metadata.totalAdversaries).toBe(2);
      expect(tactics.metadata.uniqueTactics).toBe(3);
    });

    test('should count tactic frequency', () => {
      const adversaries = [
        { name: 'APT1', tactics: ['execution', 'execution', 'persistence'] },
        { name: 'APT2', tactics: ['execution', 'initial-access'] },
      ];
      const tactics = mitre.generateAdversaryTactics(adversaries);
      const executionTactic = tactics.metadata.topTactics.find(t => t.tactic === 'execution');
      expect(executionTactic.count).toBe(3);
    });

    test('should limit displayed tactics to 8', () => {
      const adversaries = [
        {
          name: 'APT',
          tactics: [
            'initial-access',
            'execution',
            'persistence',
            'privilege-escalation',
            'defense-evasion',
            'credential-access',
            'discovery',
            'lateral-movement',
            'collection',
            'command-and-control',
          ],
        },
      ];
      const tactics = mitre.generateAdversaryTactics(adversaries);
      expect(tactics.metadata.topTactics.length).toBeLessThanOrEqual(8);
    });

    test('should sort tactics by frequency', () => {
      const adversaries = [
        { name: 'APT1', tactics: ['a', 'b', 'c', 'c', 'd', 'd', 'd'] },
      ];
      const tactics = mitre.generateAdversaryTactics(adversaries);
      if (tactics.metadata.topTactics.length > 1) {
        expect(tactics.metadata.topTactics[0].count).toBeGreaterThanOrEqual(tactics.metadata.topTactics[1].count);
      }
    });

    test('should escape tactic names', () => {
      const adversaries = [
        { name: 'APT', tactics: ['<img src=x>'] },
      ];
      const tactics = mitre.generateAdversaryTactics(adversaries);
      expect(tactics.html).toContain('&lt;img');
    });

    test('should handle adversaries without tactics', () => {
      const adversaries = [{ name: 'APT' }];
      const tactics = mitre.generateAdversaryTactics(adversaries);
      expect(tactics.metadata.totalAdversaries).toBe(1);
    });

    test('should handle null adversaries', () => {
      const tactics = mitre.generateAdversaryTactics(null);
      expect(tactics.metadata.totalAdversaries).toBe(0);
    });
  });

  describe('generatePremiumMITRE', () => {
    test('should generate complete premium MITRE dashboard', () => {
      const dashboard = mitre.generatePremiumMITRE(
        {
          tactics: [{ name: 'Initial Access', coverage: 0.8 }],
          techniques: [{ id: 'T1566', name: 'Phishing', coverage: 0.9 }],
          adversaries: [{ name: 'APT1', tactics: ['initial-access'] }],
        },
        {
          detections: [{ status: 'detected' }],
        }
      );

      expect(dashboard.type).toBe('premium-mitre');
      expect(dashboard.html).toContain('Premium MITRE ATT&CK Analysis');
      expect(dashboard.components).toBeDefined();
    });

    test('should include all component types', () => {
      const dashboard = mitre.generatePremiumMITRE({}, {});
      expect(dashboard.components.tacticCoverage).toBeDefined();
      expect(dashboard.components.techniqueHeatmap).toBeDefined();
      expect(dashboard.components.detectionMapping).toBeDefined();
      expect(dashboard.components.adversaryTactics).toBeDefined();
    });

    test('should include metadata', () => {
      const dashboard = mitre.generatePremiumMITRE(
        {
          tactics: Array.from({ length: 5 }, () => ({})),
          techniques: Array.from({ length: 10 }, () => ({})),
          adversaries: Array.from({ length: 3 }, () => ({})),
        },
        {
          detections: Array.from({ length: 7 }, () => ({})),
        }
      );

      expect(dashboard.metadata.totalTactics).toBe(5);
      expect(dashboard.metadata.totalTechniques).toBe(10);
      expect(dashboard.metadata.totalDetections).toBe(7);
      expect(dashboard.metadata.totalAdversaries).toBe(3);
      expect(dashboard.metadata.generatedAt).toBeDefined();
    });

    test('should handle empty investigation and assessment', () => {
      const dashboard = mitre.generatePremiumMITRE({}, {});
      expect(dashboard.type).toBe('premium-mitre');
      expect(dashboard.html).toContain('Premium MITRE ATT&CK Analysis');
    });

    test('should include all component HTML', () => {
      const dashboard = mitre.generatePremiumMITRE(
        {
          tactics: [{ name: 'Tactic' }],
          techniques: [{ id: 'T1', name: 'Technique' }],
          adversaries: [{ name: 'Adversary' }],
        },
        {
          detections: [{ status: 'detected' }],
        }
      );

      expect(dashboard.html).toContain('Tactic Coverage');
      expect(dashboard.html).toContain('Technique Coverage Heatmap');
      expect(dashboard.html).toContain('Detection Mapping');
      expect(dashboard.html).toContain('Adversary Tactic Frequency');
    });
  });

  describe('Color Utilities', () => {
    test('should return critical color for high coverage', () => {
      const color = mitre.getCoverageColor(0.9);
      expect(color).toBeDefined();
    });

    test('should return warning color for medium-high coverage', () => {
      const color = mitre.getCoverageColor(0.7);
      expect(color).toBeDefined();
    });

    test('should return accent color for medium coverage', () => {
      const color = mitre.getCoverageColor(0.5);
      expect(color).toBeDefined();
    });

    test('should return success color for low coverage', () => {
      const color = mitre.getCoverageColor(0.2);
      expect(color).toBeDefined();
    });

    test('should handle edge case coverage values', () => {
      expect(mitre.getCoverageColor(0)).toBeDefined();
      expect(mitre.getCoverageColor(1)).toBeDefined();
      expect(mitre.getCoverageColor(0.8)).toBeDefined();
      expect(mitre.getCoverageColor(0.6)).toBeDefined();
      expect(mitre.getCoverageColor(0.4)).toBeDefined();
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = mitre.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = mitre.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = mitre.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape quotes', () => {
      const escaped = mitre.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = mitre.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(mitre.escapeHtml(null)).toBe('');
      expect(mitre.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very large tactic counts', () => {
      const tactics = Array.from({ length: 50 }, (_, i) => ({
        name: `Tactic ${i}`,
        coverage: Math.random(),
      }));
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.metadata.totalTactics).toBe(50);
    });

    test('should handle very large technique counts', () => {
      const techniques = Array.from({ length: 500 }, (_, i) => ({
        id: `T${i}`,
        name: `Technique ${i}`,
        coverage: Math.random() * 0.5,
      }));
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.metadata.totalTechniques).toBe(500);
      expect(heatmap.metadata.displayedTechniques).toBe(12);
    });

    test('should handle detection mapping with all statuses', () => {
      const detections = Array.from({ length: 100 }, (_, i) => ({
        status: ['detected', 'partial', 'undetected'][i % 3],
      }));
      const mapping = mitre.generateDetectionMapping(detections);
      expect(mapping.metadata.total).toBe(100);
    });

    test('should handle special characters in tactic names', () => {
      const tactics = [{ name: 'T&T / Advanced' }];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.html).toContain('&amp;');
    });

    test('should handle unicode in technique names', () => {
      const techniques = [{ id: 'T1', name: 'Technique 中文 🔐', coverage: 0.5 }];
      const heatmap = mitre.generateTechniqueHeatmap(techniques);
      expect(heatmap.html).toContain('中文');
    });

    test('should generate valid HTML structures', () => {
      const coverage = mitre.generateTacticCoverage([]);
      expect(coverage.html).toMatch(/<div[^>]*>/);
      expect(coverage.html).toMatch(/<\/div>/);
    });

    test('should handle adversaries with no tactics', () => {
      const adversaries = [
        { name: 'APT1' },
        { name: 'APT2', tactics: [] },
      ];
      const tactics = mitre.generateAdversaryTactics(adversaries);
      expect(tactics.metadata.totalAdversaries).toBe(2);
    });

    test('should handle extremely high coverage values', () => {
      const tactics = [{ name: 'Covered', coverage: 1.5 }];
      const coverage = mitre.generateTacticCoverage(tactics);
      expect(coverage.html).toContain('150%');
    });
  });
});
