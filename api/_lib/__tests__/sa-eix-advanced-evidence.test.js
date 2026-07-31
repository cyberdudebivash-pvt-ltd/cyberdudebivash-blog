'use strict';

const { SentinelApexAdvancedEvidence } = require('../sa-eix-advanced-evidence');

describe('SentinelApexAdvancedEvidence', () => {
  let evidence;

  beforeEach(() => {
    evidence = new SentinelApexAdvancedEvidence();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(evidence).toBeDefined();
      expect(evidence.designTokens).toBeDefined();
      expect(evidence.theme).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexAdvancedEvidence({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
      expect(custom.designTokens).toBeDefined();
    });
  });

  describe('generateEvidenceCard', () => {
    test('should generate evidence card with all parameters', () => {
      const card = evidence.generateEvidenceCard('Test Evidence', 'malware', 'Test description', 'verified');
      expect(card.type).toBe('evidence-card');
      expect(card.html).toContain('Test Evidence');
      expect(card.html).toContain('malware');
      expect(card.metadata.title).toBe('Test Evidence');
    });

    test('should generate evidence card with minimal parameters', () => {
      const card = evidence.generateEvidenceCard('Evidence');
      expect(card.type).toBe('evidence-card');
      expect(card.html).toContain('Evidence');
    });

    test('should support verified status', () => {
      const card = evidence.generateEvidenceCard('Test', 'indicator', '', 'verified');
      expect(card.metadata.verificationLevel).toBe('verified');
      expect(card.html).toContain('Verified');
    });

    test('should support partial verification status', () => {
      const card = evidence.generateEvidenceCard('Test', 'indicator', '', 'partial');
      expect(card.metadata.verificationLevel).toBe('partial');
      expect(card.html).toContain('Partial');
    });

    test('should support unverified status', () => {
      const card = evidence.generateEvidenceCard('Test', 'indicator', '', 'unverified');
      expect(card.metadata.verificationLevel).toBe('unverified');
      expect(card.html).toContain('Unverified');
    });

    test('should support pending status', () => {
      const card = evidence.generateEvidenceCard('Test', 'indicator', '', 'pending');
      expect(card.metadata.verificationLevel).toBe('pending');
      expect(card.html).toContain('Pending');
    });

    test('should escape evidence title', () => {
      const card = evidence.generateEvidenceCard('<script>alert(1)</script>', 'indicator');
      expect(card.html).toContain('&lt;script&gt;');
    });

    test('should escape evidence description', () => {
      const card = evidence.generateEvidenceCard('Test', 'indicator', '&malicious');
      expect(card.html).toContain('&amp;malicious');
    });

    test('should include metadata', () => {
      const card = evidence.generateEvidenceCard('Test', 'domain', 'Description', 'verified');
      expect(card.metadata.verificationColor).toBeDefined();
      expect(card.metadata.typeColor).toBeDefined();
    });

    test('should handle various evidence types', () => {
      const types = ['indicator', 'malware', 'domain', 'ip', 'url', 'hash', 'email'];
      types.forEach(type => {
        const card = evidence.generateEvidenceCard('Test', type);
        expect(card.metadata.type).toBe(type);
      });
    });
  });

  describe('generateEvidenceChain', () => {
    test('should generate evidence chain with empty items', () => {
      const chain = evidence.generateEvidenceChain([]);
      expect(chain.type).toBe('evidence-chain');
      expect(chain.html).toContain('Evidence Timeline');
      expect(chain.metadata.itemCount).toBe(0);
    });

    test('should generate evidence chain with items', () => {
      const items = [
        { title: 'First', detail: 'Initial detection', verification: 'verified' },
        { title: 'Second', detail: 'Confirmation', verification: 'partial' },
      ];
      const chain = evidence.generateEvidenceChain(items);
      expect(chain.metadata.itemCount).toBe(2);
      expect(chain.html).toContain('First');
      expect(chain.html).toContain('Second');
    });

    test('should number chain items sequentially', () => {
      const items = Array.from({ length: 5 }, (_, i) => ({
        title: `Item ${i}`,
      }));
      const chain = evidence.generateEvidenceChain(items);
      expect(chain.html).toContain('1');
      expect(chain.html).toContain('2');
      expect(chain.html).toContain('5');
    });

    test('should include timestamps in chain', () => {
      const items = [
        { title: 'Event', timestamp: '2026-07-31T10:00:00Z' },
      ];
      const chain = evidence.generateEvidenceChain(items);
      expect(chain.html).toContain('2026-07-31T10:00:00Z');
    });

    test('should escape chain item titles', () => {
      const items = [{ title: '<img src=x>' }];
      const chain = evidence.generateEvidenceChain(items);
      expect(chain.html).toContain('&lt;img');
    });

    test('should escape chain item details', () => {
      const items = [{ detail: '&malicious' }];
      const chain = evidence.generateEvidenceChain(items);
      expect(chain.html).toContain('&amp;malicious');
    });

    test('should include metadata about items', () => {
      const items = Array.from({ length: 3 }, (_, i) => ({
        title: `Item ${i}`,
        verification: 'verified',
      }));
      const chain = evidence.generateEvidenceChain(items);
      expect(chain.metadata.items.length).toBe(3);
    });
  });

  describe('generateSourceAttribution', () => {
    test('should generate source attribution with empty sources', () => {
      const attribution = evidence.generateSourceAttribution([]);
      expect(attribution.type).toBe('source-attribution');
      expect(attribution.html).toContain('Source Attribution');
      expect(attribution.metadata.sourceCount).toBe(0);
    });

    test('should generate source attribution with sources', () => {
      const sources = [
        { name: 'OpenINTEL', type: 'dns', confidence: 0.95 },
        { name: 'Recorded Future', type: 'threat-intel', confidence: 0.88 },
      ];
      const attribution = evidence.generateSourceAttribution(sources);
      expect(attribution.metadata.sourceCount).toBe(2);
      expect(attribution.html).toContain('OpenINTEL');
      expect(attribution.html).toContain('Recorded Future');
    });

    test('should limit sources to 6 displayed', () => {
      const sources = Array.from({ length: 10 }, (_, i) => ({
        name: `Source ${i}`,
        confidence: 0.9,
      }));
      const attribution = evidence.generateSourceAttribution(sources);
      expect(attribution.metadata.sourceCount).toBe(6);
      expect(attribution.metadata.totalSources).toBe(10);
    });

    test('should display confidence percentages', () => {
      const sources = [
        { name: 'Source A', confidence: 0.95 },
        { name: 'Source B', confidence: 0.5 },
      ];
      const attribution = evidence.generateSourceAttribution(sources);
      expect(attribution.html).toContain('95%');
      expect(attribution.html).toContain('50%');
    });

    test('should escape source names', () => {
      const sources = [{ name: '<img src=x>', confidence: 0.9 }];
      const attribution = evidence.generateSourceAttribution(sources);
      expect(attribution.html).toContain('&lt;img');
    });

    test('should escape source types', () => {
      const sources = [{ name: 'Source', type: '&malicious' }];
      const attribution = evidence.generateSourceAttribution(sources);
      expect(attribution.html).toContain('&amp;malicious');
    });

    test('should include total source count', () => {
      const sources = Array.from({ length: 5 }, (_, i) => ({
        name: `Source ${i}`,
      }));
      const attribution = evidence.generateSourceAttribution(sources);
      expect(attribution.html).toContain('Unique Sources');
    });

    test('should handle sources without confidence', () => {
      const sources = [{ name: 'Source' }];
      const attribution = evidence.generateSourceAttribution(sources);
      expect(attribution.html).toContain('Source');
    });
  });

  describe('generateVerificationStatus', () => {
    test('should generate verification status with empty data', () => {
      const status = evidence.generateVerificationStatus({});
      expect(status.type).toBe('verification-status');
      expect(status.html).toContain('Verification Status');
      expect(status.metadata.total).toBe(0);
    });

    test('should generate verification status with data', () => {
      const data = {
        verified: 15,
        partial: 8,
        unverified: 3,
        pending: 2,
      };
      const status = evidence.generateVerificationStatus(data);
      expect(status.metadata.verified).toBe(15);
      expect(status.metadata.partial).toBe(8);
      expect(status.metadata.unverified).toBe(3);
      expect(status.metadata.pending).toBe(2);
      expect(status.metadata.total).toBe(28);
    });

    test('should calculate verification percentages', () => {
      const data = {
        verified: 50,
        partial: 25,
        unverified: 15,
        pending: 10,
      };
      const status = evidence.generateVerificationStatus(data);
      expect(status.metadata.verifiedPercent).toBe(50);
      expect(status.html).toContain('50%');
    });

    test('should handle zero totals', () => {
      const status = evidence.generateVerificationStatus({});
      expect(status.metadata.total).toBe(0);
      expect(status.metadata.verifiedPercent).toBe(0);
    });

    test('should display all verification levels', () => {
      const data = {
        verified: 10,
        partial: 10,
        unverified: 10,
        pending: 10,
      };
      const status = evidence.generateVerificationStatus(data);
      expect(status.html).toContain('Verified');
      expect(status.html).toContain('Partial');
      expect(status.html).toContain('Unverified');
      expect(status.html).toContain('Pending');
    });

    test('should display total claims count', () => {
      const data = {
        verified: 25,
        partial: 10,
        unverified: 5,
        pending: 10,
      };
      const status = evidence.generateVerificationStatus(data);
      expect(status.html).toContain('Total Claims');
    });
  });

  describe('generateEvidenceCluster', () => {
    test('should generate evidence cluster with empty evidence', () => {
      const cluster = evidence.generateEvidenceCluster('Cluster', []);
      expect(cluster.type).toBe('evidence-cluster');
      expect(cluster.metadata.itemCount).toBe(0);
    });

    test('should generate evidence cluster with items', () => {
      const items = [
        { type: 'ip', value: '192.168.1.1', confidence: 0.95 },
        { type: 'domain', value: 'example.com', confidence: 0.88 },
      ];
      const cluster = evidence.generateEvidenceCluster('IPs & Domains', items);
      expect(cluster.metadata.itemCount).toBe(2);
      expect(cluster.html).toContain('192.168.1.1');
      expect(cluster.html).toContain('example.com');
    });

    test('should limit cluster to 8 items displayed', () => {
      const items = Array.from({ length: 15 }, (_, i) => ({
        type: 'indicator',
        value: `item${i}`,
      }));
      const cluster = evidence.generateEvidenceCluster('Large Cluster', items);
      expect(cluster.metadata.displayedCount).toBe(8);
      expect(cluster.metadata.itemCount).toBe(15);
    });

    test('should escape evidence values', () => {
      const items = [{ value: '<script>alert(1)</script>' }];
      const cluster = evidence.generateEvidenceCluster('Test', items);
      expect(cluster.html).toContain('&lt;script&gt;');
    });

    test('should display confidence levels', () => {
      const items = [
        { value: 'test1', confidence: 0.95 },
        { value: 'test2', confidence: 0.5 },
      ];
      const cluster = evidence.generateEvidenceCluster('Test', items);
      expect(cluster.html).toContain('95%');
      expect(cluster.html).toContain('50%');
    });

    test('should display cluster item count summary', () => {
      const items = Array.from({ length: 5 }, (_, i) => ({
        value: `item${i}`,
      }));
      const cluster = evidence.generateEvidenceCluster('Test', items);
      expect(cluster.html).toContain('5 item');
    });

    test('should handle singular item count', () => {
      const cluster = evidence.generateEvidenceCluster('Test', [{ value: 'single' }]);
      expect(cluster.html).toContain('1 item');
    });

    test('should escape cluster name', () => {
      const cluster = evidence.generateEvidenceCluster('<div>Cluster</div>', []);
      expect(cluster.html).toContain('&lt;div&gt;');
    });
  });

  describe('generateAdvancedEvidence', () => {
    test('should generate complete advanced evidence dashboard', () => {
      const dashboard = evidence.generateAdvancedEvidence(
        {
          evidence: [
            { type: 'ip', value: '192.168.1.1' },
            { type: 'domain', value: 'example.com' },
          ],
        },
        {
          sources: [
            { name: 'OpenINTEL', confidence: 0.95 },
          ],
          verification: {
            verified: 10,
            partial: 5,
            unverified: 2,
            pending: 1,
          },
        }
      );

      expect(dashboard.type).toBe('advanced-evidence');
      expect(dashboard.html).toContain('Advanced Evidence Analysis');
      expect(dashboard.components).toBeDefined();
    });

    test('should include all component types', () => {
      const dashboard = evidence.generateAdvancedEvidence({}, {});
      expect(dashboard.components.evidenceCard).toBeDefined();
      expect(dashboard.components.evidenceChain).toBeDefined();
      expect(dashboard.components.sourceAttribution).toBeDefined();
      expect(dashboard.components.verificationStatus).toBeDefined();
      expect(dashboard.components.evidenceCluster).toBeDefined();
    });

    test('should include metadata', () => {
      const dashboard = evidence.generateAdvancedEvidence(
        { evidence: Array.from({ length: 5 }, (_, i) => ({ value: `e${i}` })) },
        { sources: Array.from({ length: 3 }, (_, i) => ({ name: `s${i}` })) }
      );

      expect(dashboard.metadata.totalEvidence).toBe(5);
      expect(dashboard.metadata.totalSources).toBe(3);
      expect(dashboard.metadata.generatedAt).toBeDefined();
    });

    test('should handle empty investigation and assessment', () => {
      const dashboard = evidence.generateAdvancedEvidence({}, {});
      expect(dashboard.type).toBe('advanced-evidence');
      expect(dashboard.html).toContain('Advanced Evidence Analysis');
    });

    test('should include all component HTML', () => {
      const dashboard = evidence.generateAdvancedEvidence(
        { evidence: [{ value: 'test' }] },
        {}
      );

      expect(dashboard.html).toContain('Primary Evidence Base');
      expect(dashboard.html).toContain('Evidence Timeline');
      expect(dashboard.html).toContain('Source Attribution');
      expect(dashboard.html).toContain('Verification Status');
      expect(dashboard.html).toContain('Primary Indicators');
    });
  });

  describe('Color Utilities', () => {
    describe('getEvidenceTypeColor', () => {
      test('should return color for indicator type', () => {
        const color = evidence.getEvidenceTypeColor('indicator');
        expect(color).toBeDefined();
      });

      test('should return color for malware type', () => {
        const color = evidence.getEvidenceTypeColor('malware');
        expect(color).toBeDefined();
      });

      test('should return color for domain type', () => {
        const color = evidence.getEvidenceTypeColor('domain');
        expect(color).toBeDefined();
      });

      test('should return color for ip type', () => {
        const color = evidence.getEvidenceTypeColor('ip');
        expect(color).toBeDefined();
      });

      test('should return color for url type', () => {
        const color = evidence.getEvidenceTypeColor('url');
        expect(color).toBeDefined();
      });

      test('should return color for hash type', () => {
        const color = evidence.getEvidenceTypeColor('hash');
        expect(color).toBeDefined();
      });

      test('should return color for email type', () => {
        const color = evidence.getEvidenceTypeColor('email');
        expect(color).toBeDefined();
      });

      test('should return default color for unknown type', () => {
        const color = evidence.getEvidenceTypeColor('unknown');
        expect(color).toBeDefined();
      });
    });

    describe('getVerificationColor', () => {
      test('should return color for verified level', () => {
        const color = evidence.getVerificationColor('verified');
        expect(color).toBeDefined();
      });

      test('should return color for partial level', () => {
        const color = evidence.getVerificationColor('partial');
        expect(color).toBeDefined();
      });

      test('should return color for unverified level', () => {
        const color = evidence.getVerificationColor('unverified');
        expect(color).toBeDefined();
      });

      test('should return color for pending level', () => {
        const color = evidence.getVerificationColor('pending');
        expect(color).toBeDefined();
      });

      test('should return default color for unknown level', () => {
        const color = evidence.getVerificationColor('unknown');
        expect(color).toBeDefined();
      });
    });

    describe('getConfidenceColor', () => {
      test('should return success for high confidence', () => {
        const color = evidence.getConfidenceColor(0.9);
        expect(color).toBeDefined();
      });

      test('should return accent for medium-high confidence', () => {
        const color = evidence.getConfidenceColor(0.7);
        expect(color).toBeDefined();
      });

      test('should return warning for medium confidence', () => {
        const color = evidence.getConfidenceColor(0.5);
        expect(color).toBeDefined();
      });

      test('should return critical for low confidence', () => {
        const color = evidence.getConfidenceColor(0.2);
        expect(color).toBeDefined();
      });
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = evidence.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = evidence.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = evidence.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape quotes', () => {
      const escaped = evidence.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = evidence.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(evidence.escapeHtml(null)).toBe('');
      expect(evidence.escapeHtml(undefined)).toBe('');
    });

    test('should handle empty strings', () => {
      expect(evidence.escapeHtml('')).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle evidence with very long values', () => {
      const longValue = 'A'.repeat(500);
      const card = evidence.generateEvidenceCard(longValue, 'indicator');
      expect(card.html).toContain('A');
    });

    test('should handle evidence cluster with null items', () => {
      const cluster = evidence.generateEvidenceCluster('Test', null);
      expect(cluster.metadata.itemCount).toBe(0);
    });

    test('should handle evidence chain with null items', () => {
      const chain = evidence.generateEvidenceChain(null);
      expect(chain.metadata.itemCount).toBe(0);
    });

    test('should handle source attribution with null sources', () => {
      const attribution = evidence.generateSourceAttribution(null);
      expect(attribution.metadata.sourceCount).toBe(0);
    });

    test('should handle confidence values at boundaries', () => {
      const color1 = evidence.getConfidenceColor(0);
      const color2 = evidence.getConfidenceColor(1);
      expect(color1).toBeDefined();
      expect(color2).toBeDefined();
    });

    test('should handle special unicode characters', () => {
      const card = evidence.generateEvidenceCard('Unicode 中文 🔐', 'indicator');
      expect(card.html).toContain('中文');
    });

    test('should generate valid HTML structures', () => {
      const chain = evidence.generateEvidenceChain([{ title: 'Test' }]);
      expect(chain.html).toMatch(/<div[^>]*>/);
      expect(chain.html).toMatch(/<\/div>/);
    });

    test('should handle very large evidence clusters', () => {
      const items = Array.from({ length: 100 }, (_, i) => ({
        value: `item${i}`,
      }));
      const cluster = evidence.generateEvidenceCluster('Large', items);
      expect(cluster.metadata.itemCount).toBe(100);
      expect(cluster.metadata.displayedCount).toBe(8);
    });

    test('should handle verification status with extreme values', () => {
      const status = evidence.generateVerificationStatus({
        verified: 1000,
        partial: 100,
        unverified: 10,
        pending: 1,
      });
      expect(status.metadata.total).toBe(1111);
    });
  });
});
