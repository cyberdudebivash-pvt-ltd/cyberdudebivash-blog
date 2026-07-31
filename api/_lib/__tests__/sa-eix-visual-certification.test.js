'use strict';

const { SentinelApexVisualCertification } = require('../sa-eix-visual-certification');

describe('SentinelApexVisualCertification', () => {
  let certification;

  beforeEach(() => {
    certification = new SentinelApexVisualCertification();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(certification).toBeDefined();
      expect(certification.designTokens).toBeDefined();
      expect(certification.designSystem).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexVisualCertification({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generateCertificationBadge', () => {
    test('should generate badge with default parameters', () => {
      const badge = certification.generateCertificationBadge();
      expect(badge.type).toBe('certification-badge');
      expect(badge.html).toBeDefined();
      expect(badge.metadata).toBeDefined();
    });

    test('should generate gold badge', () => {
      const badge = certification.generateCertificationBadge('gold', 'WCAG 2.1');
      expect(badge.metadata.level).toBe('gold');
      expect(badge.html).toContain('GOLD');
    });

    test('should generate silver badge', () => {
      const badge = certification.generateCertificationBadge('silver', 'WCAG 2.0');
      expect(badge.metadata.level).toBe('silver');
      expect(badge.html).toContain('SILVER');
    });

    test('should generate bronze badge', () => {
      const badge = certification.generateCertificationBadge('bronze', 'WCAG 2.0');
      expect(badge.metadata.level).toBe('bronze');
      expect(badge.html).toContain('BRONZE');
    });

    test('should generate platinum badge', () => {
      const badge = certification.generateCertificationBadge('platinum', 'WCAG 2.1 AAA');
      expect(badge.metadata.level).toBe('platinum');
      expect(badge.html).toContain('PLATINUM');
    });

    test('should include standard text', () => {
      const badge = certification.generateCertificationBadge('gold', 'WCAG 2.1 AAA');
      expect(badge.html).toContain('WCAG 2.1 AAA');
      expect(badge.metadata.standard).toBe('WCAG 2.1 AAA');
    });

    test('should assign correct color to gold badge', () => {
      const badge = certification.generateCertificationBadge('gold', 'WCAG 2.1');
      expect(badge.metadata.color).toBe('#FFD700');
    });

    test('should assign correct color to silver badge', () => {
      const badge = certification.generateCertificationBadge('silver', 'WCAG 2.1');
      expect(badge.metadata.color).toBe('#C0C0C0');
    });

    test('should assign correct color to bronze badge', () => {
      const badge = certification.generateCertificationBadge('bronze', 'WCAG 2.1');
      expect(badge.metadata.color).toBe('#CD7F32');
    });

    test('should assign correct color to platinum badge', () => {
      const badge = certification.generateCertificationBadge('platinum', 'WCAG 2.1');
      expect(badge.metadata.color).toBe('#E5E4E2');
    });

    test('should have circular badge structure', () => {
      const badge = certification.generateCertificationBadge('gold', 'Standard');
      expect(badge.html).toContain('border-radius: 50%');
    });

    test('should escape standard text', () => {
      const badge = certification.generateCertificationBadge('gold', '<img src=x>');
      expect(badge.html).toContain('&lt;img');
    });
  });

  describe('generateComplianceChecklist', () => {
    test('should generate checklist with empty criteria', () => {
      const checklist = certification.generateComplianceChecklist([]);
      expect(checklist.type).toBe('compliance-checklist');
      expect(checklist.html).toContain('Compliance Standards');
      expect(checklist.metadata.totalCriteria).toBe(0);
    });

    test('should generate checklist with criteria', () => {
      const criteria = [
        { name: 'Color Contrast', description: '7:1 minimum', status: 'passed' },
        { name: 'Typography', description: 'Accessible fonts', status: 'passed' },
      ];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.metadata.totalCriteria).toBe(2);
      expect(checklist.html).toContain('Color Contrast');
      expect(checklist.html).toContain('Typography');
    });

    test('should count passed criteria', () => {
      const criteria = [
        { name: 'Test 1', status: 'passed' },
        { name: 'Test 2', status: 'passed' },
        { name: 'Test 3', status: 'failed' },
      ];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.metadata.passedCriteria).toBe(2);
    });

    test('should display checkmark for passed items', () => {
      const criteria = [{ name: 'Passed Test', status: 'passed' }];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.html).toContain('✓');
    });

    test('should display circle for failed items', () => {
      const criteria = [{ name: 'Failed Test', status: 'failed' }];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.html).toContain('○');
    });

    test('should escape criterion names', () => {
      const criteria = [{ name: '<img src=x>', status: 'passed' }];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.html).toContain('&lt;img');
    });

    test('should escape criterion descriptions', () => {
      const criteria = [{ name: 'Test', description: '&malicious', status: 'passed' }];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.html).toContain('&amp;malicious');
    });

    test('should handle null criteria', () => {
      const checklist = certification.generateComplianceChecklist(null);
      expect(checklist.metadata.totalCriteria).toBe(0);
    });

    test('should handle mixed pass/fail status', () => {
      const criteria = [
        { name: 'Test 1', status: 'passed' },
        { name: 'Test 2', status: 'failed' },
        { name: 'Test 3', status: 'passed' },
      ];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.metadata.totalCriteria).toBe(3);
      expect(checklist.metadata.passedCriteria).toBe(2);
    });
  });

  describe('generateVisualCertification', () => {
    test('should generate complete visual certification', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.type).toBe('visual-certification');
      expect(cert.html).toBeDefined();
      expect(cert.components).toBeDefined();
    });

    test('should include certification title', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.html).toContain('Gold Standard Visual Certification');
    });

    test('should include badge component', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.components.badge).toBeDefined();
      expect(cert.components.badge.type).toBe('certification-badge');
    });

    test('should include checklist component', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.components.checklist).toBeDefined();
      expect(cert.components.checklist.type).toBe('compliance-checklist');
    });

    test('should have gold certification level', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.metadata.certification).toBe('Gold Standard');
    });

    test('should have AAA WCAG level', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.metadata.wcagLevel).toBe('AAA');
    });

    test('should include generation timestamp', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.metadata.generatedAt).toBeDefined();
    });

    test('should include all compliance criteria', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.html).toContain('Color Contrast');
      expect(cert.html).toContain('Typography');
      expect(cert.html).toContain('Responsiveness');
      expect(cert.html).toContain('Performance');
    });

    test('should display all criteria as passed', () => {
      const cert = certification.generateVisualCertification();
      const passedCount = (cert.html.match(/✓/g) || []).length;
      expect(passedCount).toBeGreaterThan(0);
    });

    test('should have valid HTML structure', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.html).toMatch(/<div[^>]*>/);
      expect(cert.html).toMatch(/<\/div>/);
    });
  });

  describe('getBadgeColor', () => {
    test('should return gold color', () => {
      const color = certification.getBadgeColor('gold');
      expect(color).toBe('#FFD700');
    });

    test('should return silver color', () => {
      const color = certification.getBadgeColor('silver');
      expect(color).toBe('#C0C0C0');
    });

    test('should return bronze color', () => {
      const color = certification.getBadgeColor('bronze');
      expect(color).toBe('#CD7F32');
    });

    test('should return platinum color', () => {
      const color = certification.getBadgeColor('platinum');
      expect(color).toBe('#E5E4E2');
    });

    test('should return default color for unknown level', () => {
      const color = certification.getBadgeColor('unknown');
      expect(color).toBeDefined();
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = certification.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = certification.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = certification.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape double quotes', () => {
      const escaped = certification.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = certification.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(certification.escapeHtml(null)).toBe('');
      expect(certification.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very long criterion names', () => {
      const longName = 'A'.repeat(500);
      const criteria = [{ name: longName, status: 'passed' }];
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.html).toContain('A');
    });

    test('should handle many criteria', () => {
      const criteria = Array.from({ length: 100 }, (_, i) => ({
        name: `Criterion ${i}`,
        status: i % 2 === 0 ? 'passed' : 'failed',
      }));
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.metadata.totalCriteria).toBe(100);
    });

    test('should handle all criteria passed', () => {
      const criteria = Array.from({ length: 10 }, (_, i) => ({
        name: `Test ${i}`,
        status: 'passed',
      }));
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.metadata.passedCriteria).toBe(10);
    });

    test('should handle all criteria failed', () => {
      const criteria = Array.from({ length: 10 }, (_, i) => ({
        name: `Test ${i}`,
        status: 'failed',
      }));
      const checklist = certification.generateComplianceChecklist(criteria);
      expect(checklist.metadata.passedCriteria).toBe(0);
    });

    test('should handle unicode characters in standard', () => {
      const badge = certification.generateCertificationBadge('gold', '✓ WCAG 2.1 中文');
      expect(badge.html).toContain('中文');
    });

    test('should handle special characters in standard', () => {
      const badge = certification.generateCertificationBadge('gold', 'WCAG & ISO 27001');
      expect(badge.html).toContain('&amp;');
    });

    test('should maintain state across multiple calls', () => {
      const cert1 = certification.generateVisualCertification();
      const cert2 = certification.generateVisualCertification();
      expect(cert1.metadata.certification).toBe(cert2.metadata.certification);
    });

    test('should handle rapid generation', () => {
      const certs = [];
      for (let i = 0; i < 50; i++) {
        certs.push(certification.generateVisualCertification());
      }
      expect(certs.length).toBe(50);
    });

    test('should generate valid timestamp format', () => {
      const cert = certification.generateVisualCertification();
      expect(new Date(cert.metadata.generatedAt).toISOString()).toBe(cert.metadata.generatedAt);
    });
  });

  describe('Compliance Standards', () => {
    test('should display WCAG 2.1 AAA as standard', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.html).toContain('WCAG 2.1 AAA');
    });

    test('should meet AAA compliance level', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.metadata.wcagLevel).toBe('AAA');
    });

    test('checklist should have 4 default criteria', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.components.checklist.metadata.totalCriteria).toBe(4);
    });

    test('all default criteria should be passed', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.components.checklist.metadata.passedCriteria).toBe(4);
    });
  });

  describe('Visual Structure', () => {
    test('badge should be centered', () => {
      const badge = certification.generateCertificationBadge('gold', 'WCAG');
      expect(badge.html).toContain('display: flex');
    });

    test('badge should have fixed dimensions', () => {
      const badge = certification.generateCertificationBadge('gold', 'WCAG');
      expect(badge.html).toContain('width: 120px');
      expect(badge.html).toContain('height: 120px');
    });

    test('checklist should have bordered layout', () => {
      const checklist = certification.generateComplianceChecklist([]);
      expect(checklist.html).toContain('border:');
    });

    test('main component should have padding', () => {
      const cert = certification.generateVisualCertification();
      expect(cert.html).toContain('padding:');
    });
  });
});
