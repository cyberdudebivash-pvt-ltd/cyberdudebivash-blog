'use strict';

const { SentinelApexProfessionalReport } = require('../sa-eix-professional-report');

describe('SentinelApexProfessionalReport', () => {
  let report;

  beforeEach(() => {
    report = new SentinelApexProfessionalReport();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(report).toBeDefined();
      expect(report.designTokens).toBeDefined();
      expect(report.theme).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexProfessionalReport({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generateReportCover', () => {
    test('should generate report cover with minimal parameters', () => {
      const cover = report.generateReportCover();
      expect(cover.type).toBe('report-cover');
      expect(cover.html).toContain('CYBERDUDEBIVASH');
    });

    test('should generate report cover with title and subtitle', () => {
      const cover = report.generateReportCover('Test Report', 'Subtitle');
      expect(cover.html).toContain('Test Report');
      expect(cover.html).toContain('Subtitle');
      expect(cover.metadata.title).toBe('Test Report');
      expect(cover.metadata.subtitle).toBe('Subtitle');
    });

    test('should include client information when provided', () => {
      const cover = report.generateReportCover('Report', '', { client: 'ACME Corp' });
      expect(cover.html).toContain('ACME Corp');
      expect(cover.metadata.client).toBe('ACME Corp');
    });

    test('should include classification when provided', () => {
      const cover = report.generateReportCover('Report', '', { classification: 'CONFIDENTIAL' });
      expect(cover.html).toContain('CONFIDENTIAL');
      expect(cover.metadata.classification).toBe('CONFIDENTIAL');
    });

    test('should include date', () => {
      const cover = report.generateReportCover('Report');
      expect(cover.html).toContain('Date');
      expect(cover.metadata.date).toBeDefined();
    });

    test('should escape HTML in title', () => {
      const cover = report.generateReportCover('<script>alert(1)</script>');
      expect(cover.html).toContain('&lt;script&gt;');
    });

    test('should escape HTML in subtitle', () => {
      const cover = report.generateReportCover('Title', '&malicious');
      expect(cover.html).toContain('&amp;malicious');
    });

    test('should escape HTML in client name', () => {
      const cover = report.generateReportCover('', '', { client: '<img src=x>' });
      expect(cover.html).toContain('&lt;img');
    });

    test('should use custom date if provided', () => {
      const customDate = '2026-07-31';
      const cover = report.generateReportCover('Report', '', { date: customDate });
      expect(cover.metadata.date).toBe(customDate);
    });
  });

  describe('generateExecutiveSummary', () => {
    test('should generate executive summary with empty data', () => {
      const summary = report.generateExecutiveSummary();
      expect(summary.type).toBe('executive-summary');
      expect(summary.html).toContain('Executive Summary');
    });

    test('should generate executive summary with summary text', () => {
      const text = 'This is a test summary';
      const summary = report.generateExecutiveSummary(text);
      expect(summary.html).toContain(text);
    });

    test('should display key findings', () => {
      const findings = ['Finding 1', 'Finding 2', 'Finding 3'];
      const summary = report.generateExecutiveSummary('Summary', findings);
      expect(summary.html).toContain('Finding 1');
      expect(summary.html).toContain('Finding 2');
      expect(summary.html).toContain('Finding 3');
    });

    test('should limit displayed findings to 5', () => {
      const findings = Array.from({ length: 10 }, (_, i) => `Finding ${i}`);
      const summary = report.generateExecutiveSummary('Summary', findings);
      expect(summary.metadata.displayedFindings).toBe(5);
      expect(summary.metadata.keyFindingsCount).toBe(10);
    });

    test('should escape finding text', () => {
      const findings = ['<img src=x>'];
      const summary = report.generateExecutiveSummary('Summary', findings);
      expect(summary.html).toContain('&lt;img');
    });

    test('should escape summary text', () => {
      const summary = report.generateExecutiveSummary('&dangerous');
      expect(summary.html).toContain('&amp;dangerous');
    });

    test('should handle null findings', () => {
      const summary = report.generateExecutiveSummary('Summary', null);
      expect(summary.metadata.keyFindingsCount).toBe(0);
    });

    test('should include metadata', () => {
      const summary = report.generateExecutiveSummary('Test summary text here');
      expect(summary.metadata.summary).toBeDefined();
      expect(summary.metadata.keyFindingsCount).toBeDefined();
    });
  });

  describe('generateFindingsSection', () => {
    test('should generate findings section with empty findings', () => {
      const findings = report.generateFindingsSection([]);
      expect(findings.type).toBe('findings-section');
      expect(findings.html).toContain('Key Findings');
      expect(findings.metadata.totalFindings).toBe(0);
    });

    test('should generate findings section with findings', () => {
      const findingsList = [
        { title: 'Finding 1', description: 'Description 1', severity: 'critical' },
        { title: 'Finding 2', description: 'Description 2', severity: 'high' },
      ];
      const findings = report.generateFindingsSection(findingsList);
      expect(findings.metadata.totalFindings).toBe(2);
      expect(findings.html).toContain('Finding 1');
      expect(findings.html).toContain('Finding 2');
    });

    test('should limit displayed findings to 8', () => {
      const findingsList = Array.from({ length: 12 }, (_, i) => ({
        title: `Finding ${i}`,
      }));
      const findings = report.generateFindingsSection(findingsList);
      expect(findings.metadata.displayedFindings).toBe(8);
      expect(findings.metadata.totalFindings).toBe(12);
    });

    test('should count severity levels', () => {
      const findingsList = [
        { title: 'F1', severity: 'critical' },
        { title: 'F2', severity: 'critical' },
        { title: 'F3', severity: 'high' },
      ];
      const findings = report.generateFindingsSection(findingsList);
      expect(findings.metadata.criticalCount).toBe(2);
      expect(findings.metadata.highCount).toBe(1);
    });

    test('should display finding severity', () => {
      const findingsList = [
        { title: 'Critical Finding', severity: 'critical' },
      ];
      const findings = report.generateFindingsSection(findingsList);
      expect(findings.html).toContain('CRITICAL');
    });

    test('should display finding impact when provided', () => {
      const findingsList = [
        { title: 'Finding', description: 'Desc', impact: 'High impact' },
      ];
      const findings = report.generateFindingsSection(findingsList);
      expect(findings.html).toContain('High impact');
    });

    test('should escape finding titles', () => {
      const findingsList = [{ title: '<img src=x>' }];
      const findings = report.generateFindingsSection(findingsList);
      expect(findings.html).toContain('&lt;img');
    });

    test('should handle null findings', () => {
      const findings = report.generateFindingsSection(null);
      expect(findings.metadata.totalFindings).toBe(0);
    });
  });

  describe('generateRecommendations', () => {
    test('should generate recommendations with empty list', () => {
      const rec = report.generateRecommendations([]);
      expect(rec.type).toBe('recommendations');
      expect(rec.html).toContain('Recommendations');
      expect(rec.metadata.totalRecommendations).toBe(0);
    });

    test('should generate recommendations with items', () => {
      const recList = [
        { title: 'Rec 1', description: 'Description 1', priority: 'critical' },
        { title: 'Rec 2', description: 'Description 2', priority: 'high' },
      ];
      const rec = report.generateRecommendations(recList);
      expect(rec.metadata.totalRecommendations).toBe(2);
      expect(rec.html).toContain('Rec 1');
      expect(rec.html).toContain('Rec 2');
    });

    test('should limit displayed recommendations to 6', () => {
      const recList = Array.from({ length: 10 }, (_, i) => ({
        title: `Rec ${i}`,
      }));
      const rec = report.generateRecommendations(recList);
      expect(rec.metadata.displayedRecommendations).toBe(6);
      expect(rec.metadata.totalRecommendations).toBe(10);
    });

    test('should count priority levels', () => {
      const recList = [
        { title: 'R1', priority: 'critical' },
        { title: 'R2', priority: 'critical' },
        { title: 'R3', priority: 'high' },
      ];
      const rec = report.generateRecommendations(recList);
      expect(rec.metadata.criticalCount).toBe(2);
      expect(rec.metadata.highCount).toBe(1);
    });

    test('should display recommendation priority', () => {
      const recList = [{ title: 'Critical Rec', priority: 'critical' }];
      const rec = report.generateRecommendations(recList);
      expect(rec.html).toContain('CRITICAL');
    });

    test('should escape recommendation titles', () => {
      const recList = [{ title: '<img src=x>' }];
      const rec = report.generateRecommendations(recList);
      expect(rec.html).toContain('&lt;img');
    });

    test('should escape recommendation descriptions', () => {
      const recList = [{ title: 'Rec', description: '&malicious' }];
      const rec = report.generateRecommendations(recList);
      expect(rec.html).toContain('&amp;malicious');
    });

    test('should handle null recommendations', () => {
      const rec = report.generateRecommendations(null);
      expect(rec.metadata.totalRecommendations).toBe(0);
    });

    test('should number recommendations', () => {
      const recList = [
        { title: 'First' },
        { title: 'Second' },
      ];
      const rec = report.generateRecommendations(recList);
      expect(rec.html).toContain('1');
      expect(rec.html).toContain('2');
    });
  });

  describe('generateReportMetadata', () => {
    test('should generate report metadata with empty data', () => {
      const meta = report.generateReportMetadata({});
      expect(meta.type).toBe('report-metadata');
      expect(meta.html).toContain('Report Information');
    });

    test('should display all metadata fields', () => {
      const metadata = {
        reportId: 'RPT-2026-001',
        preparedBy: 'Security Team',
        reviewedBy: 'Chief Security Officer',
        validUntil: '90 days',
      };
      const meta = report.generateReportMetadata(metadata);
      expect(meta.html).toContain('RPT-2026-001');
      expect(meta.html).toContain('Security Team');
      expect(meta.html).toContain('Chief Security Officer');
    });

    test('should escape metadata values', () => {
      const metadata = {
        reportId: '<img src=x>',
        preparedBy: '&team',
      };
      const meta = report.generateReportMetadata(metadata);
      expect(meta.html).toContain('&lt;img');
      expect(meta.html).toContain('&amp;team');
    });

    test('should provide defaults for missing values', () => {
      const meta = report.generateReportMetadata({});
      expect(meta.html).toContain('N/A');
      expect(meta.html).toContain('CYBERDUDEBIVASH');
    });
  });

  describe('generateProfessionalReport', () => {
    test('should generate complete professional report', () => {
      const reportConfig = {
        title: 'Test Report',
        subtitle: 'Test Subtitle',
        summary: 'Test summary',
        keyFindings: ['Finding 1'],
        findings: [{ title: 'Critical', severity: 'critical' }],
        recommendations: [{ title: 'Immediate action', priority: 'critical' }],
        metadata: { client: 'Test Client' },
      };
      const reportDoc = report.generateProfessionalReport(reportConfig);

      expect(reportDoc.type).toBe('professional-report');
      expect(reportDoc.html).toContain('professional-report');
      expect(reportDoc.components).toBeDefined();
    });

    test('should include all components', () => {
      const reportDoc = report.generateProfessionalReport({});
      expect(reportDoc.components.cover).toBeDefined();
      expect(reportDoc.components.summary).toBeDefined();
      expect(reportDoc.components.findings).toBeDefined();
      expect(reportDoc.components.recommendations).toBeDefined();
      expect(reportDoc.components.reportMetadata).toBeDefined();
    });

    test('should include metadata', () => {
      const reportConfig = {
        title: 'Custom Report',
        findings: Array.from({ length: 5 }, () => ({})),
        recommendations: Array.from({ length: 3 }, () => ({})),
      };
      const reportDoc = report.generateProfessionalReport(reportConfig);

      expect(reportDoc.metadata.title).toBe('Custom Report');
      expect(reportDoc.metadata.findingsCount).toBe(5);
      expect(reportDoc.metadata.recommendationsCount).toBe(3);
      expect(reportDoc.metadata.generatedAt).toBeDefined();
    });

    test('should handle empty report config', () => {
      const reportDoc = report.generateProfessionalReport({});
      expect(reportDoc.type).toBe('professional-report');
      expect(reportDoc.html).toContain('Security Assessment Report');
    });

    test('should include all report sections', () => {
      const reportDoc = report.generateProfessionalReport({
        findings: [{ title: 'Finding' }],
        recommendations: [{ title: 'Recommendation' }],
      });

      expect(reportDoc.html).toContain('Executive Summary');
      expect(reportDoc.html).toContain('Key Findings');
      expect(reportDoc.html).toContain('Recommendations');
      expect(reportDoc.html).toContain('Report Information');
    });

    test('should include confidentiality footer', () => {
      const reportDoc = report.generateProfessionalReport({});
      expect(reportDoc.html).toContain('confidential');
      expect(reportDoc.html).toContain('CYBERDUDEBIVASH');
    });
  });

  describe('Color Utilities', () => {
    test('should return critical color for CRITICAL severity', () => {
      const color = report.getSeverityColor('critical');
      expect(color).toBeDefined();
    });

    test('should return warning color for HIGH severity', () => {
      const color = report.getSeverityColor('high');
      expect(color).toBeDefined();
    });

    test('should return accent color for MEDIUM severity', () => {
      const color = report.getSeverityColor('medium');
      expect(color).toBeDefined();
    });

    test('should return success color for LOW severity', () => {
      const color = report.getSeverityColor('low');
      expect(color).toBeDefined();
    });

    test('should return critical color for CRITICAL priority', () => {
      const color = report.getPriorityColor('critical');
      expect(color).toBeDefined();
    });

    test('should return appropriate colors for all priority levels', () => {
      ['critical', 'high', 'medium', 'low'].forEach(priority => {
        const color = report.getPriorityColor(priority);
        expect(color).toBeDefined();
      });
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = report.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = report.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = report.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape quotes', () => {
      const escaped = report.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = report.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(report.escapeHtml(null)).toBe('');
      expect(report.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very long report titles', () => {
      const longTitle = 'A'.repeat(500);
      const cover = report.generateReportCover(longTitle);
      expect(cover.metadata.title).toBe(longTitle);
    });

    test('should handle very long summary text', () => {
      const longText = 'Text. '.repeat(200);
      const summary = report.generateExecutiveSummary(longText);
      expect(summary.metadata.summary).toBeDefined();
    });

    test('should handle very large numbers of findings', () => {
      const findings = Array.from({ length: 100 }, (_, i) => ({
        title: `Finding ${i}`,
        severity: i % 4 === 0 ? 'critical' : 'high',
      }));
      const findingsSection = report.generateFindingsSection(findings);
      expect(findingsSection.metadata.totalFindings).toBe(100);
    });

    test('should handle unicode characters', () => {
      const cover = report.generateReportCover('Report 中文 🔐');
      expect(cover.html).toContain('中文');
    });

    test('should handle special characters in findings', () => {
      const findings = [{ title: 'Finding & Challenge (Complex)' }];
      const findingsSection = report.generateFindingsSection(findings);
      expect(findingsSection.html).toContain('&amp;');
    });

    test('should generate valid HTML structure', () => {
      const cover = report.generateReportCover();
      expect(cover.html).toMatch(/<div[^>]*>/);
      expect(cover.html).toMatch(/<\/div>/);
    });

    test('should handle empty metadata', () => {
      const reportDoc = report.generateProfessionalReport({
        metadata: {},
      });
      expect(reportDoc.html).toBeDefined();
    });
  });
});
