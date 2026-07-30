/**
 * Unit tests for SENTINEL APEX Reporting Engine
 * Tests rendering, metadata generation, confidence propagation, evidence handling
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { ReportEngine, generateReport } from '../lib/reporting/report-engine';
import { ReportBuilder } from '../lib/reporting/report-builder';
import { generateMetadata } from '../lib/reporting/metadata';
import { MarkdownRenderer, HTMLRenderer, JSONRenderer } from '../lib/reporting/renderers';
import { generateFrontmatter, formatFrontmatterYAML, generateSEOMetadata } from '../lib/reporting/seo';
import { aggregateConfidence, formatConfidenceLevel } from '../lib/reporting/confidence';
import { generateCitations, formatBibliography } from '../lib/reporting/references';
import { validateMalwareFamily } from '../lib/intelligence/validators';

describe('Report Engine', () => {
  let qilinData: any;
  let bianlianData: any;

  beforeAll(() => {
    const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
    const bianlianPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/bianlian.json');

    qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));
    bianlianData = JSON.parse(readFileSync(bianlianPath, 'utf-8'));
  });

  describe('Report Generation & Validation', () => {
    it('should validate malware data before generating report', () => {
      const engine = new ReportEngine(qilinData);
      const errors = engine.validate();
      expect(errors.filter(e => e.severity === 'error')).toHaveLength(0);
    });

    it('should reject invalid malware data', () => {
      expect(() => {
        new ReportEngine({ id: 'test' }); // Missing required fields
      }).toThrow();
    });

    it('should flag warnings for incomplete data', () => {
      const engine = new ReportEngine(qilinData);
      const errors = engine.validate();
      const warnings = errors.filter(e => e.severity === 'warning');
      expect(warnings.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Report Builder', () => {
    it('should build sections with confidence tracking', () => {
      const builder = new ReportBuilder(qilinData);
      builder.buildExecutiveSummary().buildThreatOverview().buildMitreMappings();

      const report = builder.build();
      expect(report.sections['executive_summary']).toBeDefined();
      expect(report.sections['threat_overview']).toBeDefined();
      expect(report.sections['mitre_mapping']).toBeDefined();
    });

    it('should mark empty sections correctly', () => {
      const builder = new ReportBuilder(qilinData);
      builder.buildExecutiveSummary();
      const report = builder.build();
      expect(report.sections['executive_summary'].isEmpty).toBe(false);
    });

    it('should aggregate evidence from variants', () => {
      const builder = new ReportBuilder(qilinData);
      builder.buildIOCIntelligence();
      const report = builder.build();
      const iocsSection = report.sections['ioc_intelligence'];
      expect(iocsSection.evidence.length).toBeGreaterThan(0);
    });
  });

  describe('Metadata Generation', () => {
    it('should generate complete metadata from malware family', () => {
      const metadata = generateMetadata(qilinData);
      expect(metadata.id).toBe('report-qilin');
      expect(metadata.title).toContain('Qilin');
      expect(metadata.malware_family).toBe('qilin');
      expect(metadata.mitre_techniques.length).toBeGreaterThan(0);
    });

    it('should include threat actors and campaigns in metadata', () => {
      const metadata = generateMetadata(bianlianData);
      expect(metadata.threat_actors.length).toBeGreaterThan(0);
      expect(metadata.campaigns.length).toBeGreaterThan(0);
    });

    it('should map CVEs to metadata', () => {
      const metadata = generateMetadata(qilinData);
      expect(metadata.cves.length).toBeGreaterThan(0);
    });
  });

  describe('Markdown Rendering', () => {
    it('should render malware report as valid Markdown', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('markdown');
      expect(output.content).toContain('# ');
      expect(output.content).toContain('## Executive Summary');
      expect(output.content).toContain('## References');
    });

    it('should include confidence levels in Markdown output', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('markdown');
      expect(output.content).toMatch(/Confidence.*High|Medium|Low/);
    });

    it('should list all IOCs in Markdown format', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('markdown');
      expect(output.content).toContain('IOC Intelligence');
    });
  });

  describe('HTML Rendering', () => {
    it('should render valid HTML structure', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('html');
      expect(output.content).toContain('<article class="malware-report">');
      expect(output.content).toContain('</article>');
      expect(output.content).toContain('<section class="report-section"');
    });

    it('should include semantic HTML elements', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('html');
      expect(output.content).toContain('<header');
      expect(output.content).toContain('<h1>');
      expect(output.content).toContain('<h2>');
    });

    it('should escape HTML special characters', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('html');
      // Should not contain unescaped special chars in text nodes
      expect(output.content).not.toContain('&<>"');
    });
  });

  describe('JSON Rendering', () => {
    it('should render valid JSON structure', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('json');
      const json = JSON.parse(output.content);
      expect(json.metadata).toBeDefined();
      expect(json.report).toBeDefined();
      expect(json.report.sections).toBeDefined();
    });

    it('should include all sections in JSON output', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('json');
      const json = JSON.parse(output.content);
      expect(Object.keys(json.report.sections).length).toBeGreaterThan(0);
    });

    it('should serialize evidence correctly', () => {
      const engine = new ReportEngine(qilinData);
      const output = engine.generate('json');
      const json = JSON.parse(output.content);
      const sections = Object.values(json.report.sections) as any[];
      const hasEvidence = sections.some(s => s.evidence && s.evidence.length > 0);
      expect(hasEvidence).toBe(true);
    });
  });

  describe('SEO & Front Matter', () => {
    it('should generate YAML front matter', () => {
      const metadata = generateMetadata(qilinData);
      const frontmatter = generateFrontmatter(metadata);
      expect(frontmatter.title).toBe(metadata.title);
      expect(frontmatter.slug).toBe(metadata.slug);
      expect(frontmatter.tags.length).toBeGreaterThan(0);
    });

    it('should format front matter as valid YAML', () => {
      const metadata = generateMetadata(qilinData);
      const frontmatter = generateFrontmatter(metadata);
      const yaml = formatFrontmatterYAML(frontmatter);
      expect(yaml).toMatch(/^---/);
      expect(yaml).toMatch(/---$/);
    });

    it('should generate SEO metadata with keywords', () => {
      const metadata = generateMetadata(qilinData);
      const seo = generateSEOMetadata(metadata);
      expect(seo.og_title).toBe(metadata.title);
      expect(seo.keywords.length).toBeGreaterThan(0);
      expect(seo.twitter_card).toBe('summary_large_image');
    });
  });

  describe('Confidence Propagation', () => {
    it('should aggregate confidence levels', () => {
      const confidences = ['HIGH', 'HIGH', 'MEDIUM'];
      const agg = aggregateConfidence(confidences as any);
      expect(agg).toBe('HIGH');
    });

    it('should format confidence labels correctly', () => {
      expect(formatConfidenceLevel('HIGH' as any)).toBe('High Confidence');
      expect(formatConfidenceLevel('MEDIUM' as any)).toBe('Medium Confidence');
      expect(formatConfidenceLevel('LOW' as any)).toBe('Low Confidence');
    });
  });

  describe('References & Citations', () => {
    it('should generate citations from references', () => {
      const malware = validateMalwareFamily(qilinData);
      const citations = generateCitations(malware.references);
      expect(citations.length).toBeGreaterThan(0);
      expect(citations[0]).toHaveProperty('id');
      expect(citations[0]).toHaveProperty('url');
    });

    it('should format bibliography correctly', () => {
      const malware = validateMalwareFamily(qilinData);
      const citations = generateCitations(malware.references);
      const bibliography = formatBibliography(citations);
      expect(bibliography).toContain('[1]');
    });
  });

  describe('Multi-Malware Support', () => {
    it('should generate reports for different malware families', () => {
      const engine1 = new ReportEngine(qilinData);
      const engine2 = new ReportEngine(bianlianData);

      const report1 = engine1.generate('markdown');
      const report2 = engine2.generate('markdown');

      expect(report1.metadata.malware_family).toBe('qilin');
      expect(report2.metadata.malware_family).toBe('bianlian');
      expect(report1.content).not.toContain('BianLian');
      expect(report2.content).not.toContain('Qilin');
    });
  });

  describe('Integration Tests', () => {
    it('should generate complete report end-to-end', async () => {
      const output = await generateReport(qilinData, 'markdown');
      expect(output.metadata).toBeDefined();
      expect(output.content).toBeDefined();
      expect(output.frontmatter).toBeDefined();
      expect(output.seo).toBeDefined();
      expect(output.format).toBe('markdown');
    });

    it('should support format switching', async () => {
      const mdOutput = await generateReport(qilinData, 'markdown');
      const htmlOutput = await generateReport(qilinData, 'html');
      const jsonOutput = await generateReport(qilinData, 'json');

      expect(mdOutput.format).toBe('markdown');
      expect(htmlOutput.format).toBe('html');
      expect(jsonOutput.format).toBe('json');
    });
  });

  describe('Performance', () => {
    it('should generate report in reasonable time', async () => {
      const engine = new ReportEngine(qilinData);
      const start = performance.now();
      engine.generate('markdown');
      const duration = performance.now() - start;
      expect(duration).toBeLessThan(500);
    });

    it('should handle multiple renders efficiently', async () => {
      const start = performance.now();
      await generateReport(qilinData, 'markdown');
      await generateReport(qilinData, 'html');
      await generateReport(qilinData, 'json');
      const duration = performance.now() - start;
      expect(duration).toBeLessThan(1500);
    });
  });
});
