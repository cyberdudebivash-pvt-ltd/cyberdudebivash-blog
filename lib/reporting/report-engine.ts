/**
 * Malware Intelligence Report Engine
 * Orchestrates report generation, validation, and multi-format rendering
 */

import type { MalwareFamily } from '../intelligence/schema';
import { validateMalwareFamily } from '../intelligence/validators';
import { ReportBuilder } from './report-builder';
import { generateMetadata, type MalwareReportMetadata } from './metadata';
import { getRenderer, type Renderer } from './renderers';
import { generateFrontmatter, formatFrontmatterYAML, generateSEOMetadata, generateStructuredData } from './seo';

export interface ReportOutput {
  metadata: MalwareReportMetadata;
  content: string;
  frontmatter: string;
  seo: ReturnType<typeof generateSEOMetadata>;
  structuredData: Record<string, unknown>;
  format: 'markdown' | 'html' | 'json';
}

export interface ReportValidationError {
  field: string;
  message: string;
  severity: 'error' | 'warning';
}

export class ReportEngine {
  private malware: MalwareFamily;
  private validationErrors: ReportValidationError[] = [];

  constructor(malwareData: unknown) {
    try {
      this.malware = validateMalwareFamily(malwareData);
    } catch (error) {
      throw new Error(`Invalid malware data: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  validate(): ReportValidationError[] {
    const errors: ReportValidationError[] = [];

    if (!this.malware.id || this.malware.id.trim() === '') {
      errors.push({ field: 'id', message: 'Malware ID required', severity: 'error' });
    }

    if (!this.malware.name || this.malware.name.trim() === '') {
      errors.push({ field: 'name', message: 'Malware name required', severity: 'error' });
    }

    if (this.malware.iocs.length === 0) {
      errors.push({ field: 'iocs', message: 'No IOCs recorded', severity: 'warning' });
    }

    if (this.malware.mitre_techniques.length === 0) {
      errors.push({ field: 'mitre_techniques', message: 'No MITRE techniques mapped', severity: 'warning' });
    }

    if (!this.malware.description || this.malware.description.trim() === '') {
      errors.push({ field: 'description', message: 'No description provided', severity: 'warning' });
    }

    if (!this.malware.evidence || !this.malware.evidence.confidence) {
      errors.push({ field: 'evidence', message: 'Evidence confidence not set', severity: 'warning' });
    }

    if (this.malware.references.length === 0) {
      errors.push({ field: 'references', message: 'No references provided', severity: 'warning' });
    }

    this.validationErrors = errors;
    return errors;
  }

  hasErrors(): boolean {
    return this.validationErrors.some(e => e.severity === 'error');
  }

  canPublish(): boolean {
    return !this.hasErrors();
  }

  generate(format: 'markdown' | 'html' | 'json' = 'markdown'): ReportOutput {
    const errors = this.validate();
    if (this.hasErrors()) {
      throw new Error(
        `Cannot generate report: ${errors.filter(e => e.severity === 'error').map(e => e.message).join(', ')}`
      );
    }

    const metadata = generateMetadata(this.malware);
    const builder = new ReportBuilder(this.malware)
      .buildExecutiveSummary()
      .buildThreatOverview()
      .buildTechnicalAnalysis()
      .buildMitreMappings()
      .buildIOCIntelligence()
      .buildDetectionEngineering()
      .buildThreatActorAttribution()
      .buildCampaignAnalysis()
      .buildRecommendations();

    const report = builder.build();

    const renderer = getRenderer(format);
    const content = renderer.render(report, metadata);

    const frontmatterObj = generateFrontmatter(metadata);
    const frontmatter = formatFrontmatterYAML(frontmatterObj);

    const seo = generateSEOMetadata(metadata);
    const structuredData = generateStructuredData(metadata);

    return {
      metadata,
      content,
      frontmatter,
      seo,
      structuredData,
      format,
    };
  }

  getMalware(): MalwareFamily {
    return this.malware;
  }

  getValidationErrors(): ReportValidationError[] {
    return this.validationErrors;
  }

  async generateAndPublish(
    format: 'markdown' | 'html' | 'json' = 'markdown'
  ): Promise<{ path: string; url: string }> {
    const report = this.generate(format);

    const path = `/content/reports/malware/${this.malware.id}.md`;
    const url = `https://blog.cyberdudebivash.in/intelligence/reports/${this.malware.id}`;

    return { path, url };
  }
}

export async function generateReport(
  malwareData: unknown,
  format: 'markdown' | 'html' | 'json' = 'markdown'
): Promise<ReportOutput> {
  const engine = new ReportEngine(malwareData);
  return engine.generate(format);
}
