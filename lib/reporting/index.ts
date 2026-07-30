/**
 * SENTINEL APEX Reporting Engine - Public API
 * Central export point for all reporting functionality
 */

export { ReportEngine, generateReport } from './report-engine';
export type { ReportOutput, ReportValidationError } from './report-engine';

export { ReportBuilder } from './report-builder';
export type { ReportSection, MalwareReport } from './report-builder';

export { generateMetadata, metadataToFrontmatter } from './metadata';
export type { MalwareReportMetadata } from './metadata';

export { MarkdownRenderer, HTMLRenderer, JSONRenderer, getRenderer } from './renderers';
export type { Renderer } from './renderers';

export { generateFrontmatter, formatFrontmatterYAML, generateSEOMetadata, generateStructuredData } from './seo';
export type { Frontmatter, SEOMetadata } from './seo';

export { aggregateConfidence, confidenceToSeverity, evidenceHasConfidence, formatConfidenceLevel, attributionLabel } from './confidence';
export type { ConfidenceScore } from './confidence';

export { generateCitations, formatCitation, formatBibliography, isValidUrl } from './references';
export type { Citation } from './references';
