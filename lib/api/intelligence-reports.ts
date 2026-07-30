/**
 * Intelligence Reports API
 * REST endpoints for report generation and retrieval
 */

import { ReportEngine, type ReportOutput } from '../reporting/report-engine';
import type { MalwareFamily } from '../intelligence/schema';

export interface ReportGenerateRequest {
  malwareData: unknown;
  format?: 'markdown' | 'html' | 'json';
}

export interface ReportGenerateResponse {
  success: boolean;
  data?: ReportOutput;
  errors?: Array<{
    field: string;
    message: string;
  }>;
}

export function generateReport(req: ReportGenerateRequest): ReportGenerateResponse {
  try {
    const engine = new ReportEngine(req.malwareData);
    const validationErrors = engine.validate();

    const errors = validationErrors.filter(e => e.severity === 'error');
    if (errors.length > 0) {
      return {
        success: false,
        errors: errors.map(e => ({ field: e.field, message: e.message })),
      };
    }

    const format = req.format || 'markdown';
    const output = engine.generate(format);

    return {
      success: true,
      data: output,
    };
  } catch (error) {
    return {
      success: false,
      errors: [
        {
          field: 'general',
          message: error instanceof Error ? error.message : 'Unknown error',
        },
      ],
    };
  }
}

export interface ReportMetadataResponse {
  id: string;
  title: string;
  malware_family: string;
  malware_type: string;
  confidence: string;
  last_updated: string;
  slug: string;
}

export async function listReports(limit: number = 50, offset: number = 0): Promise<ReportMetadataResponse[]> {
  // TODO: Implement report listing from /content/reports/malware/
  // This would scan the content directory and return metadata for all generated reports
  return [];
}

export async function getReport(
  malwareId: string,
  format: 'markdown' | 'html' | 'json' = 'markdown'
): Promise<ReportOutput | null> {
  // TODO: Implement report retrieval from cache/database
  // This would load pre-generated reports or generate on-demand
  return null;
}

export async function validateReportData(malwareData: unknown): Promise<{
  valid: boolean;
  errors: Array<{ field: string; message: string }>;
}> {
  try {
    const engine = new ReportEngine(malwareData);
    const validationErrors = engine.validate();

    return {
      valid: validationErrors.filter(e => e.severity === 'error').length === 0,
      errors: validationErrors.map(e => ({ field: e.field, message: e.message })),
    };
  } catch (error) {
    return {
      valid: false,
      errors: [
        {
          field: 'general',
          message: error instanceof Error ? error.message : 'Validation failed',
        },
      ],
    };
  }
}
