/**
 * Quality Gates & Validators
 * Automated validation gates that block publication on errors
 */

import type { ValidationResult, QualityGateResult, GateSeverity } from './types';
import { GateSeverity } from './types';

// ============================================================================
// QUALITY GATE DEFINITIONS
// ============================================================================

export interface QualityGate {
  id: string;
  name: string;
  description: string;
  severity: GateSeverity;
  appliesToTypes: ('report' | 'ioc' | 'detection')[];
  validator: (object: any) => Promise<ValidationResult>;
}

// ============================================================================
// QUALITY GATES ENGINE
// ============================================================================

export class QualityGatesEngine {
  private gates: Map<string, QualityGate> = new Map();

  constructor() {
    this.registerDefaultGates();
  }

  /**
   * Register a quality gate
   */
  registerGate(gate: QualityGate): void {
    this.gates.set(gate.id, gate);
  }

  /**
   * Run all applicable quality gates on object
   */
  async validateObject(objectType: string, object: any): Promise<QualityGateResult> {
    const errors: ValidationResult[] = [];
    const warnings: ValidationResult[] = [];

    for (const gate of this.gates.values()) {
      if (!gate.appliesToTypes.includes(objectType as any)) {
        continue;
      }

      try {
        const result = await gate.validator(object);

        if (!result.passed) {
          if (result.severity === GateSeverity.ERROR) {
            errors.push(result);
          } else if (result.severity === GateSeverity.WARNING) {
            warnings.push(result);
          }
        }
      } catch (e) {
        errors.push({
          passed: false,
          gateName: gate.name,
          severity: GateSeverity.ERROR,
          objectType,
          message: `Gate execution failed: ${e instanceof Error ? e.message : String(e)}`,
          timestamp: new Date(),
        });
      }
    }

    const blocksPublication = errors.length > 0;

    return {
      objectType,
      objectId: object.id || 'unknown',
      allPassed: errors.length === 0 && warnings.length === 0,
      errors,
      warnings,
      blocksPublication,
      timestamp: new Date(),
    };
  }

  /**
   * Register default quality gates
   */
  private registerDefaultGates(): void {
    // Report gates
    this.registerGate({
      id: 'report_missing_metadata',
      name: 'Missing Report Metadata',
      description: 'Report must have required metadata fields',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['report'],
      validator: async (report: any) => {
        const missing: string[] = [];
        if (!report.id) missing.push('id');
        if (!report.name) missing.push('name');
        if (!report.description) missing.push('description');
        if (!report.malwareId) missing.push('malwareId');

        return {
          passed: missing.length === 0,
          gateName: 'report_missing_metadata',
          severity: GateSeverity.ERROR,
          objectType: 'report',
          message: missing.length === 0 ? 'All metadata present' : `Missing fields: ${missing.join(', ')}`,
          failureDetails: missing,
          timestamp: new Date(),
        };
      },
    });

    this.registerGate({
      id: 'report_missing_iocs',
      name: 'Report Must Have IOCs',
      description: 'Report should have at least one IOC',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['report'],
      validator: async (report: any) => {
        const iocCount = report.iocs?.length || 0;
        return {
          passed: iocCount >= 1,
          gateName: 'report_missing_iocs',
          severity: GateSeverity.ERROR,
          objectType: 'report',
          message: iocCount >= 1 ? `Report has ${iocCount} IOCs` : 'Report has no IOCs',
          suggestion: 'Add at least one indicator of compromise (IOC)',
          timestamp: new Date(),
        };
      },
    });

    this.registerGate({
      id: 'report_missing_mitre',
      name: 'Missing MITRE ATT&CK Mapping',
      description: 'Report must have MITRE ATT&CK technique mappings',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['report'],
      validator: async (report: any) => {
        const techniqueCount = report.techniques?.length || 0;
        return {
          passed: techniqueCount >= 1,
          gateName: 'report_missing_mitre',
          severity: GateSeverity.ERROR,
          objectType: 'report',
          message: techniqueCount >= 1 ? `Report maps ${techniqueCount} techniques` : 'No MITRE mappings',
          suggestion: 'Map behaviors to MITRE ATT&CK framework',
          timestamp: new Date(),
        };
      },
    });

    this.registerGate({
      id: 'report_missing_evidence',
      name: 'Missing Evidence Attribution',
      description: 'All report claims must have evidence attribution',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['report'],
      validator: async (report: any) => {
        const sections = report.sections || [];
        const unattributedSections = sections.filter((s: any) => !s.evidence || s.evidence.length === 0);

        return {
          passed: unattributedSections.length === 0,
          gateName: 'report_missing_evidence',
          severity: GateSeverity.ERROR,
          objectType: 'report',
          message: unattributedSections.length === 0
            ? 'All sections have evidence'
            : `${unattributedSections.length} sections lack evidence`,
          failureDetails: unattributedSections.map((s: any) => `Section: ${s.title}`),
          suggestion: 'Add evidence attribution to each section',
          timestamp: new Date(),
        };
      },
    });

    this.registerGate({
      id: 'report_missing_references',
      name: 'Missing or Invalid References',
      description: 'References must have complete URLs',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['report'],
      validator: async (report: any) => {
        const references = report.references || [];
        const invalidRefs = references.filter((r: any) => !r.url || !r.url.startsWith('http'));

        return {
          passed: invalidRefs.length === 0,
          gateName: 'report_missing_references',
          severity: GateSeverity.ERROR,
          objectType: 'report',
          message: invalidRefs.length === 0 ? 'All references valid' : `${invalidRefs.length} invalid references`,
          failureDetails: invalidRefs.map((r: any) => r.title),
          suggestion: 'Ensure all references have valid URLs',
          timestamp: new Date(),
        };
      },
    });

    // IOC gates
    this.registerGate({
      id: 'ioc_missing_metadata',
      name: 'Missing IOC Metadata',
      description: 'IOC must have temporal metadata',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['ioc'],
      validator: async (ioc: any) => {
        const missing: string[] = [];
        if (!ioc.firstSeen) missing.push('firstSeen');
        if (!ioc.lastSeen) missing.push('lastSeen');
        if (!ioc.confidence) missing.push('confidence');

        return {
          passed: missing.length === 0,
          gateName: 'ioc_missing_metadata',
          severity: GateSeverity.ERROR,
          objectType: 'ioc',
          message: missing.length === 0 ? 'IOC metadata complete' : `Missing: ${missing.join(', ')}`,
          failureDetails: missing,
          timestamp: new Date(),
        };
      },
    });

    // Detection gates
    this.registerGate({
      id: 'detection_missing_evidence',
      name: 'Detection Rule Lacks Evidence',
      description: 'Detection rules must have supporting evidence',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['detection'],
      validator: async (detection: any) => {
        const hasEvidence = detection.metadata?.linkedIOCs?.length > 0;
        return {
          passed: hasEvidence,
          gateName: 'detection_missing_evidence',
          severity: GateSeverity.ERROR,
          objectType: 'detection',
          message: hasEvidence ? 'Detection has evidence' : 'No evidence linked to detection',
          suggestion: 'Link detection rule to supporting IOCs and behaviors',
          timestamp: new Date(),
        };
      },
    });

    // Common gates
    this.registerGate({
      id: 'object_missing_id',
      name: 'Object Missing ID',
      description: 'Every object must have a unique ID',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['report', 'ioc', 'detection'],
      validator: async (object: any) => {
        const hasId = !!object.id;
        return {
          passed: hasId,
          gateName: 'object_missing_id',
          severity: GateSeverity.ERROR,
          objectType: object.type,
          message: hasId ? 'Object has ID' : 'No ID assigned',
          timestamp: new Date(),
        };
      },
    });

    this.registerGate({
      id: 'object_missing_timestamp',
      name: 'Object Missing Timestamp',
      description: 'Objects must have creation timestamp',
      severity: GateSeverity.ERROR,
      appliesToTypes: ['report', 'ioc', 'detection'],
      validator: async (object: any) => {
        const hasTimestamp = !!object.createdAt;
        return {
          passed: hasTimestamp,
          gateName: 'object_missing_timestamp',
          severity: GateSeverity.ERROR,
          objectType: object.type,
          message: hasTimestamp ? 'Timestamp present' : 'No creation timestamp',
          timestamp: new Date(),
        };
      },
    });
  }

  /**
   * Get all registered gates
   */
  getAllGates(): QualityGate[] {
    return Array.from(this.gates.values());
  }

  /**
   * Get gates applicable to object type
   */
  getGatesForType(objectType: string): QualityGate[] {
    return Array.from(this.gates.values()).filter(g =>
      g.appliesToTypes.includes(objectType as any)
    );
  }
}

export const qualityGatesEngine = new QualityGatesEngine();
