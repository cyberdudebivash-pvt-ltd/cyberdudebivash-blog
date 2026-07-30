/**
 * Detection Rules API
 * REST endpoints for detection rule generation and management
 */

import type { DetectionRule, GenerateDetectionRequest, GenerateDetectionResponse, DetectionSearchQuery, DetectionRuleExport, SuricataRule, SEMRule } from '../detection/schema';
import { DetectionFormat, RuleSeverity } from '../detection/schema';
import {
  generateSigmaFromIOC,
  generateYaraFromIOC,
  generateSuricataFromIOC,
  generateSEMRuleFromIOC,
  buildDetectionCollection,
  renderDetectionRuleExport,
  optimizeRuleSet,
  validateDetectionRule,
} from '../detection/index';
import type { IOCType } from '../intelligence/schema';

// ============================================================================
// IN-MEMORY DETECTION RULE STORE
// ============================================================================

const detectionRuleStore = new Map<string, DetectionRule>();

// ============================================================================
// DETECTION RULE GENERATION
// ============================================================================

export function generateDetectionRules(request: GenerateDetectionRequest): GenerateDetectionResponse {
  const rules: DetectionRule[] = [];

  const malwareName = request.malwareId || 'UnknownMalware';
  const formats = request.formats || [DetectionFormat.SIGMA, DetectionFormat.YARA, DetectionFormat.SURICATA];
  const techniques = request.techniques || [];

  // Generate base rule ID
  const ruleId = `det_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

  // Generate Sigma rule
  let sigmaRule = null;
  if (formats.includes(DetectionFormat.SIGMA)) {
    sigmaRule = generateSigmaFromIOC(request.iocType as IOCType, request.iocValue, malwareName, {
      severity: request.severity,
      techniques,
      malwareId: request.malwareId,
    });
  }

  // Generate YARA rule
  let yaraRule = null;
  if (formats.includes(DetectionFormat.YARA)) {
    yaraRule = generateYaraFromIOC(request.iocType as IOCType, request.iocValue, malwareName, {
      severity: request.severity,
    });
  }

  // Generate Suricata rules
  let suricataRules: SuricataRule[] = [];
  if (formats.includes(DetectionFormat.SURICATA)) {
    suricataRules = generateSuricataFromIOC(request.iocType as IOCType, request.iocValue, malwareName, {
      severity: request.severity,
    });
  }

  // Generate SIEM rules
  let semRules: SEMRule[] = [];
  if (formats.includes(DetectionFormat.SPLUNK) || formats.includes(DetectionFormat.ELK) || formats.includes(DetectionFormat.SENTINEL)) {
    semRules = generateSEMRuleFromIOC(request.iocType as IOCType, request.iocValue, malwareName, {
      severity: request.severity,
    });
  }

  // Create unified detection rule
  const detectionRule: DetectionRule = {
    id: ruleId,
    name: `${malwareName} - ${request.iocType} Detection`,
    description: `Automated detection rule for ${malwareName} based on ${request.iocType} indicator: ${request.iocValue}`,
    author: 'SENTINEL APEX Detection Engineering',
    date: new Date().toISOString().split('T')[0],
    severity: request.severity || RuleSeverity.HIGH,
    formats: {
      sigma: sigmaRule || undefined,
      yara: yaraRule || undefined,
      suricata: suricataRules.length > 0 ? suricataRules : undefined,
      siem: semRules.length > 0 ? semRules : undefined,
    },
    metadata: {
      linkedMalware: request.malwareId ? [request.malwareId] : [],
      linkedTechniques: techniques,
      linkedIOCs: [request.iocValue],
      coverage: 0.8,
      fpRate: 0.05,
    },
    behaviors: [],
    references: ['https://www.cyberdudebivash.in', 'https://mitre-attack.github.io'],
    enabled: true,
    tags: [malwareName.toLowerCase(), request.iocType, 'auto-generated'],
  };

  // Validate rule
  const validation = validateDetectionRule(detectionRule);
  if (!validation.valid) {
    throw new Error(`Detection rule validation failed: ${validation.errors.map(e => e.error).join('; ')}`);
  }

  rules.push(detectionRule);

  // Store rule
  detectionRuleStore.set(ruleId, detectionRule);

  // Calculate coverage
  let coverage = 0.8; // Default 80% coverage
  if (formats.includes(DetectionFormat.SIGMA) && sigmaRule) coverage += 0.05;
  if (formats.includes(DetectionFormat.YARA) && yaraRule) coverage += 0.05;
  if (formats.includes(DetectionFormat.SURICATA) && suricataRules.length > 0) coverage += 0.05;
  if ((formats.includes(DetectionFormat.SPLUNK) || formats.includes(DetectionFormat.ELK) || formats.includes(DetectionFormat.SENTINEL)) && semRules.length > 0) coverage += 0.05;
  coverage = Math.min(coverage, 1.0);

  return {
    rules,
    coverage: Math.round(coverage * 100) / 100,
    timestamp: new Date().toISOString(),
  };
}

// ============================================================================
// DETECTION RULE RETRIEVAL
// ============================================================================

export function getDetectionRule(ruleId: string): DetectionRule | undefined {
  return detectionRuleStore.get(ruleId);
}

export function searchDetectionRules(query: DetectionSearchQuery): DetectionRule[] {
  const results: DetectionRule[] = [];

  for (const rule of detectionRuleStore.values()) {
    // Filter by malware
    if (query.malwareId && !rule.metadata.linkedMalware.includes(query.malwareId)) {
      continue;
    }

    // Filter by technique
    if (query.technique && !rule.metadata.linkedTechniques.includes(query.technique)) {
      continue;
    }

    // Filter by IOC
    if (query.iocValue) {
      const hasIOC = rule.metadata.linkedIOCs.some(ioc => ioc.toLowerCase().includes(query.iocValue!.toLowerCase()));
      if (!hasIOC) continue;
    }

    // Filter by severity
    if (query.severity && rule.severity !== query.severity) {
      continue;
    }

    // Filter by behavior
    if (query.behavior && !rule.behaviors.includes(query.behavior)) {
      continue;
    }

    results.push(rule);
  }

  // Apply pagination
  const offset = query.offset || 0;
  const limit = query.limit || 100;
  return results.slice(offset, offset + limit);
}

export function listAllRules(): DetectionRule[] {
  return Array.from(detectionRuleStore.values());
}

// ============================================================================
// DETECTION RULE EXPORT
// ============================================================================

export function exportRules(ruleIds: string[], format: string): DetectionRuleExport | null {
  const rules: DetectionRule[] = [];

  for (const ruleId of ruleIds) {
    const rule = detectionRuleStore.get(ruleId);
    if (rule) {
      rules.push(rule);
    }
  }

  if (rules.length === 0) {
    return null;
  }

  const collection = buildDetectionCollection('Detection Rule Set', rules);
  return renderDetectionRuleExport(collection, format as any);
}

export function exportMalwareRules(malwareId: string, format: string): DetectionRuleExport | null {
  const rules = searchDetectionRules({ malwareId });

  if (rules.length === 0) {
    return null;
  }

  const collection = buildDetectionCollection(malwareId, rules);
  return renderDetectionRuleExport(collection, format as any);
}

// ============================================================================
// DETECTION RULE OPTIMIZATION
// ============================================================================

export function optimizeDetectionRules(): void {
  const allRules = Array.from(detectionRuleStore.values());

  if (allRules.length === 0) {
    return;
  }

  const metrics = optimizeRuleSet(allRules);

  console.log('Detection Rule Optimization Results:');
  console.log(`Total Rules: ${metrics.totalRules}`);
  console.log(`Redundant Rules Removed: ${metrics.redundantRules}`);
  console.log(`Average Coverage: ${metrics.averageCoverage}%`);
  console.log(`Average False Positive Rate: ${(metrics.averageFPRate * 100).toFixed(2)}%`);
  console.log('Recommendations:');
  for (const rec of metrics.recommendations) {
    console.log(`- ${rec}`);
  }
}

// ============================================================================
// MALWARE-SPECIFIC DETECTION GENERATION
// ============================================================================

export interface MalwareDetectionPackRequest {
  malwareId: string;
  malwareName: string;
  iocs: Array<{
    type: IOCType;
    value: string;
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  }>;
  techniques?: string[];
  formats?: DetectionFormat[];
}

export function generateMalwareDetectionPack(request: MalwareDetectionPackRequest): DetectionRule[] {
  const rules: DetectionRule[] = [];

  // Generate rules for each high-confidence IOC
  for (const ioc of request.iocs) {
    if (ioc.confidence === 'HIGH' || ioc.confidence === 'MEDIUM') {
      const response = generateDetectionRules({
        iocType: ioc.type,
        iocValue: ioc.value,
        malwareId: request.malwareId,
        techniques: request.techniques,
        formats: request.formats || [DetectionFormat.SIGMA, DetectionFormat.YARA, DetectionFormat.SURICATA],
        severity: ioc.confidence === 'HIGH' ? RuleSeverity.HIGH : RuleSeverity.MEDIUM,
      });

      rules.push(...response.rules);
    }
  }

  return rules;
}

// ============================================================================
// RULE STATISTICS
// ============================================================================

export interface DetectionRuleStats {
  totalRules: number;
  rulesByFormat: Record<string, number>;
  rulesByMalware: Record<string, number>;
  rulesBySeverity: Record<string, number>;
  avgCoverage: number;
  avgFPRate: number;
}

export function getDetectionRuleStats(): DetectionRuleStats {
  const allRules = Array.from(detectionRuleStore.values());

  const byFormat: Record<string, number> = {
    sigma: 0,
    yara: 0,
    suricata: 0,
    siem: 0,
  };

  const byMalware: Record<string, number> = {};
  const bySeverity: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  let totalCoverage = 0;
  let totalFP = 0;

  for (const rule of allRules) {
    if (rule.formats.sigma) byFormat.sigma++;
    if (rule.formats.yara) byFormat.yara++;
    if (rule.formats.suricata) byFormat.suricata++;
    if (rule.formats.siem) byFormat.siem++;

    for (const malware of rule.metadata.linkedMalware) {
      byMalware[malware] = (byMalware[malware] || 0) + 1;
    }

    bySeverity[rule.severity]++;
    totalCoverage += rule.metadata.coverage || 0;
    totalFP += rule.metadata.fpRate || 0;
  }

  return {
    totalRules: allRules.length,
    rulesByFormat: byFormat,
    rulesByMalware: byMalware,
    rulesBySeverity: bySeverity,
    avgCoverage: allRules.length > 0 ? Math.round((totalCoverage / allRules.length) * 100) / 100 : 0,
    avgFPRate: allRules.length > 0 ? Math.round((totalFP / allRules.length) * 10000) / 100 : 0,
  };
}
