/**
 * Detection Rule Optimizer
 * Deduplicates, optimizes, and consolidates detection rules
 */

import type { DetectionRule, DeduplicationResult, OptimizationMetrics, SigmaRule } from './schema';

// ============================================================================
// RULE DEDUPLICATION
// ============================================================================

export function deduplicateRules(rules: DetectionRule[]): DeduplicationResult {
  const ruleMap = new Map<string, DetectionRule>();
  const redundantRules: DetectionRule[] = [];

  for (const rule of rules) {
    const canonical = generateCanonical(rule);

    if (ruleMap.has(canonical)) {
      // Merge with existing rule
      const existing = ruleMap.get(canonical)!;
      mergeRules(existing, rule);
      redundantRules.push(rule);
    } else {
      ruleMap.set(canonical, rule);
    }
  }

  const confidence = rules.length > 0 ? ((rules.length - redundantRules.length) / rules.length) * 100 : 0;

  return {
    originalCount: rules.length,
    deduplicatedCount: ruleMap.size,
    mergedRules: Array.from(ruleMap.values()),
    redundantRules,
    confidence: Math.round(confidence) / 100,
  };
}

function generateCanonical(rule: DetectionRule): string {
  // Create a canonical representation for deduplication
  const iocs = [...rule.metadata.linkedIOCs].sort().join('|');
  const techniques = [...rule.metadata.linkedTechniques].sort().join('|');
  const behaviors = [...rule.behaviors].sort().join('|');

  return `${iocs}::${techniques}::${behaviors}`;
}

function mergeRules(target: DetectionRule, source: DetectionRule): void {
  // Merge metadata
  for (const ioc of source.metadata.linkedIOCs) {
    if (!target.metadata.linkedIOCs.includes(ioc)) {
      target.metadata.linkedIOCs.push(ioc);
    }
  }

  for (const technique of source.metadata.linkedTechniques) {
    if (!target.metadata.linkedTechniques.includes(technique)) {
      target.metadata.linkedTechniques.push(technique);
    }
  }

  for (const malware of source.metadata.linkedMalware) {
    if (!target.metadata.linkedMalware.includes(malware)) {
      target.metadata.linkedMalware.push(malware);
    }
  }

  // Average coverage
  if (source.metadata.coverage && target.metadata.coverage) {
    target.metadata.coverage = (target.metadata.coverage + source.metadata.coverage) / 2;
  }

  // Average false positive rate
  if (source.metadata.fpRate && target.metadata.fpRate) {
    target.metadata.fpRate = (target.metadata.fpRate + source.metadata.fpRate) / 2;
  }
}

// ============================================================================
// SIGMA LOGSOURCE OPTIMIZATION
// ============================================================================

export function optimizeSigmaLogsources(rules: DetectionRule[]): DetectionRule[] {
  const logsourceMap = new Map<string, DetectionRule[]>();

  // Group by logsource
  for (const rule of rules) {
    if (rule.formats.sigma) {
      const sig = rule.formats.sigma;
      const key = `${sig.logsource.category || 'unknown'}|${sig.logsource.product || 'unknown'}|${sig.logsource.service || 'unknown'}`;

      if (!logsourceMap.has(key)) {
        logsourceMap.set(key, []);
      }
      logsourceMap.get(key)!.push(rule);
    }
  }

  // Consolidate high-count logsources
  for (const [key, groupRules] of logsourceMap) {
    if (groupRules.length > 1) {
      // Could consolidate into a single complex sigma rule
      // For now, return consolidated list
    }
  }

  return rules;
}

// ============================================================================
// YARA STRING OPTIMIZATION
// ============================================================================

export function optimizeYaraStrings(rules: DetectionRule[]): DetectionRule[] {
  for (const rule of rules) {
    if (rule.formats.yara) {
      const yara = rule.formats.yara;

      // Deduplicate strings
      const stringMap = new Map<string, any>();
      for (const str of yara.strings) {
        const key = `${str.pattern}|${str.isRegex}|${str.isWide}`;
        if (!stringMap.has(key)) {
          stringMap.set(key, str);
        }
      }

      yara.strings = Array.from(stringMap.values());

      // Optimize condition
      optimizeYaraCondition(yara);
    }
  }

  return rules;
}

function optimizeYaraCondition(yaraRule: any): void {
  // Replace overly permissive conditions
  if (yaraRule.condition === 'any of them') {
    // If few strings, require more specificity
    if (yaraRule.strings.length <= 3) {
      yaraRule.condition = `all of them`;
    }
  }

  if (yaraRule.condition === 'true') {
    // Never use true condition
    yaraRule.condition = `any of them`;
  }
}

// ============================================================================
// SURICATA RULE CONSOLIDATION
// ============================================================================

export function consolidateSuricataRules(rules: DetectionRule[]): DetectionRule[] {
  for (const rule of rules) {
    if (rule.formats.suricata && rule.formats.suricata.length > 1) {
      // Group similar Suricata rules
      const sidMap = new Map<number, any>();

      for (const sRule of rule.formats.suricata) {
        if (!sidMap.has(sRule.sid as number)) {
          sidMap.set(sRule.sid as number, sRule);
        }
      }

      rule.formats.suricata = Array.from(sidMap.values());
    }
  }

  return rules;
}

// ============================================================================
// COVERAGE CALCULATION
// ============================================================================

export interface IOCCoverage {
  totalIOCs: number;
  coveredByRule: number;
  uncoveredIOCs: string[];
  coverage: number;
}

export function calculateIOCCoverage(rules: DetectionRule[], allIOCs: string[]): IOCCoverage {
  const coveredSet = new Set<string>();

  for (const rule of rules) {
    for (const ioc of rule.metadata.linkedIOCs) {
      coveredSet.add(ioc.toUpperCase());
    }
  }

  const iocSet = new Set(allIOCs.map(i => i.toUpperCase()));
  const uncovered = Array.from(iocSet).filter(ioc => !coveredSet.has(ioc));

  return {
    totalIOCs: iocSet.size,
    coveredByRule: coveredSet.size,
    uncoveredIOCs: uncovered,
    coverage: iocSet.size > 0 ? (coveredSet.size / iocSet.size) * 100 : 0,
  };
}

// ============================================================================
// FALSE POSITIVE ANALYSIS
// ============================================================================

export interface FPAnalysis {
  highRiskRules: DetectionRule[];
  mediumRiskRules: DetectionRule[];
  lowRiskRules: DetectionRule[];
  avgFPRate: number;
  recommendations: string[];
}

export function analyzeFalsePositives(rules: DetectionRule[]): FPAnalysis {
  const highRisk: DetectionRule[] = [];
  const mediumRisk: DetectionRule[] = [];
  const lowRisk: DetectionRule[] = [];

  let totalFP = 0;
  for (const rule of rules) {
    const fpRate = rule.metadata.fpRate || 0.05; // Default 5% FP rate
    totalFP += fpRate;

    if (fpRate > 0.1) {
      highRisk.push(rule);
    } else if (fpRate > 0.05) {
      mediumRisk.push(rule);
    } else {
      lowRisk.push(rule);
    }
  }

  const avgFPRate = rules.length > 0 ? totalFP / rules.length : 0;

  const recommendations: string[] = [];
  if (highRisk.length > 0) {
    recommendations.push(`${highRisk.length} rules have high FP rates (>10%) - recommend tuning`);
  }
  if (avgFPRate > 0.08) {
    recommendations.push('Average FP rate is high - consider rule threshold adjustments');
  }
  if (avgFPRate < 0.02) {
    recommendations.push('Rules are very conservative - may miss detections');
  }

  return {
    highRiskRules: highRisk,
    mediumRiskRules: mediumRisk,
    lowRiskRules: lowRisk,
    avgFPRate: Math.round(avgFPRate * 100) / 100,
    recommendations,
  };
}

// ============================================================================
// COMPREHENSIVE OPTIMIZATION
// ============================================================================

export function optimizeRuleSet(rules: DetectionRule[]): OptimizationMetrics {
  // Deduplicate
  const dedup = deduplicateRules(rules);
  const dedupRules = dedup.mergedRules;

  // Optimize formats
  optimizeSigmaLogsources(dedupRules);
  optimizeYaraStrings(dedupRules);
  consolidateSuricataRules(dedupRules);

  // Analyze
  const fpAnalysis = analyzeFalsePositives(dedupRules);
  const redundantCount = dedup.redundantRules.length;
  const avgCoverage = dedupRules.reduce((sum, r) => sum + (r.metadata.coverage || 0), 0) / dedupRules.length || 0;

  const recommendations: string[] = [];

  if (redundantCount > 0) {
    recommendations.push(`Removed ${redundantCount} duplicate rules`);
  }

  recommendations.push(...fpAnalysis.recommendations);

  if (avgCoverage > 0.8) {
    recommendations.push('Excellent IOC coverage - rule set is comprehensive');
  }

  return {
    totalRules: dedupRules.length,
    redundantRules: redundantCount,
    averageCoverage: Math.round(avgCoverage * 100) / 100,
    averageFPRate: fpAnalysis.avgFPRate,
    recommendations,
  };
}

// ============================================================================
// RULE PERFORMANCE PROFILING
// ============================================================================

export interface RulePerformanceProfile {
  ruleName: string;
  estimatedLatency: number;
  estimatedCPU: number;
  estimatedMemory: number;
  recommendation: string;
}

export function profileRulePerformance(rule: DetectionRule): RulePerformanceProfile {
  let latency = 1; // Base latency in ms
  let cpu = 1; // Relative CPU usage
  let memory = 1; // Relative memory usage

  // Sigma rules are typically fast
  if (rule.formats.sigma) {
    latency += 0.5;
    cpu += 0.3;
  }

  // YARA rules vary by complexity
  if (rule.formats.yara) {
    const stringCount = rule.formats.yara.strings.length;
    latency += stringCount * 0.2;
    cpu += stringCount * 0.1;
    memory += stringCount * 0.05;
  }

  // Suricata rules are medium complexity
  if (rule.formats.suricata && rule.formats.suricata.length > 0) {
    latency += rule.formats.suricata.length * 0.3;
    cpu += rule.formats.suricata.length * 0.2;
  }

  // SIEM rules are typically slower
  if (rule.formats.siem && rule.formats.siem.length > 0) {
    latency += rule.formats.siem.length * 0.5;
    cpu += rule.formats.siem.length * 0.3;
    memory += rule.formats.siem.length * 0.1;
  }

  let recommendation = 'Good performance profile';
  if (latency > 5) {
    recommendation = 'Consider splitting into multiple rules for better performance';
  } else if (cpu > 5) {
    recommendation = 'High CPU usage - may impact SIEM performance';
  }

  return {
    ruleName: rule.name,
    estimatedLatency: Math.round(latency * 100) / 100,
    estimatedCPU: Math.round(cpu * 100) / 100,
    estimatedMemory: Math.round(memory * 100) / 100,
    recommendation,
  };
}
