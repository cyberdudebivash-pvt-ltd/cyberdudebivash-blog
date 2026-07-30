/**
 * Detection Rule Correlator
 * Links detection rules to MITRE techniques, malware families, IOCs, campaigns
 */

import type {
  DetectionRule,
  DetectionBehavior,
  RuleMetadata,
  DetectionRuleCollection,
} from './schema';
import type { MalwareFamily, Campaign, ThreatActor, MitreTechnique } from '../intelligence/schema';

// ============================================================================
// TECHNIQUE MAPPING
// ============================================================================

export interface TechniqueMapping {
  technique_id: string;
  technique_name: string;
  behaviors: DetectionBehavior[];
}

const MITRE_TECHNIQUE_MAP: Record<string, TechniqueMapping> = {
  'T1071.001': {
    technique_id: 'T1071.001',
    technique_name: 'Application Layer Protocol: Web Protocols',
    behaviors: ['NETWORK_COMMUNICATION'],
  },
  'T1190': {
    technique_id: 'T1190',
    technique_name: 'Exploit Public-Facing Application',
    behaviors: ['PROCESS_EXECUTION'],
  },
  'T1566': {
    technique_id: 'T1566',
    technique_name: 'Phishing',
    behaviors: ['INITIAL_ACCESS'],
  },
  'T1192': {
    technique_id: 'T1192',
    technique_name: 'Spear Phishing',
    behaviors: ['INITIAL_ACCESS'],
  },
  'T1547.001': {
    technique_id: 'T1547.001',
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys',
    behaviors: ['PERSISTENCE', 'DEFENSE_EVASION'],
  },
  'T1547.012': {
    technique_id: 'T1547.012',
    technique_name: 'Boot or Logon Autostart Execution: Print Processors',
    behaviors: ['PERSISTENCE', 'DEFENSE_EVASION'],
  },
  'T1547': {
    technique_id: 'T1547',
    technique_name: 'Boot or Logon Autostart Execution',
    behaviors: ['PERSISTENCE'],
  },
  'T1110': {
    technique_id: 'T1110',
    technique_name: 'Brute Force',
    behaviors: ['CREDENTIAL_THEFT'],
  },
  'T1001': {
    technique_id: 'T1001',
    technique_name: 'Data Obfuscation',
    behaviors: ['DEFENSE_EVASION'],
  },
  'T1566.002': {
    technique_id: 'T1566.002',
    technique_name: 'Phishing: Phishing Attachment',
    behaviors: ['INITIAL_ACCESS'],
  },
  'T1486': {
    technique_id: 'T1486',
    technique_name: 'Data Encrypted for Impact',
    behaviors: ['DATA_EXFILTRATION'],
  },
  'T1105': {
    technique_id: 'T1105',
    technique_name: 'Ingress Tool Transfer',
    behaviors: ['COMMAND_AND_CONTROL'],
  },
  'T1570': {
    technique_id: 'T1570',
    technique_name: 'Lateral Tool Transfer',
    behaviors: ['LATERAL_MOVEMENT'],
  },
  'T1133': {
    technique_id: 'T1133',
    technique_name: 'External Remote Services',
    behaviors: ['PERSISTENCE', 'INITIAL_ACCESS'],
  },
};

// ============================================================================
// BEHAVIOR TO TECHNIQUE MAPPING
// ============================================================================

export function mapBehaviorToTechniques(behaviors: DetectionBehavior[]): TechniqueMapping[] {
  const techniques = new Map<string, TechniqueMapping>();

  for (const behavior of behaviors) {
    for (const [, mapping] of Object.entries(MITRE_TECHNIQUE_MAP)) {
      if (mapping.behaviors.some(b => b === behavior)) {
        if (!techniques.has(mapping.technique_id)) {
          techniques.set(mapping.technique_id, mapping);
        }
      }
    }
  }

  return Array.from(techniques.values());
}

// ============================================================================
// MALWARE RULE LINKING
// ============================================================================

export function linkRulesToMalware(rules: DetectionRule[], malwareFamilies: MalwareFamily[]): void {
  for (const rule of rules) {
    for (const family of malwareFamilies) {
      // Check if rule IOCs match malware IOCs
      const ruleIOCs = new Set<string>(rule.metadata.linkedIOCs);
      const malwareIOCs = new Set(family.iocs.map(ioc => ioc.normalized.toUpperCase()));

      for (const ruleIOC of ruleIOCs) {
        if (malwareIOCs.has(ruleIOC.toUpperCase())) {
          if (!rule.metadata.linkedMalware.includes(family.id)) {
            rule.metadata.linkedMalware.push(family.id);
          }
        }
      }

      // Check if rule techniques match malware techniques
      const ruleTechniques = new Set<string>(rule.metadata.linkedTechniques);
      const malwareTechniques = new Set(family.mitre_techniques.map(t => t.technique_id));

      for (const technique of ruleTechniques) {
        if (malwareTechniques.has(technique)) {
          if (!rule.metadata.linkedMalware.includes(family.id)) {
            rule.metadata.linkedMalware.push(family.id);
          }
        }
      }
    }
  }
}

// ============================================================================
// TECHNIQUE LINKING
// ============================================================================

export function linkRulesToTechniques(rules: DetectionRule[], techniques: MitreTechnique[]): void {
  const techniqueMap = new Map(techniques.map(t => [t.technique_id, t]));

  for (const rule of rules) {
    for (const technique of techniques) {
      // Match by behavior
      const ruleBehaviors = new Set(rule.behaviors);
      const technicateBehaviors = new Set(
        mapBehaviorToTechniques(Array.from(ruleBehaviors) as DetectionBehavior[]).map(t => t.technique_id)
      );

      if (technicateBehaviors.has(technique.technique_id)) {
        if (!rule.metadata.linkedTechniques.includes(technique.technique_id)) {
          rule.metadata.linkedTechniques.push(technique.technique_id);
        }
      }
    }
  }
}

// ============================================================================
// CAMPAIGN LINKING
// ============================================================================

export function linkRulesToCampaigns(rules: DetectionRule[], campaigns: Campaign[]): void {
  for (const rule of rules) {
    for (const campaign of campaigns) {
      // Link through malware families
      const ruleHasMalware = rule.metadata.linkedMalware.some(m => campaign.malware.includes(m));

      if (ruleHasMalware) {
        if (!rule.metadata.linkedMalware.includes(campaign.id)) {
          // Add campaign context to metadata
          if (!rule.metadata.linkedMalware.includes(`campaign_${campaign.id}`)) {
            rule.metadata.linkedMalware.push(`campaign_${campaign.id}`);
          }
        }
      }
    }
  }
}

// ============================================================================
// THREAT ACTOR LINKING
// ============================================================================

export function linkRulesToActors(rules: DetectionRule[], actors: ThreatActor[]): void {
  for (const rule of rules) {
    for (const actor of actors) {
      // Link through malware families
      const ruleHasMalware = rule.metadata.linkedMalware.some(m => actor.malware.includes(m));

      if (ruleHasMalware) {
        if (!rule.metadata.linkedMalware.includes(`actor_${actor.id}`)) {
          rule.metadata.linkedMalware.push(`actor_${actor.id}`);
        }
      }
    }
  }
}

// ============================================================================
// RULE COVERAGE CALCULATION
// ============================================================================

export interface CoverageAnalysis {
  totalRules: number;
  totalIOCs: number;
  coveredIOCs: number;
  uncoveredIOCs: string[];
  coverage: number;
  gapAnalysis: string[];
}

export function calculateRuleCoverage(rules: DetectionRule[], iocs: string[]): CoverageAnalysis {
  const ruleIOCs = new Set<string>();

  for (const rule of rules) {
    for (const ioc of rule.metadata.linkedIOCs) {
      ruleIOCs.add(ioc.toUpperCase());
    }
  }

  const iocSet = new Set(iocs.map(i => i.toUpperCase()));
  const uncoveredIOCs = Array.from(iocSet).filter(ioc => !ruleIOCs.has(ioc));
  const coveredIOCs = iocSet.size - uncoveredIOCs.length;
  const coverage = iocSet.size > 0 ? (coveredIOCs / iocSet.size) * 100 : 0;

  // Gap analysis
  const gapAnalysis: string[] = [];
  if (coverage < 50) {
    gapAnalysis.push('Low IOC coverage - recommend additional rule generation');
  }
  if (uncoveredIOCs.length > 0 && uncoveredIOCs.length <= 5) {
    gapAnalysis.push(`Missing rules for: ${uncoveredIOCs.slice(0, 5).join(', ')}`);
  }

  return {
    totalRules: rules.length,
    totalIOCs: iocSet.size,
    coveredIOCs,
    uncoveredIOCs,
    coverage: Math.round(coverage * 100) / 100,
    gapAnalysis,
  };
}

// ============================================================================
// RULE COLLECTION BUILDING
// ============================================================================

export function buildDetectionCollection(
  malwareName: string,
  rules: DetectionRule[],
  malwareFamilies?: MalwareFamily[],
  campaigns?: Campaign[]
): DetectionRuleCollection {
  // Extract metadata
  const linkedMalware = new Set<string>();
  const linkedTechniques = new Set<string>();
  let totalIOCs = 0;

  for (const rule of rules) {
    rule.metadata.linkedMalware.forEach(m => linkedMalware.add(m));
    rule.metadata.linkedTechniques.forEach(t => linkedTechniques.add(t));
    totalIOCs += rule.metadata.linkedIOCs.length;
  }

  // Link rules to malware if provided
  if (malwareFamilies) {
    linkRulesToMalware(rules, malwareFamilies);
  }

  if (campaigns) {
    linkRulesToCampaigns(rules, campaigns);
  }

  const collection: DetectionRuleCollection = {
    name: `${malwareName} Detection Rule Set`,
    description: `Comprehensive detection rules for ${malwareName} across multiple platforms (Sigma, YARA, Suricata, SIEM)`,
    author: 'SENTINEL APEX Detection Engineering',
    date: new Date().toISOString().split('T')[0],
    rules,
    metadata: {
      totalRules: rules.length,
      malwareFamilies: Array.from(linkedMalware),
      techniques: Array.from(linkedTechniques),
      iocCount: totalIOCs,
    },
  };

  return collection;
}

// ============================================================================
// RULE PRIORITIZATION
// ============================================================================

export interface RulePriority {
  rule: DetectionRule;
  priority: number;
  score: {
    iocCoverage: number;
    techniqueCoverage: number;
    falsePositiveRisk: number;
    malwareLinkage: number;
  };
}

export function prioritizeRules(rules: DetectionRule[]): RulePriority[] {
  return rules
    .map(rule => {
      const iocCoverage = rule.metadata.linkedIOCs.length > 0 ? 1 : 0;
      const techniqueCoverage = rule.metadata.linkedTechniques.length > 0 ? 0.8 : 0;
      const falsePositiveRisk = rule.metadata.fpRate ? 1 - rule.metadata.fpRate : 0.5;
      const malwareLinkage = rule.metadata.linkedMalware.length > 0 ? 1 : 0;

      const score = iocCoverage + techniqueCoverage + falsePositiveRisk + malwareLinkage;

      return {
        rule,
        priority: Math.round(score * 100),
        score: {
          iocCoverage,
          techniqueCoverage,
          falsePositiveRisk,
          malwareLinkage,
        },
      };
    })
    .sort((a, b) => b.priority - a.priority);
}

// ============================================================================
// RULE EFFECTIVENESS METRICS
// ============================================================================

export interface RuleEffectiveness {
  totalRules: number;
  avgCoverage: number;
  avgFPRate: number;
  effectivenessScore: number;
  recommendations: string[];
}

export function calculateRuleEffectiveness(rules: DetectionRule[]): RuleEffectiveness {
  if (rules.length === 0) {
    return {
      totalRules: 0,
      avgCoverage: 0,
      avgFPRate: 0,
      effectivenessScore: 0,
      recommendations: ['No rules to evaluate'],
    };
  }

  const avgCoverage =
    rules.reduce((sum, r) => sum + (r.metadata.coverage || 0), 0) / rules.length;

  const avgFPRate =
    rules.reduce((sum, r) => sum + (r.metadata.fpRate || 0), 0) / rules.length;

  const effectivenessScore = Math.round((avgCoverage * (1 - avgFPRate)) * 100);

  const recommendations: string[] = [];
  if (avgFPRate > 0.1) {
    recommendations.push('High false positive rate - consider tuning detections');
  }
  if (avgCoverage < 0.5) {
    recommendations.push('Low coverage - recommend additional rule generation');
  }
  if (effectivenessScore > 80) {
    recommendations.push('Excellent detection effectiveness - ready for production');
  }

  return {
    totalRules: rules.length,
    avgCoverage: Math.round(avgCoverage * 100) / 100,
    avgFPRate: Math.round(avgFPRate * 100) / 100,
    effectivenessScore,
    recommendations,
  };
}
