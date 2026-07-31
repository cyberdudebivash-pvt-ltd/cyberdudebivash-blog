'use strict';

const redis = require('./redis');

class GapAnalyzer {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async analyzeInvestigationGaps(investigation) {
    const gaps = [];

    // Evidence gaps
    const evidenceGaps = await this.identifyEvidenceGaps(investigation);
    gaps.push(...evidenceGaps);

    // Attribution gaps
    const attributionGaps = await this.identifyAttributionGaps(investigation);
    gaps.push(...attributionGaps);

    // Technical gaps
    const technicalGaps = await this.identifyTechnicalGaps(investigation);
    gaps.push(...technicalGaps);

    // Timeline gaps
    const timelineGaps = await this.identifyTimelineGaps(investigation);
    gaps.push(...timelineGaps);

    // Detection gaps
    const detectionGaps = await this.identifyDetectionGaps(investigation);
    gaps.push(...detectionGaps);

    return {
      investigationId: investigation.id,
      totalGaps: gaps.length,
      criticalGaps: gaps.filter(g => g.priority === 'critical'),
      highPriorityGaps: gaps.filter(g => g.priority === 'high'),
      mediumPriorityGaps: gaps.filter(g => g.priority === 'medium'),
      gaps: gaps.sort((a, b) => {
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return priorityOrder[a.priority] - priorityOrder[b.priority];
      }),
    };
  }

  async identifyEvidenceGaps(investigation) {
    const gaps = [];

    const linkedEntities = investigation.linkedIntelligence || [];
    if (!linkedEntities || linkedEntities.length < 3) {
      gaps.push({
        id: `gap_evidence_1`,
        category: 'evidence',
        description: 'Limited linked intelligence',
        detail: `Only ${linkedEntities.length} intelligence items linked. Consider expanding knowledge base integration.`,
        priority: 'high',
        impact: 'medium',
        collectingRecommendation: 'Link additional threat intelligence sources and reports',
        collectionEffort: 'medium',
      });
    }

    const investigations = investigation.linkedIntelligence || [];
    let hasReports = false;
    let hasIOCs = false;
    let hasArticles = false;

    for (const intel of investigations) {
      if (intel.type === 'THREAT_REPORT') hasReports = true;
      if (intel.type === 'IOC') hasIOCs = true;
      if (intel.type === 'ARTICLE') hasArticles = true;
    }

    if (!hasReports) {
      gaps.push({
        id: `gap_evidence_reports`,
        category: 'evidence',
        description: 'No threat reports linked',
        detail: 'Investigation lacks vendor threat reports. Link relevant security advisories and threat intelligence reports.',
        priority: 'medium',
        impact: 'medium',
        collectingRecommendation: 'Collect relevant threat intelligence reports from vendors and open-source feeds',
        collectionEffort: 'medium',
      });
    }

    if (!hasIOCs) {
      gaps.push({
        id: `gap_evidence_iocs`,
        category: 'evidence',
        description: 'No indicators of compromise',
        detail: 'No IOCs have been identified. Extract and link hashes, domains, IPs, and URLs from incidents.',
        priority: 'high',
        impact: 'high',
        collectingRecommendation: 'Extract IOCs from incident evidence and threat reports',
        collectionEffort: 'high',
      });
    }

    if (!hasArticles && investigations.length > 0) {
      gaps.push({
        id: `gap_evidence_analysis`,
        category: 'evidence',
        description: 'Limited analytical coverage',
        detail: 'Investigation references intelligence but lacks detailed analysis articles.',
        priority: 'low',
        impact: 'low',
        collectingRecommendation: 'Create detailed analysis articles documenting findings and methodology',
        collectionEffort: 'high',
      });
    }

    return gaps;
  }

  async identifyAttributionGaps(investigation) {
    const gaps = [];

    const linkedEntities = investigation.linkedIntelligence || [];
    let hasThreatActors = false;
    let hasCampaigns = false;

    for (const intel of linkedEntities) {
      if (intel.type === 'THREAT_ACTOR') hasThreatActors = true;
      if (intel.type === 'CAMPAIGN') hasCampaigns = true;
    }

    if (!hasThreatActors) {
      gaps.push({
        id: `gap_attribution_actors`,
        category: 'attribution',
        description: 'No threat actors identified',
        detail: 'Investigation has not identified or linked to threat actors. Analyze TTPs and infrastructure to attribute activity.',
        priority: 'high',
        impact: 'high',
        collectingRecommendation: 'Perform threat actor attribution analysis using infrastructure, TTPs, and historical patterns',
        collectionEffort: 'very_high',
      });
    }

    if (!hasCampaigns) {
      gaps.push({
        id: `gap_attribution_campaigns`,
        category: 'attribution',
        description: 'No campaign linkage',
        detail: 'Investigation not linked to known campaigns. Correlate activity patterns to identify campaign membership.',
        priority: 'medium',
        impact: 'medium',
        collectingRecommendation: 'Map attack patterns to known campaigns and cluster activities',
        collectionEffort: 'high',
      });
    }

    return gaps;
  }

  async identifyTechnicalGaps(investigation) {
    const gaps = [];

    const linkedEntities = investigation.linkedIntelligence || [];
    let hasIOCs = false;
    let hasMalware = false;
    let hasTechniques = false;
    let hasInfrastructure = false;

    for (const intel of linkedEntities) {
      if (intel.type === 'IOC') hasIOCs = true;
      if (intel.type === 'MALWARE') hasMalware = true;
      if (intel.mitreAttackTechs && intel.mitreAttackTechs.length > 0) hasTechniques = true;
      if (intel.type === 'INFRASTRUCTURE') hasInfrastructure = true;
    }

    if (!hasIOCs) {
      gaps.push({
        id: `gap_technical_iocs`,
        category: 'ioc',
        description: 'Missing indicators of compromise',
        detail: 'No file hashes, domains, IPs, or URLs documented. Extract indicators from malware samples and network evidence.',
        priority: 'critical',
        impact: 'high',
        collectingRecommendation: 'Extract and catalog IOCs: file hashes, C2 domains/IPs, URLs, email addresses',
        collectionEffort: 'high',
      });
    }

    if (!hasMalware) {
      gaps.push({
        id: `gap_technical_malware`,
        category: 'malware',
        description: 'No malware analysis',
        detail: 'Investigation lacks malware analysis. Analyze capabilities, IOCs, and behavioral patterns if samples exist.',
        priority: 'medium',
        impact: 'medium',
        collectingRecommendation: 'Perform static and dynamic malware analysis if samples are available',
        collectionEffort: 'very_high',
      });
    }

    if (!hasTechniques) {
      gaps.push({
        id: `gap_technical_mitre`,
        category: 'techniques',
        description: 'No MITRE ATT&CK mapping',
        detail: 'Investigation techniques not mapped to MITRE ATT&CK framework. Map observed behaviors to techniques.',
        priority: 'high',
        impact: 'medium',
        collectingRecommendation: 'Map all observed attack steps to MITRE ATT&CK techniques (T####)',
        collectionEffort: 'medium',
      });
    }

    if (!hasInfrastructure) {
      gaps.push({
        id: `gap_technical_infra`,
        category: 'infrastructure',
        description: 'Infrastructure not mapped',
        detail: 'No C2 infrastructure, hosting providers, or command channels documented.',
        priority: 'medium',
        impact: 'medium',
        collectingRecommendation: 'Map threat actor infrastructure: C2 servers, hosting providers, domain registrars',
        collectionEffort: 'high',
      });
    }

    return gaps;
  }

  async identifyTimelineGaps(investigation) {
    const gaps = [];

    const timeline = investigation.timeline || [];

    if (!timeline || timeline.length < 2) {
      gaps.push({
        id: `gap_timeline_sparse`,
        category: 'timeline',
        description: 'Incomplete timeline',
        detail: 'Timeline has very few events. Document attack progression with timestamps.',
        priority: 'medium',
        impact: 'low',
        collectingRecommendation: 'Create detailed timeline with all detected events, reconnaissance, exploitation, and post-compromise activity',
        collectionEffort: 'medium',
      });
    }

    const hasReconaissance = timeline.some(e => /recon|scan|probe/i.test(e.description || ''));
    const hasExploitation = timeline.some(e => /exploit|compromise|breach/i.test(e.description || ''));
    const hasPostComp = timeline.some(e => /exfiltration|persistence|lateral|command/i.test(e.description || ''));

    if (!hasReconaissance) {
      gaps.push({
        id: `gap_timeline_recon`,
        category: 'timeline',
        description: 'Reconnaissance phase unclear',
        detail: 'No reconnaissance activities documented in timeline.',
        priority: 'low',
        impact: 'low',
        collectingRecommendation: 'Identify and document reconnaissance and scanning activities',
        collectionEffort: 'medium',
      });
    }

    if (!hasExploitation) {
      gaps.push({
        id: `gap_timeline_exploit`,
        category: 'timeline',
        description: 'Exploitation phase unclear',
        detail: 'Initial access method not documented.',
        priority: 'high',
        impact: 'high',
        collectingRecommendation: 'Identify and document initial access vector and exploitation technique',
        collectionEffort: 'very_high',
      });
    }

    if (!hasPostComp) {
      gaps.push({
        id: `gap_timeline_postcomp`,
        category: 'timeline',
        description: 'Post-compromise activity unclear',
        detail: 'Lateral movement, command execution, or data exfiltration not documented.',
        priority: 'medium',
        impact: 'high',
        collectingRecommendation: 'Document post-compromise activity: persistence, lateral movement, command execution, data exfiltration',
        collectionEffort: 'high',
      });
    }

    return gaps;
  }

  async identifyDetectionGaps(investigation) {
    const gaps = [];

    const linkedEntities = investigation.linkedIntelligence || [];
    let hasDetectionRules = false;

    for (const intel of linkedEntities) {
      if (intel.type === 'DETECTION_RULE' || intel.detectionRules) {
        hasDetectionRules = true;
        break;
      }
    }

    if (!hasDetectionRules) {
      gaps.push({
        id: `gap_detection_rules`,
        category: 'detection',
        description: 'No detection rules created',
        detail: 'Investigation lacks YARA, Sigma, or SIEM detection rules for IOCs and behaviors.',
        priority: 'high',
        impact: 'high',
        collectingRecommendation: 'Create YARA rules for malware, Sigma rules for behaviors, SIEM signatures for network indicators',
        collectionEffort: 'high',
      });
    }

    gaps.push({
      id: `gap_detection_coverage`,
      category: 'detection',
      description: 'Detection rule coverage analysis needed',
      detail: 'Evaluate detection coverage against identified IOCs and MITRE ATT&CK techniques.',
      priority: 'medium',
      impact: 'high',
      collectingRecommendation: 'Map detection rules to IOCs and techniques, identify coverage gaps',
      collectionEffort: 'high',
    });

    return gaps;
  }

  prioritizeGaps(gaps) {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const effortOrder = { low: 0, medium: 1, high: 2, very_high: 3 };

    return gaps.sort((a, b) => {
      const priorityDiff = priorityOrder[a.priority] - priorityOrder[b.priority];
      if (priorityDiff !== 0) return priorityDiff;

      const impactA = { critical: 3, high: 2, medium: 1, low: 0 }[a.impact] || 0;
      const impactB = { critical: 3, high: 2, medium: 1, low: 0 }[b.impact] || 0;
      const impactDiff = impactB - impactA;
      if (impactDiff !== 0) return impactDiff;

      return effortOrder[a.collectionEffort] - effortOrder[b.collectionEffort];
    });
  }

  getGapCollectionPlan(gaps, investigationId) {
    const prioritized = this.prioritizeGaps(gaps);
    const plan = {
      investigationId,
      generatedAt: new Date().toISOString(),
      totalGaps: gaps.length,
      recommendedOrder: [],
    };

    for (let i = 0; i < Math.min(5, prioritized.length); i++) {
      const gap = prioritized[i];
      plan.recommendedOrder.push({
        step: i + 1,
        gapId: gap.id,
        category: gap.category,
        description: gap.description,
        priority: gap.priority,
        recommendation: gap.collectingRecommendation,
        expectedEffort: gap.collectionEffort,
        estimatedValue: gap.priority === 'critical' ? 'high' : gap.priority === 'high' ? 'medium' : 'low',
      });
    }

    return plan;
  }
}

module.exports = { GapAnalyzer };
