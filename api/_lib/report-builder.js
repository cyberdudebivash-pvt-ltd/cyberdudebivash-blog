'use strict';

const redis = require('./redis');
const crypto = require('crypto');
const {
  IntelligenceReport,
  ReportSection,
  REPORT_STATUS,
  REPORT_AUDIENCE,
} = require('./report-models');
const {
  SECTION_TYPES,
  getTemplate,
  validateReportComposition,
} = require('./report-templates');

class ReportBuilder {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async buildReport(composition, analyst = 'analyst') {
    const template = getTemplate(composition.reportType);

    const validation = validateReportComposition(composition, template);
    if (!validation.isValid) {
      return {
        success: false,
        report: null,
        validation,
        error: 'Report composition validation failed',
      };
    }

    const report = new IntelligenceReport({
      investigationId: composition.investigationId,
      reportType: composition.reportType,
      title: this.generateTitle(composition),
      description: this.generateDescription(composition),
      classification: template.defaultClassification,
      audience: composition.customizations.audience || template.supportedAudiences[0],
      createdBy: analyst,
    });

    const sections = await this.composeReport(composition, template);
    for (const section of sections) {
      report.addSection(section);
    }

    report.recordChange('creation', 'report_created', analyst);

    const key = `report:${report.id}`;
    const reportData = report.toJSON();
    await this.redis.hset(key, Object.entries(reportData).flat());
    await this.redis.zadd(`reports:investigation:${composition.investigationId}`, Date.now(), report.id);
    await this.redis.zadd(`reports:by:type:${composition.reportType}`, Date.now(), report.id);

    return {
      success: true,
      report: report.toJSON(),
      validation,
    };
  }

  async composeReport(composition, template) {
    const sections = [];
    let sequenceOrder = 1;

    for (const requiredSectionType of template.requiredSections) {
      const section = await this.buildSection(requiredSectionType, composition);
      if (section) {
        section.sequenceOrder = sequenceOrder++;
        sections.push(section);
      }
    }

    for (const optionalSectionType of template.optionalSections) {
      const section = await this.buildSection(optionalSectionType, composition);
      if (section) {
        section.sequenceOrder = sequenceOrder++;
        section.isOptional = true;
        sections.push(section);
      }
    }

    return sections;
  }

  async buildSection(sectionType, composition) {
    let section = null;

    switch (sectionType) {
      case SECTION_TYPES.EXECUTIVE_SUMMARY:
        section = this.buildExecutiveSummary(composition);
        break;
      case SECTION_TYPES.KEY_JUDGMENTS:
        section = this.buildKeyJudgments(composition);
        break;
      case SECTION_TYPES.SITUATION_OVERVIEW:
        section = this.buildSituationOverview(composition);
        break;
      case SECTION_TYPES.THREAT_OVERVIEW:
        section = this.buildThreatOverview(composition);
        break;
      case SECTION_TYPES.THREAT_ACTOR_ASSESSMENT:
        section = this.buildThreatActorAssessment(composition);
        break;
      case SECTION_TYPES.IOC_SUMMARY:
        section = this.buildIOCSummary(composition);
        break;
      case SECTION_TYPES.MITRE_ATT_CK_MAPPING:
        section = this.buildMitreMapping(composition);
        break;
      case SECTION_TYPES.INFRASTRUCTURE_ANALYSIS:
        section = this.buildInfrastructureAnalysis(composition);
        break;
      case SECTION_TYPES.TIMELINE:
        section = this.buildTimeline(composition);
        break;
      case SECTION_TYPES.DETECTION_RECOMMENDATIONS:
        section = this.buildDetectionRecommendations(composition);
        break;
      case SECTION_TYPES.MITIGATION_RECOMMENDATIONS:
        section = this.buildMitigationRecommendations(composition);
        break;
      case SECTION_TYPES.INTELLIGENCE_GAPS:
        section = this.buildIntelligenceGaps(composition);
        break;
      case SECTION_TYPES.EVIDENCE_SUMMARY:
        section = this.buildEvidenceSummary(composition);
        break;
      case SECTION_TYPES.CONFIDENCE_ASSESSMENT:
        section = this.buildConfidenceAssessment(composition);
        break;
      case SECTION_TYPES.STRATEGIC_OUTLOOK:
        section = this.buildStrategicOutlook(composition);
        break;
      case SECTION_TYPES.REFERENCES:
        section = this.buildReferences(composition);
        break;
    }

    return section;
  }

  buildExecutiveSummary(composition) {
    const summary = [];

    if (composition.selectedAssessments?.executive) {
      summary.push(`Business Impact: ${composition.selectedAssessments.executive.businessImpact}`);
      summary.push(`Operational Impact: ${composition.selectedAssessments.executive.operationalImpact}`);
      summary.push(`Priority Level: ${composition.selectedAssessments.executive.priorityLevel}`);
    }

    if (composition.selectedFindings && composition.selectedFindings.length > 0) {
      summary.push(`Key Findings: ${composition.selectedFindings.length} findings documented with evidence`);
    }

    const section = new ReportSection({
      title: 'Executive Summary',
      sectionType: SECTION_TYPES.EXECUTIVE_SUMMARY,
      content: summary.join('\n\n'),
      audience: [REPORT_AUDIENCE.EXECUTIVE],
    });

    if (composition.selectedAssessments?.executive) {
      section.addFinding(
        composition.selectedAssessments.executive.investigationId,
        'Executive assessment prepared',
        composition.selectedAssessments.executive.priorityLevel
      );
    }

    return section;
  }

  buildKeyJudgments(composition) {
    const judgments = [];

    for (const finding of composition.selectedFindings || []) {
      judgments.push({
        statement: finding.statement,
        confidence: finding.confidence,
      });
    }

    const section = new ReportSection({
      title: 'Key Judgments',
      sectionType: SECTION_TYPES.KEY_JUDGMENTS,
      content: judgments.map((j, i) => `${i + 1}. [${j.confidence}] ${j.statement}`).join('\n'),
    });

    return section;
  }

  buildSituationOverview(composition) {
    const section = new ReportSection({
      title: 'Situation Overview',
      sectionType: SECTION_TYPES.SITUATION_OVERVIEW,
      content: composition.selectedAssessments?.situation?.overview || 'Situation assessment not available',
    });

    if (composition.selectedAssessments?.situation) {
      const situation = composition.selectedAssessments.situation;
      section.addSubsection({
        title: 'Scope',
        content: situation.scope || '',
      });
      section.addSubsection({
        title: 'Affected Sectors',
        content: (situation.affectedSectors || []).join(', '),
      });
      section.addSubsection({
        title: 'Geographic Context',
        content: (situation.geographicContext || []).join(', '),
      });
    }

    return section;
  }

  buildThreatOverview(composition) {
    const section = new ReportSection({
      title: 'Threat Overview',
      sectionType: SECTION_TYPES.THREAT_OVERVIEW,
      content: `${composition.selectedFindings?.length || 0} threat findings documented`,
    });

    return section;
  }

  buildThreatActorAssessment(composition) {
    const actors = composition.selectedAssessments?.threatActors || [];

    const content = actors
      .map(actor => `Actor: ${actor.attribution}\nConfidence: ${actor.confidence}`)
      .join('\n\n');

    const section = new ReportSection({
      title: 'Threat Actor Assessment',
      sectionType: SECTION_TYPES.THREAT_ACTOR_ASSESSMENT,
      content: content || 'No threat actor assessment available',
    });

    for (const actor of actors) {
      section.addSource(actor.attribution, 'threat_actor');
    }

    return section;
  }

  buildIOCSummary(composition) {
    const iocs = composition.includedIOCs || [];

    const iocsByType = {};
    for (const ioc of iocs) {
      if (!iocsByType[ioc.type]) iocsByType[ioc.type] = [];
      iocsByType[ioc.type].push(ioc);
    }

    let content = `Total IOCs: ${iocs.length}\n\n`;
    for (const [type, indicators] of Object.entries(iocsByType)) {
      content += `${type}: ${indicators.length}\n`;
    }

    const section = new ReportSection({
      title: 'Indicators of Compromise Summary',
      sectionType: SECTION_TYPES.IOC_SUMMARY,
      content,
    });

    for (const ioc of iocs) {
      section.addEvidence(ioc.id, ioc.ioc, ioc.reliability || 'high');
    }

    return section;
  }

  buildMitreMapping(composition) {
    const techniques = composition.includedTechniques || [];

    const content = techniques
      .map(t => `${t.techniqueId}: ${t.description || ''}`)
      .join('\n') || 'No MITRE ATT&CK techniques mapped';

    const section = new ReportSection({
      title: 'MITRE ATT&CK Mapping',
      sectionType: SECTION_TYPES.MITRE_ATT_CK_MAPPING,
      content,
    });

    return section;
  }

  buildInfrastructureAnalysis(composition) {
    const infrastructure = composition.includedInfrastructure || [];

    const content = infrastructure
      .map(i => `${i.hostname || i.ip}\nProvider: ${i.provider}\nPurpose: ${i.purpose}`)
      .join('\n\n') || 'No infrastructure analysis available';

    const section = new ReportSection({
      title: 'Infrastructure Analysis',
      sectionType: SECTION_TYPES.INFRASTRUCTURE_ANALYSIS,
      content,
    });

    return section;
  }

  buildTimeline(composition) {
    const timeline = composition.timeline || [];

    const content = timeline
      .map(event => `${event.timestamp}: ${event.event}`)
      .join('\n') || 'No timeline available';

    const section = new ReportSection({
      title: 'Timeline',
      sectionType: SECTION_TYPES.TIMELINE,
      content,
    });

    return section;
  }

  buildDetectionRecommendations(composition) {
    const technical = composition.selectedAssessments?.technical;
    const opportunities = technical?.detectionOpportunities || [];

    const content = opportunities
      .map(o => `[${o.priority}] ${o.opportunity}\nDetectability: ${o.detectability}`)
      .join('\n\n') || 'No detection recommendations available';

    const section = new ReportSection({
      title: 'Detection Recommendations',
      sectionType: SECTION_TYPES.DETECTION_RECOMMENDATIONS,
      content,
    });

    return section;
  }

  buildMitigationRecommendations(composition) {
    const executive = composition.selectedAssessments?.executive;
    const actions = executive?.recommendedActions || [];

    const content = actions
      .map(a => `[${a.priority}] ${a.action}\nRationale: ${a.rationale}`)
      .join('\n\n') || 'No mitigation recommendations available';

    const section = new ReportSection({
      title: 'Mitigation Recommendations',
      sectionType: SECTION_TYPES.MITIGATION_RECOMMENDATIONS,
      content,
    });

    return section;
  }

  buildIntelligenceGaps(composition) {
    const gaps = composition.gaps || [];

    const content = gaps
      .map(g => `[${g.priority}] ${g.description}\nRecommendation: ${g.collectionRecommendation}`)
      .join('\n\n') || 'No intelligence gaps identified';

    const section = new ReportSection({
      title: 'Intelligence Gaps',
      sectionType: SECTION_TYPES.INTELLIGENCE_GAPS,
      content,
    });

    return section;
  }

  buildEvidenceSummary(composition) {
    const findings = composition.selectedFindings || [];

    let totalEvidence = 0;
    for (const finding of findings) {
      totalEvidence += (finding.evidence?.length || 0);
    }

    const content = `Total evidence items: ${totalEvidence}\nFindings with evidence: ${findings.filter(f => f.evidence?.length > 0).length}`;

    const section = new ReportSection({
      title: 'Evidence Summary',
      sectionType: SECTION_TYPES.EVIDENCE_SUMMARY,
      content,
    });

    return section;
  }

  buildConfidenceAssessment(composition) {
    const findings = composition.selectedFindings || [];

    const confidenceBreakdown = {
      confirmed: findings.filter(f => f.confidence === 'confirmed').length,
      likely: findings.filter(f => f.confidence === 'likely').length,
      possible: findings.filter(f => f.confidence === 'possible').length,
      unlikely: findings.filter(f => f.confidence === 'unlikely').length,
    };

    const content = `Confirmed: ${confidenceBreakdown.confirmed}\nLikely: ${confidenceBreakdown.likely}\nPossible: ${confidenceBreakdown.possible}\nUnlikely: ${confidenceBreakdown.unlikely}`;

    const section = new ReportSection({
      title: 'Confidence Assessment',
      sectionType: SECTION_TYPES.CONFIDENCE_ASSESSMENT,
      content,
    });

    return section;
  }

  buildStrategicOutlook(composition) {
    const section = new ReportSection({
      title: 'Strategic Outlook',
      sectionType: SECTION_TYPES.STRATEGIC_OUTLOOK,
      content: composition.selectedAssessments?.executive?.strategicImplications?.join('\n') || 'Strategic outlook to be determined',
    });

    return section;
  }

  buildReferences(composition) {
    const sources = new Set();

    for (const finding of composition.selectedFindings || []) {
      for (const evidence of finding.evidence || []) {
        sources.add(evidence.evidenceId);
      }
    }

    const content = Array.from(sources).map((s, i) => `[${i + 1}] ${s}`).join('\n');

    const section = new ReportSection({
      title: 'References',
      sectionType: SECTION_TYPES.REFERENCES,
      content: content || 'No references',
    });

    return section;
  }

  generateTitle(composition) {
    const typeNames = {
      executive_brief: 'Executive Intelligence Brief',
      technical_intelligence: 'Technical Intelligence Report',
      threat_actor_profile: 'Threat Actor Profile',
      campaign_report: 'Campaign Report',
      malware_analysis: 'Malware Analysis',
      vulnerability_intelligence: 'Vulnerability Intelligence',
      industry_threat_brief: 'Industry Threat Brief',
      ioc_package: 'IOC Package',
      detection_advisory: 'Detection Advisory',
      daily_brief: 'Daily Intelligence Brief',
      weekly_summary: 'Weekly Intelligence Summary',
      monthly_landscape: 'Monthly Threat Landscape',
      flash_alert: 'Flash Alert',
      strategic_assessment: 'Strategic Intelligence Assessment',
    };

    return typeNames[composition.reportType] || 'Intelligence Report';
  }

  generateDescription(composition) {
    return `Intelligence report generated from investigation ${composition.investigationId} containing ${composition.selectedFindings?.length || 0} findings and ${composition.includedIOCs?.length || 0} indicators.`;
  }
}

module.exports = { ReportBuilder };
