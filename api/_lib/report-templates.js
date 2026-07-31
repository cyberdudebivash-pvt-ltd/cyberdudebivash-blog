'use strict';

const {
  ReportTemplate,
  REPORT_TYPES,
  REPORT_AUDIENCE,
  REPORT_CLASSIFICATION,
} = require('./report-models');

const SECTION_TYPES = {
  EXECUTIVE_SUMMARY: 'executive_summary',
  KEY_JUDGMENTS: 'key_judgments',
  SITUATION_OVERVIEW: 'situation_overview',
  THREAT_OVERVIEW: 'threat_overview',
  CAMPAIGN_ANALYSIS: 'campaign_analysis',
  THREAT_ACTOR_ASSESSMENT: 'threat_actor_assessment',
  MALWARE_ANALYSIS: 'malware_analysis',
  INFRASTRUCTURE_ANALYSIS: 'infrastructure_analysis',
  IOC_SUMMARY: 'ioc_summary',
  MITRE_ATT_CK_MAPPING: 'mitre_attack_mapping',
  CYBER_KILL_CHAIN: 'cyber_kill_chain',
  DIAMOND_MODEL: 'diamond_model',
  TIMELINE: 'timeline',
  EVIDENCE_SUMMARY: 'evidence_summary',
  CONFIDENCE_ASSESSMENT: 'confidence_assessment',
  INTELLIGENCE_GAPS: 'intelligence_gaps',
  DETECTION_RECOMMENDATIONS: 'detection_recommendations',
  MITIGATION_RECOMMENDATIONS: 'mitigation_recommendations',
  STRATEGIC_OUTLOOK: 'strategic_outlook',
  REFERENCES: 'references',
  APPENDICES: 'appendices',
  TECHNICAL_DETAILS: 'technical_details',
  ATTRIBUTION_ANALYSIS: 'attribution_analysis',
  HISTORICAL_CONTEXT: 'historical_context',
};

const templates = {
  [REPORT_TYPES.EXECUTIVE_BRIEF]: new ReportTemplate({
    reportType: REPORT_TYPES.EXECUTIVE_BRIEF,
    name: 'Executive Intelligence Brief',
    description: 'High-level threat overview for executive leadership',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.KEY_JUDGMENTS,
      SECTION_TYPES.THREAT_OVERVIEW,
      SECTION_TYPES.DETECTION_RECOMMENDATIONS,
      SECTION_TYPES.MITIGATION_RECOMMENDATIONS,
    ],
    optionalSections: [
      SECTION_TYPES.STRATEGIC_OUTLOOK,
      SECTION_TYPES.TIMELINE,
    ],
    requiredAnalyticalInputs: [
      'executive_assessment',
    ],
    supportedAudiences: [REPORT_AUDIENCE.EXECUTIVE],
    defaultClassification: REPORT_CLASSIFICATION.TLP_AMBER,
  }),

  [REPORT_TYPES.TECHNICAL_INTELLIGENCE]: new ReportTemplate({
    reportType: REPORT_TYPES.TECHNICAL_INTELLIGENCE,
    name: 'Technical Intelligence Report',
    description: 'Detailed technical analysis for SOC and threat hunters',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.SITUATION_OVERVIEW,
      SECTION_TYPES.IOC_SUMMARY,
      SECTION_TYPES.MITRE_ATT_CK_MAPPING,
      SECTION_TYPES.INFRASTRUCTURE_ANALYSIS,
      SECTION_TYPES.DETECTION_RECOMMENDATIONS,
    ],
    optionalSections: [
      SECTION_TYPES.MALWARE_ANALYSIS,
      SECTION_TYPES.TIMELINE,
      SECTION_TYPES.CYBER_KILL_CHAIN,
      SECTION_TYPES.TECHNICAL_DETAILS,
    ],
    requiredAnalyticalInputs: [
      'technical_assessment',
      'findings',
    ],
    supportedAudiences: [REPORT_AUDIENCE.TECHNICAL, REPORT_AUDIENCE.OPERATIONAL],
    defaultClassification: REPORT_CLASSIFICATION.TLP_GREEN,
  }),

  [REPORT_TYPES.THREAT_ACTOR_PROFILE]: new ReportTemplate({
    reportType: REPORT_TYPES.THREAT_ACTOR_PROFILE,
    name: 'Threat Actor Profile',
    description: 'Comprehensive threat actor analysis',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.THREAT_ACTOR_ASSESSMENT,
      SECTION_TYPES.ATTRIBUTION_ANALYSIS,
      SECTION_TYPES.HISTORICAL_CONTEXT,
      SECTION_TYPES.INFRASTRUCTURE_ANALYSIS,
      SECTION_TYPES.MITRE_ATT_CK_MAPPING,
    ],
    optionalSections: [
      SECTION_TYPES.CAMPAIGN_ANALYSIS,
      SECTION_TYPES.TIMELINE,
      SECTION_TYPES.STRATEGIC_OUTLOOK,
    ],
    requiredAnalyticalInputs: [
      'threat_actor_assessment',
      'infrastructure',
    ],
    supportedAudiences: [REPORT_AUDIENCE.TECHNICAL, REPORT_AUDIENCE.STRATEGIC],
  }),

  [REPORT_TYPES.CAMPAIGN_REPORT]: new ReportTemplate({
    reportType: REPORT_TYPES.CAMPAIGN_REPORT,
    name: 'Campaign Report',
    description: 'Analysis of coordinated campaign activity',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.CAMPAIGN_ANALYSIS,
      SECTION_TYPES.THREAT_ACTOR_ASSESSMENT,
      SECTION_TYPES.TIMELINE,
      SECTION_TYPES.IOC_SUMMARY,
      SECTION_TYPES.MITRE_ATT_CK_MAPPING,
    ],
    optionalSections: [
      SECTION_TYPES.INFRASTRUCTURE_ANALYSIS,
      SECTION_TYPES.MALWARE_ANALYSIS,
      SECTION_TYPES.CYBER_KILL_CHAIN,
    ],
    requiredAnalyticalInputs: [
      'campaign_assessment',
      'findings',
    ],
    supportedAudiences: [REPORT_AUDIENCE.TECHNICAL, REPORT_AUDIENCE.OPERATIONAL],
  }),

  [REPORT_TYPES.MALWARE_ANALYSIS]: new ReportTemplate({
    reportType: REPORT_TYPES.MALWARE_ANALYSIS,
    name: 'Malware Analysis Report',
    description: 'Detailed malware analysis and capabilities',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.MALWARE_ANALYSIS,
      SECTION_TYPES.TECHNICAL_DETAILS,
      SECTION_TYPES.IOC_SUMMARY,
      SECTION_TYPES.DETECTION_RECOMMENDATIONS,
    ],
    optionalSections: [
      SECTION_TYPES.INFRASTRUCTURE_ANALYSIS,
      SECTION_TYPES.MITRE_ATT_CK_MAPPING,
      SECTION_TYPES.THREAT_ACTOR_ASSESSMENT,
    ],
    requiredAnalyticalInputs: [
      'malware_findings',
      'iocs',
    ],
    supportedAudiences: [REPORT_AUDIENCE.TECHNICAL, REPORT_AUDIENCE.OPERATIONAL],
  }),

  [REPORT_TYPES.IOC_PACKAGE]: new ReportTemplate({
    reportType: REPORT_TYPES.IOC_PACKAGE,
    name: 'Indicator of Compromise Package',
    description: 'Structured IOC export for detection systems',
    requiredSections: [
      SECTION_TYPES.IOC_SUMMARY,
      SECTION_TYPES.EVIDENCE_SUMMARY,
      SECTION_TYPES.REFERENCES,
    ],
    optionalSections: [
      SECTION_TYPES.MALWARE_ANALYSIS,
      SECTION_TYPES.THREAT_ACTOR_ASSESSMENT,
    ],
    requiredAnalyticalInputs: [
      'iocs',
    ],
    supportedAudiences: [REPORT_AUDIENCE.TECHNICAL, REPORT_AUDIENCE.OPERATIONAL],
    defaultClassification: REPORT_CLASSIFICATION.TLP_WHITE,
  }),

  [REPORT_TYPES.DETECTION_ADVISORY]: new ReportTemplate({
    reportType: REPORT_TYPES.DETECTION_ADVISORY,
    name: 'Detection Advisory',
    description: 'Actionable detection guidance for security teams',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.IOC_SUMMARY,
      SECTION_TYPES.DETECTION_RECOMMENDATIONS,
      SECTION_TYPES.MITRE_ATT_CK_MAPPING,
    ],
    optionalSections: [
      SECTION_TYPES.MALWARE_ANALYSIS,
      SECTION_TYPES.INFRASTRUCTURE_ANALYSIS,
    ],
    requiredAnalyticalInputs: [
      'detection_opportunities',
      'iocs',
    ],
    supportedAudiences: [REPORT_AUDIENCE.OPERATIONAL, REPORT_AUDIENCE.TECHNICAL],
  }),

  [REPORT_TYPES.FLASH_ALERT]: new ReportTemplate({
    reportType: REPORT_TYPES.FLASH_ALERT,
    name: 'Flash Alert',
    description: 'Urgent time-sensitive threat notice',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.KEY_JUDGMENTS,
      SECTION_TYPES.IOC_SUMMARY,
      SECTION_TYPES.DETECTION_RECOMMENDATIONS,
      SECTION_TYPES.MITIGATION_RECOMMENDATIONS,
    ],
    optionalSections: [],
    requiredAnalyticalInputs: [
      'findings',
      'iocs',
    ],
    supportedAudiences: [REPORT_AUDIENCE.EXECUTIVE, REPORT_AUDIENCE.OPERATIONAL],
    defaultClassification: REPORT_CLASSIFICATION.TLP_AMBER,
  }),

  [REPORT_TYPES.STRATEGIC_ASSESSMENT]: new ReportTemplate({
    reportType: REPORT_TYPES.STRATEGIC_ASSESSMENT,
    name: 'Strategic Intelligence Assessment',
    description: 'Long-term threat landscape and strategic implications',
    requiredSections: [
      SECTION_TYPES.EXECUTIVE_SUMMARY,
      SECTION_TYPES.THREAT_OVERVIEW,
      SECTION_TYPES.THREAT_ACTOR_ASSESSMENT,
      SECTION_TYPES.STRATEGIC_OUTLOOK,
      SECTION_TYPES.INTELLIGENCE_GAPS,
    ],
    optionalSections: [
      SECTION_TYPES.HISTORICAL_CONTEXT,
      SECTION_TYPES.CAMPAIGN_ANALYSIS,
    ],
    requiredAnalyticalInputs: [
      'threat_landscape',
    ],
    supportedAudiences: [REPORT_AUDIENCE.STRATEGIC, REPORT_AUDIENCE.EXECUTIVE],
    defaultClassification: REPORT_CLASSIFICATION.TLP_AMBER,
  }),
};

function getTemplate(reportType) {
  return templates[reportType] || null;
}

function listTemplates() {
  return Object.values(templates);
}

function validateReportComposition(composition, template) {
  const issues = [];

  if (!template) {
    issues.push({
      severity: 'critical',
      code: 'NO_TEMPLATE',
      message: 'No template found for report type',
    });
    return { isValid: false, issues };
  }

  for (const requiredSection of template.requiredSections) {
    const hasSection = composition.selectedSections && composition.selectedSections.some(s => s.sectionType === requiredSection);
    if (!hasSection) {
      issues.push({
        severity: 'critical',
        code: 'MISSING_REQUIRED_SECTION',
        message: `Required section missing: ${requiredSection}`,
      });
    }
  }

  for (const requiredInput of template.requiredAnalyticalInputs) {
    let hasInput = false;

    if (requiredInput === 'executive_assessment') hasInput = !!composition.selectedAssessments?.executive;
    else if (requiredInput === 'technical_assessment') hasInput = !!composition.selectedAssessments?.technical;
    else if (requiredInput === 'threat_actor_assessment') hasInput = composition.selectedAssessments?.threatActors?.length > 0;
    else if (requiredInput === 'findings') hasInput = composition.selectedFindings?.length > 0;
    else if (requiredInput === 'iocs') hasInput = composition.includedIOCs?.length > 0;
    else if (requiredInput === 'infrastructure') hasInput = composition.includedInfrastructure?.length > 0;
    else if (requiredInput === 'detection_opportunities') hasInput = !!composition.selectedAssessments?.technical;

    if (!hasInput) {
      issues.push({
        severity: 'high',
        code: 'MISSING_INPUT',
        message: `Required analytical input missing: ${requiredInput}`,
      });
    }
  }

  return {
    isValid: issues.filter(i => i.severity === 'critical').length === 0,
    issues,
  };
}

module.exports = {
  SECTION_TYPES,
  getTemplate,
  listTemplates,
  validateReportComposition,
};
