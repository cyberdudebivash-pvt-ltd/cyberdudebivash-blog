'use strict';

const crypto = require('crypto');

const REPORT_TYPES = {
  EXECUTIVE_BRIEF: 'executive_brief',
  TECHNICAL_INTELLIGENCE: 'technical_intelligence',
  THREAT_ACTOR_PROFILE: 'threat_actor_profile',
  CAMPAIGN_REPORT: 'campaign_report',
  MALWARE_ANALYSIS: 'malware_analysis',
  VULNERABILITY_INTELLIGENCE: 'vulnerability_intelligence',
  INDUSTRY_THREAT_BRIEF: 'industry_threat_brief',
  IOC_PACKAGE: 'ioc_package',
  DETECTION_ADVISORY: 'detection_advisory',
  DAILY_BRIEF: 'daily_brief',
  WEEKLY_SUMMARY: 'weekly_summary',
  MONTHLY_LANDSCAPE: 'monthly_landscape',
  FLASH_ALERT: 'flash_alert',
  STRATEGIC_ASSESSMENT: 'strategic_assessment',
};

const REPORT_CLASSIFICATION = {
  TLP_WHITE: 'tlp:white',
  TLP_GREEN: 'tlp:green',
  TLP_AMBER: 'tlp:amber',
  TLP_RED: 'tlp:red',
  INTERNAL: 'internal',
  CONFIDENTIAL: 'confidential',
};

const REPORT_AUDIENCE = {
  EXECUTIVE: 'executive',
  TECHNICAL: 'technical',
  OPERATIONAL: 'operational',
  STRATEGIC: 'strategic',
};

const REPORT_STATUS = {
  DRAFT: 'draft',
  UNDER_REVIEW: 'under_review',
  APPROVED: 'approved',
  PUBLISHED: 'published',
  SUPERSEDED: 'superseded',
  ARCHIVED: 'archived',
};

class IntelligenceReport {
  constructor(data = {}) {
    this.id = data.id || crypto.randomBytes(16).toString('hex');
    this.investigationId = data.investigationId;
    this.reportType = data.reportType;
    this.title = data.title;
    this.description = data.description || '';
    this.classification = data.classification || REPORT_CLASSIFICATION.TLP_GREEN;
    this.audience = data.audience || REPORT_AUDIENCE.TECHNICAL;
    this.version = data.version || '1.0.0';
    this.previousVersionId = data.previousVersionId || null;
    this.status = data.status || REPORT_STATUS.DRAFT;
    this.createdAt = data.createdAt || new Date().toISOString();
    this.createdBy = data.createdBy || 'analyst';
    this.publishedAt = data.publishedAt || null;
    this.publishedBy = data.publishedBy || null;
    this.reviewedAt = data.reviewedAt || null;
    this.reviewedBy = data.reviewedBy || null;
    this.sections = data.sections || [];
    this.metadata = data.metadata || {};
    this.changeHistory = data.changeHistory || [];
    this.tags = data.tags || [];
  }

  addSection(section) {
    this.sections.push({
      ...section,
      id: section.id || crypto.randomBytes(8).toString('hex'),
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  setMetadata(key, value) {
    this.metadata[key] = value;
    return this;
  }

  recordChange(changeType, detail, authorName) {
    this.changeHistory.push({
      timestamp: new Date().toISOString(),
      changeType,
      detail,
      author: authorName,
    });
    return this;
  }

  markForReview(reviewerName) {
    this.status = REPORT_STATUS.UNDER_REVIEW;
    this.reviewedBy = reviewerName;
    this.reviewedAt = new Date().toISOString();
    this.recordChange('status', 'marked_for_review', reviewerName);
    return this;
  }

  approve(approverName) {
    this.status = REPORT_STATUS.APPROVED;
    this.recordChange('status', 'approved', approverName);
    return this;
  }

  publish(publisherName) {
    this.status = REPORT_STATUS.PUBLISHED;
    this.publishedBy = publisherName;
    this.publishedAt = new Date().toISOString();
    this.recordChange('status', 'published', publisherName);
    return this;
  }

  supersede(newVersionId, reason = '') {
    this.status = REPORT_STATUS.SUPERSEDED;
    this.recordChange('status', `superseded_by:${newVersionId}`, reason);
    return this;
  }

  toJSON() {
    return {
      id: this.id,
      investigationId: this.investigationId,
      reportType: this.reportType,
      title: this.title,
      description: this.description,
      classification: this.classification,
      audience: this.audience,
      version: this.version,
      previousVersionId: this.previousVersionId,
      status: this.status,
      createdAt: this.createdAt,
      createdBy: this.createdBy,
      publishedAt: this.publishedAt,
      publishedBy: this.publishedBy,
      reviewedAt: this.reviewedAt,
      reviewedBy: this.reviewedBy,
      sectionCount: this.sections.length,
      sections: this.sections,
      metadata: this.metadata,
      changeHistory: this.changeHistory,
      tags: this.tags,
    };
  }
}

class ReportSection {
  constructor(data = {}) {
    this.id = data.id || crypto.randomBytes(8).toString('hex');
    this.title = data.title;
    this.sectionType = data.sectionType;
    this.content = data.content || '';
    this.subsections = data.subsections || [];
    this.evidenceReferences = data.evidenceReferences || [];
    this.findingReferences = data.findingReferences || [];
    this.sourceReferences = data.sourceReferences || [];
    this.sequenceOrder = data.sequenceOrder || 0;
    this.isOptional = data.isOptional || false;
    this.audience = data.audience || [REPORT_AUDIENCE.TECHNICAL];
  }

  addEvidence(evidenceId, sourceTitle, confidence = 'high') {
    this.evidenceReferences.push({
      id: crypto.randomBytes(8).toString('hex'),
      evidenceId,
      sourceTitle,
      confidence,
      citedAt: new Date().toISOString(),
    });
    return this;
  }

  addFinding(findingId, statement, confidence = 'likely') {
    this.findingReferences.push({
      id: crypto.randomBytes(8).toString('hex'),
      findingId,
      statement,
      confidence,
      citedAt: new Date().toISOString(),
    });
    return this;
  }

  addSource(sourceName, sourceType, sourceUrl = '') {
    this.sourceReferences.push({
      id: crypto.randomBytes(8).toString('hex'),
      sourceName,
      sourceType,
      sourceUrl,
      citedAt: new Date().toISOString(),
    });
    return this;
  }

  addSubsection(subsection) {
    this.subsections.push({
      ...subsection,
      id: subsection.id || crypto.randomBytes(8).toString('hex'),
    });
    return this;
  }

  toJSON() {
    return {
      id: this.id,
      title: this.title,
      sectionType: this.sectionType,
      content: this.content,
      subsectionCount: this.subsections.length,
      subsections: this.subsections,
      evidenceReferenceCount: this.evidenceReferences.length,
      evidenceReferences: this.evidenceReferences,
      findingReferenceCount: this.findingReferences.length,
      findingReferences: this.findingReferences,
      sourceReferenceCount: this.sourceReferences.length,
      sourceReferences: this.sourceReferences,
      sequenceOrder: this.sequenceOrder,
      isOptional: this.isOptional,
      audience: this.audience,
    };
  }
}

class ReportTemplate {
  constructor(data = {}) {
    this.id = data.id || crypto.randomBytes(16).toString('hex');
    this.reportType = data.reportType;
    this.name = data.name;
    this.description = data.description || '';
    this.requiredSections = data.requiredSections || [];
    this.optionalSections = data.optionalSections || [];
    this.requiredAnalyticalInputs = data.requiredAnalyticalInputs || [];
    this.validationRules = data.validationRules || [];
    this.supportedAudiences = data.supportedAudiences || [REPORT_AUDIENCE.TECHNICAL];
    this.defaultClassification = data.defaultClassification || REPORT_CLASSIFICATION.TLP_GREEN;
    this.version = data.version || '1.0.0';
    this.createdAt = data.createdAt || new Date().toISOString();
  }

  toJSON() {
    return {
      id: this.id,
      reportType: this.reportType,
      name: this.name,
      description: this.description,
      requiredSectionCount: this.requiredSections.length,
      requiredSections: this.requiredSections,
      optionalSectionCount: this.optionalSections.length,
      optionalSections: this.optionalSections,
      requiredAnalyticalInputs: this.requiredAnalyticalInputs,
      validationRules: this.validationRules,
      supportedAudiences: this.supportedAudiences,
      defaultClassification: this.defaultClassification,
      version: this.version,
      createdAt: this.createdAt,
    };
  }
}

class ReportComposition {
  constructor(reportType, investigationId) {
    this.reportType = reportType;
    this.investigationId = investigationId;
    this.selectedFindings = [];
    this.selectedAssessments = {
      situation: null,
      threatActors: [],
      technical: null,
      executive: null,
    };
    this.includedIOCs = [];
    this.includedInfrastructure = [];
    this.includedTechniques = [];
    this.timeline = null;
    this.gaps = [];
    this.customizations = {};
  }

  addFinding(findingId, finding) {
    this.selectedFindings.push({
      findingId,
      statement: finding.statement,
      confidence: finding.confidence,
      evidence: finding.evidence,
    });
    return this;
  }

  setSituationAssessment(assessment) {
    this.selectedAssessments.situation = assessment;
    return this;
  }

  addThreatActor(actorId, assessment) {
    this.selectedAssessments.threatActors.push({
      actorId,
      attribution: assessment.attribution,
      confidence: assessment.attributionConfidence,
    });
    return this;
  }

  setTechnicalAssessment(assessment) {
    this.selectedAssessments.technical = assessment;
    return this;
  }

  setExecutiveAssessment(assessment) {
    this.selectedAssessments.executive = assessment;
    return this;
  }

  addIOC(ioc) {
    this.includedIOCs.push(ioc);
    return this;
  }

  addInfrastructure(infrastructure) {
    this.includedInfrastructure.push(infrastructure);
    return this;
  }

  addTechnique(technique) {
    this.includedTechniques.push(technique);
    return this;
  }

  setTimeline(timeline) {
    this.timeline = timeline;
    return this;
  }

  addGaps(gaps) {
    this.gaps.push(...gaps);
    return this;
  }

  customizeFor(audience) {
    this.customizations.audience = audience;
    return this;
  }

  toJSON() {
    return {
      reportType: this.reportType,
      investigationId: this.investigationId,
      selectedFindingsCount: this.selectedFindings.length,
      selectedFindings: this.selectedFindings,
      selectedAssessments: this.selectedAssessments,
      includedIOCsCount: this.includedIOCs.length,
      includedIOCs: this.includedIOCs,
      includedInfrastructureCount: this.includedInfrastructure.length,
      includedInfrastructure: this.includedInfrastructure,
      includedTechniquesCount: this.includedTechniques.length,
      includedTechniques: this.includedTechniques,
      hasTimeline: !!this.timeline,
      gapsCount: this.gaps.length,
      gaps: this.gaps,
      customizations: this.customizations,
    };
  }
}

module.exports = {
  IntelligenceReport,
  ReportSection,
  ReportTemplate,
  ReportComposition,
  REPORT_TYPES,
  REPORT_CLASSIFICATION,
  REPORT_AUDIENCE,
  REPORT_STATUS,
};
