'use strict';

const crypto = require('crypto');

class AnalyticalQualityValidator {
  validate(report) {
    const issues = [];

    for (const finding of report.findings || []) {
      if (!finding.evidence || finding.evidence.length === 0) {
        issues.push({
          severity: 'critical',
          category: 'analytical',
          code: 'UNSUPPORTED_FINDING',
          message: `Finding "${finding.statement.substring(0, 50)}..." lacks supporting evidence`,
          findingId: finding.id,
          recommendation: 'Add evidence references or remove unsupported finding',
        });
      }

      if (finding.confidence === 'confirmed' && finding.evidence.length < 2) {
        issues.push({
          severity: 'high',
          category: 'analytical',
          code: 'CONFIDENCE_MISMATCH',
          message: `Finding confidence "confirmed" requires multiple independent evidence sources`,
          findingId: finding.id,
          recommendation: 'Add additional corroborating evidence or lower confidence level',
        });
      }

      if (!finding.reasoning || finding.reasoning.length < 20) {
        issues.push({
          severity: 'medium',
          category: 'analytical',
          code: 'WEAK_REASONING',
          message: `Finding reasoning is too brief. Cannot evaluate logic of conclusion.`,
          findingId: finding.id,
          recommendation: 'Provide detailed reasoning connecting evidence to finding',
        });
      }

      if (!finding.assumptions || finding.assumptions.length === 0) {
        issues.push({
          severity: 'medium',
          category: 'analytical',
          code: 'NO_ASSUMPTIONS',
          message: `Finding does not document assumptions. Assumptions should be explicit.`,
          findingId: finding.id,
          recommendation: 'Document key assumptions underlying this finding',
        });
      }

      if (!finding.limitations || finding.limitations.length === 0) {
        issues.push({
          severity: 'medium',
          category: 'analytical',
          code: 'NO_LIMITATIONS',
          message: `Finding does not document limitations. All analysis has analytical boundaries.`,
          findingId: finding.id,
          recommendation: 'Document key limitations of this analysis',
        });
      }

      if (!finding.alternativeHypotheses || finding.alternativeHypotheses.length === 0) {
        issues.push({
          severity: 'low',
          category: 'analytical',
          code: 'NO_ALTERNATIVES',
          message: `Finding does not consider alternative hypotheses.`,
          findingId: finding.id,
          recommendation: 'Document alternative explanations and why primary finding is preferred',
        });
      }
    }

    const evidenceBackedFindings = (report.findings || []).filter(f => f.evidence && f.evidence.length > 0).length;
    const evidenceBackingRatio = (report.findings || []).length > 0 ? evidenceBackedFindings / (report.findings || []).length : 0;

    if (evidenceBackingRatio < 0.8) {
      issues.push({
        severity: 'high',
        category: 'analytical',
        code: 'LOW_EVIDENCE_RATIO',
        message: `Only ${Math.round(evidenceBackingRatio * 100)}% of findings have evidence support. Target: 100%`,
        recommendation: 'Add evidence to all findings or remove unsupported findings',
      });
    }

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      criticalIssues: issues.filter(i => i.severity === 'critical'),
      issues,
      evidenceBackingRatio: Math.round(evidenceBackingRatio * 100),
    };
  }
}

class EditorialQualityValidator {
  validate(report) {
    const issues = [];

    if (!report.title || report.title.length < 5) {
      issues.push({
        severity: 'high',
        category: 'editorial',
        code: 'WEAK_TITLE',
        message: 'Report title is missing or too short',
        recommendation: 'Provide descriptive title (5+ characters)',
      });
    }

    if (!report.description || report.description.length < 20) {
      issues.push({
        severity: 'medium',
        category: 'editorial',
        code: 'WEAK_DESCRIPTION',
        message: 'Report description is missing or too short',
        recommendation: 'Provide detailed description of report scope and contents',
      });
    }

    const sectionCount = (report.sections || []).length;
    if (sectionCount < 3) {
      issues.push({
        severity: 'medium',
        category: 'editorial',
        code: 'INCOMPLETE_REPORT',
        message: `Report has only ${sectionCount} sections. Well-developed reports typically have 5+`,
        recommendation: 'Expand report with additional analysis sections',
      });
    }

    for (const section of report.sections || []) {
      if (!section.content || section.content.trim().length < 10) {
        issues.push({
          severity: 'medium',
          category: 'editorial',
          code: 'EMPTY_SECTION',
          message: `Section "${section.title}" has minimal content`,
          sectionId: section.id,
          recommendation: 'Add substantive content to this section',
        });
      }

      if (section.evidenceReferences && section.evidenceReferences.length === 0 && section.findingReferences && section.findingReferences.length === 0) {
        issues.push({
          severity: 'low',
          category: 'editorial',
          code: 'UNSOURCED_SECTION',
          message: `Section "${section.title}" has no evidence or finding references`,
          sectionId: section.id,
          recommendation: 'Add evidence or finding citations to support section content',
        });
      }
    }

    const contentWords = this.countWords(report);
    if (contentWords < 100) {
      issues.push({
        severity: 'high',
        category: 'editorial',
        code: 'INSUFFICIENT_CONTENT',
        message: `Report contains only ${contentWords} words. Professional intelligence reports typically contain 500+ words.`,
        recommendation: 'Expand report content with detailed analysis',
      });
    }

    const duplicateSections = this.findDuplicateSections(report);
    for (const duplicate of duplicateSections) {
      issues.push({
        severity: 'medium',
        category: 'editorial',
        code: 'DUPLICATE_CONTENT',
        message: `Similar content detected in sections "${duplicate.section1}" and "${duplicate.section2}"`,
        recommendation: 'Consolidate duplicate content or clarify differences',
      });
    }

    const grammarIssues = this.checkGrammar(report);
    for (const issue of grammarIssues) {
      issues.push({
        severity: 'low',
        category: 'editorial',
        code: 'GRAMMAR_ISSUE',
        message: issue.message,
        recommendation: issue.recommendation,
      });
    }

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
      contentQuality: {
        wordCount: contentWords,
        sectionCount,
        evidenceBackedSections: (report.sections || []).filter(s =>
          (s.evidenceReferences && s.evidenceReferences.length > 0) ||
          (s.findingReferences && s.findingReferences.length > 0)
        ).length,
      },
    };
  }

  countWords(report) {
    let total = 0;
    if (report.title) total += report.title.split(/\s+/).length;
    if (report.description) total += report.description.split(/\s+/).length;
    for (const section of report.sections || []) {
      if (section.content) total += section.content.split(/\s+/).length;
    }
    return total;
  }

  findDuplicateSections(report) {
    const duplicates = [];
    const sections = report.sections || [];

    for (let i = 0; i < sections.length; i++) {
      for (let j = i + 1; j < sections.length; j++) {
        const similarity = this.calculateSimilarity(sections[i].content, sections[j].content);
        if (similarity > 0.7) {
          duplicates.push({
            section1: sections[i].title,
            section2: sections[j].title,
            similarity: Math.round(similarity * 100),
          });
        }
      }
    }

    return duplicates;
  }

  calculateSimilarity(str1, str2) {
    if (!str1 || !str2) return 0;
    const words1 = new Set(str1.toLowerCase().split(/\s+/));
    const words2 = new Set(str2.toLowerCase().split(/\s+/));
    const intersection = [...words1].filter(w => words2.has(w)).length;
    const union = words1.size + words2.size - intersection;
    return union > 0 ? intersection / union : 0;
  }

  checkGrammar(report) {
    const issues = [];
    const allContent = this.getAllContent(report);

    if (/\s{2,}/.test(allContent)) {
      issues.push({
        message: 'Multiple consecutive spaces detected',
        recommendation: 'Remove extra spacing',
      });
    }

    if (/[.!?]\s[a-z]/.test(allContent)) {
      issues.push({
        message: 'Possible sentence not starting with capital letter',
        recommendation: 'Capitalize first letter of sentences',
      });
    }

    if (/\s[,;:.!?]/.test(allContent)) {
      issues.push({
        message: 'Space before punctuation detected',
        recommendation: 'Remove spaces before punctuation',
      });
    }

    return issues.slice(0, 3);
  }

  getAllContent(report) {
    let content = '';
    if (report.title) content += report.title + ' ';
    if (report.description) content += report.description + ' ';
    for (const section of report.sections || []) {
      content += section.content + ' ';
    }
    return content;
  }
}

class ComplianceValidator {
  validate(report, policies = {}) {
    const issues = [];

    if (policies.requiresClassification && !report.classification) {
      issues.push({
        severity: 'critical',
        category: 'compliance',
        code: 'MISSING_CLASSIFICATION',
        message: 'Report classification is required',
        recommendation: 'Set report classification (TLP, INTERNAL, etc.)',
      });
    }

    if (policies.requiresAudience && !report.audience) {
      issues.push({
        severity: 'critical',
        category: 'compliance',
        code: 'MISSING_AUDIENCE',
        message: 'Report audience is required',
        recommendation: 'Specify intended audience (EXECUTIVE, TECHNICAL, etc.)',
      });
    }

    if (policies.minimumFindingCount && (!report.findings || report.findings.length < policies.minimumFindingCount)) {
      issues.push({
        severity: 'high',
        category: 'compliance',
        code: 'INSUFFICIENT_FINDINGS',
        message: `Report has ${report.findings?.length || 0} findings. Minimum: ${policies.minimumFindingCount}`,
        recommendation: `Add at least ${policies.minimumFindingCount} findings to this report`,
      });
    }

    if (policies.requiresReview && report.status !== 'reviewed') {
      issues.push({
        severity: 'high',
        category: 'compliance',
        code: 'NOT_REVIEWED',
        message: 'Report has not been reviewed',
        recommendation: 'Submit report for review before publication',
      });
    }

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
    };
  }
}

module.exports = {
  AnalyticalQualityValidator,
  EditorialQualityValidator,
  ComplianceValidator,
};
