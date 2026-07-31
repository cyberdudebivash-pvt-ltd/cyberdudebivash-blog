'use strict';

const redis = require('./redis');
const crypto = require('crypto');
const { ReportBuilder } = require('./report-builder');
const { ReportExporter } = require('./report-exporters');
const { getTemplate } = require('./report-templates');
const { REPORT_STATUS } = require('./report-models');

class ReportManager {
  constructor(redisClient = redis) {
    this.redis = redisClient;
    this.builder = new ReportBuilder(redisClient);
  }

  async generateReport(composition, analyst = 'analyst') {
    const result = await this.builder.buildReport(composition, analyst);
    return result;
  }

  async createReport(investigationId, reportType, analyst = 'analyst', customizations = {}) {
    const template = getTemplate(reportType);
    if (!template) {
      return {
        success: false,
        error: `Unknown report type: ${reportType}`,
      };
    }

    return {
      success: true,
      template: template.toJSON(),
      readyToCompose: true,
    };
  }

  async getReport(reportId) {
    const key = `report:${reportId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return null;
    }

    const report = {};
    for (let i = 0; i < data.length; i += 2) {
      report[data[i]] = data[i + 1];
    }

    return report;
  }

  async listReports(investigationId, limit = 50) {
    const reportIds = await this.redis.zrevrange(`reports:investigation:${investigationId}`, 0, limit - 1);
    const reports = [];

    for (const reportId of reportIds) {
      const report = await this.getReport(reportId);
      if (report) reports.push(report);
    }

    return reports;
  }

  async reviewReport(reportId, reviewerName, feedback = '') {
    const report = await this.getReport(reportId);
    if (!report) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    report.status = REPORT_STATUS.UNDER_REVIEW;
    report.reviewedAt = new Date().toISOString();
    report.reviewedBy = reviewerName;
    report.reviewFeedback = feedback;
    report.version = this.incrementVersion(report.version);

    const key = `report:${reportId}`;
    await this.redis.hset(key, Object.entries(report).flat());

    return { success: true, report };
  }

  async approveReport(reportId, approverName) {
    const report = await this.getReport(reportId);
    if (!report) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    if (report.status !== REPORT_STATUS.UNDER_REVIEW) {
      return {
        success: false,
        error: 'Report must be under review before approval',
      };
    }

    report.status = REPORT_STATUS.APPROVED;
    report.version = this.incrementVersion(report.version);

    const key = `report:${reportId}`;
    await this.redis.hset(key, Object.entries(report).flat());

    return { success: true, report };
  }

  async publishReport(reportId, publisherName) {
    const report = await this.getReport(reportId);
    if (!report) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    if (report.status !== REPORT_STATUS.APPROVED) {
      return {
        success: false,
        error: 'Report must be approved before publishing',
      };
    }

    report.status = REPORT_STATUS.PUBLISHED;
    report.publishedAt = new Date().toISOString();
    report.publishedBy = publisherName;
    report.version = this.incrementVersion(report.version);

    const key = `report:${reportId}`;
    await this.redis.hset(key, Object.entries(report).flat());
    await this.redis.zadd(`reports:published`, Date.now(), reportId);

    return { success: true, report };
  }

  async createNewVersion(originalReportId, analyst = 'analyst') {
    const originalReport = await this.getReport(originalReportId);
    if (!originalReport) {
      return { success: false, error: `Report not found: ${originalReportId}` };
    }

    originalReport.status = REPORT_STATUS.SUPERSEDED;
    originalReport.version = this.incrementVersion(originalReport.version);

    const originalKey = `report:${originalReportId}`;
    await this.redis.hset(originalKey, Object.entries(originalReport).flat());

    const newReport = {
      ...originalReport,
      id: crypto.randomBytes(16).toString('hex'),
      status: REPORT_STATUS.DRAFT,
      previousVersionId: originalReportId,
      createdAt: new Date().toISOString(),
      createdBy: analyst,
      publishedAt: null,
      publishedBy: null,
      version: this.incrementVersion(originalReport.version),
      changeHistory: [
        ...(originalReport.changeHistory || []),
        {
          timestamp: new Date().toISOString(),
          changeType: 'new_version',
          detail: `Based on previous version ${originalReportId}`,
          author: analyst,
        },
      ],
    };

    const newKey = `report:${newReport.id}`;
    await this.redis.hset(newKey, Object.entries(newReport).flat());
    await this.redis.zadd(`reports:investigation:${newReport.investigationId}`, Date.now(), newReport.id);
    await this.redis.zadd(`reports:by:type:${newReport.reportType}`, Date.now(), newReport.id);

    return { success: true, report: newReport };
  }

  async exportReport(reportId, format = 'html') {
    const report = await this.getReport(reportId);
    if (!report) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    const content = ReportExporter.export(report, format);

    return {
      success: true,
      format,
      content,
      filename: `${report.id}.${this.getFileExtension(format)}`,
    };
  }

  async compareVersions(reportId1, reportId2) {
    const report1 = await this.getReport(reportId1);
    const report2 = await this.getReport(reportId2);

    if (!report1 || !report2) {
      return { success: false, error: 'One or both reports not found' };
    }

    const changes = {
      titleChanged: report1.title !== report2.title,
      sectionCountChanged: (report1.sectionCount || 0) !== (report2.sectionCount || 0),
      statusChanged: report1.status !== report2.status,
      classificationChanged: report1.classification !== report2.classification,
      versionProgression: {
        from: report1.version,
        to: report2.version,
      },
      changeHistory: report2.changeHistory || [],
    };

    return { success: true, comparison: changes };
  }

  async getReportStats(investigationId) {
    const reports = await this.listReports(investigationId, 100);

    const stats = {
      total: reports.length,
      byStatus: {},
      byType: {},
      byClassification: {},
      published: reports.filter(r => r.status === REPORT_STATUS.PUBLISHED).length,
      pending: reports.filter(r => r.status === REPORT_STATUS.DRAFT || r.status === REPORT_STATUS.UNDER_REVIEW).length,
    };

    for (const report of reports) {
      stats.byStatus[report.status] = (stats.byStatus[report.status] || 0) + 1;
      stats.byType[report.reportType] = (stats.byType[report.reportType] || 0) + 1;
      stats.byClassification[report.classification] = (stats.byClassification[report.classification] || 0) + 1;
    }

    return stats;
  }

  incrementVersion(versionString) {
    const parts = versionString.split('.');
    if (parts.length !== 3) return '1.0.1';

    const major = parseInt(parts[0], 10) || 0;
    const minor = parseInt(parts[1], 10) || 0;
    const patch = parseInt(parts[2], 10) || 0;

    return `${major}.${minor}.${patch + 1}`;
  }

  getFileExtension(format) {
    const extensions = {
      html: 'html',
      markdown: 'md',
      md: 'md',
      json: 'json',
      stix: 'json',
      stix2: 'json',
    };

    return extensions[format.toLowerCase()] || 'txt';
  }

  async generateProductFactory(investigationId, findings, assessments) {
    const reportTypes = [
      'executive_brief',
      'technical_intelligence',
      'threat_actor_profile',
      'detection_advisory',
    ];

    const products = {
      investigationId,
      generatedAt: new Date().toISOString(),
      products: [],
    };

    for (const reportType of reportTypes) {
      const composition = {
        reportType,
        investigationId,
        selectedFindings: findings,
        selectedAssessments: assessments,
        includedIOCs: assessments.technical?.iocs || [],
        includedInfrastructure: assessments.technical?.infrastructure || [],
        includedTechniques: assessments.technical?.techniques || [],
        gaps: [],
      };

      const result = await this.generateReport(composition, 'system');
      if (result.success) {
        products.products.push({
          reportType,
          reportId: result.report.id,
          title: result.report.title,
          status: result.report.status,
          createdAt: result.report.createdAt,
        });
      }
    }

    return products;
  }
}

module.exports = { ReportManager };
