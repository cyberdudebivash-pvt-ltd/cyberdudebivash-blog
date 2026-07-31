'use strict';

const redis = require('./redis');
const crypto = require('crypto');

class PublicationPolicyEngine {
  constructor(redisClient = redis) {
    this.redis = redisClient;
    this.defaultPolicies = this.initializeDefaultPolicies();
  }

  initializeDefaultPolicies() {
    return {
      'tlp:white': {
        name: 'TLP:WHITE - Unrestricted',
        requiredReviewers: 0,
        requiredApprovals: 1,
        executiveApprovalRequired: false,
        legalApprovalRequired: false,
        minimumQualityScore: 0.60,
        canPublishDraft: false,
      },
      'tlp:green': {
        name: 'TLP:GREEN - Community Use',
        requiredReviewers: 1,
        requiredApprovals: 1,
        executiveApprovalRequired: false,
        legalApprovalRequired: false,
        minimumQualityScore: 0.70,
        canPublishDraft: false,
      },
      'tlp:amber': {
        name: 'TLP:AMBER - Limited Distribution',
        requiredReviewers: 1,
        requiredApprovals: 2,
        executiveApprovalRequired: false,
        legalApprovalRequired: false,
        minimumQualityScore: 0.75,
        canPublishDraft: false,
      },
      'tlp:red': {
        name: 'TLP:RED - Source Required',
        requiredReviewers: 2,
        requiredApprovals: 3,
        executiveApprovalRequired: true,
        legalApprovalRequired: false,
        minimumQualityScore: 0.85,
        canPublishDraft: false,
      },
      'critical': {
        name: 'Critical Alert',
        requiredReviewers: 1,
        requiredApprovals: 2,
        executiveApprovalRequired: true,
        legalApprovalRequired: false,
        minimumQualityScore: 0.80,
        canPublishDraft: true,
      },
    };
  }

  async createPolicy(policyName, config) {
    const policy = {
      id: crypto.randomBytes(16).toString('hex'),
      name: policyName,
      classification: config.classification || 'tlp:green',
      requiredReviewers: config.requiredReviewers || 1,
      requiredApprovals: config.requiredApprovals || 1,
      executiveApprovalRequired: config.executiveApprovalRequired || false,
      legalApprovalRequired: config.legalApprovalRequired || false,
      minimumQualityScore: config.minimumQualityScore || 0.70,
      canPublishDraft: config.canPublishDraft || false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const key = `policy:${policyName}`;
    await this.redis.hset(key, Object.entries(policy).flat());
    await this.redis.zadd('policies:all', Date.now(), policyName);

    return policy;
  }

  async getPolicy(policyName) {
    let key = `policy:${policyName}`;
    let data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return this.defaultPolicies[policyName] || this.defaultPolicies['tlp:green'];
    }

    const policy = {};
    for (let i = 0; i < data.length; i += 2) {
      policy[data[i]] = data[i + 1];
    }

    return policy;
  }

  async validatePublicationReadiness(report, qualityScore) {
    const policy = await this.getPolicy(report.classification || 'tlp:green');
    const issues = [];

    if (qualityScore < policy.minimumQualityScore) {
      issues.push({
        severity: 'critical',
        code: 'QUALITY_THRESHOLD_NOT_MET',
        message: `Report quality score ${qualityScore} does not meet minimum ${policy.minimumQualityScore}`,
        recommendation: 'Improve report quality before publication',
      });
    }

    if (report.status === 'draft' && !policy.canPublishDraft) {
      issues.push({
        severity: 'critical',
        code: 'DRAFT_PUBLICATION_NOT_ALLOWED',
        message: 'Draft reports cannot be published with this classification',
        recommendation: 'Complete review and approval before publication',
      });
    }

    if (policy.requiredReviewers > 0 && (!report.reviewers || report.reviewers.length < policy.requiredReviewers)) {
      const reviewerCount = report.reviewers?.length || 0;
      issues.push({
        severity: 'high',
        code: 'INSUFFICIENT_REVIEWERS',
        message: `Policy requires ${policy.requiredReviewers} reviewers, only ${reviewerCount} assigned`,
        recommendation: `Assign ${policy.requiredReviewers - reviewerCount} additional reviewers`,
      });
    }

    if (policy.requiredApprovals > 0 && (!report.approvals || report.approvals.length < policy.requiredApprovals)) {
      const approvalCount = report.approvals?.length || 0;
      issues.push({
        severity: 'high',
        code: 'INSUFFICIENT_APPROVALS',
        message: `Policy requires ${policy.requiredApprovals} approvals, only ${approvalCount} obtained`,
        recommendation: `Obtain ${policy.requiredApprovals - approvalCount} additional approvals`,
      });
    }

    if (policy.executiveApprovalRequired && (!report.executiveApproval || !report.executiveApproval.approved)) {
      issues.push({
        severity: 'high',
        code: 'EXECUTIVE_APPROVAL_REQUIRED',
        message: 'Executive approval required for this classification',
        recommendation: 'Obtain executive approval before publication',
      });
    }

    if (policy.legalApprovalRequired && (!report.legalApproval || !report.legalApproval.approved)) {
      issues.push({
        severity: 'critical',
        code: 'LEGAL_APPROVAL_REQUIRED',
        message: 'Legal approval required for this classification',
        recommendation: 'Obtain legal approval before publication',
      });
    }

    return {
      isReady: issues.filter(i => i.severity === 'critical').length === 0,
      policy,
      issues,
    };
  }

  async recordApproval(reportId, approvalType, approverName, approverRole) {
    const key = `report:${reportId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    const report = {};
    for (let i = 0; i < data.length; i += 2) {
      report[data[i]] = data[i + 1];
    }

    let approvals = [];
    if (report.approvals) {
      try {
        approvals = JSON.parse(report.approvals);
      } catch (e) {
        approvals = [];
      }
    }

    approvals.push({
      id: crypto.randomBytes(8).toString('hex'),
      type: approvalType,
      approver: approverName,
      role: approverRole,
      approvedAt: new Date().toISOString(),
    });

    report.approvals = JSON.stringify(approvals);

    if (approvalType === 'executive') {
      report.executiveApproval = JSON.stringify({
        approved: true,
        approver: approverName,
        approvedAt: new Date().toISOString(),
      });
    } else if (approvalType === 'legal') {
      report.legalApproval = JSON.stringify({
        approved: true,
        approver: approverName,
        approvedAt: new Date().toISOString(),
      });
    }

    await this.redis.hset(key, Object.entries(report).flat());

    return { success: true, report };
  }

  async recordReview(reportId, reviewerName, comments = '') {
    const key = `report:${reportId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    const report = {};
    for (let i = 0; i < data.length; i += 2) {
      report[data[i]] = data[i + 1];
    }

    let reviewers = [];
    if (report.reviewers) {
      try {
        reviewers = JSON.parse(report.reviewers);
      } catch (e) {
        reviewers = [];
      }
    }

    reviewers.push({
      id: crypto.randomBytes(8).toString('hex'),
      reviewer: reviewerName,
      comments,
      reviewedAt: new Date().toISOString(),
    });

    report.reviewers = JSON.stringify(reviewers);

    await this.redis.hset(key, Object.entries(report).flat());

    return { success: true, report };
  }

  async getPolicyCompliance(reportId) {
    const key = `report:${reportId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    const report = {};
    for (let i = 0; i < data.length; i += 2) {
      report[data[i]] = data[i + 1];
    }

    const policy = await this.getPolicy(report.classification);

    let reviewers = [];
    let approvals = [];
    if (report.reviewers) {
      try {
        reviewers = JSON.parse(report.reviewers);
      } catch (e) {
        reviewers = [];
      }
    }
    if (report.approvals) {
      try {
        approvals = JSON.parse(report.approvals);
      } catch (e) {
        approvals = [];
      }
    }

    const hasExecutiveApproval = !!report.executiveApproval;
    const hasLegalApproval = !!report.legalApproval;

    const complianceStatus = {
      reportId,
      classification: report.classification,
      policy,
      reviewersCompliance: {
        required: policy.requiredReviewers,
        obtained: reviewers.length,
        satisfied: reviewers.length >= policy.requiredReviewers,
        reviewers,
      },
      approvalsCompliance: {
        required: policy.requiredApprovals,
        obtained: approvals.length,
        satisfied: approvals.length >= policy.requiredApprovals,
        approvals,
      },
      executiveApprovalCompliance: {
        required: policy.executiveApprovalRequired,
        satisfied: hasExecutiveApproval || !policy.executiveApprovalRequired,
      },
      legalApprovalCompliance: {
        required: policy.legalApprovalRequired,
        satisfied: hasLegalApproval || !policy.legalApprovalRequired,
      },
      overallCompliance: reviewers.length >= policy.requiredReviewers &&
        approvals.length >= policy.requiredApprovals &&
        (hasExecutiveApproval || !policy.executiveApprovalRequired) &&
        (hasLegalApproval || !policy.legalApprovalRequired),
    };

    return complianceStatus;
  }
}

module.exports = { PublicationPolicyEngine };
