'use strict';

const redis = require('../../_lib/redis');
const { PublicationManager } = require('../../_lib/publication-manager');

const pubMgr = new PublicationManager(redis);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function ok(res, data, status = 200) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: true,
    meta: { timestamp: new Date().toISOString() },
    ...data,
  });
}

function fail(res, status, code, message) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: false,
    error: { code, message },
    meta: { timestamp: new Date().toISOString() },
  });
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
    return res.status(200).end();
  }

  const pathParts = (req.url || '').split('?')[0].split('/').filter(Boolean);
  const action = pathParts[pathParts.length - 1];
  const id = pathParts[pathParts.length - 2];

  // Quality review
  if (req.method === 'POST' && action === 'review' && id) {
    return handleQualityReview(req, res, id);
  }

  // Get review
  if (req.method === 'GET' && action === 'review' && id) {
    return handleGetReview(req, res, id);
  }

  // List reviews
  if (req.method === 'GET' && action === 'reviews' && id) {
    return handleListReviews(req, res, id);
  }

  // Get certification
  if (req.method === 'GET' && action === 'certification' && id) {
    return handleGetCertification(req, res, id);
  }

  // Approve for publication
  if (req.method === 'POST' && action === 'approve' && id) {
    return handleApproveForPublication(req, res, id);
  }

  // Request executive approval
  if (req.method === 'POST' && action === 'executive-approval' && id) {
    return handleExecutiveApproval(req, res, id);
  }

  // Get policy compliance
  if (req.method === 'GET' && action === 'compliance' && id) {
    return handleGetCompliance(req, res, id);
  }

  // Publication report
  if (req.method === 'GET' && action === 'publication-report' && id) {
    return handlePublicationReport(req, res, id);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleQualityReview(req, res, investigationId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { reportId, analyst } = body;
    if (!reportId) {
      return fail(res, 400, 'MISSING_ID', 'reportId required');
    }

    const reportKey = `report:${reportId}`;
    const reportData = await redis.hgetall(reportKey);

    if (!reportData || reportData.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Report not found: ${reportId}`);
    }

    const report = {};
    for (let i = 0; i < reportData.length; i += 2) {
      report[reportData[i]] = reportData[i + 1];
    }

    const review = await pubMgr.performFullQualityReview(report, investigationId, analyst || 'analyst');

    return ok(res, { review }, 201);
  } catch (e) {
    return fail(res, 500, 'REVIEW_FAILED', e.message);
  }
}

async function handleGetReview(req, res, reviewId) {
  try {
    const review = await pubMgr.getReview(reviewId);
    if (!review) {
      return fail(res, 404, 'NOT_FOUND', `Review not found: ${reviewId}`);
    }

    return ok(res, { review });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleListReviews(req, res, investigationId) {
  try {
    const limit = parseInt(req.query.limit || '20', 10);
    const reviews = await pubMgr.listReviews(investigationId, limit);

    return ok(res, {
      investigationId,
      reviews,
      count: reviews.length,
    });
  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', e.message);
  }
}

async function handleGetCertification(req, res, reportId) {
  try {
    const certification = await pubMgr.getReportCertification(reportId);

    return ok(res, { certification });
  } catch (e) {
    return fail(res, 500, 'CERT_FAILED', e.message);
  }
}

async function handleApproveForPublication(req, res, reportId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { approver, role } = body;
    if (!approver) {
      return fail(res, 400, 'MISSING_APPROVER', 'approver name required');
    }

    const result = await pubMgr.approveForPublication(reportId, approver, role || 'analyst');

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'APPROVAL_FAILED', e.message);
  }
}

async function handleExecutiveApproval(req, res, reportId) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { approver } = body;
    if (!approver) {
      return fail(res, 400, 'MISSING_APPROVER', 'approver name required');
    }

    const result = await pubMgr.requestExecutiveApproval(reportId, approver);

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'EXEC_APPROVAL_FAILED', e.message);
  }
}

async function handleGetCompliance(req, res, reportId) {
  try {
    const compliance = await pubMgr.getPolicyCompliance(reportId);

    return ok(res, { compliance });
  } catch (e) {
    return fail(res, 500, 'COMPLIANCE_FAILED', e.message);
  }
}

async function handlePublicationReport(req, res, reportId) {
  try {
    const report = await pubMgr.generatePublicationReport(reportId);

    if (!report.success) {
      return fail(res, 404, 'NOT_FOUND', report.error);
    }

    return ok(res, { report });
  } catch (e) {
    return fail(res, 500, 'REPORT_FAILED', e.message);
  }
}
