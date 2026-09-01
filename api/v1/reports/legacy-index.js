'use strict';

const redis = require('../../_lib/redis');
const { ReportManager } = require('../../_lib/report-manager');
const { AnalysisManager } = require('../../_lib/analysis-manager');

const reportMgr = new ReportManager(redis);
const analysisMgr = new AnalysisManager(redis);

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
  const resourceType = pathParts[pathParts.length - 3];

  // Generate report
  if (req.method === 'POST' && action === 'generate') {
    return handleGenerateReport(req, res);
  }

  // Create report (template preparation)
  if (req.method === 'POST' && action === 'reports') {
    return handleCreateReport(req, res);
  }

  // List reports
  if (req.method === 'GET' && action === 'reports') {
    return handleListReports(req, res);
  }

  // Get report
  if (req.method === 'GET' && resourceType === 'reports' && id) {
    return handleGetReport(req, res, id);
  }

  // Review report
  if (req.method === 'PUT' && action === 'review' && id) {
    return handleReviewReport(req, res, id);
  }

  // Approve report
  if (req.method === 'PUT' && action === 'approve' && id) {
    return handleApproveReport(req, res, id);
  }

  // Publish report
  if (req.method === 'PUT' && action === 'publish' && id) {
    return handlePublishReport(req, res, id);
  }

  // Export report
  if (req.method === 'GET' && action === 'export' && id) {
    return handleExportReport(req, res, id);
  }

  // New version
  if (req.method === 'POST' && action === 'new-version' && id) {
    return handleNewVersion(req, res, id);
  }

  // Compare versions
  if (req.method === 'GET' && action === 'compare' && id) {
    return handleCompareVersions(req, res, id);
  }

  // Report stats
  if (req.method === 'GET' && action === 'stats' && id) {
    return handleReportStats(req, res, id);
  }

  // Product factory
  if (req.method === 'POST' && action === 'factory' && id) {
    return handleProductFactory(req, res, id);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleGenerateReport(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { reportType, investigationId, selectedFindings, selectedAssessments, includedIOCs, includedInfrastructure, includedTechniques, gaps, analyst } = body;

    if (!reportType || !investigationId) {
      return fail(res, 400, 'MISSING_FIELD', 'reportType and investigationId required');
    }

    const composition = {
      reportType,
      investigationId,
      selectedFindings: selectedFindings || [],
      selectedAssessments: selectedAssessments || {},
      includedIOCs: includedIOCs || [],
      includedInfrastructure: includedInfrastructure || [],
      includedTechniques: includedTechniques || [],
      gaps: gaps || [],
      customizations: body.customizations || {},
    };

    const result = await reportMgr.generateReport(composition, analyst || 'analyst');

    if (!result.success) {
      return fail(res, 400, 'GENERATION_FAILED', result.error);
    }

    return ok(res, {
      report: result.report,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'GENERATE_FAILED', e.message);
  }
}

async function handleCreateReport(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, reportType, analyst, customizations } = body;

    if (!investigationId || !reportType) {
      return fail(res, 400, 'MISSING_FIELD', 'investigationId and reportType required');
    }

    const result = await reportMgr.createReport(investigationId, reportType, analyst || 'analyst', customizations || {});

    return ok(res, result, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleListReports(req, res) {
  try {
    const investigationId = req.query.investigationId;
    const limit = parseInt(req.query.limit || '50', 10);

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const reports = await reportMgr.listReports(investigationId, limit);
    const stats = await reportMgr.getReportStats(investigationId);

    return ok(res, {
      investigationId,
      reports,
      count: reports.length,
      stats,
    });
  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', e.message);
  }
}

async function handleGetReport(req, res, id) {
  try {
    const report = await reportMgr.getReport(id);
    if (!report) {
      return fail(res, 404, 'NOT_FOUND', `Report not found: ${id}`);
    }

    return ok(res, { report });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleReviewReport(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { reviewer, feedback } = body;

    if (!reviewer) {
      return fail(res, 400, 'MISSING_REVIEWER', 'reviewer name required');
    }

    const result = await reportMgr.reviewReport(id, reviewer, feedback || '');

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'REVIEW_FAILED', e.message);
  }
}

async function handleApproveReport(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { approver } = body;

    if (!approver) {
      return fail(res, 400, 'MISSING_APPROVER', 'approver name required');
    }

    const result = await reportMgr.approveReport(id, approver);

    if (!result.success) {
      return fail(res, 400, 'APPROVAL_FAILED', result.error);
    }

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'APPROVE_FAILED', e.message);
  }
}

async function handlePublishReport(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { publisher } = body;

    if (!publisher) {
      return fail(res, 400, 'MISSING_PUBLISHER', 'publisher name required');
    }

    const result = await reportMgr.publishReport(id, publisher);

    if (!result.success) {
      return fail(res, 400, 'PUBLISH_FAILED', result.error);
    }

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'PUBLISH_FAILED', e.message);
  }
}

async function handleExportReport(req, res, id) {
  try {
    const format = req.query.format || 'html';

    const result = await reportMgr.exportReport(id, format);

    if (!result.success) {
      return fail(res, 404, 'NOT_FOUND', result.error);
    }

    res.setHeader('Content-Type', this.getContentType(format));
    res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
    res.status(200).send(result.content);
  } catch (e) {
    return fail(res, 500, 'EXPORT_FAILED', e.message);
  }
}

async function handleNewVersion(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { analyst } = body;

    const result = await reportMgr.createNewVersion(id, analyst || 'analyst');

    if (!result.success) {
      return fail(res, 400, 'VERSION_FAILED', result.error);
    }

    return ok(res, result, 201);
  } catch (e) {
    return fail(res, 500, 'VERSION_FAILED', e.message);
  }
}

async function handleCompareVersions(req, res, id) {
  try {
    const compareId = req.query.compareId;

    if (!compareId) {
      return fail(res, 400, 'MISSING_ID', 'compareId query parameter required');
    }

    const result = await reportMgr.compareVersions(id, compareId);

    if (!result.success) {
      return fail(res, 404, 'NOT_FOUND', result.error);
    }

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'COMPARE_FAILED', e.message);
  }
}

async function handleReportStats(req, res, id) {
  try {
    const stats = await reportMgr.getReportStats(id);

    return ok(res, {
      investigationId: id,
      stats,
    });
  } catch (e) {
    return fail(res, 500, 'STATS_FAILED', e.message);
  }
}

async function handleProductFactory(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const findings = await analysisMgr.getInvestigationFindings(id, 100);
    const analysis = await analysisMgr.getAnalysisReport(id);

    const products = await reportMgr.generateProductFactory(id, findings, {
      situation: analysis.assessments.situation,
      technical: analysis.assessments.technical,
      executive: analysis.assessments.executive,
      threatActors: [],
    });

    return ok(res, products, 201);
  } catch (e) {
    return fail(res, 500, 'FACTORY_FAILED', e.message);
  }
}
