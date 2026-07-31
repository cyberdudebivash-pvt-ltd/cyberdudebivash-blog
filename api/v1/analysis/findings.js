'use strict';

const redis = require('../../_lib/redis');
const { AnalysisManager } = require('../../_lib/analysis-manager');

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

  if (req.method === 'POST' && action === 'findings') {
    return handleCreateFinding(req, res);
  }

  if (req.method === 'GET' && action === 'findings') {
    return handleListFindings(req, res);
  }

  if (req.method === 'GET' && action && id) {
    const resourceType = pathParts[pathParts.length - 3];
    if (resourceType === 'findings') {
      return handleGetFinding(req, res, id);
    }
  }

  if (req.method === 'PUT' && action === 'review' && id) {
    return handleReviewFinding(req, res, id);
  }

  if (req.method === 'PUT' && action === 'publish' && id) {
    return handlePublishFinding(req, res, id);
  }

  if (req.method === 'GET' && action === 'report' && id) {
    return handleGetAnalysisReport(req, res, id);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCreateFinding(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, statement, confidence, evidence, reasoning, assumptions, limitations, alternativeHypotheses, tags, type } = body;

    if (!investigationId || !statement) {
      return fail(res, 400, 'MISSING_FIELD', 'investigationId and statement required');
    }

    const result = await analysisMgr.createAnalyticalFinding(investigationId, {
      statement,
      type: type || 'technical',
      confidence: confidence || 'possible',
      evidence: evidence || [],
      reasoning: reasoning || '',
      assumptions: assumptions || [],
      limitations: limitations || [],
      alternativeHypotheses: alternativeHypotheses || [],
      tags: tags || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      finding: result.finding,
      validation: result.validation,
      scoring: result.scoring,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleListFindings(req, res) {
  try {
    const investigationId = req.query.investigationId;
    const status = req.query.status;
    const limit = parseInt(req.query.limit || '50', 10);

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const findings = await analysisMgr.getInvestigationFindings(investigationId, limit);

    let filtered = findings;
    if (status) {
      filtered = findings.filter(f => f.status === status);
    }

    return ok(res, {
      investigationId,
      findings: filtered,
      count: filtered.length,
      totalCount: findings.length,
    });
  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', e.message);
  }
}

async function handleGetFinding(req, res, id) {
  try {
    const finding = await analysisMgr.getFinding(id);
    if (!finding) {
      return fail(res, 404, 'NOT_FOUND', `Finding not found: ${id}`);
    }

    return ok(res, { finding });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleReviewFinding(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { reviewer, approved, feedback } = body;

    if (!reviewer) {
      return fail(res, 400, 'MISSING_REVIEWER', 'reviewer name required');
    }

    const result = await analysisMgr.reviewFinding(id, reviewer, approved === true, feedback || '');

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'REVIEW_FAILED', e.message);
  }
}

async function handlePublishFinding(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { publisher } = body;

    if (!publisher) {
      return fail(res, 400, 'MISSING_PUBLISHER', 'publisher name required');
    }

    const result = await analysisMgr.publishFinding(id, publisher);

    if (!result.success) {
      return fail(res, 400, 'PUBLISH_FAILED', result.error);
    }

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'PUBLISH_FAILED', e.message);
  }
}

async function handleGetAnalysisReport(req, res, id) {
  try {
    const report = await analysisMgr.getAnalysisReport(id);

    return ok(res, { report });
  } catch (e) {
    return fail(res, 500, 'REPORT_FAILED', e.message);
  }
}
