/**
 * SENTINEL APEX — Intelligence Objects API
 * REST endpoints for managing intelligence lifecycle.
 *
 * POST   /api/v1/intelligence/objects — create new intelligence
 * GET    /api/v1/intelligence/objects — search/list intelligence
 * GET    /api/v1/intelligence/objects/{id} — retrieve single object
 * PUT    /api/v1/intelligence/objects/{id} — update object
 * POST   /api/v1/intelligence/objects/{id}/review — submit for review
 * POST   /api/v1/intelligence/objects/{id}/approve — approve for publication
 * POST   /api/v1/intelligence/objects/{id}/publish — publish to production
 * POST   /api/v1/intelligence/objects/{id}/retract — retract published object
 * GET    /api/v1/intelligence/objects/{id}/history — version history
 */
'use strict';

const redis = require('../../_lib/redis');
const { IntelligenceManager } = require('../../_lib/intelligence-manager');
const { INTELLIGENCE_TYPES, LIFECYCLE_STATES, CONFIDENCE_LEVELS } = require('../../_lib/intelligence-object');

const manager = new IntelligenceManager(redis);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function ok(res, data, status = 200) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: true,
    meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v5.0', timestamp: new Date().toISOString() },
    ...data,
  });
}

function fail(res, status, code, message) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: false,
    error: { code, message },
    meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v5.0', timestamp: new Date().toISOString() },
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

  // POST /api/v1/intelligence/objects — create new intelligence
  if (req.method === 'POST' && !id && action === 'objects') {
    return handleCreateIntelligence(req, res);
  }

  // GET /api/v1/intelligence/objects — search/list
  if (req.method === 'GET' && action === 'objects' && !id) {
    return handleSearchIntelligence(req, res);
  }

  // GET /api/v1/intelligence/objects/{id} — retrieve
  if (req.method === 'GET' && id && !action) {
    return handleGetIntelligence(req, res, id);
  }

  // PUT /api/v1/intelligence/objects/{id} — update
  if (req.method === 'PUT' && id && !action) {
    return handleUpdateIntelligence(req, res, id);
  }

  // POST /api/v1/intelligence/objects/{id}/review — submit for review
  if (req.method === 'POST' && action === 'review' && id) {
    return handleSubmitReview(req, res, id);
  }

  // POST /api/v1/intelligence/objects/{id}/approve — approve
  if (req.method === 'POST' && action === 'approve' && id) {
    return handleApprove(req, res, id);
  }

  // POST /api/v1/intelligence/objects/{id}/publish — publish
  if (req.method === 'POST' && action === 'publish' && id) {
    return handlePublish(req, res, id);
  }

  // POST /api/v1/intelligence/objects/{id}/retract — retract
  if (req.method === 'POST' && action === 'retract' && id) {
    return handleRetract(req, res, id);
  }

  // GET /api/v1/intelligence/objects/{id}/history — history
  if (req.method === 'GET' && action === 'history' && id) {
    return handleGetHistory(req, res, id);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCreateIntelligence(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { type, title, description, content, confidence, severity, tags } = body;

    if (!type || !INTELLIGENCE_TYPES[type]) {
      return fail(res, 400, 'INVALID_TYPE', `type must be one of: ${Object.keys(INTELLIGENCE_TYPES).join(', ')}`);
    }
    if (!title) {
      return fail(res, 400, 'MISSING_TITLE', 'title is required');
    }

    const actor = body.createdBy || 'api';
    const result = await manager.storeIntelligence(type, {
      title,
      description: description || '',
      content: content || {},
      confidence: confidence || 'MEDIUM',
      severity: severity || 'MEDIUM',
      tags: tags || [],
    }, actor);

    return ok(res, {
      message: 'Intelligence object created.',
      intelligence: result,
    }, 201);

  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleSearchIntelligence(req, res) {
  try {
    const filters = {
      type: req.query.type,
      status: req.query.status,
      confidence: req.query.confidence,
      severity: req.query.severity,
      q: req.query.q,
    };

    const results = await manager.searchIntelligence(Object.fromEntries(Object.entries(filters).filter(([_, v]) => v)));

    return ok(res, {
      results,
      count: results.length,
      filters,
    });

  } catch (e) {
    return fail(res, 500, 'SEARCH_FAILED', e.message);
  }
}

async function handleGetIntelligence(req, res, id) {
  try {
    const obj = await manager.getIntelligence(id);
    if (!obj) {
      return fail(res, 404, 'NOT_FOUND', `Intelligence object not found: ${id}`);
    }

    return ok(res, { intelligence: obj });

  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleUpdateIntelligence(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const result = await manager.updateIntelligence(id, body, body.updatedBy || 'api', body.reason || '');

    return ok(res, {
      message: 'Intelligence object updated.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'UPDATE_FAILED', e.message);
  }
}

async function handleSubmitReview(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const result = await manager.transitionIntelligence(
      id,
      LIFECYCLE_STATES.REVIEW,
      body.actor || 'api',
      body.reason || 'Submitted for review'
    );

    return ok(res, {
      message: 'Intelligence submitted for review.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'REVIEW_FAILED', e.message);
  }
}

async function handleApprove(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const result = await manager.transitionIntelligence(
      id,
      LIFECYCLE_STATES.APPROVED,
      body.actor || 'api',
      body.reason || 'Approved for publication'
    );

    return ok(res, {
      message: 'Intelligence approved.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'APPROVE_FAILED', e.message);
  }
}

async function handlePublish(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const result = await manager.publishIntelligence(id, body.actor || 'api');

    return ok(res, {
      message: 'Intelligence published to production.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'PUBLISH_FAILED', e.message);
  }
}

async function handleRetract(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const result = await manager.retractIntelligence(
      id,
      body.actor || 'api',
      body.reason || ''
    );

    return ok(res, {
      message: 'Intelligence retracted from production.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'RETRACT_FAILED', e.message);
  }
}

async function handleGetHistory(req, res, id) {
  try {
    const history = await manager.getIntelligenceHistory(id);
    if (!history) {
      return fail(res, 404, 'NOT_FOUND', `Intelligence object not found: ${id}`);
    }

    return ok(res, { history });

  } catch (e) {
    return fail(res, 500, 'HISTORY_FAILED', e.message);
  }
}
