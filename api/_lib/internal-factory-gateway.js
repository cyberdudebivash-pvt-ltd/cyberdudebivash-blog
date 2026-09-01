'use strict';

/**
 * Security boundary for the legacy ReportManager/ProductFactory HTTP entry
 * points. The engines remain available for internal reuse, but their HTTP
 * surfaces are control-plane operations, not public CTI. Every request must
 * be attributable to a configured analyst identity before it reaches legacy
 * generation/review/approval/publish/export code.
 */
const sec = require('./security');
const { requireAnalyst } = require('./analyst-auth');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Analyst-Key',
};
const MAX_LIMIT = 100;
const MAX_QUERY_LENGTH = 200;

function applyCors(res) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
}

function fail(res, status, code, message) {
  applyCors(res);
  sec.applySecurityHeaders(res);
  return res.status(status).json({
    success: false,
    error: { code, message },
    meta: { timestamp: new Date().toISOString() },
  });
}

function boundQuery(req, res) {
  req.query = req.query || {};

  if (req.query.q !== undefined && String(req.query.q).length > MAX_QUERY_LENGTH) {
    fail(res, 400, 'QUERY_TOO_LONG', `q must be ${MAX_QUERY_LENGTH} characters or fewer.`);
    return false;
  }

  if (req.query.limit !== undefined) {
    const raw = String(req.query.limit).trim();
    if (!/^\d+$/.test(raw)) {
      fail(res, 400, 'INVALID_LIMIT', `limit must be an integer between 1 and ${MAX_LIMIT}.`);
      return false;
    }
    const parsed = Number(raw);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
      fail(res, 400, 'INVALID_LIMIT', `limit must be an integer between 1 and ${MAX_LIMIT}.`);
      return false;
    }
    req.query.limit = String(Math.min(parsed, MAX_LIMIT));
  }
  return true;
}

function injectVerifiedActor(req, analyst) {
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (_) { return; }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return;

  // Legacy handlers historically trusted these fields from the body. They
  // now always come from the authenticated analyst identity instead.
  req.body = {
    ...body,
    analyst: analyst.id,
    reviewer: analyst.id,
    approver: analyst.id,
    publisher: analyst.id,
    role: analyst.role || 'analyst',
  };
}

function createInternalFactoryGateway(legacyHandler, deps = {}) {
  if (typeof legacyHandler !== 'function') throw new TypeError('legacyHandler must be a function');
  const guardRequest = deps.guardRequest || sec.guardRequest;
  const requireAnalystFn = deps.requireAnalyst || requireAnalyst;

  return async function internalFactoryGateway(req, res) {
    if (req.method === 'OPTIONS') {
      applyCors(res);
      sec.applySecurityHeaders(res);
      return res.status(204).end();
    }

    const guarded = await guardRequest(req, res, {
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      maxBodyBytes: 65536,
    });
    if (!guarded) return;

    const analyst = await requireAnalystFn(req, res, fail);
    if (!analyst) return;

    if (!boundQuery(req, res)) return;
    injectVerifiedActor(req, analyst);
    req.verifiedAnalyst = analyst;

    return legacyHandler(req, res);
  };
}

module.exports = {
  CORS_HEADERS,
  MAX_LIMIT,
  MAX_QUERY_LENGTH,
  boundQuery,
  injectVerifiedActor,
  createInternalFactoryGateway,
};
