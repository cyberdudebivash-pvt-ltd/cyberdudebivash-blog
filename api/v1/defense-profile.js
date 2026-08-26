/**
 * SENTINEL APEX — Customer Defense Profile
 * Single serverless function handling Defense Profile CRUD, matching the
 * established api/v1/watchlists.js router convention exactly (guardRequest
 * -> globalIpRateLimit -> authenticate() per handler -> action= dispatch ->
 * successResponse/apiError).
 *
 * Routing: /api/v1/defense-profile?action={action}
 *
 *  action=get             GET   The caller's Defense Profile (or {profile: null} if none configured)
 *  action=save             POST  Whole-resource create-or-replace. Body: {name?, technologies?, telemetry?}
 *  action=delete             POST  Delete the caller's Defense Profile. Body: {}
 *  action=taxonomy             GET   Static reference vocabulary (technologies, data sources, status values) for the profile wizard
 *  action=entitlements            GET   The caller's current Defense Profile limits
 *
 * Every action requires authenticate() -- ownership is always re-derived
 * from the authenticated caller's userId, never from the request body
 * (mandate Phase 9: "Never accept authorization ownership from owner_id /
 * customer_id / workspace_id ... inside request payload").
 *
 * Customer-specific detection COVERAGE for a CVE/campaign is deliberately
 * NOT an action on this router -- it is an entity-keyed GET lookup, the
 * same shape of problem as intel.js's existing `dossier`/`detection-coverage`
 * actions, so it lives there instead (action=defense-coverage) rather than
 * bolting a GET-only entity lookup onto this CRUD-oriented, POST-capable
 * router (mandate Phase 38: "Do not create excessive router files").
 */
'use strict';

const sec = require('../_lib/security');
const { authenticate, successResponse, apiError } = require('../_lib/middleware');
const { parseBody } = require('../_lib/payment-utils');
const store = require('../_lib/defense-profile-store');
const taxonomy = require('../_lib/defense-taxonomy');

const VALID_ACTIONS = 'get, save, delete, taxonomy, entitlements';
const FIELDS = {
  save: ['name', 'technologies', 'telemetry'],
  delete: [],
};

module.exports = async (req, res) => {
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes: 20480, // bounded, but a full technology+telemetry payload is larger than a watchlist's
  });
  if (!ok_guard) return;

  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  if (!action) {
    return apiError(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);
  }

  switch (action) {
    case 'get':           return handleGet(req, res);
    case 'save':            return handleSave(req, res);
    case 'delete':             return handleDelete(req, res);
    case 'taxonomy':              return handleTaxonomy(req, res);
    case 'entitlements':              return handleEntitlements(req, res);
    default:
      return apiError(res, 400, 'INVALID_ACTION', `Unknown action: "${action}". Valid: ${VALID_ACTIONS}`);
  }
};

async function readValidatedBody(req, res, action) {
  if (req.method !== 'POST') {
    apiError(res, 405, 'METHOD_NOT_ALLOWED', `POST required for action=${action}`);
    return null;
  }
  let body;
  try {
    body = await parseBody(req);
  } catch (_) {
    apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON.');
    return null;
  }
  const whitelistErr = sec.assertFieldWhitelist(body || {}, FIELDS[action] || []);
  if (whitelistErr) {
    apiError(res, 400, 'INVALID_FIELDS', whitelistErr);
    return null;
  }
  return body || {};
}

function mapStoreError(res, result) {
  const status = result.error === 'NOT_FOUND' ? 404 : 400;
  const message = result.message || (result.error === 'NOT_FOUND' ? 'No Defense Profile configured.' : 'Request could not be completed.');
  return apiError(res, status, result.error || 'BAD_REQUEST', message);
}

/* ─── GET ?action=get ─────────────────────────────────────────── */
async function handleGet(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const result = await store.getProfile(user.userId);
  return successResponse(res, { profile: result.profile });
}

/* ─── POST ?action=save ───────────────────────────────────────── */
async function handleSave(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'save');
  if (body === null) return;

  const result = await store.saveProfile(user.userId, {
    name: body.name, technologies: body.technologies, telemetry: body.telemetry,
  });
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { profile: result.profile });
}

/* ─── POST ?action=delete ─────────────────────────────────────── */
async function handleDelete(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'delete');
  if (body === null) return;

  const result = await store.deleteProfile(user.userId);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { deleted: true });
}

/* ─── GET ?action=taxonomy ────────────────────────────────────── */
async function handleTaxonomy(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  return successResponse(res, {
    categories: taxonomy.TECHNOLOGY_CATEGORIES,
    technologies: taxonomy.TECHNOLOGY_CATEGORIES.reduce((acc, c) => {
      acc[c] = taxonomy.technologyOptionsFor(c);
      return acc;
    }, {}),
    data_sources: taxonomy.DATA_SOURCES,
    telemetry_status_values: taxonomy.TELEMETRY_STATUS_VALUES,
  });
}

/* ─── GET ?action=entitlements ────────────────────────────────── */
async function handleEntitlements(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const entitlements = store.getDefenseProfileEntitlements(user.tier);
  const result = await store.getProfile(user.userId);
  return successResponse(res, { entitlements, usage: { profile_configured: !!result.profile } });
}
