/**
 * SENTINEL APEX — Customer SIEM Connectors (Controlled SIEM Deployment
 * Gateway v1)
 * Single serverless function handling connector CRUD + connection
 * testing, matching the established api/v1/watchlists.js / api/v1/
 * defense-profile.js router convention exactly (guardRequest ->
 * globalIpRateLimit -> authenticate() per handler -> action= dispatch ->
 * successResponse/apiError).
 *
 * Routing: /api/v1/connectors?action={action}
 *
 *  action=platforms          GET   Known SIEM platforms + capability flags (never a customer's own connectors)
 *  action=entitlements       GET   The caller's connector plan limits
 *  action=list               GET   The caller's own connectors (never a credential value)
 *  action=get&id=            GET   One connector
 *  action=create             POST  Body: {platform, name, target_config, credential?}
 *  action=rotate-credential&id=  POST  Body: {credential}
 *  action=test-connection&id=    POST  Read-only remote check -- never creates/modifies a remote resource
 *  action=disable&id=            POST  Disconnect: stops future deployments, revokes the local credential, preserves history
 *
 * Every action requires authenticate() -- ownership is always re-derived
 * from the authenticated caller's userId, never from the request body.
 */
'use strict';

const sec = require('../_lib/security');
const { authenticate, successResponse, apiError } = require('../_lib/middleware');
const { parseBody } = require('../_lib/payment-utils');
const store = require('../_lib/siem-connector-store');
const taxonomy = require('../_lib/siem-connector-taxonomy');
const { getConnectorModule } = require('../_lib/connectors/connector-registry');

const VALID_ACTIONS = 'platforms, entitlements, list, get, create, rotate-credential, test-connection, disable';
const FIELDS = {
  create: ['platform', 'name', 'target_config', 'credential'],
  'rotate-credential': ['credential'],
  'test-connection': [],
  disable: [],
};

module.exports = async (req, res) => {
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes: 10240,
  });
  if (!ok_guard) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  if (!action) return apiError(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);

  switch (action) {
    case 'platforms': return handlePlatforms(req, res);
    case 'entitlements': return handleEntitlements(req, res);
    case 'list': return handleList(req, res);
    case 'get': return handleGet(req, res);
    case 'create': return handleCreate(req, res);
    case 'rotate-credential': return handleRotateCredential(req, res);
    case 'test-connection': return handleTestConnection(req, res);
    case 'disable': return handleDisable(req, res);
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
  const status = ({
    NOT_FOUND: 404,
    TIER_RESTRICTED: 403,
    CONNECTOR_LIMIT_REACHED: 403,
    PLATFORM_NOT_IMPLEMENTED: 400,
    UNKNOWN_PLATFORM: 400,
    ENCRYPTION_NOT_CONFIGURED: 503,
    CONNECTOR_DISABLED: 409,
  })[result.error] || 400;
  return apiError(res, status, result.error || 'BAD_REQUEST', result.message || 'Request could not be completed.');
}

/* Never returns platform-selectable ids the caller can't actually deploy
 * to yet -- known-but-unimplemented platforms are still listed (Section
 * 26/85 honesty: the UI should say "not yet supported", not 404), each
 * carrying its own capability flags so the client never has to guess. */
async function handlePlatforms(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  return successResponse(res, {
    platforms: Object.entries(taxonomy.KNOWN_PLATFORMS).map(([id, p]) => ({
      id, label: p.label, detection_format: p.detection_format,
      capabilities: p.capabilities, is_sandbox: !!p.is_sandbox,
      required_target_fields: p.required_target_fields || [],
      required_credential_fields: p.required_credential_fields || [],
      least_privilege_role: p.least_privilege_role || null,
      not_implemented_reason: p.not_implemented_reason || null,
    })),
  });
}

async function handleEntitlements(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  return successResponse(res, { entitlements: store.getSiemConnectorEntitlements(user.tier) });
}

async function handleList(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const connectors = await store.listConnectors(user.userId);
  return successResponse(res, { connectors });
}

async function handleGet(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Connector id required.');
  const result = await store.getConnectorSafe(user.userId, id);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { connector: result.connector });
}

async function handleCreate(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'create');
  if (body === null) return;
  const result = await store.createConnector(user.userId, user.tier, {
    platform: body.platform, name: body.name, target_config: body.target_config, credential: body.credential,
  });
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { connector: result.connector });
}

async function handleRotateCredential(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Connector id required.');
  const body = await readValidatedBody(req, res, 'rotate-credential');
  if (body === null) return;
  const result = await store.rotateCredential(user.userId, id, body.credential);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { connector: result.connector });
}

/* Read-only remote check (Section 25/26): must never create/modify a
 * remote resource. The connector module's testConnection() is documented
 * to only perform read-only calls (e.g. Microsoft Sentinel: GET the
 * analytics-rule collection, never a PUT). */
async function handleTestConnection(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Connector id required.');
  const body = await readValidatedBody(req, res, 'test-connection');
  if (body === null) return;

  const credResult = await store.getConnectorWithCredential(user.userId, id);
  if (credResult.error) return mapStoreError(res, credResult);
  const module_ = getConnectorModule(credResult.connector.platform);
  if (!module_) return apiError(res, 400, 'PLATFORM_NOT_IMPLEMENTED', 'This connector platform is not implemented.');

  let outcome;
  try {
    outcome = await module_.testConnection(credResult.connector);
  } catch (e) {
    outcome = { result: 'UNAVAILABLE', detail: sec.safeError(e, 'Connection test failed.') };
  }
  await store.recordConnectionTest(user.userId, id, outcome);
  return successResponse(res, { result: outcome.result, detail: outcome.detail });
}

async function handleDisable(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Connector id required.');
  const body = await readValidatedBody(req, res, 'disable');
  if (body === null) return;
  const result = await store.disableConnector(user.userId, id);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { disabled: true });
}
