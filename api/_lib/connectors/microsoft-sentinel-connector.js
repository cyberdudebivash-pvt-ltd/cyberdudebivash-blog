'use strict';
/**
 * SENTINEL APEX — Microsoft Sentinel Connector (Controlled SIEM
 * Deployment Gateway v1)
 *
 * Resource: Microsoft.SecurityInsights/alertRules ("Scheduled" kind),
 * scoped under a specific Log Analytics workspace. Verified against
 * current official Microsoft documentation before implementation, not
 * from stale training-data knowledge:
 *
 *   PUT/GET/DELETE https://management.azure.com/subscriptions/{subscriptionId}
 *     /resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights
 *     /workspaces/{workspaceName}/providers/Microsoft.SecurityInsights
 *     /alertRules/{ruleId}?api-version=2025-06-01
 *
 *   Source: https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update
 *   (fetched live; "ScheduledAlertRule" request/response schema, required
 *   vs. optional properties, and the etag/systemData shape below are
 *   transcribed directly from that page, not guessed). api-version pinned
 *   to 2025-06-01 — a stable (non "-preview") version documented as
 *   current at research time; the same Learn page lists 2025-03-01 and
 *   2025-09-01 as sibling stable versions and 2025-07-01-preview/
 *   2025-10-01-preview as preview-only, deliberately not used here.
 *
 * DELETE is implemented via the same resource URI and the standard ARM
 * DELETE-on-a-resource convention (universal across every ARM resource
 * type this platform's research reviewed) — disclosed as a LOWER-
 * CONFIDENCE inference than PUT/GET, since the specific "Alert Rules -
 * Delete" reference page was not itself fetched this round. DISABLE (the
 * default, preferred lifecycle action per Section 56/35) does not depend
 * on this: it is a PUT with properties.enabled=false, fully covered by
 * the verified create-or-update contract.
 *
 * Auth: Azure AD OAuth2 client-credentials flow (a registered Azure AD
 * application / service principal), POST to
 * https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token,
 * scope=https://management.azure.com/.default. Least-privilege role:
 * "Microsoft Sentinel Contributor" assigned at the SPECIFIC Log Analytics
 * workspace scope (never subscription- or tenant-wide) — the minimum
 * built-in role that can create/update analytics rules; "Sentinel Reader"/
 * "Sentinel Responder" cannot (verified via Microsoft's own Sentinel
 * roles documentation).
 *
 * Vendor sandbox execution: NOT VERIFIED. This sandbox has no Azure
 * tenant, subscription, or credentials of any kind, and (consistent with
 * every prior tranche in this repository's history) no authenticated
 * Cloudflare access either. Every code path below is verified against
 * Microsoft's current published API contract and covered by unit tests
 * with a mocked fetch — never claimed as proven against a live Azure
 * Sentinel workspace. See the certification doc's "Vendor sandbox
 * verification" section.
 *
 * Controlled Read-Only SIEM Hunting Connectors v1 adds executeHuntQuery/
 * testHuntQueryConnection/normalizeResults, gated by capabilities.
 * hunt_query_supported (siem-connector-taxonomy.js) — a genuinely
 * SEPARATE Azure resource/OAuth scope/RBAC role from everything above,
 * verified live against current official Microsoft documentation
 * (learn.microsoft.com/azure/azure-monitor/logs/api/access-api and
 * .../request-format, fetched live):
 *
 *   POST https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query
 *   Body: {"query": "<kql>", "timespan": "<start>/<end>"}
 *   Response: {"tables":[{"name","columns":[{"name","type"}],"rows":[[...]]}]}
 *
 * workspaceId here is the Log Analytics workspace's own GUID ("Workspace
 * ID" in the Azure Portal overview blade) — NOT the ARM resource path
 * (subscription/resource group/workspace_name) the alertRules API above
 * uses. Auth: the SAME Azure AD client-credentials flow, but a DIFFERENT
 * scope, `https://api.loganalytics.io/.default` (vs. `https://
 * management.azure.com/.default` for deploy) — a different Azure resource
 * entirely, requiring a different least-privilege built-in RBAC role,
 * "Reader" on the target Log Analytics workspace ("Microsoft Sentinel
 * Contributor" grants no data-plane query access at all). `timespan` is
 * the API's OWN native, separate time-range parameter — time bounds are
 * NEVER string-concatenated into the KQL query text, so this one
 * parameter type is inherently immune to injection by construction
 * (Section 65/73), not by escaping.
 */

const crypto = require('crypto');
const { ConnectorError, normalizeObservationRows } = require('./connector-contract');

const PLATFORM_ID = 'microsoft-sentinel';
const API_VERSION = '2025-06-01';
const TOKEN_TIMEOUT_MS = 10000;
const API_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2MB -- Microsoft's own API, not attacker-controlled, but bounded anyway (Section 108)
const ARM_SCOPE = 'https://management.azure.com/.default';
const LOG_ANALYTICS_SCOPE = 'https://api.loganalytics.io/.default'; // deliberately different from ARM_SCOPE -- see file header
const LOG_ANALYTICS_QUERY_BASE = 'https://api.loganalytics.azure.com/v1/workspaces';

function armBaseUrl({ subscription_id, resource_group, workspace_name }) {
  return `https://management.azure.com/subscriptions/${encodeURIComponent(subscription_id)}` +
    `/resourceGroups/${encodeURIComponent(resource_group)}` +
    `/providers/Microsoft.OperationalInsights/workspaces/${encodeURIComponent(workspace_name)}` +
    `/providers/Microsoft.SecurityInsights/alertRules`;
}

/** Deterministic, not random — the same (connector, detection, target)
 *  intent always derives the same ruleId, which IS the idempotency
 *  mechanism (Section 39/41): a retried deploy() PUTs the same URI. */
function deriveRuleId(remoteResourceName) {
  const hash = crypto.createHash('sha256').update(String(remoteResourceName)).digest('hex');
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

function mapSeverity(rawLevel) {
  const s = String(rawLevel || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'High';
  if (s === 'medium') return 'Medium';
  if (s === 'low') return 'Low';
  if (s === 'informational' || s === 'info') return 'Informational';
  return 'Medium'; // undocumented/unrecognized level -- safe, disclosed default, never silently "High"
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // redirect: 'error' -- never follow a redirect (mirrors notification-
    // dispatch.js#deliverWebhookChannel()'s exact outbound-fetch
    // discipline), even though this endpoint is a fixed, Microsoft-owned
    // hostname and SSRF via a customer-supplied URL does not apply here.
    return await fetch(url, { ...options, redirect: 'error', signal: controller.signal });
  } catch (e) {
    if (e.name === 'AbortError') {
      throw new ConnectorError('TIMEOUT', `Request to ${new URL(url).hostname} timed out after ${timeoutMs}ms.`, { retryable: true });
    }
    throw new ConnectorError('REMOTE_ERROR', `Network error contacting ${new URL(url).hostname}: ${e.message}`, { retryable: true });
  } finally {
    clearTimeout(timer);
  }
}

async function readBoundedJson(res) {
  const contentLength = Number(res.headers.get('content-length') || 0);
  if (contentLength && contentLength > MAX_RESPONSE_BYTES) {
    throw new ConnectorError('RESPONSE_TOO_LARGE', `Response body (${contentLength} bytes) exceeds the ${MAX_RESPONSE_BYTES}-byte bound.`, { retryable: false });
  }
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) {
    throw new ConnectorError('RESPONSE_TOO_LARGE', `Response body exceeds the ${MAX_RESPONSE_BYTES}-byte bound.`, { retryable: false });
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

/** Fetches a fresh bearer token on every call -- simpler and safer than
 *  cross-request token caching under Workers' uncertain isolate lifetime;
 *  deployment/hunting operations are infrequent enough that this is not a
 *  meaningful cost (a documented, deliberate simplicity choice, not an
 *  oversight -- revisit only with real latency evidence). `scope` is the
 *  ONLY difference between the deploy (ARM) and hunt (Log Analytics)
 *  token requests -- same tenant/client_id/client_secret, genuinely
 *  different Azure resource being requested. */
async function requestAccessToken(connector, scope) {
  const { tenant_id, client_id } = connector.target_config;
  const { client_secret } = connector.credential;
  const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(tenant_id)}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id,
    client_secret,
    scope,
  });
  const res = await fetchWithTimeout(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }, TOKEN_TIMEOUT_MS);

  if (res.status === 401 || res.status === 400) {
    throw new ConnectorError('AUTH_FAILED', 'Azure AD rejected the connector credential (invalid client id/secret/tenant).', { retryable: false, httpStatus: res.status });
  }
  if (!res.ok) {
    throw new ConnectorError('REMOTE_ERROR', `Azure AD token endpoint returned HTTP ${res.status}.`, { retryable: res.status >= 500, httpStatus: res.status });
  }
  const json = await readBoundedJson(res);
  if (!json || !json.access_token) {
    throw new ConnectorError('AUTH_FAILED', 'Azure AD token response did not include an access_token.', { retryable: false });
  }
  return json.access_token;
}

async function getAccessToken(connector) {
  return requestAccessToken(connector, ARM_SCOPE);
}

/** Separate from getAccessToken() -- never assumed interchangeable with
 *  it (Section 18). Throws the same ConnectorError shape on failure. */
async function getHuntAccessToken(connector) {
  return requestAccessToken(connector, LOG_ANALYTICS_SCOPE);
}

function classifyAzureResponse(res, { targetNotFoundMessage, permissionDeniedMessage }) {
  if (res.status === 401) return new ConnectorError('AUTH_FAILED', 'Azure rejected the bearer token.', { retryable: false, httpStatus: 401 });
  if (res.status === 403) return new ConnectorError('PERMISSION_DENIED', permissionDeniedMessage, { retryable: false, httpStatus: 403 });
  if (res.status === 404) return new ConnectorError('TARGET_NOT_FOUND', targetNotFoundMessage, { retryable: false, httpStatus: 404 });
  if (res.status === 429) return new ConnectorError('RATE_LIMITED', 'Azure rate-limited this request.', { retryable: true, httpStatus: 429 });
  if (res.status >= 500) return new ConnectorError('REMOTE_ERROR', `Azure returned HTTP ${res.status}.`, { retryable: true, httpStatus: res.status });
  if (!res.ok) return new ConnectorError('REMOTE_ERROR', `Azure returned unexpected HTTP ${res.status}.`, { retryable: false, httpStatus: res.status });
  return null;
}

function classifyArmResponse(res) {
  return classifyAzureResponse(res, {
    targetNotFoundMessage: 'The configured subscription/resource group/workspace was not found.',
    permissionDeniedMessage: 'The connector’s service principal lacks permission for this operation (expected role: Microsoft Sentinel Contributor on the target workspace).',
  });
}

/** A 400 from the Log Analytics query API is well-documented as meaning
 *  the query itself is syntactically invalid KQL or references an unknown
 *  table/column -- a genuine query defect, not a provider/auth issue, so
 *  this is classified as QUERY_REJECTED (the same code a pre-flight
 *  rejection uses) rather than falling through to the generic
 *  REMOTE_ERROR classifyAzureResponse() would otherwise assign. This is
 *  the ONE realistic path through which hunt-query-engine.js's
 *  QUERY_DEFECT -> QUERY_ERROR detection-feedback routing actually fires
 *  for a real vendor call (every other rejection is caught by this
 *  platform's own pre-flight checks before ever reaching the network).
 *  Deliberately NOT applied to classifyArmResponse() -- a 400 on the
 *  alertRules control-plane API more often reflects a malformed request
 *  body than specifically bad KQL, and that already-certified deploy path
 *  is out of scope for this tranche's evidence. */
function classifyLogAnalyticsResponse(res) {
  if (res.status === 400) {
    return new ConnectorError('QUERY_REJECTED', 'The Log Analytics API rejected this query as syntactically invalid or referencing an unknown table/column.', { retryable: false, httpStatus: 400 });
  }
  return classifyAzureResponse(res, {
    targetNotFoundMessage: 'The configured workspace_id was not found.',
    permissionDeniedMessage: 'The connector’s service principal lacks data-plane query permission for this workspace (expected role: Reader on the target Log Analytics workspace).',
  });
}

async function testConnection(connector) {
  let token;
  try {
    token = await getAccessToken(connector);
  } catch (e) {
    if (e instanceof ConnectorError && e.code === 'AUTH_FAILED') return { result: 'AUTH_FAILED', detail: e.message };
    return { result: 'UNAVAILABLE', detail: e.message };
  }
  // Read-only: GET the workspace-scoped alertRules collection (list),
  // never a specific rule -- proves auth + permission + target existence
  // without depending on any deployment already existing.
  const url = `${armBaseUrl(connector.target_config)}?api-version=${API_VERSION}`;
  let res;
  try {
    res = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, API_TIMEOUT_MS);
  } catch (e) {
    return { result: 'UNAVAILABLE', detail: e.message };
  }
  const err = classifyArmResponse(res);
  if (err) {
    if (err.code === 'AUTH_FAILED') return { result: 'AUTH_FAILED', detail: err.message };
    if (err.code === 'PERMISSION_DENIED') return { result: 'INSUFFICIENT_PERMISSION', detail: err.message };
    if (err.code === 'TARGET_NOT_FOUND') return { result: 'TARGET_NOT_FOUND', detail: err.message };
    return { result: 'UNAVAILABLE', detail: err.message };
  }
  return { result: 'CONNECTED', detail: 'Successfully listed analytics rules in the target workspace.' };
}

function mapIntent(_connector, intent) {
  return {
    nativePayload: {
      kind: 'Scheduled',
      properties: {
        displayName: intent.title.slice(0, 500),
        description: `${intent.description || ''}\n\nSENTINEL APEX detection ${intent.detection_id} v${intent.detection_version}.`.slice(0, 5000),
        severity: mapSeverity(intent.severity_raw),
        enabled: !!intent.enabled,
        query: intent.query,
        queryFrequency: 'PT1H',
        queryPeriod: 'PT1H',
        triggerOperator: 'GreaterThan',
        triggerThreshold: 0,
        suppressionEnabled: false,
        suppressionDuration: 'PT5H',
        techniques: [intent.technique_id],
        customDetails: {
          sentinel_apex_detection_id: intent.detection_id,
          sentinel_apex_detection_version: String(intent.detection_version),
        },
      },
    },
  };
}

/** The canonical {query,severity,enabled,techniques} shape this intent
 *  WOULD produce if deployed — same shape readBack() returns, so
 *  deployment-engine.js can hash both sides identically (Section 46/47). */
function toCanonicalObserved(intent) {
  return {
    query: intent.query,
    severity: mapSeverity(intent.severity_raw),
    enabled: !!intent.enabled,
    techniques: [intent.technique_id].sort(),
  };
}

async function deploy(connector, intent) {
  const token = await getAccessToken(connector);
  const ruleId = deriveRuleId(intent.remote_resource_name);
  const url = `${armBaseUrl(connector.target_config)}/${ruleId}?api-version=${API_VERSION}`;
  const { nativePayload } = mapIntent(connector, intent);

  const res = await fetchWithTimeout(url, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(nativePayload),
  }, API_TIMEOUT_MS);

  const err = classifyArmResponse(res);
  if (err) throw err;
  if (res.status !== 200 && res.status !== 201) {
    throw new ConnectorError('REMOTE_ERROR', `Unexpected HTTP ${res.status} from Microsoft Sentinel.`, { retryable: false, httpStatus: res.status });
  }
  const json = await readBoundedJson(res);
  return { remote_resource_id: json?.id || url, remote_etag: json?.etag || null, raw: json };
}

async function readBack(connector, remoteResourceName) {
  const token = await getAccessToken(connector);
  const ruleId = deriveRuleId(remoteResourceName);
  const url = `${armBaseUrl(connector.target_config)}/${ruleId}?api-version=${API_VERSION}`;

  const res = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, API_TIMEOUT_MS);
  if (res.status === 404) return { found: false, observed: null, etag: null, raw: null };
  const err = classifyArmResponse(res);
  if (err) throw err;

  const json = await readBoundedJson(res);
  const props = (json && json.properties) || {};
  return {
    found: true,
    observed: {
      query: props.query || '',
      severity: props.severity || '',
      enabled: !!props.enabled,
      techniques: [...(props.techniques || [])].sort(),
    },
    etag: json?.etag || null,
    raw: json,
  };
}

async function disable(connector, remoteResourceName) {
  const current = await readBack(connector, remoteResourceName);
  if (!current.found) return { ok: false };
  const token = await getAccessToken(connector);
  const ruleId = deriveRuleId(remoteResourceName);
  const url = `${armBaseUrl(connector.target_config)}/${ruleId}?api-version=${API_VERSION}`;
  const payload = {
    kind: 'Scheduled',
    etag: current.etag || undefined,
    properties: {
      ...current.raw.properties,
      enabled: false,
    },
  };
  const res = await fetchWithTimeout(url, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }, API_TIMEOUT_MS);
  const err = classifyArmResponse(res);
  if (err) throw err;
  return { ok: res.status === 200 || res.status === 201 };
}

/** Lower-confidence than PUT/GET/disable -- see file header. Standard ARM
 *  DELETE-on-resource-URI convention, not independently verified against
 *  a fetched "Alert Rules - Delete" reference this round. */
async function deleteRemote(connector, remoteResourceName) {
  const token = await getAccessToken(connector);
  const ruleId = deriveRuleId(remoteResourceName);
  const url = `${armBaseUrl(connector.target_config)}/${ruleId}?api-version=${API_VERSION}`;
  const res = await fetchWithTimeout(url, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }, API_TIMEOUT_MS);
  if (res.status === 404) return { ok: true }; // already gone -- deletion is idempotent
  const err = classifyArmResponse(res);
  if (err) throw err;
  return { ok: res.status === 200 || res.status === 204 };
}

/** Read-only: a minimal, always-valid query touching no real table, so
 *  this proves auth + the Reader role's data-plane query permission
 *  without depending on any specific table/data existing in the
 *  workspace. Never inferred from testConnection()'s result -- a real,
 *  independent call against the hunting-specific scope/endpoint. */
async function testHuntQueryConnection(connector) {
  const workspaceId = connector.target_config.workspace_id;
  if (!workspaceId) {
    return { result: 'UNAVAILABLE', detail: 'No workspace_id configured on this connector -- required for hunt query execution (separate from the workspace_name used for deployment).' };
  }
  let token;
  try {
    token = await getHuntAccessToken(connector);
  } catch (e) {
    if (e instanceof ConnectorError && e.code === 'AUTH_FAILED') return { result: 'AUTH_FAILED', detail: e.message };
    return { result: 'UNAVAILABLE', detail: e.message };
  }
  const url = `${LOG_ANALYTICS_QUERY_BASE}/${encodeURIComponent(workspaceId)}/query`;
  let res;
  try {
    res = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'print 1', timespan: 'PT1M' }),
    }, API_TIMEOUT_MS);
  } catch (e) {
    return { result: 'UNAVAILABLE', detail: e.message };
  }
  const err = classifyLogAnalyticsResponse(res);
  if (err) {
    if (err.code === 'AUTH_FAILED') return { result: 'AUTH_FAILED', detail: err.message };
    if (err.code === 'PERMISSION_DENIED') return { result: 'INSUFFICIENT_PERMISSION', detail: err.message };
    if (err.code === 'TARGET_NOT_FOUND') return { result: 'TARGET_NOT_FOUND', detail: err.message };
    return { result: 'UNAVAILABLE', detail: err.message };
  }
  return { result: 'CONNECTED', detail: 'Successfully executed a minimal read-only query against the target Log Analytics workspace.' };
}

/** Read-only remote search. Never creates/modifies/deletes any remote
 *  resource -- a POST to the Log Analytics Query API is itself a
 *  read-only data-plane operation (Microsoft's own documented contract),
 *  never the alertRules control-plane this connector's deploy() path
 *  uses. */
async function executeHuntQuery(connector, { query, format, timeStart, timeEnd, rowLimit }) {
  if (format !== 'kql') {
    throw new ConnectorError('QUERY_REJECTED', `Microsoft Sentinel hunt queries must be in kql format (got "${format}").`, { retryable: false });
  }
  if (!Number.isInteger(rowLimit) || rowLimit < 1) {
    throw new ConnectorError('QUERY_REJECTED', 'rowLimit must be a positive integer.', { retryable: false });
  }
  if (!timeStart || !timeEnd) {
    throw new ConnectorError('QUERY_REJECTED', 'timeStart and timeEnd are required.', { retryable: false });
  }
  const workspaceId = connector.target_config.workspace_id;
  if (!workspaceId) {
    throw new ConnectorError('QUERY_REJECTED', 'No workspace_id configured on this connector -- required for hunt query execution.', { retryable: false });
  }

  const token = await getHuntAccessToken(connector);
  const url = `${LOG_ANALYTICS_QUERY_BASE}/${encodeURIComponent(workspaceId)}/query`;
  // timespan is the Log Analytics API's OWN native time-range parameter
  // (an ISO 8601 interval) -- time bounds are NEVER string-concatenated
  // into the query text itself, so this one parameter type is inherently
  // immune to KQL injection by construction, not by escaping.
  const timespan = `${timeStart}/${timeEnd}`;
  const res = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, timespan }),
  }, API_TIMEOUT_MS);

  const err = classifyLogAnalyticsResponse(res);
  if (err) throw err;

  const json = await readBoundedJson(res);
  const table = json && Array.isArray(json.tables) ? json.tables[0] : null;
  if (!table || !Array.isArray(table.columns) || !Array.isArray(table.rows)) {
    // A 2xx response that doesn't match the documented
    // {tables:[{columns,rows}]} shape is itself a REMOTE_ERROR, never
    // silently treated as zero results -- silent-empty-success on a
    // malformed response would misclassify a provider-side defect as a
    // genuine NO_SIGNAL hunt outcome.
    throw new ConnectorError('REMOTE_ERROR', 'Log Analytics response did not match the expected {tables:[{columns,rows}]} shape.', { retryable: false });
  }

  const columnNames = table.columns.map(c => (c && typeof c.name === 'string') ? c.name : '');
  const truncated = table.rows.length > rowLimit;
  const boundedRows = truncated ? table.rows.slice(0, rowLimit) : table.rows;
  const rows = boundedRows.map(rowArray => {
    const obj = {};
    columnNames.forEach((name, idx) => {
      if (name) obj[name] = Array.isArray(rowArray) ? rowArray[idx] : undefined;
    });
    return obj;
  });

  // Deliberately minimal `raw` (unlike deploy()/readBack()'s, which carry
  // the full ARM resource for disable()'s merge-PUT) -- nothing downstream
  // needs the full vendor payload for a read-only hunt result, and
  // keeping it minimal avoids letting a bulky remote-telemetry blob leak
  // into logs/persistence by accident.
  return { rows, truncated, raw: { table_name: table.name || null } };
}

/** Pure, no I/O — delegates to connector-contract.js's single shared
 *  implementation (every connector's normalizeResults shares it). */
function normalizeResults(_connector, rawRows) {
  return normalizeObservationRows(rawRows);
}

module.exports = {
  platformId: PLATFORM_ID,
  API_VERSION,
  testConnection,
  mapIntent,
  toCanonicalObserved,
  deploy,
  readBack,
  disable,
  deleteRemote,
  testHuntQueryConnection,
  executeHuntQuery,
  normalizeResults,
  // exported for direct unit testing
  deriveRuleId,
  mapSeverity,
};
