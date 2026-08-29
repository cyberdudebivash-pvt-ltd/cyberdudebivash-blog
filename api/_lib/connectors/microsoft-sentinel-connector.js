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
 */

const crypto = require('crypto');
const { ConnectorError } = require('./connector-contract');

const PLATFORM_ID = 'microsoft-sentinel';
const API_VERSION = '2025-06-01';
const TOKEN_TIMEOUT_MS = 10000;
const API_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2MB -- Microsoft's own API, not attacker-controlled, but bounded anyway (Section 108)

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
 *  deployment operations are infrequent enough that this is not a
 *  meaningful cost (a documented, deliberate simplicity choice, not an
 *  oversight -- revisit only with real latency evidence). */
async function getAccessToken(connector) {
  const { tenant_id, client_id } = connector.target_config;
  const { client_secret } = connector.credential;
  const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(tenant_id)}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id,
    client_secret,
    scope: 'https://management.azure.com/.default',
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

function classifyArmResponse(res) {
  if (res.status === 401) return new ConnectorError('AUTH_FAILED', 'Azure Resource Manager rejected the bearer token.', { retryable: false, httpStatus: 401 });
  if (res.status === 403) return new ConnectorError('PERMISSION_DENIED', 'The connector’s service principal lacks permission for this operation (expected role: Microsoft Sentinel Contributor on the target workspace).', { retryable: false, httpStatus: 403 });
  if (res.status === 404) return new ConnectorError('TARGET_NOT_FOUND', 'The configured subscription/resource group/workspace was not found.', { retryable: false, httpStatus: 404 });
  if (res.status === 429) return new ConnectorError('RATE_LIMITED', 'Azure Resource Manager rate-limited this request.', { retryable: true, httpStatus: 429 });
  if (res.status >= 500) return new ConnectorError('REMOTE_ERROR', `Azure Resource Manager returned HTTP ${res.status}.`, { retryable: true, httpStatus: res.status });
  if (!res.ok) return new ConnectorError('REMOTE_ERROR', `Azure Resource Manager returned unexpected HTTP ${res.status}.`, { retryable: false, httpStatus: res.status });
  return null;
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
  // exported for direct unit testing
  deriveRuleId,
  mapSeverity,
};
