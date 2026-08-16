'use strict';

/**
 * Node req/res compatibility layer for running this repo's existing
 * api/** handlers — module.exports = async (req, res) => {...}, written
 * against Vercel's Node request/response API — inside a Cloudflare
 * Worker's Web-standard fetch handler, unmodified.
 *
 * Scope is deliberately narrow: it implements exactly the req/res surface
 * PRE-MIGRATION-FORENSICS.md §3 documents as actually used across api/**
 * (method, url, headers, query, body, res.status/json/send/end/setHeader),
 * not a general Node http polyfill. Verified against api/_lib/middleware.js
 * and api/_lib/security.js's actual req/res usage, not assumed.
 */

const RAW_BODY_METHODS_WITHOUT_BODY = new Set(['GET', 'HEAD', 'OPTIONS']);
const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

/**
 * @param {Request} request Web-standard Request from the Worker's fetch handler
 * @param {{ api?: { bodyParser?: boolean } }} [handlerConfig] the target
 *   handler module's own exported `config` (e.g.
 *   api/v1/billing/webhook.js's `module.exports.config = { api: { bodyParser: false } }`).
 *   Same discriminator Vercel itself reads — reused here rather than
 *   inventing a parallel Workers-specific route list.
 */
async function toNodeRequest(request, handlerConfig = {}) {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  const headers = {};
  for (const [key, value] of request.headers) {
    headers[key.toLowerCase()] = value;
  }

  // security.js's getIp() trusts x-forwarded-for first, falling back to
  // x-real-ip then req.socket?.remoteAddress. x-forwarded-for is
  // client-suppliable and therefore spoofable (a malicious client could
  // set it directly to defeat per-IP rate limiting); Cloudflare's
  // cf-connecting-ip is set by Cloudflare's own edge from the real
  // connection and cannot be overridden by the client. When present, it
  // must WIN over any client-supplied x-forwarded-for, not just fill a
  // gap — this makes getIp() both correct and spoof-resistant with zero
  // changes to security.js.
  if (headers['cf-connecting-ip']) {
    headers['x-forwarded-for'] = headers['cf-connecting-ip'];
  }

  const query = {};
  for (const [key, value] of url.searchParams) {
    query[key] = value;
  }

  const req = {
    method,
    url: url.pathname + url.search,
    headers,
    query,
    body: undefined,
  };

  if (RAW_BODY_METHODS_WITHOUT_BODY.has(method)) {
    return req;
  }

  if (handlerConfig?.api?.bodyParser === false) {
    // Matches Vercel's config.api.bodyParser = false convention (see
    // api/v1/billing/webhook.js, api/v1/billing/razorpay-webhook.js): the
    // handler reads the exact raw bytes itself via security.js#readRawBody
    // for signature verification. Attach the original Web Request so
    // readRawBody's Workers branch can read it — see the __cfRequest
    // branch added there.
    req.__cfRequest = request;
    return req;
  }

  const contentType = headers['content-type'] || '';
  if (contentType.includes('application/json')) {
    const text = await request.text();
    req.body = text ? JSON.parse(text) : {};
  } else if (contentType.includes('application/x-www-form-urlencoded')) {
    const text = await request.text();
    req.body = Object.fromEntries(new URLSearchParams(text));
  } else if (contentType) {
    req.body = await request.text();
  }

  return req;
}

/**
 * Returns { res, response } — `res` is the Node-res-shaped object to hand
 * to an existing handler; `response` resolves to a real Web Response once
 * the handler calls one of res.json/send/end.
 */
function createNodeResponse() {
  let statusCode = 200;
  const headers = new Headers();
  let bodyText;
  let resolved = false;
  let resolveResponse;
  const response = new Promise(resolve => { resolveResponse = resolve; });

  function finish() {
    if (resolved) return; // first call wins, matching Node res semantics
    resolved = true;
    const finalBody = NULL_BODY_STATUSES.has(statusCode) ? null : (bodyText ?? '');
    resolveResponse(new Response(finalBody, { status: statusCode, headers }));
  }

  const res = {
    setHeader(key, value) {
      headers.set(key, String(value));
      return res;
    },
    // Defensive alias only — no confirmed real caller uses res.set() as of
    // this writing (the one grep hit that suggested it was a false
    // positive on re-check). Kept because it's zero-cost and matches the
    // Express convention the rest of this shim already follows.
    set(key, value) {
      return res.setHeader(key, value);
    },
    status(code) {
      statusCode = code;
      return res;
    },
    json(body) {
      if (!headers.has('content-type')) headers.set('content-type', 'application/json');
      bodyText = JSON.stringify(body);
      finish();
      return res;
    },
    send(body) {
      if (typeof body === 'object' && body !== null) return res.json(body);
      bodyText = body === undefined ? '' : String(body);
      finish();
      return res;
    },
    end(body) {
      if (body !== undefined) bodyText = String(body);
      finish();
      return res;
    },
  };

  return { res, response };
}

module.exports = { toNodeRequest, createNodeResponse };
