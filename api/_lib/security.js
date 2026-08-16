/**
 * CYBERDUDEBIVASH SENTINEL APEX — Central Security Module
 * Covers: Phase 1 (Request Guard), Phase 2 (Input Validation),
 *         Phase 4 (Rate Limiting), Phase 6 (TTL), Phase 8 (Safe Errors),
 *         Phase 11 (Security Headers)
 *
 * Import in every router:
 *   const sec = require('../_lib/security');
 */
'use strict';
const crypto = require('crypto');
const redis  = require('./redis');

/* ══════════════════════════════════════════════════════════════════
   CONSTANTS
══════════════════════════════════════════════════════════════════ */
const MAX_BODY_BYTES          = 10 * 1024;   // 10 KB
const GLOBAL_RATE_LIMIT       = 10;          // req/min per IP  (all endpoints)
const ADMIN_RATE_LIMIT        = 50;          // req/min per IP  (admin endpoints)
const PAYMENT_SUBMIT_LIMIT    = 3;           // submissions/day per IP
const INTENT_CREATE_LIMIT     = 5;           // intents/day per IP

/* Allowed HTTP methods globally */
const ALLOWED_METHODS = new Set(['GET', 'POST', 'OPTIONS', 'HEAD']);

/* TTL constants (seconds) */
const TTL = {
  INTENT:      86400,         // 24 h
  SUBMISSION:  90 * 86400,    // 90 d  — duplicate guard + data retention
  RATE_MIN:    60,            // 1 min — for req/min buckets
  RATE_DAY:    86400,         // 1 day — for per-day buckets
};
exports.TTL = TTL;

/* ══════════════════════════════════════════════════════════════════
   PHASE 1 — GLOBAL REQUEST GUARD
   Call at the very top of every router BEFORE anything else.
   Returns true if the request should continue, false if rejected.
══════════════════════════════════════════════════════════════════ */
async function guardRequest(req, res, opts = {}) {
  const {
    allowedMethods = ['GET', 'POST', 'OPTIONS'],
    requireJsonBody = false,   // true → enforce Content-Type: application/json for POST
    maxBodyBytes    = MAX_BODY_BYTES,
  } = opts;

  /* ── Apply security headers on every response ──────────────── */
  applySecurityHeaders(res);

  /* ── Method allowlist ───────────────────────────────────────── */
  const method = (req.method || '').toUpperCase();
  if (!ALLOWED_METHODS.has(method) || !allowedMethods.includes(method)) {
    _reject(res, 405, 'METHOD_NOT_ALLOWED', `Only ${allowedMethods.join(', ')} allowed`);
    return false;
  }

  /* ── CORS pre-flight fast-path ──────────────────────────────── */
  if (method === 'OPTIONS') {
    res.status(204).end();
    return false; // handled
  }

  /* ── Content-Type enforcement for POST bodies ───────────────── */
  if ((method === 'POST' || requireJsonBody) && req.headers['content-type']) {
    const ct = req.headers['content-type'].toLowerCase();
    if (!ct.includes('application/json') && !ct.includes('application/x-www-form-urlencoded')) {
      _reject(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json');
      return false;
    }
  }

  /* ── Payload size limit ─────────────────────────────────────── */
  const cl = parseInt(req.headers['content-length'] || '0', 10);
  if (cl > maxBodyBytes) {
    _reject(res, 413, 'PAYLOAD_TOO_LARGE', `Request body must not exceed ${Math.round(maxBodyBytes / 1024)} KB`);
    return false;
  }

  /* ── Strip dangerous request headers (defensive) ───────────── */
  const dangerousHeaders = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url'];
  dangerousHeaders.forEach(h => { delete req.headers[h]; });

  return true;
}
exports.guardRequest = guardRequest;

/* ══════════════════════════════════════════════════════════════════
   PHASE 4 — RATE LIMITING
══════════════════════════════════════════════════════════════════ */

/** Extract real client IP — trusts Vercel's x-forwarded-for chain */
function getIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim().slice(0, 45); // cap to IPv6 max
  return (req.headers['x-real-ip'] || req.socket?.remoteAddress || '0.0.0.0').slice(0, 45);
}
exports.getIp = getIp;

/**
 * Global per-IP rate limit: 10 req/min.
 * Bucket key: ratelimit:global:{ip}:{epoch_minute}
 * Returns true if request is allowed.
 */
async function globalIpRateLimit(req, res) {
  const ip     = getIp(req);
  const minute = Math.floor(Date.now() / 60000);
  const key    = `ratelimit:global:${ip}:${minute}`;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, TTL.RATE_MIN);
    if (count > GLOBAL_RATE_LIMIT) {
      res.setHeader('Retry-After', '60');
      res.setHeader('X-RateLimit-Limit-Global', String(GLOBAL_RATE_LIMIT));
      _reject(res, 429, 'RATE_LIMIT_EXCEEDED', `Global rate limit: ${GLOBAL_RATE_LIMIT} requests/minute per IP`);
      return false;
    }
  } catch (_) {
    // Redis down → fail open on global limit (API key rate limit still protects intel)
  }
  return true;
}
exports.globalIpRateLimit = globalIpRateLimit;

/**
 * Admin per-IP rate limit: 50 req/min (trusted internal use).
 */
async function adminIpRateLimit(req, res) {
  const ip     = getIp(req);
  const minute = Math.floor(Date.now() / 60000);
  const key    = `ratelimit:admin:${ip}:${minute}`;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, TTL.RATE_MIN);
    if (count > ADMIN_RATE_LIMIT) {
      res.setHeader('Retry-After', '60');
      _reject(res, 429, 'ADMIN_RATE_LIMIT', `Admin rate limit: ${ADMIN_RATE_LIMIT} requests/minute`);
      return false;
    }
  } catch (_) { /* fail open for admin */ }
  return true;
}
exports.adminIpRateLimit = adminIpRateLimit;

/**
 * Payment intent creation: 5 per IP per day.
 */
async function intentIpRateLimit(req, res) {
  const ip  = getIp(req);
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const key = `ratelimit:intent:${ip}:${day}`;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, TTL.RATE_DAY);
    if (count > INTENT_CREATE_LIMIT) {
      _reject(res, 429, 'INTENT_RATE_LIMIT', `Maximum ${INTENT_CREATE_LIMIT} payment intents per IP per day`);
      return false;
    }
  } catch (_) { /* fail open */ }
  return true;
}
exports.intentIpRateLimit = intentIpRateLimit;

/**
 * Payment submission: 3 per IP per day.
 */
async function submissionIpRateLimit(req, res) {
  const ip  = getIp(req);
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const key = `ratelimit:submit:${ip}:${day}`;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, TTL.RATE_DAY);
    if (count > PAYMENT_SUBMIT_LIMIT) {
      _reject(res, 429, 'SUBMISSION_RATE_LIMIT', `Maximum ${PAYMENT_SUBMIT_LIMIT} payment submissions per IP per day`);
      return false;
    }
  } catch (_) { /* fail open */ }
  return true;
}
exports.submissionIpRateLimit = submissionIpRateLimit;

/**
 * Minimum-interval throttle for external workflow dispatchers.
 * Bucket key: throttle:dispatch:{workflow}:{window_index}
 * Guards against an external scheduler (e.g. Vercel Cron) firing a GitHub
 * Actions workflow_dispatch far more often than the workflow's own
 * `schedule:` cron intends — this exact drift (dispatcher firing every
 * ~5 min against a workflow meant to run every 2h) caused a Blogger API
 * 429 burst that got BLOGGER_REFRESH_TOKEN revoked (invalid_grant) for
 * 2.5+ days in July 2026. Returns true if the dispatch should proceed.
 * Fails open on Redis errors — same posture as the rate limiters above.
 */
async function workflowDispatchThrottle(workflow, minIntervalMinutes) {
  const windowMs = minIntervalMinutes * 60000;
  const windowIndex = Math.floor(Date.now() / windowMs);
  const key = `throttle:dispatch:${workflow}:${windowIndex}`;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, minIntervalMinutes * 60);
    return count === 1;
  } catch (_) {
    return true; // Redis down → fail open, matches globalIpRateLimit posture
  }
}
exports.workflowDispatchThrottle = workflowDispatchThrottle;

/* ══════════════════════════════════════════════════════════════════
   PHASE 2 — INPUT VALIDATION
══════════════════════════════════════════════════════════════════ */

/** RFC-compliant email validation */
function validateEmail(s) {
  if (typeof s !== 'string') return false;
  const e = s.trim().toLowerCase();
  return /^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}$/.test(e) && e.length <= 320;
}
exports.validateEmail = validateEmail;

/** Strict UUID v4 format */
function validateUUID(s) {
  if (typeof s !== 'string') return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s.trim());
}
exports.validateUUID = validateUUID;

/**
 * UTR / transaction reference validation.
 * Alphanumeric only, 8–64 chars.
 * (Real IMPS/NEFT UTRs are 12–22 chars; we allow 8–64 for flexibility.)
 */
function validateUTR(s) {
  if (typeof s !== 'string') return false;
  const t = s.trim().toUpperCase();
  return /^[A-Z0-9]{8,64}$/.test(t);
}
exports.validateUTR = validateUTR;
exports.normalizeUTR = (s) => (typeof s === 'string' ? s.trim().toUpperCase().replace(/[^A-Z0-9]/g, '') : '');

/**
 * Plan type validation.
 */
function validatePlan(s) {
  return s === 'starter' || s === 'pro' || s === 'enterprise';
}
exports.validatePlan = validatePlan;

/**
 * Field whitelist enforcer.
 * body        — parsed request body object
 * allowed     — array of allowed field names
 * Returns null if OK, or an error string if unexpected fields found.
 */
function assertFieldWhitelist(body, allowed) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'Request body must be a JSON object';
  const extra = Object.keys(body).filter(k => !allowed.includes(k));
  if (extra.length > 0) {
    return `Unexpected fields: ${extra.map(f => `"${f}"`).join(', ')}. Allowed: ${allowed.join(', ')}`;
  }
  return null;
}
exports.assertFieldWhitelist = assertFieldWhitelist;

/** Safe string sanitizer — strips HTML, control chars, nulls */
function sanitize(input, maxLen = 500) {
  if (input === null || input === undefined) return '';
  return String(input)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars (keep \t \n \r)
    .replace(/<[^>]*>/g, '')                             // HTML tags
    .replace(/[<>"'`]/g, '')                             // dangerous chars
    .trim()
    .slice(0, maxLen);
}
exports.sanitize = sanitize;

/* ══════════════════════════════════════════════════════════════════
   PHASE 8 — SAFE ERROR HANDLING
══════════════════════════════════════════════════════════════════ */

/**
 * Converts any caught Error into a safe client-facing message.
 * Never leaks stack traces, Redis keys, or internal identifiers.
 */
function safeError(e, fallback = 'An internal error occurred. Please retry or contact support.') {
  if (!e) return fallback;
  const msg = String(e.message || '');
  // Block messages that leak internals
  const dangerous = ['redis', 'upstash', 'password', 'secret', 'token', 'stack', 'user:key:', 'payment:'];
  const isDangerous = dangerous.some(d => msg.toLowerCase().includes(d));
  if (isDangerous) return fallback;
  // Allow short, safe messages
  if (msg.length > 0 && msg.length <= 200 && !isDangerous) return msg;
  return fallback;
}
exports.safeError = safeError;

/* ══════════════════════════════════════════════════════════════════
   PHASE 11 — SECURITY HEADERS
══════════════════════════════════════════════════════════════════ */

/**
 * Apply hardened security headers on every response.
 * Called automatically by guardRequest().
 */
function applySecurityHeaders(res) {
  // Prevent MIME-type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Clickjacking protection
  res.setHeader('X-Frame-Options', 'DENY');

  // Basic CSP for API endpoints (no scripts, no frames)
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; frame-ancestors 'none'"
  );

  // HSTS — 2 years, includeSubDomains
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

  // Stop browsers from sending Referer to third parties
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Disable browser features we don't need
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  // Prevent caching of API responses
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

  // Platform identifier
  res.setHeader('X-Powered-By', 'CYBERDUDEBIVASH SENTINEL APEX v4.0');

  // CORS — explicit headers
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, X-API-Key, Content-Type, X-Admin-Key, stripe-signature');
  res.setHeader('Access-Control-Max-Age', '86400');
}
exports.applySecurityHeaders = applySecurityHeaders;

/* ══════════════════════════════════════════════════════════════════
   WEBHOOK RAW BODY READER
   Payment-gateway webhooks (Stripe, Razorpay) sign the exact raw bytes
   they sent. Vercel auto-parses JSON bodies before the handler runs, so
   re-serializing req.body is not guaranteed byte-identical to what was
   signed. Webhook handlers must export `config.api.bodyParser = false`
   and call this to read the true raw stream for signature verification.
══════════════════════════════════════════════════════════════════ */
function readRawBody(req, maxBytes = 262144) {
  // Cloudflare Workers path: workers/lib/node-compat.js's toNodeRequest()
  // attaches the original Web Request here for bodyParser:false routes,
  // since Workers' Request has no Node stream-event API. A real Node
  // IncomingMessage never has this property, so the existing stream-read
  // path below is completely unreached and unchanged when it's absent.
  if (req.__cfRequest) {
    return req.__cfRequest.arrayBuffer().then(buf => {
      if (buf.byteLength > maxBytes) throw new Error('PAYLOAD_TOO_LARGE');
      return Buffer.from(buf).toString('utf8');
    });
  }

  return new Promise((resolve, reject) => {
    let data = '';
    let bytes = 0;
    let settled = false;
    req.on('data', chunk => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        settled = true;
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => { if (!settled) { settled = true; resolve(data); } });
    req.on('error', (err) => { if (!settled) { settled = true; reject(err); } });
  });
}
exports.readRawBody = readRawBody;

/* ══════════════════════════════════════════════════════════════════
   PHASE 3 — ADMIN AUTH
══════════════════════════════════════════════════════════════════ */

/**
 * Verify X-Admin-Key header using timing-safe comparison.
 * Only accepts the header — not Authorization or query params.
 */
function verifyAdminKey(req) {
  const adminKey = process.env.ADMIN_SECRET_KEY;
  if (!adminKey || adminKey.length < 16) return false; // not configured
  const provided = String(req.headers['x-admin-key'] || '');
  if (!provided) return false;
  // Timing-safe comparison at a fixed 128-char width
  const expected = adminKey.padEnd(128).slice(0, 128);
  const actual   = provided.padEnd(128).slice(0, 128);
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(actual, 'utf8'))
      && provided === adminKey; // also do exact match to catch length attacks
  } catch (_) {
    return false;
  }
}
exports.verifyAdminKey = verifyAdminKey;

/* ══════════════════════════════════════════════════════════════════
   INTERNAL HELPERS
══════════════════════════════════════════════════════════════════ */

function _reject(res, status, code, message) {
  if (res.headersSent) return;
  res.status(status).json({
    success: false,
    error:   { code, message },
    meta:    { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
  });
}
