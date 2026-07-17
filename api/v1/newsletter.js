/**
 * SENTINEL APEX — Newsletter Signup Endpoint
 * POST /api/v1/newsletter
 * Body: { email, name?, segment?, source?, role?, industry?, primary_challenge? }
 *
 * Server-side Resend integration — the API key never reaches the browser
 * (unlike a client-side ESP call). Every lead is also backed up in Redis
 * so no signup is lost if Resend is unconfigured or briefly unavailable.
 *
 * role/industry/primary_challenge are optional, free-text-but-sanitized
 * qualification fields (lightweight profile, not a full lead-qualification
 * system — see enterprise report Module 7 scoping). Same 3-year lead TTL
 * as the rest of this record; no new PII-retention policy needed since
 * these are short, non-sensitive classification strings.
 */
'use strict';
const redis  = require('../_lib/redis');
const resend = require('../_lib/resend');
const sec    = require('../_lib/security');
const {
  normalizeEmail, emailKey, now, ok, fail, parseBody, auditLog,
} = require('../_lib/payment-utils');

const FIELDS = ['email', 'name', 'segment', 'source', 'role', 'industry', 'primary_challenge'];
const VALID_SEGMENTS = new Set(['general', 'cve-alerts', 'ai-security', 'mssp', 'enterprise', 'webinar']);
const NEWSLETTER_LIMIT_PER_IP_PER_DAY = 10;
const LEAD_TTL_SECONDS = 3 * 365 * 86400; // 3 years

async function newsletterIpRateLimit(req, res) {
  const ip  = sec.getIp(req);
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const key = `ratelimit:newsletter:${ip}:${day}`;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, 86400);
    if (count > NEWSLETTER_LIMIT_PER_IP_PER_DAY) {
      fail(res, 429, 'RATE_LIMIT_EXCEEDED', `Maximum ${NEWSLETTER_LIMIT_PER_IP_PER_DAY} signups per IP per day`);
      return false;
    }
  } catch (_) { /* fail open */ }
  return true;
}

module.exports = async (req, res) => {
  const guardOk = await sec.guardRequest(req, res, { allowedMethods: ['POST', 'OPTIONS'], maxBodyBytes: 4096 });
  if (!guardOk) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const body = await parseBody(req);
  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email      = normalizeEmail(body.email);
  const name       = sec.sanitize(body.name || '', 100);
  const segmentRaw = sec.sanitize(String(body.segment || 'general').toLowerCase(), 40);
  const segment    = VALID_SEGMENTS.has(segmentRaw) ? segmentRaw : 'general';
  const source     = sec.sanitize(body.source || 'website', 60);
  const role       = sec.sanitize(body.role || '', 80);
  const industry   = sec.sanitize(body.industry || '', 80);
  const primaryChallenge = sec.sanitize(body.primary_challenge || '', 200);

  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }

  if (!(await newsletterIpRateLimit(req, res))) return;

  const ip = sec.getIp(req);

  let espStatus = 'not_configured';
  if (resend.configured()) {
    try {
      await resend.addContact(email, name);
      espStatus = 'subscribed';
    } catch (e) {
      espStatus = 'esp_error';
      await auditLog('NEWSLETTER_ESP_ERROR', { email, error: sec.safeError(e) });
    }
  }

  try {
    await redis.hmset(`newsletter:lead:${emailKey(email)}`, {
      email, name, segment, source, ip,
      role, industry, primaryChallenge,
      subscribedAt: now(),
      espStatus,
    });
    await redis.expire(`newsletter:lead:${emailKey(email)}`, LEAD_TTL_SECONDS);
    await redis.zadd('newsletter:leads', Date.now(), email);
  } catch (_) {
    // Redis backup is best-effort — never block the response on it.
  }

  await auditLog('NEWSLETTER_SIGNUP', { email, segment, source, role, industry, espStatus, ip });

  return ok(res, {
    message: espStatus === 'subscribed'
      ? 'Subscribed successfully.'
      : 'Lead captured.',
    subscription: { email, segment, esp_status: espStatus },
  });
};
