/**
 * GET /api/v1/admin/payments/audit
 * SENTINEL APEX Manual Payment System — Phase 11
 *
 * Returns the full payment audit log from Redis sorted set.
 * Protected by X-Admin-Key header.
 *
 * Query params:
 *   ?limit=100    — entries to return (max 500)
 *   ?offset=0     — pagination offset
 *   ?action=      — filter by action type (PAYMENT_APPROVED, PAYMENT_REJECTED, etc.)
 */
'use strict';
const redis = require('../../../_lib/redis');
const { isAdminAuthorized, cors, ok, fail, auditLog, getIp } = require('../../../_lib/payment-utils');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  if (!isAdminAuthorized(req)) {
    await auditLog('ADMIN_AUTH_FAIL', { ip: getIp(req), endpoint: 'audit' });
    return fail(res, 401, 'UNAUTHORIZED', 'Valid X-Admin-Key header required.');
  }

  const limit    = Math.min(parseInt(req.query?.limit || '100', 10), 500);
  const offset   = Math.max(parseInt(req.query?.offset || '0', 10), 0);
  const filter   = String(req.query?.action || '').toUpperCase();

  try {
    // Fetch most recent entries (ZREVRANGE = newest first)
    const raw = await redis.zrevrange('audit:payment:log', 0, 999);
    if (!raw || !Array.isArray(raw)) {
      return ok(res, { entries: [], total: 0, limit, offset });
    }

    let entries = raw.map(item => {
      try { return JSON.parse(item); } catch (_) { return { raw: item }; }
    });

    if (filter) {
      entries = entries.filter(e => (e.action || '').toUpperCase().includes(filter));
    }

    const total = entries.length;
    const page  = entries.slice(offset, offset + limit);

    return ok(res, {
      entries: page,
      total,
      limit,
      offset,
      filter: filter || 'none',
      action_types: [
        'INTENT_CREATED',
        'PAYMENT_SUBMITTED',
        'PAYMENT_APPROVED',
        'PAYMENT_REJECTED',
        'TIER_UPGRADED',
        'ADMIN_AUTH_FAIL',
        'DUPLICATE_TXN',
        'RATE_LIMIT_HIT',
        'EMAIL_MISMATCH',
        'INVALID_INTENT',
      ],
    });

  } catch (e) {
    return fail(res, 500, 'AUDIT_FETCH_FAILED', `Failed to fetch audit log: ${e.message}`);
  }
};
