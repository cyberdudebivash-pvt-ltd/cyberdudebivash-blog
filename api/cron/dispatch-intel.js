/**
 * SENTINEL APEX — External Cron Dispatcher
 * GitHub's own `schedule:` trigger throttles high-frequency cron expressions
 * (observed: 5-30 minute schedules firing every ~4h in practice). Vercel
 * Cron calls this endpoint on a reliable external timer; it forwards a
 * workflow_dispatch to GitHub Actions so the affected workflows actually
 * run at their intended cadence.
 *
 * Routing: /api/cron/dispatch-intel?workflow={workflow_file}
 * Auth:    Authorization: Bearer <CRON_SECRET>  (Vercel attaches this
 *          automatically on cron-triggered requests when CRON_SECRET is
 *          set as a project env var)
 *
 * Required env vars:
 *   CRON_SECRET          — shared secret Vercel signs cron requests with
 *   GITHUB_DISPATCH_TOKEN — fine-grained PAT scoped to Actions:write on this repo only
 */
'use strict';
const crypto = require('crypto');
const sec = require('../_lib/security');
const mw  = require('../_lib/middleware');

const GITHUB_OWNER = process.env.GITHUB_REPO_OWNER || 'cyberdudebivash';
const GITHUB_REPO  = process.env.GITHUB_REPO_NAME  || 'cyberdudebivash-blog';

// Strict allowlist — the workflow id must never be taken from anywhere but this list.
const ALLOWED_WORKFLOWS = new Set([
  'blogger-syndication.yml',
  'sentinel-apex.yml',
  'freshness-check.yml',
]);

// Minimum minutes between forwarded dispatches per workflow — must track
// each workflow file's own `schedule:` cron. This is the guard that was
// missing when the external caller (Vercel Cron / whatever scheduler is
// configured outside this repo) fired blogger-syndication.yml every ~5 min
// instead of its intended 2h cadence, causing the July 2026 outage. If the
// caller's schedule drifts again, this endpoint now throttles it back to
// the intended rate instead of forwarding every call to GitHub.
const MIN_INTERVAL_MINUTES = {
  'sentinel-apex.yml': 30,        // matches sentinel-apex.yml: "0,30 * * * *"
  'blogger-syndication.yml': 120, // matches blogger-syndication.yml: "15 */2 * * *"
  'freshness-check.yml': 30,      // matches freshness-check.yml: "*/30 * * * *"
};

/** Timing-safe comparison against CRON_SECRET. Fails closed if unconfigured. */
function verifyCronSecret(req) {
  const expected = process.env.CRON_SECRET;
  if (!expected || expected.length < 16) return false;
  const auth = String(req.headers['authorization'] || '');
  if (!auth.startsWith('Bearer ')) return false;
  const provided = auth.slice(7).trim();
  const a = expected.padEnd(128).slice(0, 128);
  const b = provided.padEnd(128).slice(0, 128);
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
      && provided === expected;
  } catch (_) {
    return false;
  }
}

module.exports = async (req, res) => {
  const okGuard = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'] });
  if (!okGuard) return;

  if (!(await sec.globalIpRateLimit(req, res))) return;

  if (!verifyCronSecret(req)) {
    mw.apiError(res, 401, 'UNAUTHORIZED', 'Valid cron secret required');
    return;
  }

  const workflow = String(req.query?.workflow || '').trim();
  if (!ALLOWED_WORKFLOWS.has(workflow)) {
    mw.apiError(res, 400, 'INVALID_WORKFLOW',
      `workflow must be one of: ${[...ALLOWED_WORKFLOWS].join(', ')}`);
    return;
  }

  const allowed = await sec.workflowDispatchThrottle(workflow, MIN_INTERVAL_MINUTES[workflow]);
  if (!allowed) {
    mw.successResponse(res, { throttled: true, workflow, min_interval_minutes: MIN_INTERVAL_MINUTES[workflow] });
    return;
  }

  const token = process.env.GITHUB_DISPATCH_TOKEN;
  if (!token) {
    mw.apiError(res, 503, 'NOT_CONFIGURED', 'GITHUB_DISPATCH_TOKEN is not configured');
    return;
  }

  try {
    const ghRes = await fetch(
      `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${workflow}/dispatches`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'Content-Type': 'application/json',
          'User-Agent': 'cyberdudebivash-cron-dispatcher',
        },
        body: JSON.stringify({ ref: 'main' }),
      }
    );

    if (ghRes.status === 204) {
      mw.successResponse(res, { dispatched: workflow });
      return;
    }

    // GitHub error bodies may include internal detail — log server-side only, never echo to caller.
    const detail = await ghRes.text().catch(() => '');
    console.error('GitHub dispatch failed', { workflow, status: ghRes.status, detail: detail.slice(0, 300) });
    mw.apiError(res, 502, 'DISPATCH_FAILED', `GitHub dispatch returned HTTP ${ghRes.status}`);
  } catch (e) {
    mw.apiError(res, 502, 'DISPATCH_FAILED', sec.safeError(e, 'Failed to reach GitHub Actions API'));
  }
};
