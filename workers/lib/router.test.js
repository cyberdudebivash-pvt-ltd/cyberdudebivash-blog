'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { handleFetch, dispatch, handleScheduled, HANDLER_MODULES } = require('./router');
const { DIRECT_API_HANDLERS, DYNAMIC_API_HANDLERS } = require('./route-table');

function fakeEnv(assetsFetchImpl) {
  const calls = [];
  return {
    calls,
    env: {
      ASSETS: {
        async fetch(req) {
          calls.push(req);
          return assetsFetchImpl ? assetsFetchImpl(req) : new Response('asset-body', { status: 200 });
        },
      },
    },
  };
}

describe('router — HANDLER_MODULES parity with route-table.js', () => {
  test('every DIRECT_API_HANDLERS entry has a static require() in HANDLER_MODULES', () => {
    for (const p of DIRECT_API_HANDLERS) {
      assert.ok(p in HANDLER_MODULES, `${p} is in route-table.js's DIRECT_API_HANDLERS but missing from router.js's HANDLER_MODULES`);
    }
  });

  test('every DYNAMIC_API_HANDLERS entry has a static require() in HANDLER_MODULES', () => {
    for (const [, handlerPath] of DYNAMIC_API_HANDLERS) {
      assert.ok(handlerPath in HANDLER_MODULES, `${handlerPath} is in route-table.js's DYNAMIC_API_HANDLERS but missing from router.js's HANDLER_MODULES`);
    }
  });

  test('HANDLER_MODULES has no keys route-table.js does not know about', () => {
    const known = new Set([...DIRECT_API_HANDLERS, ...DYNAMIC_API_HANDLERS.map(([, p]) => p)]);
    for (const key of Object.keys(HANDLER_MODULES)) {
      assert.ok(known.has(key), `HANDLER_MODULES has ${key}, which route-table.js does not resolve to any route`);
    }
  });
});

describe('handleFetch — routing by type', () => {
  test('unmatched path defers to env.ASSETS.fetch with the original request', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/posts/some-article.html');
    const response = await handleFetch(request, env);
    assert.equal(calls.length, 1);
    assert.equal(calls[0], request);
    assert.equal(response.status, 200);
  });

  test('blocked path returns 404 without ever calling env.ASSETS', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/CLAUDE.md');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 404);
    assert.equal(calls.length, 0);
  });

  test('/rss redirects to /rss.xml with a 308, without calling env.ASSETS', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/rss');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 308);
    assert.equal(new URL(response.headers.get('location')).pathname, '/rss.xml');
    assert.equal(calls.length, 0);
  });

  test('/feed.xml resolves as an asset rewrite to /rss.xml, fetched via env.ASSETS', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/feed.xml');
    await handleFetch(request, env);
    assert.equal(calls.length, 1);
    assert.equal(new URL(calls[0].url).pathname, '/rss.xml');
  });
});

describe('handleFetch — real end-to-end handler dispatch', () => {
  test('GET /api/v1/intel?action=stats runs the real handler through the compat shim', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=stats');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.success, true);
    assert.ok(body.stats);
  });

  test('GET /api/v1/intel/live is rewritten to action=live and reaches the same real handler', async () => {
    const { env } = fakeEnv();
    // No API key configured in this environment -- expect the handler's
    // own real 401, not a routing failure. Proves the rewrite→dispatch
    // path reaches actual application logic, not just a 200/404 shortcut.
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel/live');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 401);
    const body = await response.json();
    assert.equal(body.error.code, 'UNAUTHORIZED');
  });

  test('dispatch() to an unknown handlerPath fails closed with 404', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/does-not-exist');
    const response = await dispatch('api/v1/does-not-exist', request, {});
    assert.equal(response.status, 404);
  });

  test('GET /api/v1/intelligence/objects/{id} (apexSubpath route) reaches the real handler, not a 404', async () => {
    // Proves the full chain end-to-end: route-table.js's APEX_SUBPATH_HANDLERS
    // prefix match -> dispatch()'s req.query merge -> the real objects.js
    // handler's resolvePathParts()/requireAnalyst. No ANALYST_KEYS configured
    // in this environment, so the real handler's own 401 (not a routing 404)
    // proves the sub-path actually reached application logic.
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intelligence/objects/intel-123');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 401);
    const body = await response.json();
    assert.equal(body.error.code, 'UNAUTHORIZED');
  });

  test('POST /api/v1/workbench/cases/{id}/notes (apexSubpath route, multi-segment) reaches the real handler', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/workbench/cases/case-1/notes', { method: 'POST' });
    const response = await handleFetch(request, env);
    assert.equal(response.status, 401);
    const body = await response.json();
    assert.equal(body.error.code, 'UNAUTHORIZED');
  });
});

describe('handleFetch — malformed/oversized body handling (real handler dispatch)', () => {
  test('malformed JSON to a real handler returns a clean 400, not an uncaught exception', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/newsletter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"email": "a@b.com", not valid json',
    });
    const response = await handleFetch(request, env);
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.error.code, 'INVALID_JSON');
    // Confirms this went through applyBaselineHeaders(), not a bare Response
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  });

  test('an oversized body to a real handler returns a clean 413, not an uncaught exception', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/newsletter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: 'a'.repeat(5 * 1024 * 1024) }),
    });
    const response = await handleFetch(request, env);
    assert.equal(response.status, 413);
    const body = await response.json();
    assert.equal(body.error.code, 'PAYLOAD_TOO_LARGE');
  });

  test('a bodyParser:false route (webhook) is unaffected by the generic body-parse error path', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/billing/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': 't=1,v1=deadbeef' },
      body: '{"not":"valid json at all',
    });
    const response = await handleFetch(request, env);
    // Reaches the handler's own signature check first (readRawBody never
    // parses JSON) rather than tripping the generic INVALID_JSON path.
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.error, 'Invalid signature');
  });
});

// Dormant Cloudflare Cron Trigger entry point (Alert Orchestration v1) --
// see handleScheduled's own doc in router.js for why it is never live
// today. Tested via the `deps` injection seam so this stays plain
// node:test-runnable without a real Redis-backed change-engine.js/
// notification-dispatch.js in the loop -- those two functions already
// have full Jest coverage (fake-redis-backed) under api/_lib/__tests__/.
describe('handleScheduled — dormant Cloudflare Cron entry point', () => {
  test('calls evaluateWatchedEntities then processDueDeliveries and returns a summary', async () => {
    const calls = [];
    const deps = {
      changeEngine: { evaluateWatchedEntities: async () => { calls.push('evaluate'); return { evaluated: 3 }; } },
      notificationDispatch: { processDueDeliveries: async () => { calls.push('deliver'); return { delivered: 2 }; } },
    };
    const summary = await handleScheduled({ cron: '*/30 * * * *' }, {}, {}, deps);
    assert.deepEqual(calls, ['evaluate', 'deliver']);
    assert.equal(summary.trigger, 'cloudflare_cron');
    assert.equal(summary.cron, '*/30 * * * *');
    assert.deepEqual(summary.evaluation, { evaluated: 3 });
    assert.deepEqual(summary.delivery, { delivered: 2 });
    assert.ok(typeof summary.elapsed_ms === 'number');
  });

  test('propagates a failure from either step rather than swallowing it', async () => {
    const deps = {
      changeEngine: { evaluateWatchedEntities: async () => { throw new Error('redis unavailable'); } },
      notificationDispatch: { processDueDeliveries: async () => ({ delivered: 0 }) },
    };
    await assert.rejects(() => handleScheduled({}, {}, {}, deps), /redis unavailable/);
  });
});
