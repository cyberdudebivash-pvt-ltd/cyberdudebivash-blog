'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { resolveRoute, DIRECT_API_HANDLERS, DYNAMIC_API_HANDLERS } = require('./route-table');

describe('resolveRoute — blocked paths', () => {
  for (const p of ['/CLAUDE.md', '/OPERATIONS.md', '/AUDIT-REPORT-2026-05-28.md', '/BUSINESS-TRANSFORMATION-ROADMAP-2026.md']) {
    test(`blocks exact path ${p}`, () => {
      assert.deepEqual(resolveRoute(p), { type: 'blocked' });
    });
  }

  for (const p of ['/Sentinel-APEX/README.md', '/eito/anything', '/platform/open-issues.md', '/prompts/x.txt']) {
    test(`blocks prefix-matched path ${p}`, () => {
      assert.deepEqual(resolveRoute(p), { type: 'blocked' });
    });
  }

  test('does not block a path that merely starts similarly', () => {
    // /platform-review.html must NOT be blocked by the /platform/ prefix rule
    assert.notDeepEqual(resolveRoute('/platform-review.html'), { type: 'blocked' });
  });
});

describe('resolveRoute — redirect', () => {
  test('/rss redirects permanently to /rss.xml', () => {
    assert.deepEqual(resolveRoute('/rss'), { type: 'redirect', to: '/rss.xml', status: 308 });
  });
});

describe('resolveRoute — feed asset aliases', () => {
  for (const p of ['/feed', '/feed.xml', '/atom.xml']) {
    test(`${p} resolves to the /rss.xml asset`, () => {
      assert.deepEqual(resolveRoute(p), { type: 'asset', path: '/rss.xml' });
    });
  }
});

describe('resolveRoute — root index alias', () => {
  test('/ resolves to the /index.html asset (compensates for html_handling: "none" disabling Cloudflare\'s automatic root resolution — see wrangler.jsonc and ASSET_REWRITES\' comment)', () => {
    assert.deepEqual(resolveRoute('/'), { type: 'asset', path: '/index.html' });
  });

  test('does not rewrite a non-root path that merely starts with /', () => {
    assert.equal(resolveRoute('/about.html'), null);
  });
});

describe('resolveRoute — pretty-URL rewrites', () => {
  const cases = [
    ['/api/v1/intel/live', 'api/v1/intel', { action: 'live' }],
    ['/api/v1/intel/top-threats', 'api/v1/intel', { action: 'top' }],
    ['/api/v1/intel/cve/CVE-2026-9147', 'api/v1/intel', { action: 'cve', id: 'CVE-2026-9147' }],
    ['/api/v1/intel/iocs', 'api/v1/intel', { action: 'iocs' }],
    ['/api/v1/intel/ransomware', 'api/v1/intel', { action: 'ransomware' }],
    ['/api/v1/intel/search', 'api/v1/intel', { action: 'search' }],
    ['/api/v1/intel/graph', 'api/v1/intel', { action: 'graph' }],
    ['/api/v1/intel/campaigns', 'api/v1/intel', { action: 'campaigns' }],
    ['/api/v1/intel/campaign/campaign:abc', 'api/v1/intel', { action: 'campaign', id: 'campaign:abc' }],
    ['/api/v1/intel/top-actors', 'api/v1/intel', { action: 'top-actors' }],
    ['/api/v1/auth/register', 'api/v1/auth', { action: 'register' }],
    ['/api/v1/auth/me', 'api/v1/auth', { action: 'me' }],
    ['/api/v1/keys/usage', 'api/v1/auth', { action: 'usage' }],
    ['/api/v1/billing/create-intent', 'api/v1/billing', { action: 'create-intent' }],
    ['/api/v1/billing/submit-payment', 'api/v1/billing', { action: 'submit-payment' }],
    ['/api/v1/billing/payment-status', 'api/v1/billing', { action: 'status' }],
    ['/api/v1/billing/subscribe', 'api/v1/billing', { action: 'subscribe' }],
    ['/api/v1/billing/razorpay/order', 'api/v1/billing', { action: 'create-razorpay-order' }],
    ['/api/v1/billing/razorpay/verify', 'api/v1/billing', { action: 'verify-razorpay-payment' }],
    ['/api/v1/billing/products/checkout', 'api/v1/billing', { action: 'create-product-checkout' }],
    ['/api/v1/admin/payments/pending', 'api/v1/admin', { action: 'pending' }],
    ['/api/v1/admin/payments/approve', 'api/v1/admin', { action: 'approve' }],
    ['/api/v1/admin/payments/reject', 'api/v1/admin', { action: 'reject' }],
    ['/api/v1/admin/payments/audit', 'api/v1/admin', { action: 'audit' }],
    ['/api/v1/admin/payments/razorpay-orders', 'api/v1/admin', { action: 'razorpay-orders' }],
    ['/api/v1/admin/payments/product-orders', 'api/v1/admin', { action: 'product-orders' }],
  ];

  for (const [p, handlerPath, query] of cases) {
    test(`${p} -> ${handlerPath}?${new URLSearchParams(query)}`, () => {
      assert.deepEqual(resolveRoute(p), { type: 'handler', handlerPath, query });
    });
  }
});

describe('resolveRoute — direct api/** filesystem routes', () => {
  test('every real handler file on disk has a route (32-function parity check)', () => {
    const files = [];
    function walk(dir) {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === '_lib' || entry.name === '__tests__') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith('.js') && !entry.name.endsWith('.test.js')) files.push(full);
      }
    }
    walk(path.join(__dirname, '..', '..', 'api'));

    assert.equal(files.length, 32, 'expected exactly 32 routable api/** functions — update route-table.js if this changes');

    const INDEX_HANDLERS = new Set(['api/v1/products/index', 'api/v1/quality/index', 'api/v1/reports/index']);
    // [id]-bracket files have no single literal URL — checked with a real
    // sample id in the "dynamic [id] segments" describe block instead.
    const DYNAMIC_FILE_SUFFIX = /\[id]$/;

    for (const file of files) {
      const rel = path.relative(path.join(__dirname, '..', '..'), file).replace(/\\/g, '/').replace(/\.js$/, '');
      if (DYNAMIC_FILE_SUFFIX.test(rel)) {
        assert.ok(DYNAMIC_API_HANDLERS.some(([, handlerPath]) => handlerPath === rel), `${rel} has no entry in DYNAMIC_API_HANDLERS`);
        continue;
      }
      const urlPath = INDEX_HANDLERS.has(rel) ? `/${rel.replace(/\/index$/, '')}` : `/${rel}`;
      const route = resolveRoute(urlPath);
      assert.ok(route, `no route resolved for ${urlPath} (from ${file})`);
      assert.equal(route.type, 'handler', `${urlPath} did not resolve to a handler`);
      assert.equal(route.handlerPath, rel, `${urlPath} resolved to the wrong handler`);
    }
  });

  test('api/v1/products/index.js is reached at /api/v1/products, not /api/v1/products/index', () => {
    assert.deepEqual(resolveRoute('/api/v1/products'), { type: 'handler', handlerPath: 'api/v1/products/index', query: {} });
  });
});

describe('resolveRoute — dynamic [id] segments', () => {
  test('/api/v1/ioc/search hits the static search handler, not [id]', () => {
    assert.deepEqual(resolveRoute('/api/v1/ioc/search'), { type: 'handler', handlerPath: 'api/v1/ioc/search', query: {} });
  });

  test('/api/v1/ioc/<anything else> hits [id] with that value', () => {
    assert.deepEqual(resolveRoute('/api/v1/ioc/T1059.001'), { type: 'handler', handlerPath: 'api/v1/ioc/[id]', query: { id: 'T1059.001' } });
  });

  test('/api/v1/detections/rules (bare) hits the list handler, not [id]', () => {
    assert.deepEqual(resolveRoute('/api/v1/detections/rules'), { type: 'handler', handlerPath: 'api/v1/detections/rules', query: {} });
  });

  test('/api/v1/detections/rules/<id> hits [id] with that value', () => {
    assert.deepEqual(resolveRoute('/api/v1/detections/rules/rule-42'), { type: 'handler', handlerPath: 'api/v1/detections/rules/[id]', query: { id: 'rule-42' } });
  });
});

describe('resolveRoute — no match', () => {
  test('a plain content path defers to the static asset layer', () => {
    assert.equal(resolveRoute('/posts/some-article.html'), null);
  });

  test('an unrecognized api-shaped path also defers (404s as a missing asset, not a fabricated handler)', () => {
    assert.equal(resolveRoute('/api/v1/does-not-exist'), null);
  });
});

describe('table sanity', () => {
  test('DIRECT_API_HANDLERS and DYNAMIC_API_HANDLERS together account for all 32 handlers with no overlap', () => {
    const dynamicPaths = DYNAMIC_API_HANDLERS.map(([, handlerPath]) => handlerPath);
    const all = [...DIRECT_API_HANDLERS, ...dynamicPaths];
    assert.equal(all.length, 32);
    assert.equal(new Set(all).size, 32, 'duplicate handler path across DIRECT_API_HANDLERS/DYNAMIC_API_HANDLERS');
  });
});
