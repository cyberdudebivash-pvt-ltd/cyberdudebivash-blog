'use strict';
// Regression coverage for GECTP v1's registration welcome-email feature:
// previously no automated communication of any kind existed on account
// creation (api/_lib/resend.js only supported adding a contact to the
// newsletter audience) — a user who closed the tab before copying their
// API key had no recovery path. This tests the two new pieces added to
// close that gap: resend.js's generic sendEmail()/canSendEmail(), and
// auth.js's buildWelcomeEmail() content builder. It does not exercise the
// live call site in handleRegister() itself, which needs a real Redis
// connection; that integration path is exercised manually against the
// deployed environment, not in this unit suite.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');

test('resend.canSendEmail() is independent of RESEND_AUDIENCE_ID (unlike configured())', () => {
  const prevKey = process.env.RESEND_API_KEY;
  const prevAud = process.env.RESEND_AUDIENCE_ID;
  try {
    process.env.RESEND_API_KEY = 'test_key';
    delete process.env.RESEND_AUDIENCE_ID;
    delete require.cache[require.resolve(path.join(ROOT, 'api', '_lib', 'resend.js'))];
    const resend = require(path.join(ROOT, 'api', '_lib', 'resend.js'));
    assert.strictEqual(resend.canSendEmail(), true);
    assert.strictEqual(resend.configured(), false, 'configured() must still require an audience — unchanged');
  } finally {
    if (prevKey === undefined) delete process.env.RESEND_API_KEY; else process.env.RESEND_API_KEY = prevKey;
    if (prevAud === undefined) delete process.env.RESEND_AUDIENCE_ID; else process.env.RESEND_AUDIENCE_ID = prevAud;
    delete require.cache[require.resolve(path.join(ROOT, 'api', '_lib', 'resend.js'))];
  }
});

test('resend.canSendEmail() is false with no API key configured', () => {
  const prevKey = process.env.RESEND_API_KEY;
  try {
    delete process.env.RESEND_API_KEY;
    delete require.cache[require.resolve(path.join(ROOT, 'api', '_lib', 'resend.js'))];
    const resend = require(path.join(ROOT, 'api', '_lib', 'resend.js'));
    assert.strictEqual(resend.canSendEmail(), false);
  } finally {
    if (prevKey === undefined) delete process.env.RESEND_API_KEY; else process.env.RESEND_API_KEY = prevKey;
    delete require.cache[require.resolve(path.join(ROOT, 'api', '_lib', 'resend.js'))];
  }
});

test('resend.sendEmail() posts to /emails with the expected shape and never touches the audience endpoint', async () => {
  const prevKey = process.env.RESEND_API_KEY;
  const prevFetch = global.fetch;
  try {
    process.env.RESEND_API_KEY = 'test_key';
    delete require.cache[require.resolve(path.join(ROOT, 'api', '_lib', 'resend.js'))];
    const resend = require(path.join(ROOT, 'api', '_lib', 'resend.js'));

    let capturedUrl, capturedBody;
    global.fetch = async (url, opts) => {
      capturedUrl = url;
      capturedBody = JSON.parse(opts.body);
      return { ok: true, json: async () => ({ id: 'email_123' }) };
    };

    await resend.sendEmail({ to: 'analyst@example.com', subject: 'Subject', html: '<p>hi</p>', text: 'hi' });

    assert.strictEqual(capturedUrl, 'https://api.resend.com/emails');
    assert.ok(!capturedUrl.includes('/audiences/'), 'sendEmail must not hit the audience/contacts endpoint');
    assert.strictEqual(capturedBody.to, 'analyst@example.com');
    assert.strictEqual(capturedBody.subject, 'Subject');
    assert.ok(capturedBody.from.includes('cyberdudebivash.com'), 'from address must use the configured sending domain');
  } finally {
    if (prevKey === undefined) delete process.env.RESEND_API_KEY; else process.env.RESEND_API_KEY = prevKey;
    global.fetch = prevFetch;
    delete require.cache[require.resolve(path.join(ROOT, 'api', '_lib', 'resend.js'))];
  }
});

const { buildWelcomeEmail } = require(path.join(ROOT, 'api', 'v1', 'auth.js'));

test('buildWelcomeEmail() includes the API key in both html and text bodies', () => {
  const email = buildWelcomeEmail({
    name: 'Jordan', apiKey: 'sk_live_abc123', tier: 'free', rateLimit: 100,
    dashboardUrl: 'https://blog.cyberdudebivash.in/api-dashboard.html',
    docsUrl: 'https://blog.cyberdudebivash.in/api.html',
    upgradeUrl: 'https://blog.cyberdudebivash.in/pricing.html',
  });
  assert.ok(email.text.includes('sk_live_abc123'));
  assert.ok(email.html.includes('sk_live_abc123'));
  assert.ok(email.subject.length > 0);
});

test('buildWelcomeEmail() greets by name when provided, falls back generically otherwise', () => {
  const named = buildWelcomeEmail({
    name: 'Jordan', apiKey: 'k', tier: 'free', rateLimit: 100,
    dashboardUrl: 'd', docsUrl: 'x', upgradeUrl: 'u',
  });
  assert.ok(named.text.startsWith('Hi Jordan,'));

  const anon = buildWelcomeEmail({
    name: '', apiKey: 'k', tier: 'free', rateLimit: 100,
    dashboardUrl: 'd', docsUrl: 'x', upgradeUrl: 'u',
  });
  assert.ok(anon.text.startsWith('Hi,'));
});

test('buildWelcomeEmail() includes all three URLs and the tier/rate limit', () => {
  const email = buildWelcomeEmail({
    name: '', apiKey: 'k', tier: 'pro', rateLimit: 25000,
    dashboardUrl: 'https://example.com/dash',
    docsUrl: 'https://example.com/docs',
    upgradeUrl: 'https://example.com/upgrade',
  });
  for (const url of ['https://example.com/dash', 'https://example.com/docs', 'https://example.com/upgrade']) {
    assert.ok(email.html.includes(url), `expected ${url} in html body`);
  }
  assert.ok(email.text.includes('PRO'));
  assert.ok(email.text.includes('25000'));
});
