'use strict';

// stripe.js reads STRIPE_WEBHOOK_SECRET into a module-level const at
// require() time (not per-call), so it must be set before the first
// require below. Jest gives each test file its own module registry, so
// this doesn't leak into other test files.
process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_secret_for_unit_tests_only';

const crypto = require('crypto');
const { verifyWebhook } = require('../stripe');

const SECRET = process.env.STRIPE_WEBHOOK_SECRET;

function sign(rawBody, timestamp = Math.floor(Date.now() / 1000)) {
  const payload = `${timestamp}.${rawBody}`;
  const v1 = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return `t=${timestamp},v1=${v1}`;
}

describe('stripe.js verifyWebhook', () => {
  test('accepts a correctly-signed payload', () => {
    const body = JSON.stringify({ type: 'checkout.session.completed' });
    expect(verifyWebhook(body, sign(body))).toBe(true);
  });

  test('rejects a signature computed for a different body (tamper-evidence)', () => {
    const original = JSON.stringify({ amount: 100 });
    const tampered = JSON.stringify({ amount: 999999 });
    expect(verifyWebhook(tampered, sign(original))).toBe(false);
  });

  test('rejects a well-formed but wrong-value signature (same length, wrong content)', () => {
    const body = JSON.stringify({ type: 'x' });
    const wrongSig = `t=${Math.floor(Date.now() / 1000)},v1=${'0'.repeat(64)}`;
    expect(verifyWebhook(body, wrongSig)).toBe(false);
  });

  // The actual regression case: crypto.timingSafeEqual throws (rather than
  // returning false) when the two buffers differ in byte length, and `sig`
  // is attacker-controlled from the request header. Before this fix,
  // verifyWebhook let that TypeError escape uncaught -- reachable by any
  // anonymous request with a short v1= value, no valid secret required.
  test('a short/malformed-length signature returns false instead of throwing', () => {
    const body = JSON.stringify({ type: 'x' });
    const shortSig = `t=${Math.floor(Date.now() / 1000)},v1=deadbeef`; // 4 bytes, not 32
    expect(() => verifyWebhook(body, shortSig)).not.toThrow();
    expect(verifyWebhook(body, shortSig)).toBe(false);
  });

  test('a v1 value with odd-length/invalid hex returns false instead of throwing', () => {
    const body = JSON.stringify({ type: 'x' });
    const oddSig = `t=${Math.floor(Date.now() / 1000)},v1=abc`;
    expect(() => verifyWebhook(body, oddSig)).not.toThrow();
    expect(verifyWebhook(body, oddSig)).toBe(false);
  });

  test('rejects a signature missing the v1 component', () => {
    const body = JSON.stringify({ type: 'x' });
    expect(verifyWebhook(body, `t=${Math.floor(Date.now() / 1000)}`)).toBe(false);
  });

  test('rejects a signature missing the t component', () => {
    const body = JSON.stringify({ type: 'x' });
    const v1 = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    expect(verifyWebhook(body, `v1=${v1}`)).toBe(false);
  });
});
