'use strict';

const {
  signPayload, verifySignature, generateWebhookSecret, isSafeWebhookUrl,
  isBlockedIpv4, isBlockedIpv6,
} = require('../webhook-signing');

describe('signPayload / verifySignature — HMAC scheme (mirrors stripe.js inbound verification)', () => {
  test('a correctly signed payload verifies', () => {
    const secret = 'test_secret';
    const ts = Math.floor(Date.now() / 1000);
    const body = JSON.stringify({ hello: 'world' });
    const header = signPayload(secret, ts, body);
    expect(header).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(verifySignature(secret, header, body)).toBe(true);
  });

  test('wrong secret fails verification', () => {
    const ts = Math.floor(Date.now() / 1000);
    const body = 'x';
    const header = signPayload('secret_a', ts, body);
    expect(verifySignature('secret_b', header, body)).toBe(false);
  });

  test('tampered body fails verification', () => {
    const secret = 's';
    const ts = Math.floor(Date.now() / 1000);
    const header = signPayload(secret, ts, 'original');
    expect(verifySignature(secret, header, 'tampered')).toBe(false);
  });

  test('an expired timestamp fails verification even with a correct signature', () => {
    const secret = 's';
    const oldTs = Math.floor(Date.now() / 1000) - 3600; // 1 hour old
    const body = 'x';
    const header = signPayload(secret, oldTs, body);
    expect(verifySignature(secret, header, body, { maxAgeSeconds: 300 })).toBe(false);
  });

  test('rejects a malformed header (missing v1, missing t, garbage)', () => {
    expect(verifySignature('s', '', 'x')).toBe(false);
    expect(verifySignature('s', 't=123', 'x')).toBe(false);
    expect(verifySignature('s', 'v1=abc', 'x')).toBe(false);
    expect(verifySignature('s', 'not,a=valid,header', 'x')).toBe(false);
    expect(verifySignature('s', 't=not-a-number,v1=abc', 'x')).toBe(false);
  });

  test('a signature with a mismatched byte length does not throw (timingSafeEqual guard)', () => {
    const secret = 's';
    const ts = Math.floor(Date.now() / 1000);
    expect(() => verifySignature(secret, `t=${ts},v1=zz`, 'x')).not.toThrow();
    expect(verifySignature(secret, `t=${ts},v1=zz`, 'x')).toBe(false);
  });
});

describe('generateWebhookSecret', () => {
  test('produces a whsec_-prefixed, sufficiently long, unique value each call', () => {
    const a = generateWebhookSecret();
    const b = generateWebhookSecret();
    expect(a).toMatch(/^whsec_[0-9a-f]{48}$/);
    expect(a).not.toEqual(b);
  });
});

describe('isBlockedIpv4 — range table', () => {
  test.each([
    ['127.0.0.1', true], ['127.255.255.255', true],
    ['10.0.0.1', true], ['10.255.255.255', true],
    ['172.16.0.1', true], ['172.31.255.255', true],
    ['192.168.0.1', true], ['192.168.255.255', true],
    ['169.254.169.254', true], // cloud metadata
    ['0.0.0.0', true],
    ['100.64.0.1', true], // CGNAT
    ['255.255.255.255', true],
    ['224.0.0.1', true], // multicast
    ['8.8.8.8', false],
    ['1.1.1.1', false],
    ['93.184.216.34', false],
    ['172.15.255.255', false], // just outside 172.16.0.0/12
    ['172.32.0.0', false], // just outside 172.16.0.0/12
  ])('%s -> blocked=%s', (ip, expected) => {
    expect(isBlockedIpv4(ip)).toBe(expected);
  });

  test('malformed IPv4-shaped strings fail closed (blocked)', () => {
    expect(isBlockedIpv4('999.999.999.999')).toBe(true);
    expect(isBlockedIpv4('1.2.3')).toBe(true);
    expect(isBlockedIpv4('not.an.ip.address')).toBe(true);
  });
});

describe('isBlockedIpv6 — range table', () => {
  test.each([
    ['::1', true],
    ['::', true],
    ['fe80::1', true], // link-local
    ['fc00::1', true], // unique-local
    ['fd12:3456:789a::1', true], // unique-local
    ['ff02::1', true], // multicast
    ['::ffff:127.0.0.1', true], // IPv4-mapped loopback
    ['::ffff:169.254.169.254', true], // IPv4-mapped cloud metadata
    ['2001:4860:4860::8888', false], // real public address (Google DNS)
    ['::ffff:8.8.8.8', false], // IPv4-mapped public address
  ])('%s -> blocked=%s', (ip, expected) => {
    expect(isBlockedIpv6(ip)).toBe(expected);
  });
});

describe('isSafeWebhookUrl — SSRF guard', () => {
  test('accepts a normal public https URL', async () => {
    const result = await isSafeWebhookUrl('https://example.com/webhook');
    expect(result).toEqual({ safe: true });
  });

  test('rejects http (non-https)', async () => {
    const result = await isSafeWebhookUrl('http://example.com/webhook');
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('HTTPS_REQUIRED');
  });

  test('rejects localhost and .local hosts', async () => {
    expect((await isSafeWebhookUrl('https://localhost/x')).reason).toBe('BLOCKED_HOST');
    expect((await isSafeWebhookUrl('https://my-service.local/x')).reason).toBe('BLOCKED_HOST');
  });

  test('rejects a private/loopback/link-local IPv4 literal directly in the URL', async () => {
    expect((await isSafeWebhookUrl('https://127.0.0.1/x')).reason).toBe('BLOCKED_IP');
    expect((await isSafeWebhookUrl('https://10.0.0.5/x')).reason).toBe('BLOCKED_IP');
    expect((await isSafeWebhookUrl('https://192.168.1.1/x')).reason).toBe('BLOCKED_IP');
  });

  test('rejects the cloud metadata address explicitly', async () => {
    expect((await isSafeWebhookUrl('https://169.254.169.254/latest/meta-data')).reason).toBe('BLOCKED_IP');
  });

  test('rejects a bracketed IPv6 loopback literal', async () => {
    const result = await isSafeWebhookUrl('https://[::1]/x');
    expect(result.safe).toBe(false);
    expect(result.reason).toBe('BLOCKED_IP'); // not DNS_LOOKUP_FAILED -- see the bracket-stripping fix
  });

  test('rejects an unparseable URL and a non-resolvable hostname', async () => {
    expect((await isSafeWebhookUrl('not a url')).reason).toBe('INVALID_URL');
    const bogus = await isSafeWebhookUrl('https://this-host-does-not-exist.invalid.example.test/x');
    expect(bogus.safe).toBe(false);
    expect(bogus.reason).toBe('DNS_LOOKUP_FAILED');
  });

  test('rejects a redirect-hiding IP literal disguised with extra whitespace/case (defense-in-depth)', async () => {
    // URL parsing itself normalizes case/whitespace before this guard ever
    // runs, but confirm the guard still blocks the normalized form.
    const result = await isSafeWebhookUrl('HTTPS://169.254.169.254/x');
    expect(result.safe).toBe(false);
  });
});
