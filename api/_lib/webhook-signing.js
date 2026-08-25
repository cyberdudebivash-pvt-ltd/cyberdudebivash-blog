/**
 * SENTINEL APEX — Outbound Webhook Signing & SSRF Guard
 *
 * Two independent, pure-crypto/pure-validation concerns, deliberately
 * separated from notification-dispatch.js's I/O and retry orchestration
 * so both can be unit-tested without a network or Redis.
 *
 * Signature scheme: HMAC-SHA256 over `${timestamp}.${rawBody}`, header
 * format `t=<unix-seconds>,v1=<hex>`. This is not a new invention — it
 * mirrors api/_lib/stripe.js's own inbound-webhook verification pattern
 * exactly (same timestamp-prefixed HMAC construction, same
 * crypto.timingSafeEqual comparison discipline), just run in the
 * opposite direction: stripe.js verifies signatures Stripe sent us; this
 * module produces the equivalent for webhooks *we* send customers. Using
 * the same widely-recognized scheme customers already know from Stripe/
 * GitHub is a deliberate choice, not an oversight — zero new protocol for
 * integrators to learn.
 *
 * SSRF guard (isSafeWebhookUrl): a customer-registered webhook URL is
 * fetched by our own server on every delivery — the classic SSRF vector
 * (a URL pointing at localhost, a private RFC1918 range, or a cloud
 * metadata endpoint like 169.254.169.254 could pivot an outbound request
 * into an internal one). Checked at BOTH preference-save time and again
 * immediately before every delivery attempt (notification-dispatch.js) —
 * never trust a URL just because it passed validation once, since DNS
 * records can change between save and delivery (see Known Limitations in
 * the certification doc for the disclosed residual DNS-rebinding window
 * this two-time-check narrows but cannot fully close without a
 * connect-time IP-pinning HTTP client, which this repo's zero-npm-
 * dependency convention — see resend.js/redis.js's own module docstrings
 * — does not build here).
 */
'use strict';

const crypto = require('crypto');
const dns = require('dns');
const { URL } = require('url');

const SIGNATURE_VERSION = 'v1';
// Reject a signed request whose timestamp is older than this when
// *verifying* (not used for our own outbound sends, but exported for any
// future inbound-relay use and for symmetry with stripe.js's own window).
const MAX_SIGNATURE_AGE_SECONDS = 300;

function signPayload(secret, timestampSeconds, rawBody) {
  const payload = `${timestampSeconds}.${rawBody}`;
  const digest = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `t=${timestampSeconds},${SIGNATURE_VERSION}=${digest}`;
}

// Mirrors stripe.js's verification structure (parse t=/v1= pairs, recompute,
// timingSafeEqual) -- provided for completeness/testability of the scheme
// (e.g. a future "replay this delivery" debug tool) even though v1's own
// delivery path only ever signs, never verifies its own output.
function verifySignature(secret, header, rawBody, { maxAgeSeconds = MAX_SIGNATURE_AGE_SECONDS } = {}) {
  if (!header || typeof header !== 'string') return false;
  const parts = {};
  for (const kv of header.split(',')) {
    const idx = kv.indexOf('=');
    if (idx === -1) continue;
    parts[kv.slice(0, idx).trim()] = kv.slice(idx + 1).trim();
  }
  const timestamp = parts.t;
  const sig = parts[SIGNATURE_VERSION];
  if (!timestamp || !sig) return false;
  if (!/^\d+$/.test(timestamp)) return false;
  if (maxAgeSeconds && Math.abs(Date.now() / 1000 - Number(timestamp)) > maxAgeSeconds) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
  } catch (_) {
    return false;
  }
}

function generateWebhookSecret() {
  return 'whsec_' + crypto.randomBytes(24).toString('hex');
}

/* ───────────────────────── SSRF guard ───────────────────────── */

// Accepts a dotted-quad string (e.g. '10.0.0.0') -- both call sites below
// (a real address being checked, and a range table base) are strings.
function ipv4ToInt(ip) {
  return ip.split('.').map(Number).reduce((acc, o) => (acc << 8) + o, 0) >>> 0;
}

function inIpv4Range(intIp, baseStr, maskBits) {
  const maskInt = maskBits === 0 ? 0 : (0xffffffff << (32 - maskBits)) >>> 0;
  return (intIp & maskInt) === (ipv4ToInt(baseStr) & maskInt);
}

// RFC1918 + loopback + link-local (incl. the AWS/GCP/Azure/OCI metadata
// address 169.254.169.254) + CGNAT + documentation/reserved/multicast
// ranges. Deliberately over-inclusive -- a false positive here just means
// a legitimate customer needs a public endpoint (the overwhelmingly
// common case for a real webhook receiver), while a false negative is an
// actual SSRF hole.
const BLOCKED_IPV4_RANGES = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4], ['255.255.255.255', 32],
];

function isBlockedIpv4(ip) {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return true; // malformed -> fail closed
  const intIp = ipv4ToInt(ip);
  return BLOCKED_IPV4_RANGES.some(([base, bits]) => inIpv4Range(intIp, base, bits));
}

// IPv6: loopback, unspecified, unique-local (fc00::/7), link-local
// (fe80::/10), multicast (ff00::/8), and IPv4-mapped (::ffff:a.b.c.d,
// unwrapped and re-checked against the IPv4 ranges above).
function isBlockedIpv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIpv4(mapped[1]);
  // Expand to first hextet for prefix checks (good enough for the
  // well-known blocked prefixes below; a full 128-bit range library is
  // not needed for fc00::/7, fe80::/10, ff00::/8, whose prefixes are
  // fully determined by the first hextet's high bits).
  const first = lower.split(':')[0].padStart(4, '0');
  const firstInt = parseInt(first, 16);
  if (Number.isNaN(firstInt)) return true; // malformed -> fail closed
  if ((firstInt & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((firstInt & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((firstInt & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  return false;
}

function isBlockedIp(ip) {
  const net = require('net');
  if (net.isIPv4(ip)) return isBlockedIpv4(ip);
  if (net.isIPv6(ip)) return isBlockedIpv6(ip);
  return true; // not a recognizable IP literal -> fail closed
}

// Async: performs a real DNS lookup so a hostname resolving to a private
// address is caught, not just an IP literal typed directly into the URL.
// Fails closed on any lookup error (unresolvable host is not deliverable
// anyway, and "can't verify it's safe" must not mean "assume it's safe").
async function isSafeWebhookUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_) {
    return { safe: false, reason: 'INVALID_URL' };
  }
  if (parsed.protocol !== 'https:') return { safe: false, reason: 'HTTPS_REQUIRED' };
  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    return { safe: false, reason: 'BLOCKED_HOST' };
  }
  const net = require('net');
  // WHATWG URL wraps an IPv6 host literal in brackets (parsed.hostname for
  // "https://[::1]/x" is the 6-character string "[::1]") -- net.isIP()
  // expects the bare address, so an unstripped literal would silently
  // miss this branch and fall through to the DNS-lookup path below (which
  // still fails closed since "[::1]" isn't a resolvable hostname, but for
  // the wrong reason, and would incorrectly reject a legitimate public
  // IPv6 endpoint that ISN'T in a blocked range).
  const bareHost = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (net.isIP(bareHost)) {
    return isBlockedIp(bareHost) ? { safe: false, reason: 'BLOCKED_IP' } : { safe: true };
  }
  let addresses;
  try {
    addresses = await dns.promises.lookup(hostname, { all: true, verbatim: true });
  } catch (_) {
    return { safe: false, reason: 'DNS_LOOKUP_FAILED' };
  }
  if (!addresses.length) return { safe: false, reason: 'DNS_LOOKUP_FAILED' };
  if (addresses.some(a => isBlockedIp(a.address))) return { safe: false, reason: 'BLOCKED_IP' };
  return { safe: true };
}

module.exports = {
  SIGNATURE_VERSION,
  MAX_SIGNATURE_AGE_SECONDS,
  signPayload,
  verifySignature,
  generateWebhookSecret,
  isSafeWebhookUrl,
  // exported for direct unit testing of the range tables
  isBlockedIpv4,
  isBlockedIpv6,
};
