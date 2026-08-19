'use strict';
// Regression tests for validateRenderedPost() (fetch-live-intel.js) --
// P0-REPORTX-2026-08-19. This is the Node pipeline's analog of
// automation/report_integrity.py::validate_publication(): a fail-closed
// pass over the ASSEMBLED HTML, run once per item immediately before
// safeWriteSync(), independent of qualityGate()'s pre-generation field
// checks. Mirrors cve-correlation.test.js's require pattern.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const { validateRenderedPost } = require(path.join(ROOT, 'fetch-live-intel.js'));

const MIN_LEN = 8000;

function padded(body) {
  // Real posts run 38-51KB; pad well past the 8000-char floor so only the
  // condition under test can fail a case, not incidental shortness.
  return body + '<!-- padding -->'.repeat(Math.ceil((MIN_LEN + 500) / 16));
}

function baseItem(overrides = {}) {
  return { id: 'CVE-2026-TEST', cisaKev: false, exploited: false, ...overrides };
}

test('a clean, sufficiently long report with no forbidden content passes', () => {
  const html = padded('<p>Available sources do not confirm in-the-wild exploitation.</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, true);
  assert.deepStrictEqual(result.reasons, []);
});

test('rejects HTML shorter than the minimum length floor', () => {
  const html = '<p>Too short.</p>';
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
  assert.ok(result.reasons.some(r => r.includes('below the')), result.reasons.join('; '));
});

test('rejects a literal "undefined" template artifact', () => {
  const html = padded('<p>Affected vendor: undefined</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
  assert.ok(result.reasons.some(r => r.includes('undefined')), result.reasons.join('; '));
});

test('rejects a literal "NaN" template artifact', () => {
  const html = padded('<p>CVSS score: NaN</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
  assert.ok(result.reasons.some(r => r.includes('NaN')), result.reasons.join('; '));
});

test('rejects a literal "[object Object]" template artifact', () => {
  const html = padded('<p>Source: [object Object]</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
  assert.ok(result.reasons.some(r => r.includes('object Object')), result.reasons.join('; '));
});

test('rejects lorem ipsum placeholder content', () => {
  const html = padded('<p>Lorem ipsum dolor sit amet.</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
});

test('rejects the placeholder UUID', () => {
  const html = padded('<p>Reference: 00000000-0000-0000-0000-000000000000</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
});

test('rejects a false human-review claim', () => {
  const html = padded('<p>This report was human reviewed before publication.</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
  assert.ok(result.reasons.some(r => r.includes('human-review')), result.reasons.join('; '));
});

test('rejects a confirmed-exploitation claim when neither cisaKev nor exploited is true', () => {
  const html = padded('<p>CISA has confirmed active exploitation in the wild (listed in the Known Exploited Vulnerabilities catalog).</p>');
  const result = validateRenderedPost(baseItem({ cisaKev: false, exploited: false }), html);
  assert.strictEqual(result.pass, false);
  assert.ok(result.reasons.some(r => r.includes('confirmed-exploitation')), result.reasons.join('; '));
});

test('allows a confirmed-exploitation claim when cisaKev is true', () => {
  const html = padded('<p>CISA has confirmed active exploitation in the wild (listed in the Known Exploited Vulnerabilities catalog).</p>');
  const result = validateRenderedPost(baseItem({ cisaKev: true }), html);
  assert.strictEqual(result.pass, true);
});

test('allows a confirmed-exploitation claim when exploited is true (cisaKev false)', () => {
  const html = padded('<p>Active exploitation has been reported in the wild — prioritize accordingly.</p>');
  const result = validateRenderedPost(baseItem({ cisaKev: false, exploited: true }), html);
  assert.strictEqual(result.pass, true);
});

test('does not false-positive on "TBD" as a legitimate honest-unknown stat value', () => {
  // Regression: real generatePostHTML() output renders "TBD" as the
  // "Exploited ITW" stat-tile value when exploitation status is honestly
  // unknown -- found live 2026-08-19 running this validator against a
  // real synthetic item before the pattern was narrowed.
  const html = padded('<div class="stat"><div class="sv">TBD</div><div class="sl">Exploited ITW</div></div>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, true, result.reasons.join('; '));
});

test('does not false-positive on "undefined behavior" as legitimate CVE terminology', () => {
  // Regression: found live 2026-08-19 in the real corpus
  // (cve-2026-42327-rust-openssl.html) -- "undefined behavior" is
  // standard memory-safety vulnerability language, not a template leak.
  const html = padded('<p>rust-openssl has undefined behavior in X509Ref::ocsp_responders for certain certificates.</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, true, result.reasons.join('; '));
});

test('still rejects a bare "undefined" that is not part of "undefined behavior"', () => {
  const html = padded('<p>Affected vendor: undefined</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
});

test('does not false-positive on "Lorem Ipsum" as a real named malware family', () => {
  // Regression: found live 2026-08-19 in the real corpus
  // (lorem-ipsum-malware-pivots-to-clickfix-delivery.html) -- a real
  // published report about an actual malware family named "Lorem Ipsum".
  const html = padded("<h1>'Lorem Ipsum' Malware Pivots to ClickFix Delivery</h1><p>The Lorem Ipsum loader has been observed dropping a new payload.</p>");
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, true, result.reasons.join('; '));
});

test('still rejects the actual classic lorem-ipsum filler passage', () => {
  const html = padded('<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
});

test('reports multiple independent reasons together rather than stopping at the first', () => {
  const html = padded('<p>undefined and NaN and lorem ipsum dolor sit amet</p>');
  const result = validateRenderedPost(baseItem(), html);
  assert.strictEqual(result.pass, false);
  assert.ok(result.reasons.length >= 3, `expected >=3 reasons, got: ${result.reasons.join('; ')}`);
});
