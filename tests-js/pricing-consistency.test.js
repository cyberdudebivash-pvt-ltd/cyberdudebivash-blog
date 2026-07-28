'use strict';
// Regression test for the SOC Pro pricing-integrity incident: pricing.html and
// payment-flow.js displayed ₹1,499/$18 while the backend (api/_lib/payment-
// utils.js) charged ₹4,099 — four independent hardcoded copies of the same
// price had drifted apart. The checkout UI now fetches its price from the
// canonical GET /api/v1/billing?action=plans endpoint at runtime (see
// docs/PRICING.md), which structurally prevents that specific drift. This
// test guards the remaining hardcoded copies: the client-side fallback
// constants (only used if that fetch fails) and the wider marketing surface
// that still hardcodes prices in prose/UI strings.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const { PLANS } = require(path.join(ROOT, 'api', '_lib', 'payment-utils.js'));

/* ─── The backend is the canonical source — pin its expected values ──── */

test('canonical PLANS.pro matches the known-correct price (₹1,499/mo)', () => {
  assert.strictEqual(PLANS.pro.amount, 1499);
  assert.strictEqual(PLANS.pro.currency, 'INR');
  assert.ok(PLANS.pro.upiNote.includes('₹1,499'), 'upiNote must quote the same amount it charges');
});

test('canonical PLANS.starter and PLANS.enterprise are unchanged from their known-correct values', () => {
  assert.strictEqual(PLANS.starter.amount, 2499);
  assert.strictEqual(PLANS.enterprise.amount, 4999);
});

/* ─── Client-side fallback constants must agree with the backend ─────── */
/* These only render if GET action=plans fails, but a wrong fallback is a
   silent reintroduction of the exact bug this test exists to catch. */

function readFile(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

test('payment-flow.js fallback PLANS.pro matches the backend amount', () => {
  const src = readFile('payment-flow.js');
  const m = src.match(/pro:\s*\{[^}]*amount:\s*(\d+)/);
  assert.ok(m, 'could not find fallback pro.amount in payment-flow.js');
  assert.strictEqual(Number(m[1]), PLANS.pro.amount);
});

test('pricing.html fallback PLANS.pro matches the backend amount', () => {
  const src = readFile('pricing.html');
  const m = src.match(/pro:\s*\{[^}]*amount:\s*(\d+)/);
  assert.ok(m, 'could not find fallback pro.amount in pricing.html');
  assert.strictEqual(Number(m[1]), PLANS.pro.amount);
});

/* ─── No stale price should remain in the wider marketing surface ────── */
/* The 2026-07-17 incident: SOC Pro was reduced from $49/₹4,099 to $18/
   ₹1,499, and the rollout missed the backend plus several marketing files.
   These files are known to reference the SOC Pro price by exact string —
   assert the current price is present and the stale one is gone. A file
   legitimately mentioning $49 for something else (one-time products are
   priced independently) would only false-positive here if it also happens
   to pair that "$49" with the literal substring "SOC Pro" — acceptable
   specificity for a regression guard, not a general-purpose price linter. */
const MARKETING_FILES_MUST_NOT_SAY_STALE_PRICE = [
  'ai-monetization-engine.js', 'ux-controller.js', 'revenue-cta-block.js',
  'conversion-engine.js', 'auto-intel-engine.js', 'seo-engine.js', 'api.html',
];

for (const file of MARKETING_FILES_MUST_NOT_SAY_STALE_PRICE) {
  test(`${file} does not pair "SOC Pro" with the stale $49 price`, () => {
    const src = readFile(file);
    // Match "$49" within ~40 chars of "SOC Pro" in either order.
    const stale = /SOC Pro[\s\S]{0,40}\$49|\$49[\s\S]{0,40}SOC Pro/i;
    assert.ok(!stale.test(src), `${file} still pairs "SOC Pro" with $49 somewhere`);
  });
}

/* ─── bare "Enterprise" tier-name collision guard ─────────────────────── */
/* Found and fixed directly (not caught by any existing test before this):
   three separate pages each named a "Custom"-priced, sales-assisted
   Enterprise plan just "Enterprise" — colliding with pricing.html's
   canonical $60/mo self-serve Enterprise API tier. All three use different
   markup (enterprise.html: <div class="tier-name">, api.html:
   <div class="plan-tier">, index.html: <div class="pt-name">), which is why
   no single existing check caught all of them. Renamed to "Enterprise
   Managed" (two different products, not a price conflict — confirmed with
   the business owner). */

const BARE_ENTERPRISE_TIER_NAME_LOCATIONS = [
  { file: 'enterprise.html', divClass: 'tier-name' },
  { file: 'api.html', divClass: 'plan-tier' },
  { file: 'index.html', divClass: 'pt-name' },
];

for (const { file, divClass } of BARE_ENTERPRISE_TIER_NAME_LOCATIONS) {
  test(`${file} has no tier named exactly "Enterprise" (would collide with pricing.html's $60/mo Enterprise tier)`, () => {
    const src = readFile(file);
    const re = new RegExp(`<div class="${divClass}"[^>]*>([^<]+)</div>`, 'g');
    const tierNames = [...src.matchAll(re)].map(m => m[1].trim());
    assert.ok(tierNames.length > 0, `expected at least one <div class="${divClass}"> in ${file}`);
    assert.ok(
      !tierNames.includes('Enterprise'),
      `${file} has a bare "Enterprise" tier name (found: ${JSON.stringify(tierNames)}) — ` +
      'this collides with pricing.html\'s $60/mo Enterprise tier; use a disambiguated name ' +
      '(e.g. "Enterprise Managed") if this is a different product, or match the canonical price if not.'
    );
  });
}

/* ─── api.html's SOC Professional card: a second, undetected copy of the ─
   same $49 incident ────────────────────────────────────────────────────── */
/* The 2026-07-17 remediation (docs/PRICING.md) explicitly lists api.html's
   Schema.org structured data as fixed, but its separate, human-visible
   pricing card further down the page was never touched: it showed $49/mo
   (undetected because the stale-price regex above requires "$49" within 40
   chars of "SOC Pro", but this card renders the price as split markup,
   `<sup>$</sup>49`, breaking the literal "$49" substring match entirely),
   a fabricated "$470/yr (save 20%)" annual option that no backend code
   supports at any price, and a 5,000/day limit belonging to the Starter
   tier, not the 25,000/day SOC Professional actually gets. */

test('api.html\'s SOC Professional card shows the canonical $18/mo price, not the stale $49', () => {
  const src = readFile('api.html');
  const m = src.match(/SOC Professional<\/div>\s*<div class="plan-price"><sup>\$<\/sup>(\d+)<\/div>/);
  assert.ok(m, 'could not find the SOC Professional price card in api.html');
  // $18 is docs/PRICING.md's documented USD equivalent of the canonical
  // PLANS.pro.amount (₹1,499), independently pinned by the test above.
  assert.strictEqual(Number(m[1]), 18, 'expected the canonical $18/mo display price');
});

test('api.html does not advertise annual billing (no backend support exists for it anywhere in api/)', () => {
  const src = readFile('api.html');
  assert.ok(!/\$470\/yr|save 20%/i.test(src), 'api.html still advertises an unimplemented annual-billing discount');
});

test('api.html\'s SOC Professional card shows the canonical 25,000/day limit, not Starter\'s 5,000/day', () => {
  const src = readFile('api.html');
  const section = src.slice(src.indexOf('SOC Professional'), src.indexOf('SOC Professional') + 600);
  assert.ok(section.includes('25,000 / day'), 'expected 25,000 / day in the SOC Professional plan-limits block');
});
