'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { PLANS, TIERS, getPlan, hasFeature } = require('../api/_lib/subscription-catalog');
const { FLAGS, isEnabled } = require('../api/_lib/feature-flags');
const { isValidEnterpriseAccountShape } = require('../api/_lib/enterprise-account-schema');

/* ─── subscription-catalog ───────────────────────────────────── */

test('every tier in the existing middleware TIERS vocabulary has a plan defined', () => {
  for (const tier of TIERS) {
    assert.ok(PLANS[tier], `missing plan definition for tier "${tier}"`);
    assert.strictEqual(PLANS[tier].tier, tier);
  }
});

test('getPlan returns null for an unknown tier', () => {
  assert.strictEqual(getPlan('platinum-vip'), null);
});

test('plan apiRequestsPerDay mirrors middleware.js RATE_LIMITS exactly (single source of truth)', () => {
  const { RATE_LIMITS } = require('../api/_lib/middleware');
  for (const tier of TIERS) {
    assert.strictEqual(PLANS[tier].apiRequestsPerDay, RATE_LIMITS[tier]);
  }
});

test('hasFeature is true for a feature on the plan and false otherwise', () => {
  assert.strictEqual(hasFeature('pro', 'content-graph-entity'), true);
  assert.strictEqual(hasFeature('free', 'stix-export'), false);
  assert.strictEqual(hasFeature('unknown-tier', 'anything'), false);
});

/* ─── feature-flags ──────────────────────────────────────────── */

test('isEnabled reflects the FLAGS registry', () => {
  assert.strictEqual(isEnabled('content-graph-api'), true);
  assert.strictEqual(isEnabled('semantic-search'), false);
});

test('isEnabled returns false for an unregistered flag rather than throwing', () => {
  assert.strictEqual(isEnabled('does-not-exist'), false);
});

test('FLAGS registry entries all declare a description', () => {
  for (const [key, flag] of Object.entries(FLAGS)) {
    assert.ok(flag.description, `flag "${key}" missing a description`);
  }
});

/* ─── enterprise-account-schema ──────────────────────────────── */

function validAccount(overrides = {}) {
  return {
    accountId: 'acct_123',
    companyName: 'Acme Corp',
    primaryContactEmail: 'ciso@acme.example',
    seats: 25,
    tier: 'enterprise',
    createdAt: '2026-07-17T00:00:00Z',
    ...overrides,
  };
}

test('isValidEnterpriseAccountShape accepts a well-formed record', () => {
  assert.strictEqual(isValidEnterpriseAccountShape(validAccount()), true);
});

test('isValidEnterpriseAccountShape rejects a record missing a required field', () => {
  const { tier, ...missingTier } = validAccount();
  assert.strictEqual(isValidEnterpriseAccountShape(missingTier), false);
});

test('isValidEnterpriseAccountShape rejects an invalid tier not in TIERS', () => {
  assert.strictEqual(isValidEnterpriseAccountShape(validAccount({ tier: 'platinum' })), false);
});

test('isValidEnterpriseAccountShape rejects a malformed email', () => {
  assert.strictEqual(isValidEnterpriseAccountShape(validAccount({ primaryContactEmail: 'not-an-email' })), false);
});

test('isValidEnterpriseAccountShape rejects zero/negative seats', () => {
  assert.strictEqual(isValidEnterpriseAccountShape(validAccount({ seats: 0 })), false);
});

test('isValidEnterpriseAccountShape rejects an unparseable createdAt', () => {
  assert.strictEqual(isValidEnterpriseAccountShape(validAccount({ createdAt: 'not-a-date' })), false);
});

test('isValidEnterpriseAccountShape rejects null/non-object input', () => {
  assert.strictEqual(isValidEnterpriseAccountShape(null), false);
  assert.strictEqual(isValidEnterpriseAccountShape('a string'), false);
});
