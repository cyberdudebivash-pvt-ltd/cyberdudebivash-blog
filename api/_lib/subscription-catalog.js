/**
 * SENTINEL APEX — Subscription Plan Catalog (architecture only)
 *
 * Recurring subscription plan *definitions* — distinct from the one-time
 * digital PRODUCTS catalog (products-catalog.js). Reuses the existing
 * tier vocabulary already enforced by middleware.js's authenticate()
 * (TIERS/RATE_LIMITS) rather than introducing a second source of truth
 * for what a tier is — this is a display/metadata layer over it.
 *
 * Per Phase 4 scoping: architecture and data only. Nothing here enforces
 * entitlements at request time — that still happens exactly as it does
 * today, via middleware.js's RATE_LIMITS lookup. hasFeature() below is a
 * pure helper, not wired into any live route yet.
 */
'use strict';
const { TIERS, RATE_LIMITS } = require('./middleware');

const PLANS = {
  free: {
    tier: 'free',
    name: 'Free',
    priceUsdMonthly: 0,
    apiRequestsPerDay: RATE_LIMITS.free,
    features: ['live-intel-api-read', 'cve-lookup', 'stats-endpoint'],
  },
  starter: {
    tier: 'starter',
    name: 'Starter API',
    priceUsdMonthly: null, // not yet publicly priced
    apiRequestsPerDay: RATE_LIMITS.starter,
    features: ['live-intel-api-read', 'cve-lookup', 'search', 'campaigns-limited'],
  },
  pro: {
    tier: 'pro',
    name: 'SOC Pro',
    // Canonical price per OPERATIONS.md §2.2 is Razorpay INR 1,499 (~$18).
    // Do not change without also reconciling api/_lib/stripe.js's
    // STRIPE_PRICE_PRO — OPERATIONS.md documents a known mismatch risk.
    priceUsdMonthly: 18,
    apiRequestsPerDay: RATE_LIMITS.pro,
    features: ['live-intel-api-read', 'cve-lookup', 'search', 'campaigns-full', 'graph-full', 'iocs', 'content-graph-entity'],
  },
  enterprise: {
    tier: 'enterprise',
    name: 'Enterprise',
    priceUsdMonthly: null, // contact sales
    apiRequestsPerDay: RATE_LIMITS.enterprise,
    features: ['live-intel-api-read', 'cve-lookup', 'search', 'campaigns-full', 'graph-full', 'iocs', 'stix-export', 'content-graph-entity', 'priority-support'],
    contactSales: true,
  },
};

function getPlan(tier) {
  return PLANS[tier] || null;
}

function hasFeature(tier, featureKey) {
  const plan = getPlan(tier);
  return !!plan && plan.features.includes(featureKey);
}

module.exports = { PLANS, TIERS, getPlan, hasFeature };
