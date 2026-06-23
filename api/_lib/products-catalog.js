/**
 * SENTINEL APEX — Digital Product Catalog
 * Single source of truth for one-time digital product checkout (Stripe).
 * Mirrors the products listed on /products.html. Prices are in USD cents
 * (Stripe's smallest currency unit). Keep IDs in sync with the
 * data-product-id attributes on /products.html buy buttons.
 *
 * Fulfillment is currently manual: a paid order is recorded in Redis and
 * surfaced via GET /api/v1/admin?action=product-orders so the deliverable
 * can be emailed to the buyer. No automated file-delivery infra exists yet.
 */
'use strict';

const PRODUCTS = {
  'sigma-megapack-2026': {
    name:     'CYBERDUDEBIVASH SENTINEL APEX Sigma Rule Megapack 2026',
    amount:   14900,
    currency: 'usd',
  },
  'ransomware-yara-pack-2026': {
    name:     '2026 Ransomware YARA Rule Pack',
    amount:   8900,
    currency: 'usd',
  },
  'q2-2026-threat-report': {
    name:     'Q2 2026 Threat Landscape Report — Enterprise Edition',
    amount:   19900,
    currency: 'usd',
  },
  'soc-playbook-2026': {
    name:     'SOC Analyst Master Playbook 2026',
    amount:   7900,
    currency: 'usd',
  },
  'red-team-kit-2026': {
    name:     'Enterprise Red Team Operator Kit 2026',
    amount:   12900,
    currency: 'usd',
  },
  'soc-automation-bundle': {
    name:     'SOC Automation Scripts Bundle',
    amount:   9900,
    currency: 'usd',
  },
  'cve-2026-detection-pack': {
    name:     'CVE-2026 Critical Exploit Detection Pack',
    amount:   4900,
    currency: 'usd',
  },
  'apt-profile-pack-2026': {
    name:     'APT Group Profile Pack — 2026 Edition',
    amount:   14900,
    currency: 'usd',
  },
  'ransomware-defense-playbook': {
    name:     'Ransomware Defense Playbook — Enterprise',
    amount:   10900,
    currency: 'usd',
  },
  'complete-arsenal-bundle': {
    name:     'CYBERDUDEBIVASH SENTINEL APEX Complete Arsenal Bundle',
    amount:   49900,
    currency: 'usd',
  },
  'soc-starter-bundle': {
    name:     'SOC Starter Bundle',
    amount:   14900,
    currency: 'usd',
  },
  'enterprise-detection-bundle': {
    name:     'Enterprise Detection Bundle',
    amount:   24900,
    currency: 'usd',
  },
};

function getProduct(productId) {
  return PRODUCTS[productId] || null;
}

module.exports = { PRODUCTS, getProduct };
