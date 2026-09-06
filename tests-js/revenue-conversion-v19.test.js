'use strict';

const fs = require('fs');
const path = require('path');

const revenue = require('../revenue-conversion-v19.js');
const middleware = require('../api/_lib/middleware.js');
const assets = require('../scripts/build-cloudflare-assets.js');

describe('P0 Revenue Conversion v19', () => {
  test('only canonical paid tiers may enter direct checkout', () => {
    expect(revenue.sanitizePlan('starter')).toBe('starter');
    expect(revenue.sanitizePlan('PRO')).toBe('pro');
    expect(revenue.sanitizePlan('enterprise')).toBe('enterprise');
    expect(revenue.sanitizePlan('free')).toBeNull();
    expect(revenue.sanitizePlan('admin')).toBeNull();
  });

  test('campaign attribution is bounded to non-sensitive tokens', () => {
    const a = revenue.parseAttribution('?utm_source=sentinel apex report&utm_medium=cti/dossier&utm_campaign=x%20y&utm_content=pro<script>');
    expect(a).toEqual({
      source: 'sentinel_apex_report',
      medium: 'cti_dossier',
      campaign: 'x_y',
      content: 'pro_script_',
    });
    const payload = revenue.eventPayload('pro', a, { step: 2 });
    expect(payload.plan).toBe('pro');
    expect(payload.revenue_surface).toBe('buy_v19');
    expect(payload).not.toHaveProperty('email');
    expect(payload).not.toHaveProperty('api_key');
    expect(payload).not.toHaveProperty('payment_id');
  });

  test('API quota exhaustion recommends exactly one next paid tier', () => {
    expect(middleware.nextPaidTier('free')).toBe('starter');
    expect(middleware.nextPaidTier('starter')).toBe('pro');
    expect(middleware.nextPaidTier('pro')).toBe('enterprise');
    expect(middleware.nextPaidTier('enterprise')).toBeNull();
  });

  test('API upgrade URL goes straight to checkout with measurable attribution', () => {
    const url = new URL(middleware.upgradeCheckoutUrl('starter'));
    expect(url.origin + url.pathname).toBe('https://blog.cyberdudebivash.in/buy.html');
    expect(url.searchParams.get('plan')).toBe('pro');
    expect(url.searchParams.get('checkout')).toBe('1');
    expect(url.searchParams.get('utm_source')).toBe('api_rate_limit');
    expect(url.searchParams.get('utm_medium')).toBe('api');
    expect(url.searchParams.get('utm_campaign')).toBe('p0_revenue_conversion_v19');
    expect(middleware.upgradeCheckoutUrl('enterprise')).toBeNull();
  });

  test('Cloudflare bundle explicitly publishes both v19 checkout assets', () => {
    expect(assets.PUBLIC_ROOT_FILES).toContain('buy.html');
    expect(assets.PUBLIC_ROOT_FILES).toContain('revenue-conversion-v19.js');
  });

  test('buy page is focused on payment and deliberately excludes overlay conversion engines', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'buy.html'), 'utf8');
    expect(html).toContain('/payment-flow.js');
    expect(html).toContain('/revenue-conversion-v19.js');
    expect(html).toContain('G-XTGLNMNNC7');
    expect(html).not.toContain('/conversion-engine.js');
    expect(html).not.toContain('/monetization.js');
    expect(html).toContain('No account yet:');
    expect(html).toContain('never implies that a threat claim is more certain because it is paid');
  });

  test('revenue controller source never handles customer identity or payment credentials', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'revenue-conversion-v19.js'), 'utf8');
    expect(source).not.toMatch(/razorpay_payment_id/);
    expect(source).not.toMatch(/razorpay_signature/);
    expect(source).not.toMatch(/api[_-]?key/i);
    expect(source).not.toMatch(/\bemail\s*:/i);
  });
});
