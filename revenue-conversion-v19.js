/*
 * CYBERDUDEBIVASH SENTINEL APEX — Revenue Conversion Controller v19
 *
 * P0 objective: reduce paid-subscription checkout friction without changing
 * canonical prices, entitlements, payment verification, or customer identity.
 *
 * Privacy boundary: browser analytics emitted here contain plan + campaign
 * attribution only. Email, API keys, intent/order/payment IDs and payment
 * details are never copied into analytics payloads.
 */
(function (root, factory) {
  'use strict';
  const api = factory(root || null);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.ApexRevenueConversionV19 = api;
})(typeof window !== 'undefined' ? window : null, function (root) {
  'use strict';

  const VALID_PLANS = Object.freeze(['starter', 'pro', 'enterprise']);
  const FALLBACK_PLANS = Object.freeze({
    starter: {
      label: 'API Starter', amount: 999, currency: 'INR',
      features: ['5,000 API calls/day', 'Weekly threat intelligence digest', 'Unlimited full-text search', 'Single authenticated API key'],
    },
    pro: {
      label: 'SOC Pro', amount: 1499, currency: 'INR',
      features: ['25,000 API calls/day', 'Complete IOC feed access', 'SIGMA + Yara detection rules', 'Authenticated full-intelligence API depth'],
    },
    enterprise: {
      label: 'Enterprise', amount: 4999, currency: 'INR',
      features: ['Extended API capacity', 'STIX 2.1 bundle export', 'Bulk CSV/JSON export', 'Priority support and all Pro capabilities'],
    },
  });

  function sanitizePlan(value) {
    const plan = String(value || '').trim().toLowerCase();
    return VALID_PLANS.includes(plan) ? plan : null;
  }

  function safeToken(value, maxLen) {
    return String(value || '')
      .replace(/[^a-zA-Z0-9_.-]/g, '_')
      .slice(0, maxLen || 80);
  }

  function parseAttribution(search) {
    const params = new URLSearchParams(String(search || '').replace(/^\?/, ''));
    return {
      source: safeToken(params.get('utm_source') || 'direct', 80),
      medium: safeToken(params.get('utm_medium') || 'checkout', 80),
      campaign: safeToken(params.get('utm_campaign') || 'p0_revenue_conversion_v19', 100),
      content: safeToken(params.get('utm_content') || 'direct_checkout', 100),
    };
  }

  function formatPrice(plan) {
    const currency = plan && plan.currency === 'USD' ? '$' : '₹';
    const amount = Number(plan && plan.amount);
    if (!Number.isFinite(amount)) return '—';
    return `${currency}${amount.toLocaleString(plan && plan.currency === 'USD' ? 'en-US' : 'en-IN')}/month`;
  }

  function eventPayload(plan, attribution, extra) {
    return Object.assign({
      plan: sanitizePlan(plan) || 'unknown',
      revenue_surface: 'buy_v19',
      utm_source: attribution.source,
      utm_medium: attribution.medium,
      utm_campaign: attribution.campaign,
      utm_content: attribution.content,
    }, extra || {});
  }

  function track(name, plan, attribution, extra) {
    if (!root) return;
    const payload = eventPayload(plan, attribution, extra);
    try {
      if (typeof root.trackEvent === 'function') {
        root.trackEvent(name, payload);
        return;
      }
      if (typeof root.gtag === 'function') {
        root.gtag('event', name, Object.assign({ platform: 'sentinel_apex' }, payload));
      }
    } catch (_) {}
  }

  function instrumentPaymentFlow(flow, plan, attribution) {
    if (!flow || flow.__cdbRevenueV19Instrumented) return flow;
    let completionTracked = false;

    if (typeof flow.startUpgrade === 'function') {
      const innerStart = flow.startUpgrade.bind(flow);
      flow.startUpgrade = async function (requestedPlan) {
        const selected = sanitizePlan(requestedPlan) || plan;
        track('checkout_start', selected, attribution, { checkout_version: 'v19' });
        return innerStart(selected);
      };
    }

    if (typeof flow._go === 'function') {
      const innerGo = flow._go.bind(flow);
      flow._go = function (step) {
        const result = innerGo(step);
        const n = Number(step);
        if (n >= 1 && n <= 5) {
          track('checkout_step', plan, attribution, { step: n });
          if (n === 5 && !completionTracked) {
            completionTracked = true;
            track('checkout_complete', plan, attribution, { checkout_version: 'v19' });
          }
        }
        return result;
      };
    }

    if (typeof flow.close === 'function') {
      const innerClose = flow.close.bind(flow);
      flow.close = function () {
        track('checkout_closed', plan, attribution, { before_completion: !completionTracked });
        return innerClose();
      };
    }

    Object.defineProperty(flow, '__cdbRevenueV19Instrumented', {
      value: true, enumerable: false, configurable: false,
    });
    return flow;
  }

  async function loadCanonicalPlan(plan) {
    if (!root || typeof root.fetch !== 'function') return FALLBACK_PLANS[plan];
    try {
      const response = await root.fetch('/api/v1/billing?action=plans', { credentials: 'same-origin' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = await response.json();
      const plans = body.plans || (body.data && body.data.plans) || {};
      const canonical = plans[plan];
      if (!canonical) throw new Error('PLAN_NOT_FOUND');
      return {
        label: canonical.label || FALLBACK_PLANS[plan].label,
        amount: Number(canonical.amount),
        currency: canonical.currency || 'INR',
        features: FALLBACK_PLANS[plan].features,
      };
    } catch (_) {
      return FALLBACK_PLANS[plan];
    }
  }

  function applyPlanUI(planKey, plan) {
    if (!root || !root.document) return;
    const doc = root.document;
    const set = (id, value) => {
      const node = doc.getElementById(id);
      if (node) node.textContent = value;
    };
    set('buyPlanName', plan.label);
    set('buyPlanPrice', formatPrice(plan));
    set('buyPlanTag', planKey.toUpperCase());
    set('buyCtaLabel', `Continue to ${plan.label} Checkout`);
    const list = doc.getElementById('buyFeatures');
    if (list) {
      list.innerHTML = '';
      for (const feature of plan.features || []) {
        const li = doc.createElement('li');
        li.textContent = feature;
        list.appendChild(li);
      }
    }
  }

  let activePlan = null;
  let activeAttribution = null;

  async function begin() {
    if (!root) return false;
    const flow = root.ApexPaymentFlow;
    if (!flow || !activePlan) return false;
    instrumentPaymentFlow(flow, activePlan, activeAttribution);
    await flow.startUpgrade(activePlan);
    return true;
  }

  async function init() {
    if (!root || !root.document || !root.location) return null;
    const params = new URLSearchParams(root.location.search || '');
    activePlan = sanitizePlan(params.get('plan')) || 'pro';
    activeAttribution = parseAttribution(root.location.search || '');

    const plan = await loadCanonicalPlan(activePlan);
    applyPlanUI(activePlan, plan);
    track('checkout_landing_view', activePlan, activeAttribution, { checkout_version: 'v19' });

    const flow = root.ApexPaymentFlow;
    if (flow) instrumentPaymentFlow(flow, activePlan, activeAttribution);

    const button = root.document.getElementById('buyNowButton');
    if (button) button.addEventListener('click', begin);

    if (params.get('checkout') === '1') {
      root.setTimeout(function () { begin(); }, 120);
    }
    return { plan: activePlan, attribution: activeAttribution };
  }

  if (root && root.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', init, { once: true });
    else init();
  }

  return {
    VALID_PLANS,
    FALLBACK_PLANS,
    sanitizePlan,
    safeToken,
    parseAttribution,
    formatPrice,
    eventPayload,
    instrumentPaymentFlow,
    loadCanonicalPlan,
    begin,
    init,
  };
});
