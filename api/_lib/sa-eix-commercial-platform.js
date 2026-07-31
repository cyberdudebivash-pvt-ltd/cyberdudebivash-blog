'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexCommercialPlatform {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generatePricingTier(name = '', price = 0, features = [], highlighted = false) {
    const t = this.designTokens;
    const borderColor = highlighted ? t.colors.primary[500] : this.theme.border.primary;

    const featuresList = (features || []).map((f) => `
      <div style="display: flex; align-items: flex-start; gap: ${t.spacing[2]}; margin-bottom: ${t.spacing[2]};">
        <div style="color: ${t.colors.success}; font-weight: bold; flex-shrink: 0;">✓</div>
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">
          ${this.escapeHtml(f)}
        </div>
      </div>
    `).join('');

    return {
      type: 'pricing-tier',
      html: `
        <div class="pricing-tier" style="background: ${this.theme.background.secondary}; border: 2px solid ${borderColor}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; ${highlighted ? 'transform: scale(1.05);' : ''}">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[2]} 0;">
            ${this.escapeHtml(name)}
          </h3>
          <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.primary[500]}; font-weight: ${t.typography.fontWeight.bold}; margin-bottom: ${t.spacing[4]};">
            $${price.toLocaleString()}<span style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">/month</span>
          </div>
          <button style="width: 100%; padding: ${t.spacing[3]}; background: ${t.colors.primary[500]}; color: white; border: none; border-radius: ${t.radius.md}; font-weight: ${t.typography.fontWeight.bold}; margin-bottom: ${t.spacing[4]}; cursor: pointer;">
            Get Started
          </button>
          <div>
            ${featuresList}
          </div>
        </div>
      `,
      metadata: { name, price, featureCount: (features || []).length, highlighted },
    };
  }

  generateRevenueMetrics(metrics = {}) {
    const t = this.designTokens;

    const arr = (metrics.annualRecurringRevenue || 0) / 1000;
    const mrrValue = (metrics.monthlyRecurringRevenue || 0) / 1000;
    const churnRate = Math.round((metrics.churnRate || 0) * 100);
    const ltv = Math.round(metrics.customerLifetimeValue || 0) / 1000;

    return {
      type: 'revenue-metrics',
      html: `
        <div class="revenue-metrics" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0;">Revenue Metrics</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: ${t.spacing[3]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">ARR</div>
              <div style="font-size: ${t.typography.fontSize.xl}; font-weight: ${t.typography.fontWeight.bold}; color: ${t.colors.primary[500]};">
                $${arr.toFixed(1)}K
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">MRR</div>
              <div style="font-size: ${t.typography.fontSize.xl}; font-weight: ${t.typography.fontWeight.bold}; color: ${t.colors.success};">
                $${mrrValue.toFixed(1)}K
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">Churn</div>
              <div style="font-size: ${t.typography.fontSize.xl}; font-weight: ${t.typography.fontWeight.bold}; color: ${churnRate > 5 ? t.colors.warning : t.colors.success};">
                ${churnRate}%
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">LTV</div>
              <div style="font-size: ${t.typography.fontSize.xl}; font-weight: ${t.typography.fontWeight.bold}; color: ${t.colors.accent[500]};">
                $${ltv.toFixed(1)}K
              </div>
            </div>
          </div>
        </div>
      `,
      metadata: metrics,
    };
  }

  generateCommercialPlatform(commercial = {}) {
    const t = this.designTokens;

    const tiers = [
      { name: 'Starter', price: 499, features: ['API Access', 'Basic Support', 'Email Alerts'] },
      { name: 'Professional', price: 1999, features: ['Advanced API', 'Priority Support', 'Custom Dashboards'], highlighted: true },
      { name: 'Enterprise', price: 0, features: ['Unlimited Access', '24/7 Dedicated Support', 'White-Label Options'] },
    ];

    const tiersHtml = tiers.map(tier => this.generatePricingTier(tier.name, tier.price, tier.features, tier.highlighted).html).join('');
    const revenue = this.generateRevenueMetrics(commercial.metrics || {});

    return {
      type: 'commercial-platform',
      html: `
        <div class="commercial-platform" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          <h2 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; text-align: center; font-family: ${t.typography.fontFamily.heading};">Pricing Plans</h2>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]}; max-width: 1200px; margin-left: auto; margin-right: auto;">
            ${tiersHtml}
          </div>

          <div style="max-width: 1200px; margin: 0 auto;">
            ${revenue.html}
          </div>
        </div>
      `,
      components: { revenue },
      metadata: {
        pricingTiers: tiers.length,
        generatedAt: new Date().toISOString(),
      },
    };
  }

  escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

module.exports = { SentinelApexCommercialPlatform };
