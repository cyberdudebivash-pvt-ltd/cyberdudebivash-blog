'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexEnterpriseCustomer {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateCustomerCard(name = '', tier = 'professional', metrics = {}) {
    const t = this.designTokens;
    const tierColor = this.getTierColor(tier);

    const successPercent = metrics.success ? Math.round(metrics.success * 100) : 0;
    const usagePercent = metrics.usage ? Math.round(metrics.usage * 100) : 0;

    return {
      type: 'customer-card',
      html: `
        <div class="customer-card" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[5]}; border-top: 4px solid ${tierColor};">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: ${t.spacing[3]};">
            <div>
              <h3 style="font-size: ${t.typography.fontSize.base}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[1]} 0;">
                ${this.escapeHtml(name || 'Enterprise Customer')}
              </h3>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${tierColor}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase;">
                ${tier.toUpperCase()}
              </div>
            </div>
            <div style="background: ${tierColor}20; color: ${tierColor}; padding: ${t.spacing[1]} ${t.spacing[2]}; border-radius: ${t.radius.md}; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold};">
              ACTIVE
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: ${t.spacing[3]}; margin-top: ${t.spacing[3]};">
            <div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Success Rate</div>
              <div style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
                ${successPercent}%
              </div>
            </div>
            <div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">API Usage</div>
              <div style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
                ${usagePercent}%
              </div>
            </div>
          </div>
        </div>
      `,
      metadata: {
        name,
        tier,
        successRate: successPercent,
        apiUsage: usagePercent,
      },
    };
  }

  generateSuccessMetrics(customers = []) {
    const t = this.designTokens;

    const totalCustomers = (customers || []).length;
    const activeCustomers = (customers || []).filter(c => c.status === 'active').length;
    const avgSuccessRate = totalCustomers > 0
      ? Math.round(((customers || []).reduce((sum, c) => sum + (c.successRate || 0), 0) / totalCustomers) * 100)
      : 0;

    return {
      type: 'success-metrics',
      html: `
        <div class="success-metrics" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Customer Success</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.primary[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Total Customers</div>
              <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${totalCustomers}
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.success};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Active</div>
              <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${activeCustomers}
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.accent[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Avg Success</div>
              <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${avgSuccessRate}%
              </div>
            </div>
          </div>
        </div>
      `,
      metadata: {
        totalCustomers,
        activeCustomers,
        averageSuccessRate: avgSuccessRate,
        churnRate: totalCustomers > 0 ? Math.round(((totalCustomers - activeCustomers) / totalCustomers) * 100) : 0,
      },
    };
  }

  generatePremiumFeatures(features = []) {
    const t = this.designTokens;

    const featureElements = (features || []).slice(0, 8).map((feature) => `
      <div style="background: ${this.theme.background.primary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]};">
        <div style="display: flex; align-items: flex-start; gap: ${t.spacing[2]}; margin-bottom: ${t.spacing[2]};">
          <div style="color: ${t.colors.primary[500]}; font-weight: bold; flex-shrink: 0;">✓</div>
          <div>
            <h4 style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0;">
              ${this.escapeHtml(feature.name || 'Feature')}
            </h4>
            <p style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin: ${t.spacing[1]} 0 0 0;">
              ${this.escapeHtml(feature.description || '')}
            </p>
          </div>
        </div>
      </div>
    `).join('');

    return {
      type: 'premium-features',
      html: `
        <div class="premium-features" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Enterprise Features</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: ${t.spacing[3]};">
            ${featureElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No features available</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalFeatures: (features || []).length,
        displayedFeatures: Math.min((features || []).length, 8),
      },
    };
  }

  generateEngagementTimeline(events = []) {
    const t = this.designTokens;

    const eventElements = (events || []).slice(0, 6).map((event, idx) => {
      const isLast = idx === Math.min((events || []).length, 6) - 1;

      return `
        <div style="display: flex;">
          <div style="display: flex; flex-direction: column; align-items: center; margin-right: ${t.spacing[3]};">
            <div style="width: 32px; height: 32px; border-radius: 50%; background: ${t.colors.primary[500]}; display: flex; align-items: center; justify-content: center; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold}; color: white; margin-bottom: ${t.spacing[2]};">
              ✓
            </div>
            ${!isLast ? `<div style="width: 2px; height: ${t.spacing[6]}; background: ${this.theme.border.secondary};"></div>` : ''}
          </div>
          <div style="flex: 1; padding-bottom: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; border-radius: ${t.radius.md}; padding: ${t.spacing[3]};">
              <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
                ${this.escapeHtml(event.type || 'Event')}
              </div>
              ${event.date ? `
                <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[1]};">
                  ${this.escapeHtml(event.date)}
                </div>
              ` : ''}
            </div>
          </div>
        </div>
      `;
    }).join('');

    return {
      type: 'engagement-timeline',
      html: `
        <div class="engagement-timeline" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Customer Engagement</h3>

          <div style="position: relative;">
            ${eventElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No events recorded</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalEvents: (events || []).length,
        displayedEvents: Math.min((events || []).length, 6),
      },
    };
  }

  generateEnterpriseCustomer(customer = {}, engagement = {}) {
    const customerCard = this.generateCustomerCard(
      customer.name || 'Enterprise Account',
      customer.tier || 'professional',
      customer.metrics || {}
    );

    const successMetrics = this.generateSuccessMetrics([customer]);
    const premiumFeatures = this.generatePremiumFeatures(customer.features || []);
    const engagementTimeline = this.generateEngagementTimeline(engagement.events || []);

    const t = this.designTokens;

    return {
      type: 'enterprise-customer',
      html: `
        <div class="enterprise-customer" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          <h2 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Enterprise Customer Portal</h2>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
            ${customerCard.html}
            ${successMetrics.html}
          </div>

          <div style="margin-bottom: ${t.spacing[8]};">
            ${premiumFeatures.html}
          </div>

          <div>
            ${engagementTimeline.html}
          </div>
        </div>
      `,
      components: {
        customerCard,
        successMetrics,
        premiumFeatures,
        engagementTimeline,
      },
      metadata: {
        customerName: customer.name || 'Enterprise Account',
        customerTier: customer.tier || 'professional',
        engagementEvents: (engagement.events || []).length,
        generatedAt: new Date().toISOString(),
      },
    };
  }

  getTierColor(tier) {
    const t = this.designTokens;
    const tierMap = {
      enterprise: t.colors.critical,
      premium: t.colors.warning,
      professional: t.colors.accent[500],
      starter: t.colors.success,
    };
    return tierMap[tier] || t.colors.accent[500];
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

module.exports = { SentinelApexEnterpriseCustomer };
