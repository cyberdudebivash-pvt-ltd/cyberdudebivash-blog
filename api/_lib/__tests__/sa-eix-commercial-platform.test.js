'use strict';

const { SentinelApexCommercialPlatform } = require('../sa-eix-commercial-platform');

describe('SentinelApexCommercialPlatform', () => {
  let platform;

  beforeEach(() => {
    platform = new SentinelApexCommercialPlatform();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(platform).toBeDefined();
      expect(platform.designTokens).toBeDefined();
      expect(platform.theme).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexCommercialPlatform({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generatePricingTier', () => {
    test('should generate pricing tier with defaults', () => {
      const tier = platform.generatePricingTier();
      expect(tier.type).toBe('pricing-tier');
      expect(tier.html).toBeDefined();
      expect(tier.metadata).toBeDefined();
    });

    test('should generate pricing tier with name', () => {
      const tier = platform.generatePricingTier('Professional', 1999);
      expect(tier.html).toContain('Professional');
      expect(tier.metadata.name).toBe('Professional');
    });

    test('should display price correctly', () => {
      const tier = platform.generatePricingTier('Professional', 1999);
      expect(tier.html).toContain('1,999');
      expect(tier.html).toContain('/month');
      expect(tier.metadata.price).toBe(1999);
    });

    test('should display features list', () => {
      const features = ['Feature 1', 'Feature 2', 'Feature 3'];
      const tier = platform.generatePricingTier('Pro', 999, features);
      expect(tier.html).toContain('Feature 1');
      expect(tier.html).toContain('Feature 2');
      expect(tier.html).toContain('Feature 3');
      expect(tier.metadata.featureCount).toBe(3);
    });

    test('should highlight tier when specified', () => {
      const tier = platform.generatePricingTier('Premium', 1999, [], true);
      expect(tier.html).toContain('scale(1.05)');
      expect(tier.metadata.highlighted).toBe(true);
    });

    test('should not highlight tier by default', () => {
      const tier = platform.generatePricingTier('Basic', 499);
      expect(tier.metadata.highlighted).toBe(false);
    });

    test('should use primary color for highlighted tier border', () => {
      const tier = platform.generatePricingTier('Premium', 1999, [], true);
      expect(tier.html).toContain('4A89BC');
    });

    test('should use theme border for non-highlighted tier', () => {
      const tier = platform.generatePricingTier('Basic', 499, [], false);
      expect(tier.html).toContain('border:');
    });

    test('should include Get Started button', () => {
      const tier = platform.generatePricingTier('Pro', 999);
      expect(tier.html).toContain('Get Started');
    });

    test('should have button styling', () => {
      const tier = platform.generatePricingTier('Pro', 999);
      expect(tier.html).toContain('cursor: pointer');
    });

    test('should escape feature names', () => {
      const features = ['<img src=x>'];
      const tier = platform.generatePricingTier('Pro', 999, features);
      expect(tier.html).toContain('&lt;img');
    });

    test('should escape tier name', () => {
      const tier = platform.generatePricingTier('<script>', 999);
      expect(tier.html).toContain('&lt;script');
    });

    test('should display checkmarks for features', () => {
      const features = ['Feature 1', 'Feature 2'];
      const tier = platform.generatePricingTier('Pro', 999, features);
      const checkmarks = (tier.html.match(/✓/g) || []).length;
      expect(checkmarks).toBeGreaterThanOrEqual(2);
    });

    test('should handle zero price', () => {
      const tier = platform.generatePricingTier('Enterprise', 0);
      expect(tier.html).toContain('$0');
    });

    test('should handle large prices', () => {
      const tier = platform.generatePricingTier('Enterprise', 9999);
      expect(tier.html).toContain('9,999');
    });

    test('should format prices with localization', () => {
      const tier = platform.generatePricingTier('Pro', 1000);
      expect(tier.html).toContain('1,000');
    });

    test('should handle empty features array', () => {
      const tier = platform.generatePricingTier('Basic', 499, []);
      expect(tier.metadata.featureCount).toBe(0);
    });

    test('should handle null features', () => {
      const tier = platform.generatePricingTier('Basic', 499, null);
      expect(tier.metadata.featureCount).toBe(0);
    });
  });

  describe('generateRevenueMetrics', () => {
    test('should generate revenue metrics with empty data', () => {
      const metrics = platform.generateRevenueMetrics({});
      expect(metrics.type).toBe('revenue-metrics');
      expect(metrics.html).toBeDefined();
      expect(metrics.metadata).toBeDefined();
    });

    test('should display ARR metric', () => {
      const metrics = platform.generateRevenueMetrics({
        annualRecurringRevenue: 500000,
      });
      expect(metrics.html).toContain('ARR');
      expect(metrics.html).toContain('500');
    });

    test('should display MRR metric', () => {
      const metrics = platform.generateRevenueMetrics({
        monthlyRecurringRevenue: 50000,
      });
      expect(metrics.html).toContain('MRR');
      expect(metrics.html).toContain('50');
    });

    test('should display churn rate metric', () => {
      const metrics = platform.generateRevenueMetrics({
        churnRate: 0.05,
      });
      expect(metrics.html).toContain('Churn');
      expect(metrics.html).toContain('5%');
    });

    test('should display LTV metric', () => {
      const metrics = platform.generateRevenueMetrics({
        customerLifetimeValue: 50000,
      });
      expect(metrics.html).toContain('LTV');
      expect(metrics.html).toContain('50');
    });

    test('should format large numbers with K suffix', () => {
      const metrics = platform.generateRevenueMetrics({
        annualRecurringRevenue: 1000000,
      });
      expect(metrics.html).toContain('1000');
    });

    test('should calculate churn rate as percentage', () => {
      const metrics = platform.generateRevenueMetrics({
        churnRate: 0.1,
      });
      expect(metrics.html).toContain('10%');
    });

    test('should use warning color for high churn rate', () => {
      const metrics = platform.generateRevenueMetrics({
        churnRate: 0.1,
      });
      expect(metrics.html).toContain('F39C12');
    });

    test('should use success color for low churn rate', () => {
      const metrics = platform.generateRevenueMetrics({
        churnRate: 0.02,
      });
      expect(metrics.html).toContain('2ECC71');
    });

    test('should include metrics title', () => {
      const metrics = platform.generateRevenueMetrics({});
      expect(metrics.html).toContain('Revenue Metrics');
    });

    test('should have grid layout', () => {
      const metrics = platform.generateRevenueMetrics({});
      expect(metrics.html).toContain('display: grid');
    });

    test('should handle zero metrics', () => {
      const metrics = platform.generateRevenueMetrics({
        annualRecurringRevenue: 0,
        monthlyRecurringRevenue: 0,
        churnRate: 0,
        customerLifetimeValue: 0,
      });
      expect(metrics.metadata).toBeDefined();
    });

    test('should handle missing metric fields', () => {
      const metrics = platform.generateRevenueMetrics({
        annualRecurringRevenue: 100000,
      });
      expect(metrics.html).toContain('ARR');
    });
  });

  describe('generateCommercialPlatform', () => {
    test('should generate complete commercial platform', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.type).toBe('commercial-platform');
      expect(commercial.html).toBeDefined();
      expect(commercial.components).toBeDefined();
    });

    test('should include pricing plans title', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('Pricing Plans');
    });

    test('should include three pricing tiers', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.metadata.pricingTiers).toBe(3);
    });

    test('should include Starter tier', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('Starter');
      expect(commercial.html).toContain('499');
    });

    test('should include Professional tier', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('Professional');
      expect(commercial.html).toContain('1,999');
    });

    test('should include Enterprise tier', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('Enterprise');
    });

    test('should highlight Professional tier', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('scale(1.05)');
    });

    test('should include revenue metrics component', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform({});
      expect(commercial.components.revenue).toBeDefined();
    });

    test('should use custom metrics if provided', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform({
        metrics: {
          annualRecurringRevenue: 1000000,
          monthlyRecurringRevenue: 83333,
        },
      });
      expect(commercial.html).toContain('1000');
    });

    test('should include generation timestamp', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.metadata.generatedAt).toBeDefined();
    });

    test('should have responsive grid layout', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('grid-template-columns');
    });

    test('should include all tier features', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('API Access');
      expect(commercial.html).toContain('Priority Support');
      expect(commercial.html).toContain('Unlimited Access');
    });

    test('should have proper max-width constraint', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('max-width: 1200px');
    });
  });

  describe('Pricing Tiers Structure', () => {
    test('Starter tier should have correct details', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('Starter');
      expect(commercial.html).toContain('Basic Support');
    });

    test('Professional tier should be highlighted', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      const professionalHighlight = commercial.html.indexOf('Professional');
      const scaleTransform = commercial.html.indexOf('scale(1.05)');
      expect(scaleTransform).toBeGreaterThan(-1);
    });

    test('Enterprise tier should have flexible pricing', () => {
      const platform = new SentinelApexCommercialPlatform();
      const commercial = platform.generateCommercialPlatform();
      expect(commercial.html).toContain('Enterprise');
      expect(commercial.html).toContain('$0');
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = platform.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = platform.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = platform.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape double quotes', () => {
      const escaped = platform.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = platform.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(platform.escapeHtml(null)).toBe('');
      expect(platform.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very long tier name', () => {
      const longName = 'A'.repeat(500);
      const tier = platform.generatePricingTier(longName, 999);
      expect(tier.metadata.name).toBe(longName);
    });

    test('should handle very large price', () => {
      const tier = platform.generatePricingTier('Enterprise', 999999);
      expect(tier.metadata.price).toBe(999999);
    });

    test('should handle many features', () => {
      const features = Array.from({ length: 50 }, (_, i) => `Feature ${i}`);
      const tier = platform.generatePricingTier('Pro', 999, features);
      expect(tier.metadata.featureCount).toBe(50);
    });

    test('should handle special characters in tier name', () => {
      const tier = platform.generatePricingTier('Pro & Advanced', 999);
      expect(tier.html).toContain('&amp;');
    });

    test('should handle special characters in features', () => {
      const features = ['Feature & Other'];
      const tier = platform.generatePricingTier('Pro', 999, features);
      expect(tier.html).toContain('&amp;');
    });

    test('should handle unicode in tier name', () => {
      const tier = platform.generatePricingTier('Pro 中文', 999);
      expect(tier.html).toContain('中文');
    });

    test('should handle unicode in features', () => {
      const features = ['功能 Feature'];
      const tier = platform.generatePricingTier('Pro', 999, features);
      expect(tier.html).toContain('功能');
    });

    test('should handle rapid tier generation', () => {
      const tiers = [];
      for (let i = 0; i < 100; i++) {
        tiers.push(platform.generatePricingTier(`Tier ${i}`, i * 100));
      }
      expect(tiers.length).toBe(100);
    });

    test('should handle rapid platform generation', () => {
      const platforms = [];
      for (let i = 0; i < 50; i++) {
        platforms.push(platform.generateCommercialPlatform());
      }
      expect(platforms.length).toBe(50);
    });

    test('should generate valid timestamp format', () => {
      const p = new SentinelApexCommercialPlatform();
      const commercial = p.generateCommercialPlatform();
      expect(new Date(commercial.metadata.generatedAt).toISOString()).toBe(
        commercial.metadata.generatedAt
      );
    });

    test('should maintain state across multiple calls', () => {
      const tier1 = platform.generatePricingTier('Pro', 999);
      const tier2 = platform.generatePricingTier('Pro', 999);
      expect(tier1.metadata.name).toBe(tier2.metadata.name);
    });

    test('should handle negative price gracefully', () => {
      const tier = platform.generatePricingTier('Test', -100);
      expect(tier.metadata.price).toBe(-100);
    });

    test('should handle decimal prices', () => {
      const tier = platform.generatePricingTier('Test', 99.99);
      expect(tier.metadata.price).toBe(99.99);
    });
  });

  describe('Monetization Features', () => {
    test('should include Get Started buttons', () => {
      const p = new SentinelApexCommercialPlatform();
      const commercial = p.generateCommercialPlatform();
      const buttons = (commercial.html.match(/Get Started/g) || []).length;
      expect(buttons).toBe(3);
    });

    test('should display feature benefits', () => {
      const p = new SentinelApexCommercialPlatform();
      const commercial = p.generateCommercialPlatform();
      expect(commercial.html).toContain('API Access');
    });

    test('should highlight premium tier visually', () => {
      const p = new SentinelApexCommercialPlatform();
      const commercial = p.generateCommercialPlatform();
      expect(commercial.html).toContain('scale(1.05)');
    });
  });

  describe('Revenue Display', () => {
    test('should show revenue metrics', () => {
      const p = new SentinelApexCommercialPlatform();
      const commercial = p.generateCommercialPlatform();
      expect(commercial.html).toContain('Revenue Metrics');
    });

    test('should include ARR, MRR, Churn, LTV', () => {
      const p = new SentinelApexCommercialPlatform();
      const commercial = p.generateCommercialPlatform();
      expect(commercial.html).toContain('ARR');
      expect(commercial.html).toContain('MRR');
      expect(commercial.html).toContain('Churn');
      expect(commercial.html).toContain('LTV');
    });
  });

  describe('Visual Design', () => {
    test('pricing tier should have border styling', () => {
      const tier = platform.generatePricingTier('Pro', 999);
      expect(tier.html).toContain('border:');
    });

    test('pricing tier should have background color', () => {
      const tier = platform.generatePricingTier('Pro', 999);
      expect(tier.html).toContain('background:');
    });

    test('pricing tier should have padding', () => {
      const tier = platform.generatePricingTier('Pro', 999);
      expect(tier.html).toContain('padding:');
    });

    test('pricing tier should have border radius', () => {
      const tier = platform.generatePricingTier('Pro', 999);
      expect(tier.html).toContain('border-radius:');
    });

    test('commercial platform should have centered layout', () => {
      const p = new SentinelApexCommercialPlatform();
      const commercial = p.generateCommercialPlatform();
      expect(commercial.html).toContain('margin-left: auto');
      expect(commercial.html).toContain('margin-right: auto');
    });
  });
});
