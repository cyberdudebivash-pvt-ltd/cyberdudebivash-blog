'use strict';

const { SentinelApexEnterpriseCustomer } = require('../sa-eix-enterprise-customer');

describe('SentinelApexEnterpriseCustomer', () => {
  let customer;

  beforeEach(() => {
    customer = new SentinelApexEnterpriseCustomer();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(customer).toBeDefined();
      expect(customer.designTokens).toBeDefined();
      expect(customer.theme).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexEnterpriseCustomer({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generateCustomerCard', () => {
    test('should generate customer card with defaults', () => {
      const card = customer.generateCustomerCard();
      expect(card.type).toBe('customer-card');
      expect(card.html).toContain('Enterprise Customer');
      expect(card.metadata.tier).toBe('professional');
    });

    test('should generate customer card with name', () => {
      const card = customer.generateCustomerCard('ACME Corp');
      expect(card.html).toContain('ACME Corp');
      expect(card.metadata.name).toBe('ACME Corp');
    });

    test('should display customer tier', () => {
      const card = customer.generateCustomerCard('Test', 'enterprise');
      expect(card.html).toContain('ENTERPRISE');
      expect(card.metadata.tier).toBe('enterprise');
    });

    test('should display success metrics', () => {
      const card = customer.generateCustomerCard('Test', 'professional', {
        success: 0.95,
        usage: 0.75,
      });
      expect(card.html).toContain('95%');
      expect(card.html).toContain('75%');
    });

    test('should escape customer name', () => {
      const card = customer.generateCustomerCard('<img src=x>');
      expect(card.html).toContain('&lt;img');
    });

    test('should handle zero metrics', () => {
      const card = customer.generateCustomerCard('Test', 'professional', {
        success: 0,
        usage: 0,
      });
      expect(card.metadata.successRate).toBe(0);
      expect(card.metadata.apiUsage).toBe(0);
    });

    test('should handle all tier types', () => {
      ['enterprise', 'premium', 'professional', 'starter'].forEach(tier => {
        const card = customer.generateCustomerCard('Test', tier);
        expect(card.metadata.tier).toBe(tier);
      });
    });

    test('should show ACTIVE status', () => {
      const card = customer.generateCustomerCard('Test');
      expect(card.html).toContain('ACTIVE');
    });
  });

  describe('generateSuccessMetrics', () => {
    test('should generate success metrics with empty customers', () => {
      const metrics = customer.generateSuccessMetrics([]);
      expect(metrics.type).toBe('success-metrics');
      expect(metrics.html).toContain('Customer Success');
      expect(metrics.metadata.totalCustomers).toBe(0);
    });

    test('should generate success metrics with customers', () => {
      const customers = [
        { name: 'Customer1', status: 'active', successRate: 0.9 },
        { name: 'Customer2', status: 'active', successRate: 0.8 },
      ];
      const metrics = customer.generateSuccessMetrics(customers);
      expect(metrics.metadata.totalCustomers).toBe(2);
      expect(metrics.metadata.activeCustomers).toBe(2);
    });

    test('should calculate average success rate', () => {
      const customers = [
        { status: 'active', successRate: 0.8 },
        { status: 'active', successRate: 0.6 },
      ];
      const metrics = customer.generateSuccessMetrics(customers);
      expect(metrics.metadata.averageSuccessRate).toBe(70);
    });

    test('should calculate churn rate', () => {
      const customers = [
        { status: 'active' },
        { status: 'inactive' },
        { status: 'inactive' },
      ];
      const metrics = customer.generateSuccessMetrics(customers);
      expect(metrics.metadata.churnRate).toBe(67);
    });

    test('should count active customers', () => {
      const customers = [
        { status: 'active' },
        { status: 'active' },
        { status: 'inactive' },
      ];
      const metrics = customer.generateSuccessMetrics(customers);
      expect(metrics.metadata.activeCustomers).toBe(2);
    });

    test('should handle null customers', () => {
      const metrics = customer.generateSuccessMetrics(null);
      expect(metrics.metadata.totalCustomers).toBe(0);
    });

    test('should display all metrics', () => {
      const metrics = customer.generateSuccessMetrics([{ status: 'active' }]);
      expect(metrics.html).toContain('Total Customers');
      expect(metrics.html).toContain('Active');
      expect(metrics.html).toContain('Avg Success');
    });
  });

  describe('generatePremiumFeatures', () => {
    test('should generate premium features with empty list', () => {
      const features = customer.generatePremiumFeatures([]);
      expect(features.type).toBe('premium-features');
      expect(features.html).toContain('Enterprise Features');
      expect(features.metadata.totalFeatures).toBe(0);
    });

    test('should generate premium features with features', () => {
      const featureList = [
        { name: 'Advanced Analytics', description: 'Real-time threat analysis' },
        { name: 'Custom Integrations', description: 'API access' },
      ];
      const features = customer.generatePremiumFeatures(featureList);
      expect(features.metadata.totalFeatures).toBe(2);
      expect(features.html).toContain('Advanced Analytics');
      expect(features.html).toContain('Custom Integrations');
    });

    test('should limit displayed features to 8', () => {
      const featureList = Array.from({ length: 12 }, (_, i) => ({
        name: `Feature ${i}`,
      }));
      const features = customer.generatePremiumFeatures(featureList);
      expect(features.metadata.displayedFeatures).toBe(8);
      expect(features.metadata.totalFeatures).toBe(12);
    });

    test('should escape feature names', () => {
      const featureList = [{ name: '<img src=x>' }];
      const features = customer.generatePremiumFeatures(featureList);
      expect(features.html).toContain('&lt;img');
    });

    test('should escape feature descriptions', () => {
      const featureList = [{ name: 'Feature', description: '&malicious' }];
      const features = customer.generatePremiumFeatures(featureList);
      expect(features.html).toContain('&amp;malicious');
    });

    test('should handle null features', () => {
      const features = customer.generatePremiumFeatures(null);
      expect(features.metadata.totalFeatures).toBe(0);
    });

    test('should include checkmark for each feature', () => {
      const features = customer.generatePremiumFeatures([{ name: 'Feature' }]);
      expect(features.html).toContain('✓');
    });
  });

  describe('generateEngagementTimeline', () => {
    test('should generate engagement timeline with empty events', () => {
      const timeline = customer.generateEngagementTimeline([]);
      expect(timeline.type).toBe('engagement-timeline');
      expect(timeline.html).toContain('Customer Engagement');
      expect(timeline.metadata.totalEvents).toBe(0);
    });

    test('should generate engagement timeline with events', () => {
      const events = [
        { type: 'Onboarding', date: '2026-07-01' },
        { type: 'Demo Completed', date: '2026-07-15' },
      ];
      const timeline = customer.generateEngagementTimeline(events);
      expect(timeline.metadata.totalEvents).toBe(2);
      expect(timeline.html).toContain('Onboarding');
      expect(timeline.html).toContain('Demo Completed');
    });

    test('should limit displayed events to 6', () => {
      const events = Array.from({ length: 10 }, (_, i) => ({
        type: `Event ${i}`,
      }));
      const timeline = customer.generateEngagementTimeline(events);
      expect(timeline.metadata.displayedEvents).toBe(6);
      expect(timeline.metadata.totalEvents).toBe(10);
    });

    test('should escape event types', () => {
      const events = [{ type: '<img src=x>' }];
      const timeline = customer.generateEngagementTimeline(events);
      expect(timeline.html).toContain('&lt;img');
    });

    test('should escape event dates', () => {
      const events = [{ type: 'Event', date: '&malicious' }];
      const timeline = customer.generateEngagementTimeline(events);
      expect(timeline.html).toContain('&amp;malicious');
    });

    test('should handle null events', () => {
      const timeline = customer.generateEngagementTimeline(null);
      expect(timeline.metadata.totalEvents).toBe(0);
    });

    test('should display event timeline visually', () => {
      const timeline = customer.generateEngagementTimeline([{ type: 'Event' }]);
      expect(timeline.html).toContain('✓');
    });
  });

  describe('generateEnterpriseCustomer', () => {
    test('should generate complete enterprise customer portal', () => {
      const portal = customer.generateEnterpriseCustomer(
        {
          name: 'ACME Corp',
          tier: 'enterprise',
          metrics: { success: 0.95, usage: 0.85 },
        },
        {
          events: [{ type: 'Setup', date: '2026-07-01' }],
        }
      );

      expect(portal.type).toBe('enterprise-customer');
      expect(portal.html).toContain('Enterprise Customer Portal');
      expect(portal.components).toBeDefined();
    });

    test('should include all component types', () => {
      const portal = customer.generateEnterpriseCustomer({}, {});
      expect(portal.components.customerCard).toBeDefined();
      expect(portal.components.successMetrics).toBeDefined();
      expect(portal.components.premiumFeatures).toBeDefined();
      expect(portal.components.engagementTimeline).toBeDefined();
    });

    test('should include metadata', () => {
      const portal = customer.generateEnterpriseCustomer(
        { name: 'Test Customer', tier: 'premium' },
        { events: Array.from({ length: 5 }, () => ({})) }
      );

      expect(portal.metadata.customerName).toBe('Test Customer');
      expect(portal.metadata.customerTier).toBe('premium');
      expect(portal.metadata.engagementEvents).toBe(5);
      expect(portal.metadata.generatedAt).toBeDefined();
    });

    test('should handle empty customer and engagement data', () => {
      const portal = customer.generateEnterpriseCustomer({}, {});
      expect(portal.type).toBe('enterprise-customer');
      expect(portal.html).toContain('Enterprise Customer Portal');
    });

    test('should include all component HTML', () => {
      const portal = customer.generateEnterpriseCustomer(
        { name: 'Test', tier: 'enterprise', features: [{ name: 'Feature' }] },
        { events: [{ type: 'Event' }] }
      );

      expect(portal.html).toContain('Customer Success');
      expect(portal.html).toContain('Enterprise Features');
      expect(portal.html).toContain('Customer Engagement');
    });
  });

  describe('Color Utilities', () => {
    test('should return enterprise color for enterprise tier', () => {
      const color = customer.getTierColor('enterprise');
      expect(color).toBeDefined();
    });

    test('should return premium color for premium tier', () => {
      const color = customer.getTierColor('premium');
      expect(color).toBeDefined();
    });

    test('should return professional color for professional tier', () => {
      const color = customer.getTierColor('professional');
      expect(color).toBeDefined();
    });

    test('should return starter color for starter tier', () => {
      const color = customer.getTierColor('starter');
      expect(color).toBeDefined();
    });

    test('should return default color for unknown tier', () => {
      const color = customer.getTierColor('unknown');
      expect(color).toBeDefined();
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = customer.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = customer.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = customer.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape quotes', () => {
      const escaped = customer.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = customer.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(customer.escapeHtml(null)).toBe('');
      expect(customer.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very large customer lists', () => {
      const customers = Array.from({ length: 500 }, (_, i) => ({
        name: `Customer ${i}`,
        status: i % 2 === 0 ? 'active' : 'inactive',
      }));
      const metrics = customer.generateSuccessMetrics(customers);
      expect(metrics.metadata.totalCustomers).toBe(500);
    });

    test('should handle very large feature lists', () => {
      const features = Array.from({ length: 50 }, (_, i) => ({
        name: `Feature ${i}`,
        description: `Description ${i}`,
      }));
      const premiumFeatures = customer.generatePremiumFeatures(features);
      expect(premiumFeatures.metadata.totalFeatures).toBe(50);
      expect(premiumFeatures.metadata.displayedFeatures).toBe(8);
    });

    test('should handle very large event counts', () => {
      const events = Array.from({ length: 100 }, (_, i) => ({
        type: `Event ${i}`,
        date: `2026-07-${(i % 31) + 1}`,
      }));
      const timeline = customer.generateEngagementTimeline(events);
      expect(timeline.metadata.totalEvents).toBe(100);
    });

    test('should handle unicode characters', () => {
      const card = customer.generateCustomerCard('ACME 中文 🔐');
      expect(card.html).toContain('中文');
    });

    test('should handle special characters', () => {
      const card = customer.generateCustomerCard('Corp & Associates (Pvt) Ltd');
      expect(card.html).toContain('&amp;');
    });

    test('should generate valid HTML structure', () => {
      const card = customer.generateCustomerCard();
      expect(card.html).toMatch(/<div[^>]*>/);
      expect(card.html).toMatch(/<\/div>/);
    });

    test('should handle 100% success rate', () => {
      const card = customer.generateCustomerCard('Test', 'professional', {
        success: 1.0,
      });
      expect(card.metadata.successRate).toBe(100);
    });

    test('should handle extreme metric values', () => {
      const card = customer.generateCustomerCard('Test', 'professional', {
        success: 1.5,
        usage: 2.0,
      });
      expect(card.metadata.successRate).toBe(150);
      expect(card.metadata.apiUsage).toBe(200);
    });
  });
});
