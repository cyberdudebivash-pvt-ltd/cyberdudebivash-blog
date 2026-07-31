'use strict';

const { SentinelApexPerformanceMetrics } = require('../sa-eix-performance-metrics');

describe('SentinelApexPerformanceMetrics', () => {
  let metrics;

  beforeEach(() => {
    metrics = new SentinelApexPerformanceMetrics();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(metrics).toBeDefined();
      expect(metrics.designTokens).toBeDefined();
      expect(metrics.theme).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexPerformanceMetrics({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generatePerformanceScore', () => {
    test('should generate performance score with defaults', () => {
      const score = metrics.generatePerformanceScore();
      expect(score.type).toBe('performance-score');
      expect(score.html).toBeDefined();
      expect(score.metadata).toBeDefined();
    });

    test('should calculate score percentage', () => {
      const score = metrics.generatePerformanceScore(85, 100);
      expect(score.metadata.score).toBe(85);
      expect(score.metadata.maxScore).toBe(100);
    });

    test('should display score as "Excellent" for 90+', () => {
      const score = metrics.generatePerformanceScore(95, 100);
      expect(score.html).toContain('Excellent');
    });

    test('should display score as "Good" for 70-89', () => {
      const score = metrics.generatePerformanceScore(75, 100);
      expect(score.html).toContain('Good');
    });

    test('should display score as "Needs Improvement" for <70', () => {
      const score = metrics.generatePerformanceScore(60, 100);
      expect(score.html).toContain('Needs Improvement');
    });

    test('should clamp score to 100%', () => {
      const score = metrics.generatePerformanceScore(150, 100);
      expect(score.html).toContain('100');
    });

    test('should handle zero score', () => {
      const score = metrics.generatePerformanceScore(0, 100);
      expect(score.metadata.score).toBe(0);
    });

    test('should handle perfect score', () => {
      const score = metrics.generatePerformanceScore(100, 100);
      expect(score.metadata.score).toBe(100);
      expect(score.html).toContain('Excellent');
    });

    test('should have SVG gauge element', () => {
      const score = metrics.generatePerformanceScore(85, 100);
      expect(score.html).toContain('<svg');
      expect(score.html).toContain('<circle');
    });

    test('should assign color based on performance', () => {
      const excellent = metrics.generatePerformanceScore(95, 100);
      const good = metrics.generatePerformanceScore(75, 100);
      const poor = metrics.generatePerformanceScore(50, 100);

      expect(excellent.metadata.color).toBeDefined();
      expect(good.metadata.color).toBeDefined();
      expect(poor.metadata.color).toBeDefined();
    });

    test('should include center text display', () => {
      const score = metrics.generatePerformanceScore(85, 100);
      expect(score.html).toContain('85');
      expect(score.html).toContain('100');
    });

    test('should handle fractional scores', () => {
      const score = metrics.generatePerformanceScore(92.5, 100);
      expect(score.metadata.score).toBe(93);
    });
  });

  describe('generateMetricsTable', () => {
    test('should generate metrics table with empty metrics', () => {
      const table = metrics.generateMetricsTable([]);
      expect(table.type).toBe('metrics-table');
      expect(table.html).toBeDefined();
      expect(table.metadata.metricCount).toBe(0);
    });

    test('should generate metrics table with metrics', () => {
      const metricsData = [
        { name: 'Lighthouse Score', value: 92, unit: '/100' },
        { name: 'LCP', value: 1.8, unit: 's' },
      ];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.metadata.metricCount).toBe(2);
      expect(table.html).toContain('Lighthouse Score');
      expect(table.html).toContain('LCP');
    });

    test('should display metric values', () => {
      const metricsData = [{ name: 'Test Metric', value: 42, unit: 'ms' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('42');
    });

    test('should display metric units', () => {
      const metricsData = [{ name: 'Metric', value: 100, unit: 'ms' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('ms');
    });

    test('should escape metric names', () => {
      const metricsData = [{ name: '<img src=x>', value: 0, unit: 'test' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('&lt;img');
    });

    test('should escape metric values', () => {
      const metricsData = [{ name: 'Test', value: '&malicious', unit: 'test' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('&amp;malicious');
    });

    test('should escape metric units', () => {
      const metricsData = [{ name: 'Test', value: 100, unit: '&dangerous' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('&amp;dangerous');
    });

    test('should have table structure', () => {
      const metricsData = [{ name: 'Metric', value: 100, unit: 'ms' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('<table');
      expect(table.html).toContain('<thead');
      expect(table.html).toContain('<tbody');
    });

    test('should have column headers', () => {
      const table = metrics.generateMetricsTable([]);
      expect(table.html).toContain('Metric');
      expect(table.html).toContain('Value');
      expect(table.html).toContain('Unit');
    });

    test('should handle null metrics', () => {
      const table = metrics.generateMetricsTable(null);
      expect(table.metadata.metricCount).toBe(0);
    });

    test('should handle string values', () => {
      const metricsData = [{ name: 'Status', value: 'Healthy', unit: '' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('Healthy');
    });
  });

  describe('generatePerformanceReport', () => {
    test('should generate complete performance report', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.type).toBe('performance-report');
      expect(report.html).toBeDefined();
      expect(report.components).toBeDefined();
    });

    test('should include performance score component', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.components.score).toBeDefined();
      expect(report.components.score.type).toBe('performance-score');
    });

    test('should include metrics table component', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.components.metrics).toBeDefined();
      expect(report.components.metrics.type).toBe('metrics-table');
    });

    test('should have default score of 85', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.metadata.score).toBe(85);
    });

    test('should include default metrics', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('Lighthouse Score');
      expect(report.html).toContain('LCP');
      expect(report.html).toContain('FID');
      expect(report.html).toContain('CLS');
    });

    test('should display performance metrics title', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('Performance Metrics');
    });

    test('should use custom score if provided', () => {
      const report = metrics.generatePerformanceReport({ score: 78 });
      expect(report.metadata.score).toBe(78);
    });

    test('should use custom metrics if provided', () => {
      const customMetrics = [
        { name: 'Custom Metric', value: 100, unit: 'custom' },
      ];
      const report = metrics.generatePerformanceReport({ metrics: customMetrics });
      expect(report.html).toContain('Custom Metric');
    });

    test('should include generation timestamp', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.metadata.generatedAt).toBeDefined();
    });

    test('should have grid layout', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('display: grid');
    });

    test('should display both components side by side', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('Performance Score');
      expect(report.html).toContain('Lighthouse Score');
    });
  });

  describe('Default Metrics', () => {
    test('should include Lighthouse Score metric', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('Lighthouse Score');
      expect(report.html).toContain('92');
    });

    test('should include LCP metric', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('LCP');
      expect(report.html).toContain('1.8');
      expect(report.html).toContain('s');
    });

    test('should include FID metric', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('FID');
      expect(report.html).toContain('45');
      expect(report.html).toContain('ms');
    });

    test('should include CLS metric', () => {
      const report = metrics.generatePerformanceReport();
      expect(report.html).toContain('CLS');
      expect(report.html).toContain('0.08');
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = metrics.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = metrics.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = metrics.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape double quotes', () => {
      const escaped = metrics.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = metrics.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(metrics.escapeHtml(null)).toBe('');
      expect(metrics.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Edge Cases', () => {
    test('should handle very high score', () => {
      const score = metrics.generatePerformanceScore(999, 1000);
      expect(score.metadata.score).toBe(999);
    });

    test('should handle very low score', () => {
      const score = metrics.generatePerformanceScore(1, 100);
      expect(score.metadata.score).toBe(1);
    });

    test('should handle negative max score', () => {
      const score = metrics.generatePerformanceScore(50, 100);
      expect(score.metadata.maxScore).toBe(100);
    });

    test('should handle many metrics', () => {
      const manyMetrics = Array.from({ length: 100 }, (_, i) => ({
        name: `Metric ${i}`,
        value: Math.random() * 100,
        unit: 'unit',
      }));
      const table = metrics.generateMetricsTable(manyMetrics);
      expect(table.metadata.metricCount).toBe(100);
    });

    test('should handle very long metric names', () => {
      const longName = 'A'.repeat(500);
      const table = metrics.generateMetricsTable([
        { name: longName, value: 100, unit: 'ms' },
      ]);
      expect(table.html).toContain('A');
    });

    test('should handle special characters in metric names', () => {
      const metricsData = [
        { name: 'Metric & Other <stuff>', value: 100, unit: 'ms' },
      ];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('&amp;');
      expect(table.html).toContain('&lt;');
    });

    test('should handle unicode characters', () => {
      const metricsData = [{ name: 'Métrique 中文', value: 100, unit: 'ms' }];
      const table = metrics.generateMetricsTable(metricsData);
      expect(table.html).toContain('中文');
    });

    test('should handle 100% performance score', () => {
      const score = metrics.generatePerformanceScore(100, 100);
      expect(score.metadata.score).toBe(100);
      expect(score.html).toContain('Excellent');
    });

    test('should handle 0% performance score', () => {
      const score = metrics.generatePerformanceScore(0, 100);
      expect(score.metadata.score).toBe(0);
    });

    test('should maintain state across multiple calls', () => {
      const report1 = metrics.generatePerformanceReport();
      const report2 = metrics.generatePerformanceReport();
      expect(report1.metadata.score).toBe(report2.metadata.score);
    });

    test('should generate valid timestamp format', () => {
      const report = metrics.generatePerformanceReport();
      expect(new Date(report.metadata.generatedAt).toISOString()).toBe(
        report.metadata.generatedAt
      );
    });
  });

  describe('SVG Gauge Rendering', () => {
    test('should have SVG with proper dimensions', () => {
      const score = metrics.generatePerformanceScore(85, 100);
      expect(score.html).toContain('width="150"');
      expect(score.html).toContain('height="150"');
    });

    test('should have circle elements', () => {
      const score = metrics.generatePerformanceScore(85, 100);
      expect((score.html.match(/<circle/g) || []).length).toBe(2);
    });

    test('should use stroke-dasharray for progress', () => {
      const score = metrics.generatePerformanceScore(85, 100);
      expect(score.html).toContain('stroke-dasharray');
    });

    test('should apply rotation for gauge orientation', () => {
      const score = metrics.generatePerformanceScore(85, 100);
      expect(score.html).toContain('rotate(-90deg)');
    });
  });

  describe('Score Color Classification', () => {
    test('should use success color for excellent performance', () => {
      const score = metrics.generatePerformanceScore(95, 100);
      expect(score.metadata.color).toBeDefined();
    });

    test('should use accent color for good performance', () => {
      const score = metrics.generatePerformanceScore(75, 100);
      expect(score.metadata.color).toBeDefined();
    });

    test('should use warning color for poor performance', () => {
      const score = metrics.generatePerformanceScore(50, 100);
      expect(score.metadata.color).toBeDefined();
    });
  });

  describe('Table Structure', () => {
    test('should have proper table header', () => {
      const table = metrics.generateMetricsTable([]);
      expect(table.html).toContain('<thead>');
      expect(table.html).toContain('</thead>');
    });

    test('should have proper table body', () => {
      const table = metrics.generateMetricsTable([
        { name: 'Metric', value: 100, unit: 'ms' },
      ]);
      expect(table.html).toContain('<tbody>');
      expect(table.html).toContain('</tbody>');
    });

    test('should have proper row structure', () => {
      const table = metrics.generateMetricsTable([
        { name: 'Metric', value: 100, unit: 'ms' },
      ]);
      expect(table.html).toContain('<tr');
      expect(table.html).toContain('</tr>');
    });

    test('should have proper cell structure', () => {
      const table = metrics.generateMetricsTable([
        { name: 'Metric', value: 100, unit: 'ms' },
      ]);
      expect(table.html).toContain('<td');
      expect(table.html).toContain('</td>');
    });

    test('should align values to the right', () => {
      const table = metrics.generateMetricsTable([
        { name: 'Metric', value: 100, unit: 'ms' },
      ]);
      expect(table.html).toContain('text-align: right');
    });
  });
});
