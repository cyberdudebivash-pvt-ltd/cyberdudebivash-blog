'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexPerformanceMetrics {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generatePerformanceScore(score = 0, maxScore = 100) {
    const t = this.designTokens;
    const percent = Math.min((score / maxScore) * 100, 100);
    const color = percent >= 90 ? t.colors.success : percent >= 70 ? t.colors.accent[500] : t.colors.warning;

    return {
      type: 'performance-score',
      html: `
        <div class="performance-score" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; text-align: center;">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[3]} 0;">Performance Score</h3>

          <div style="position: relative; width: 150px; height: 150px; margin: 0 auto ${t.spacing[4]} auto;">
            <svg width="150" height="150" style="transform: rotate(-90deg);">
              <circle cx="75" cy="75" r="65" fill="none" stroke="${this.theme.background.tertiary}" stroke-width="8" />
              <circle cx="75" cy="75" r="65" fill="none" stroke="${color}" stroke-width="8" stroke-dasharray="${(percent / 100) * 408.4} 408.4" stroke-linecap="round" />
            </svg>
            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;">
              <div style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${color};">
                ${Math.round(score)}
              </div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
                / ${maxScore}
              </div>
            </div>
          </div>

          <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[2]};">
            ${percent >= 90 ? 'Excellent' : percent >= 70 ? 'Good' : 'Needs Improvement'}
          </div>
        </div>
      `,
      metadata: { score: Math.round(score), maxScore, color },
    };
  }

  generateMetricsTable(metrics = []) {
    const t = this.designTokens;

    const rows = (metrics || []).map((metric) => `
      <tr style="border-bottom: 1px solid ${this.theme.border.secondary};">
        <td style="padding: ${t.spacing[2]}; text-align: left; font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary};">
          ${this.escapeHtml(metric.name || 'Metric')}
        </td>
        <td style="padding: ${t.spacing[2]}; text-align: right; font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
          ${this.escapeHtml(String(metric.value || '0'))}
        </td>
        <td style="padding: ${t.spacing[2]}; text-align: right; font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">
          ${this.escapeHtml(metric.unit || '')}
        </td>
      </tr>
    `).join('');

    return {
      type: 'metrics-table',
      html: `
        <div class="metrics-table" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; overflow: hidden;">
          <table style="width: 100%; border-collapse: collapse;">
            <thead>
              <tr style="background: ${this.theme.background.primary};">
                <th style="padding: ${t.spacing[3]}; text-align: left; font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">Metric</th>
                <th style="padding: ${t.spacing[3]}; text-align: right; font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">Value</th>
                <th style="padding: ${t.spacing[3]}; text-align: right; font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">Unit</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      `,
      metadata: { metricCount: (metrics || []).length },
    };
  }

  generatePerformanceReport(performance = {}) {
    const t = this.designTokens;
    const score = this.generatePerformanceScore(performance.score || 85, 100);
    const metrics = this.generateMetricsTable(performance.metrics || [
      { name: 'Lighthouse Score', value: 92, unit: '/100' },
      { name: 'LCP', value: 1.8, unit: 's' },
      { name: 'FID', value: 45, unit: 'ms' },
      { name: 'CLS', value: 0.08, unit: '' },
    ]);

    return {
      type: 'performance-report',
      html: `
        <div class="performance-report" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          <h2 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Performance Metrics</h2>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
            ${score.html}
            ${metrics.html}
          </div>
        </div>
      `,
      components: { score, metrics },
      metadata: {
        score: performance.score || 85,
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

module.exports = { SentinelApexPerformanceMetrics };
