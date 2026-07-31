'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexPremiumMITRE {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateTacticCoverage(tactics = []) {
    const t = this.designTokens;

    const tacticMetrics = (tactics || []).map((tactic) => {
      const coveragePercent = tactic.coverage ? Math.round(tactic.coverage * 100) : 0;
      const coverageColor = this.getCoverageColor(tactic.coverage || 0);
      const techniqueCount = tactic.techniques ? tactic.techniques.length : 0;

      return `
        <div style="margin-bottom: ${t.spacing[4]};">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: ${t.spacing[2]};">
            <div>
              <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; text-transform: capitalize;">
                ${this.escapeHtml(tactic.name || 'tactic')}
              </div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
                ${techniqueCount} technique${techniqueCount !== 1 ? 's' : ''}
              </div>
            </div>
            <div style="text-align: right;">
              <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${coverageColor};">
                ${coveragePercent}%
              </div>
            </div>
          </div>
          <div style="height: 6px; background: ${this.theme.background.primary}; border-radius: ${t.radius.full}; overflow: hidden;">
            <div style="height: 100%; width: ${coveragePercent}%; background: linear-gradient(90deg, ${coverageColor}, ${t.colors.primary[500]}); border-radius: ${t.radius.full};"></div>
          </div>
        </div>
      `;
    }).join('');

    const totalTactics = (tactics || []).length;
    const avgCoverage = totalTactics > 0 ? Math.round(((tactics || []).reduce((sum, t) => sum + (t.coverage || 0), 0) / totalTactics) * 100) : 0;

    return {
      type: 'tactic-coverage',
      html: `
        <div class="tactic-coverage" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Tactic Coverage</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.primary[500]};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Average Coverage</div>
            <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
              ${avgCoverage}%
            </div>
          </div>

          <div>
            ${tacticMetrics}
          </div>
        </div>
      `,
      metadata: {
        totalTactics,
        averageCoverage: avgCoverage,
        tactics: (tactics || []).map(t => ({
          name: t.name,
          coverage: Math.round((t.coverage || 0) * 100),
          techniques: t.techniques ? t.techniques.length : 0,
        })),
      },
    };
  }

  generateTechniqueHeatmap(techniques = []) {
    const t = this.designTokens;

    const techniqueElements = (techniques || []).slice(0, 12).map((technique) => {
      const coverage = technique.coverage || 0;
      const heatColor = this.getCoverageColor(coverage);

      return `
        <div style="background: ${this.theme.background.primary}; border-left: 3px solid ${heatColor}; border-radius: ${t.radius.md}; padding: ${t.spacing[2]}; position: relative;">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: ${t.spacing[1]};">
            <div style="flex: 1;">
              <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.mono};">
                ${this.escapeHtml(technique.id || 'T0000')}
              </div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
                ${this.escapeHtml(technique.name || 'technique')}
              </div>
            </div>
          </div>
          <div style="height: 4px; background: ${this.theme.background.tertiary}; border-radius: ${t.radius.full}; overflow: hidden;">
            <div style="height: 100%; width: ${coverage * 100}%; background: ${heatColor}; border-radius: ${t.radius.full};"></div>
          </div>
        </div>
      `;
    }).join('');

    const totalTechniques = (techniques || []).length;
    const coveredTechniques = (techniques || []).filter(t => (t.coverage || 0) > 0).length;

    return {
      type: 'technique-heatmap',
      html: `
        <div class="technique-heatmap" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Technique Coverage Heatmap</h3>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: ${t.spacing[3]}; margin-bottom: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.accent[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Total Techniques</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${totalTechniques}
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.success};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Covered</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${coveredTechniques}
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: ${t.spacing[3]};">
            ${techniqueElements}
          </div>
        </div>
      `,
      metadata: {
        totalTechniques,
        coveredTechniques,
        displayedTechniques: Math.min((techniques || []).length, 12),
        coveragePercent: totalTechniques > 0 ? Math.round((coveredTechniques / totalTechniques) * 100) : 0,
      },
    };
  }

  generateDetectionMapping(detections = []) {
    const t = this.designTokens;

    const detectionsByStatus = {
      detected: (detections || []).filter(d => d.status === 'detected').length,
      partial: (detections || []).filter(d => d.status === 'partial').length,
      undetected: (detections || []).filter(d => d.status === 'undetected').length,
    };

    const detectionMetrics = [
      { label: 'Detected', count: detectionsByStatus.detected, color: t.colors.success },
      { label: 'Partial', count: detectionsByStatus.partial, color: t.colors.accent[500] },
      { label: 'Undetected', count: detectionsByStatus.undetected, color: t.colors.warning },
    ];

    const metricsHTML = detectionMetrics.map(metric => `
      <div style="display: flex; align-items: center; gap: ${t.spacing[2]}; margin-bottom: ${t.spacing[2]};">
        <div style="width: 10px; height: 10px; border-radius: 50%; background: ${metric.color};"></div>
        <div style="flex: 1; font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">
          ${metric.label}
        </div>
        <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
          ${metric.count}
        </div>
      </div>
    `).join('');

    const totalDetections = (detections || []).length;
    const detectionRate = totalDetections > 0 ? Math.round((detectionsByStatus.detected / totalDetections) * 100) : 0;

    return {
      type: 'detection-mapping',
      html: `
        <div class="detection-mapping" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Detection Mapping</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.success};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Detection Rate</div>
            <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
              ${detectionRate}%
            </div>
          </div>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md};">
            ${metricsHTML}
          </div>
        </div>
      `,
      metadata: {
        detected: detectionsByStatus.detected,
        partial: detectionsByStatus.partial,
        undetected: detectionsByStatus.undetected,
        total: totalDetections,
        detectionRate,
      },
    };
  }

  generateAdversaryTactics(adversaries = []) {
    const t = this.designTokens;

    const tacticFreq = {};
    (adversaries || []).forEach(adv => {
      (adv.tactics || []).forEach(tactic => {
        tacticFreq[tactic] = (tacticFreq[tactic] || 0) + 1;
      });
    });

    const sortedTactics = Object.entries(tacticFreq)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8);

    const tacticBars = sortedTactics.map(([tactic, count]) => {
      const maxCount = Math.max(...sortedTactics.map(([, c]) => c), 1);
      const percent = (count / maxCount) * 100;

      return `
        <div style="display: flex; align-items: center; gap: ${t.spacing[3]}; margin-bottom: ${t.spacing[3]};">
          <div style="min-width: 120px; font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; text-transform: capitalize;">
            ${this.escapeHtml(tactic.replace(/-/g, ' '))}
          </div>
          <div style="flex: 1; height: 8px; background: ${this.theme.background.tertiary}; border-radius: ${t.radius.full}; overflow: hidden;">
            <div style="height: 100%; width: ${percent}%; background: linear-gradient(90deg, ${t.colors.critical}, ${t.colors.accent[500]}); border-radius: ${t.radius.full};"></div>
          </div>
          <div style="min-width: 30px; text-align: right; font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
            ${count}
          </div>
        </div>
      `;
    }).join('');

    const totalAdversaries = (adversaries || []).length;
    const uniqueTactics = Object.keys(tacticFreq).length;

    return {
      type: 'adversary-tactics',
      html: `
        <div class="adversary-tactics" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Adversary Tactic Frequency</h3>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: ${t.spacing[3]}; margin-bottom: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.critical};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Adversaries</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${totalAdversaries}
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.accent[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Unique Tactics</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${uniqueTactics}
              </div>
            </div>
          </div>

          <div>
            ${tacticBars || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No tactic data</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalAdversaries,
        uniqueTactics,
        topTactics: sortedTactics.map(([tactic, count]) => ({
          tactic,
          count,
        })),
      },
    };
  }

  generatePremiumMITRE(investigation = {}, assessment = {}) {
    const tactics = investigation.tactics || [];
    const techniques = investigation.techniques || [];
    const detections = assessment.detections || [];
    const adversaries = investigation.adversaries || [];

    const tacticCoverage = this.generateTacticCoverage(tactics);
    const techniqueHeatmap = this.generateTechniqueHeatmap(techniques);
    const detectionMapping = this.generateDetectionMapping(detections);
    const adversaryTactics = this.generateAdversaryTactics(adversaries);

    const t = this.designTokens;

    return {
      type: 'premium-mitre',
      html: `
        <div class="premium-mitre" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          <h2 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Premium MITRE ATT&CK Analysis</h2>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
            ${tacticCoverage.html}
            ${detectionMapping.html}
          </div>

          <div style="margin-bottom: ${t.spacing[8]};">
            ${techniqueHeatmap.html}
          </div>

          <div>
            ${adversaryTactics.html}
          </div>
        </div>
      `,
      components: {
        tacticCoverage,
        techniqueHeatmap,
        detectionMapping,
        adversaryTactics,
      },
      metadata: {
        totalTactics: tactics.length,
        totalTechniques: techniques.length,
        totalDetections: detections.length,
        totalAdversaries: adversaries.length,
        generatedAt: new Date().toISOString(),
      },
    };
  }

  getCoverageColor(coverage) {
    const t = this.designTokens;
    if (coverage >= 0.8) return t.colors.critical;
    if (coverage >= 0.6) return t.colors.warning;
    if (coverage >= 0.4) return t.colors.accent[500];
    return t.colors.success;
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

module.exports = { SentinelApexPremiumMITRE };
