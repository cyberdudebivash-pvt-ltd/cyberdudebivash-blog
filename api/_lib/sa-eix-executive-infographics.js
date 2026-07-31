'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexExecutiveInfographics {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateKPICard(label, value, metric, status = 'normal') {
    const t = this.designTokens;
    const statusColor = this.getStatusColor(status);
    const borderColor = status === 'critical' ? t.colors.critical : status === 'warning' ? t.colors.warning : t.colors.success;

    return {
      type: 'kpi-card',
      html: `
        <div class="kpi-card" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; border-left: 6px solid ${borderColor};">
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: ${t.spacing[3]}; font-weight: ${t.typography.fontWeight.semibold};">
            ${this.escapeHtml(label)}
          </div>
          <div style="display: flex; align-items: baseline; gap: ${t.spacing[2]}; margin-bottom: ${t.spacing[3]};">
            <div style="font-size: ${t.typography.fontSize['5xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${statusColor}; font-family: ${t.typography.fontFamily.mono};">
              ${this.escapeHtml(String(value))}
            </div>
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; font-weight: ${t.typography.fontWeight.semibold};">
              ${this.escapeHtml(metric)}
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: ${t.spacing[2]};">
            <div style="width: 12px; height: 12px; border-radius: 50%; background: ${statusColor};"></div>
            <span style="font-size: ${t.typography.fontSize.xs}; color: ${statusColor}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase;">
              ${status.replace(/_/g, ' ')}
            </span>
          </div>
        </div>
      `,
      metadata: {
        label,
        value,
        metric,
        status,
        color: statusColor,
      },
    };
  }

  generateBusinessImpactChart(threats = []) {
    const t = this.designTokens;

    const impactElements = (threats || []).slice(0, 5).map((threat, idx) => {
      const impact = threat.businessImpact || 'Medium';
      const impactScore = threat.impactScore || (idx + 1) * 20;
      const impactPercent = Math.min(impactScore, 100);
      const impactColor = impactPercent > 80 ? t.colors.critical : impactPercent > 60 ? t.colors.warning : t.colors.accent[500];

      return `
        <div style="margin-bottom: ${t.spacing[4]};">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: ${t.spacing[2]};">
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold};">
              ${this.escapeHtml(threat.name || `Threat ${idx + 1}`)}
            </div>
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${impactColor}; font-weight: ${t.typography.fontWeight.bold};">
              ${impactPercent}%
            </div>
          </div>
          <div style="height: 6px; background: ${this.theme.background.tertiary}; border-radius: ${t.radius.full}; overflow: hidden;">
            <div style="height: 100%; width: ${impactPercent}%; background: linear-gradient(90deg, ${impactColor}, ${t.colors.primary[500]}); border-radius: ${t.radius.full};"></div>
          </div>
        </div>
      `;
    }).join('');

    return {
      type: 'business-impact-chart',
      html: `
        <div class="business-impact-chart" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Business Impact Assessment</h3>
          ${impactElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No threats identified</div>'}
        </div>
      `,
      metadata: {
        threatCount: Math.min((threats || []).length, 5),
        threats: (threats || []).slice(0, 5).map(t => ({ name: t.name, impact: t.businessImpact })),
      },
    };
  }

  generateRiskGauge(riskLevel = 0, maxRisk = 100) {
    const t = this.designTokens;
    const riskPercent = Math.min((riskLevel / maxRisk) * 100, 100);
    const riskColor = riskPercent > 80 ? t.colors.critical : riskPercent > 60 ? t.colors.warning : riskPercent > 40 ? t.colors.accent[500] : t.colors.success;
    const riskLabel = riskPercent > 80 ? 'CRITICAL' : riskPercent > 60 ? 'HIGH' : riskPercent > 40 ? 'MEDIUM' : 'LOW';

    const arcStart = -Math.PI / 2;
    const arcEnd = arcStart + (Math.PI * riskPercent / 100);
    const radius = 60;
    const centerX = 100;
    const centerY = 100;

    const x1 = centerX + radius * Math.cos(arcStart);
    const y1 = centerY + radius * Math.sin(arcStart);
    const x2 = centerX + radius * Math.cos(arcEnd);
    const y2 = centerY + radius * Math.sin(arcEnd);

    const largeArc = riskPercent > 50 ? 1 : 0;

    return {
      type: 'risk-gauge',
      html: `
        <div class="risk-gauge" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; display: flex; flex-direction: column; align-items: center;">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Risk Gauge</h3>

          <svg width="220" height="220" style="margin-bottom: ${t.spacing[4]};">
            <circle cx="110" cy="110" r="60" fill="none" stroke="${this.theme.background.tertiary}" stroke-width="12" stroke-dasharray="188.4" stroke-dashoffset="0" />
            <path d="M ${x1} ${y1} A 60 60 0 ${largeArc} 1 ${x2} ${y2}" fill="none" stroke="${riskColor}" stroke-width="12" stroke-linecap="round" />

            <circle cx="110" cy="110" r="45" fill="${this.theme.background.primary}" />

            <text x="110" y="105" font-size="32" font-weight="bold" text-anchor="middle" dominant-baseline="middle" fill="${riskColor}" font-family="${t.typography.fontFamily.mono}">
              ${Math.round(riskPercent)}
            </text>
            <text x="110" y="125" font-size="12" text-anchor="middle" dominant-baseline="middle" fill="${this.theme.text.secondary}">
              %
            </text>
          </svg>

          <div style="text-align: center;">
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${riskColor}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase; letter-spacing: 0.5px;">
              ${riskLabel}
            </div>
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[2]};">
              Risk Level: ${Math.round(riskLevel)}/${maxRisk}
            </div>
          </div>
        </div>
      `,
      metadata: {
        riskLevel: Math.round(riskPercent),
        riskLabel,
        riskColor,
      },
    };
  }

  generateOperationalReadiness(readiness = {}) {
    const {
      detection = 0,
      response = 0,
      recovery = 0,
      resilience = 0,
    } = readiness;

    const t = this.designTokens;
    const metrics = [
      { label: 'Detection', value: Math.round(detection * 100), color: t.colors.accent[500] },
      { label: 'Response', value: Math.round(response * 100), color: t.colors.primary[500] },
      { label: 'Recovery', value: Math.round(recovery * 100), color: t.colors.success },
      { label: 'Resilience', value: Math.round(resilience * 100), color: t.colors.warning },
    ];

    const metricsHTML = metrics.map(metric => `
      <div style="display: flex; flex-direction: column; align-items: center; flex: 1;">
        <svg width="100" height="100" style="margin-bottom: ${t.spacing[2]};">
          <circle cx="50" cy="50" r="40" fill="none" stroke="${this.theme.background.tertiary}" stroke-width="6" />
          <circle cx="50" cy="50" r="40" fill="none" stroke="${metric.color}" stroke-width="6" stroke-dasharray="${(metric.value / 100) * 251.2} 251.2" stroke-linecap="round" style="transform: rotate(-90deg); transform-origin: 50px 50px;" />
          <text x="50" y="50" font-size="20" font-weight="bold" text-anchor="middle" dominant-baseline="middle" fill="${metric.color}" font-family="${t.typography.fontFamily.mono}">
            ${metric.value}
          </text>
        </svg>
        <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; font-weight: ${t.typography.fontWeight.semibold};">
          ${metric.label}
        </div>
      </div>
    `).join('');

    return {
      type: 'operational-readiness',
      html: `
        <div class="operational-readiness" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Operational Readiness</h3>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: ${t.spacing[6]};">
            ${metricsHTML}
          </div>
        </div>
      `,
      metadata: {
        detection: Math.round(detection * 100),
        response: Math.round(response * 100),
        recovery: Math.round(recovery * 100),
        resilience: Math.round(resilience * 100),
      },
    };
  }

  generateFinancialExposure(exposure = {}) {
    const {
      potentialLoss = 0,
      currency = 'USD',
      confidence = 0,
      businessImpact = 'Unknown',
    } = exposure;

    const t = this.designTokens;
    const confidencePercent = Math.round(confidence * 100);
    const confidenceColor = this.getConfidenceColor(confidence);

    const formatCurrency = (amount) => {
      const symbol = currency === 'USD' ? '$' : currency === 'EUR' ? '€' : '£';
      if (amount >= 1e9) return symbol + (amount / 1e9).toFixed(1) + 'B';
      if (amount >= 1e6) return symbol + (amount / 1e6).toFixed(1) + 'M';
      if (amount >= 1e3) return symbol + (amount / 1e3).toFixed(1) + 'K';
      return symbol + amount.toFixed(0);
    };

    return {
      type: 'financial-exposure',
      html: `
        <div class="financial-exposure" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Financial Exposure</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[6]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; text-align: center; border-left: 6px solid ${t.colors.critical};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Potential Loss</div>
            <div style="font-size: ${t.typography.fontSize['5xl']}; color: ${t.colors.critical}; font-weight: ${t.typography.fontWeight.bold}; font-family: ${t.typography.fontFamily.mono};">
              ${formatCurrency(potentialLoss)}
            </div>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Business Impact</div>
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold};">
                ${this.escapeHtml(businessImpact)}
              </div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Confidence</div>
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${confidenceColor}; font-weight: ${t.typography.fontWeight.bold};">
                ${confidencePercent}%
              </div>
            </div>
          </div>
        </div>
      `,
      metadata: {
        potentialLoss: Math.round(potentialLoss),
        currency,
        confidence: confidencePercent,
        businessImpact,
      },
    };
  }

  generateCriticalAssets(assets = []) {
    const t = this.designTokens;

    const assetElements = (assets || []).slice(0, 8).map(asset => `
      <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[3]};">
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold}; margin-bottom: ${t.spacing[1]};">
          ${this.escapeHtml(asset.name || 'Asset')}
        </div>
        <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
          ${this.escapeHtml(asset.type || 'unknown')}
        </div>
        ${asset.risk ? `
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.getSeverityColor(asset.risk)}; margin-top: ${t.spacing[1]}; font-weight: ${t.typography.fontWeight.semibold};">
            ${asset.risk}
          </div>
        ` : ''}
      </div>
    `).join('');

    return {
      type: 'critical-assets',
      html: `
        <div class="critical-assets" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Critical Assets At Risk</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.critical};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Total Assets At Risk</div>
            <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${t.colors.critical}; font-weight: ${t.typography.fontWeight.bold};">
              ${(assets || []).length}
            </div>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: ${t.spacing[3]};">
            ${assetElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No assets identified</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalAssets: (assets || []).length,
        assetsAtRisk: Math.min((assets || []).length, 8),
      },
    };
  }

  generateExecutiveInfographics(product = {}, investigation = {}, assessment = {}) {
    const kpiCard1 = this.generateKPICard('Threat Level', investigation.severity || 'UNKNOWN', 'severity', investigation.severity === 'CRITICAL' ? 'critical' : 'normal');
    const kpiCard2 = this.generateKPICard('Detection Ready', `${Math.round((assessment.detectionReadiness || 0) * 100)}%`, 'capability', 'normal');
    const kpiCard3 = this.generateKPICard('Affected Systems', `${(investigation.infrastructure || []).length}`, 'nodes', 'warning');
    const kpiCard4 = this.generateKPICard('Threat Actors', `${(investigation.threatActors || []).length}`, 'groups', 'normal');

    const businessImpact = this.generateBusinessImpactChart(investigation.threatActors);
    const riskGauge = this.generateRiskGauge(assessment.riskLevel || 0, 100);
    const operationalReadiness = this.generateOperationalReadiness(assessment.operationalReadiness || {});
    const financialExposure = this.generateFinancialExposure(assessment.financialExposure || {});
    const criticalAssets = this.generateCriticalAssets(investigation.criticalAssets);

    const t = this.designTokens;

    return {
      type: 'executive-infographics',
      html: `
        <div class="executive-infographics" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          <h2 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Executive Summary</h2>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: ${t.spacing[4]}; margin-bottom: ${t.spacing[8]};">
            ${kpiCard1.html}
            ${kpiCard2.html}
            ${kpiCard3.html}
            ${kpiCard4.html}
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
            ${businessImpact.html}
            ${riskGauge.html}
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
            ${operationalReadiness.html}
            ${financialExposure.html}
          </div>

          <div style="margin-top: ${t.spacing[8]};">
            ${criticalAssets.html}
          </div>
        </div>
      `,
      components: {
        kpiCards: [kpiCard1, kpiCard2, kpiCard3, kpiCard4],
        businessImpact,
        riskGauge,
        operationalReadiness,
        financialExposure,
        criticalAssets,
      },
      metadata: {
        productId: product.id,
        investigation: investigation.id,
        threatLevel: investigation.severity,
        generatedAt: new Date().toISOString(),
      },
    };
  }

  getStatusColor(status) {
    const t = this.designTokens;
    const statusMap = {
      normal: t.colors.success,
      warning: t.colors.warning,
      critical: t.colors.critical,
    };
    return statusMap[status] || t.colors.accent[500];
  }

  getConfidenceColor(confidence) {
    const t = this.designTokens;
    if (confidence >= 0.8) return t.colors.success;
    if (confidence >= 0.6) return t.colors.accent[500];
    if (confidence >= 0.4) return t.colors.warning;
    return t.colors.critical;
  }

  getSeverityColor(severity) {
    const t = this.designTokens;
    const severityMap = {
      CRITICAL: t.colors.critical,
      HIGH: t.colors.warning,
      MEDIUM: t.colors.accent[500],
      LOW: t.colors.success,
      UNKNOWN: this.theme.text.secondary,
    };
    return severityMap[severity] || severityMap.UNKNOWN;
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

module.exports = { SentinelApexExecutiveInfographics };
