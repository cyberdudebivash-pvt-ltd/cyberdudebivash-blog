'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexSOCCommandCenter {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateThreatCommandHeader(investigation = {}) {
    const {
      threatActors = [],
      severity = 'UNKNOWN',
      confidence = 0,
      businessImpact = '',
      threatLevel = 'UNKNOWN',
    } = investigation;

    const severityColor = this.getSeverityColor(severity);
    const threatActorNames = threatActors.map(a => a.name || a).join(', ') || 'No threat actors identified';
    const t = this.designTokens;

    return {
      type: 'threat-command-header',
      html: `
        <div class="soc-threat-header" style="background: linear-gradient(135deg, ${this.theme.background.primary} 0%, ${this.theme.background.secondary} 100%); border-bottom: 3px solid ${severityColor}; padding: ${t.spacing[6]} ${t.spacing[8]}; display: flex; justify-content: space-between; align-items: center;">
          <div style="flex: 1;">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; letter-spacing: 1px; margin-bottom: ${t.spacing[2]};">Active Threat</div>
            <h1 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0; font-family: ${t.typography.fontFamily.heading};">
              ${this.escapeHtml(threatActorNames)}
            </h1>
            <div style="margin-top: ${t.spacing[3]}; color: ${this.theme.text.secondary}; font-size: ${t.typography.fontSize.sm};">
              ${this.escapeHtml(businessImpact || 'High operational impact')}
            </div>
          </div>
          <div style="display: flex; gap: ${t.spacing[6]}; align-items: flex-start;">
            <div style="text-align: right;">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Severity</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${severityColor}; font-family: ${t.typography.fontFamily.mono};">
                ${severity}
              </div>
            </div>
            <div style="text-align: right;">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Confidence</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.getConfidenceColor(confidence)}; font-family: ${t.typography.fontFamily.mono};">
                ${Math.round(confidence * 100)}%
              </div>
            </div>
          </div>
        </div>
      `,
      metadata: {
        threatActors: threatActorNames,
        severity,
        confidence,
        businessImpact,
      },
    };
  }

  generateExecutiveCommandRibbon(investigation = {}) {
    const {
      campaigns = [],
      targetedSectors = [],
      infrastructure = [],
      mitreTechniques = [],
    } = investigation;

    const campaignText = (campaigns && campaigns[0]) ? campaigns[0].name || campaigns[0] : 'No campaigns identified';
    const sectorsText = (targetedSectors && targetedSectors.length) ? targetedSectors.join(', ') : 'Multiple sectors';
    const infrastructureCount = (infrastructure && infrastructure.length) || 0;
    const techniqueCount = (mitreTechniques && mitreTechniques.length) || 0;
    const t = this.designTokens;

    const ribbonItems = [
      { label: 'Campaign', value: this.escapeHtml(campaignText), icon: '▶' },
      { label: 'Sectors', value: this.escapeHtml(sectorsText), icon: '◉' },
      { label: 'Infrastructure', value: `${infrastructureCount} nodes`, icon: '⧉' },
      { label: 'Techniques', value: `${techniqueCount} tactics`, icon: '▲' },
    ];

    const ribbonHTML = ribbonItems.map(item => `
      <div style="display: flex; align-items: center; gap: ${t.spacing[3]}; padding: ${t.spacing[4]}; border-right: 1px solid ${this.theme.border.primary};">
        <div style="font-size: ${t.typography.fontSize.lg}; color: ${t.colors.accent[500]};">${item.icon}</div>
        <div>
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; letter-spacing: 0.5px;">${item.label}</div>
          <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold};">${item.value}</div>
        </div>
      </div>
    `).join('');

    return {
      type: 'executive-command-ribbon',
      html: `
        <div class="executive-ribbon" style="background: ${this.theme.background.secondary}; border-bottom: 1px solid ${this.theme.border.primary}; display: flex; overflow-x: auto;">
          ${ribbonHTML}
        </div>
      `,
      metadata: {
        campaign: campaignText,
        sectors: sectorsText,
        infrastructureCount,
        techniqueCount,
      },
    };
  }

  generateSOCMetricsRibbon(enhancement = {}) {
    const threatInformation = enhancement.presentationEnhancements?.coverPage?.sections?.threatInformation || {};
    const header = enhancement.presentationEnhancements?.coverPage?.sections?.header || {};

    const {
      detectionCoverage = 0,
      incidentCount = 0,
      alertCount = 0,
    } = threatInformation;

    const { threatScore = 0 } = header;

    const t = this.designTokens;
    const metrics = [
      {
        label: 'Detection Coverage',
        value: Math.round(detectionCoverage * 100),
        unit: '%',
        color: this.getStatusColor('success'),
      },
      {
        label: 'Threat Score',
        value: Math.round(threatScore),
        unit: '/100',
        color: this.getSeverityColor(threatScore > 75 ? 'CRITICAL' : threatScore > 50 ? 'HIGH' : 'MEDIUM'),
      },
      {
        label: 'Active Incidents',
        value: incidentCount,
        unit: '',
        color: t.colors.warning,
      },
      {
        label: 'Alerts (24h)',
        value: alertCount,
        unit: '',
        color: t.colors.critical,
      },
    ];

    const metricsHTML = metrics.map(metric => `
      <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: ${t.spacing[4]}; border-right: 1px solid ${this.theme.border.primary}; flex: 1;">
        <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: ${t.spacing[2]};">${metric.label}</div>
        <div style="display: flex; align-items: baseline; gap: ${t.spacing[2]};">
          <div style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${metric.color}; font-family: ${t.typography.fontFamily.mono};">${metric.value}</div>
          <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">${metric.unit}</div>
        </div>
      </div>
    `).join('');

    return {
      type: 'soc-metrics-ribbon',
      html: `
        <div class="soc-metrics" style="background: ${this.theme.background.primary}; border-bottom: 1px solid ${this.theme.border.primary}; display: flex; overflow-x: auto;">
          ${metricsHTML}
        </div>
      `,
      metadata: {
        detectionCoverage: Math.round(detectionCoverage * 100),
        threatScore: Math.round(threatScore),
        incidentCount,
        alertCount,
      },
    };
  }

  generateThreatScoreWidget(investigation = {}, enhancement = {}) {
    const threatScore = enhancement.presentationEnhancements?.coverPage?.sections?.header?.threatScore || 0;
    const maxScore = 100;
    const percentage = (threatScore / maxScore) * 100;

    const getScoreCategory = (score) => {
      if (score >= 80) return { label: 'CRITICAL', color: this.designTokens.colors.critical };
      if (score >= 60) return { label: 'HIGH', color: this.designTokens.colors.warning };
      if (score >= 40) return { label: 'MEDIUM', color: this.designTokens.colors.accent[500] };
      return { label: 'LOW', color: this.designTokens.colors.success };
    };

    const scoreCategory = getScoreCategory(threatScore);
    const t = this.designTokens;

    const circleRadius = 45;
    const circumference = 2 * Math.PI * circleRadius;
    const strokeDashoffset = circumference - (percentage / 100) * circumference;

    return {
      type: 'threat-score-widget',
      html: `
        <div class="threat-score-widget" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; display: flex; flex-direction: column; align-items: center; justify-content: center; min-width: 200px;">
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[4]}; letter-spacing: 0.5px;">Threat Score</div>
          <svg width="140" height="140" style="margin: ${t.spacing[4]} 0;">
            <circle cx="70" cy="70" r="${circleRadius}" fill="none" stroke="${this.theme.background.tertiary}" stroke-width="8" />
            <circle cx="70" cy="70" r="${circleRadius}" fill="none" stroke="${scoreCategory.color}" stroke-width="8" stroke-dasharray="${circumference}" stroke-dashoffset="${strokeDashoffset}" stroke-linecap="round" style="transform: rotate(-90deg); transform-origin: 70px 70px; transition: stroke-dashoffset 0.5s;" />
            <text x="70" y="70" font-size="28" font-weight="bold" text-anchor="middle" dominant-baseline="middle" fill="${scoreCategory.color}" font-family="${t.typography.fontFamily.mono}">${Math.round(threatScore)}</text>
            <text x="70" y="90" font-size="12" text-anchor="middle" dominant-baseline="middle" fill="${this.theme.text.secondary}">/100</text>
          </svg>
          <div style="font-size: ${t.typography.fontSize.sm}; color: ${scoreCategory.color}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase; letter-spacing: 0.5px;">${scoreCategory.label}</div>
        </div>
      `,
      metadata: {
        threatScore,
        category: scoreCategory.label,
        percentage: Math.round(percentage),
      },
    };
  }

  generateRiskIndicator(severity = 'MEDIUM', label = 'Risk Level') {
    const riskColor = this.getSeverityColor(severity);
    const t = this.designTokens;

    return {
      type: 'risk-indicator',
      html: `
        <div class="risk-indicator" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]}; display: flex; align-items: center; gap: ${t.spacing[3]};">
          <div style="width: 16px; height: 16px; border-radius: 50%; background: ${riskColor}; box-shadow: 0 0 12px ${riskColor}80;"></div>
          <div>
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">${label}</div>
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${riskColor}; font-weight: ${t.typography.fontWeight.bold};">${severity}</div>
          </div>
        </div>
      `,
      metadata: {
        severity,
        label,
        color: riskColor,
      },
    };
  }

  generateConfidenceIndicator(confidence = 0, label = 'Confidence') {
    const confidenceColor = this.getConfidenceColor(confidence);
    const confidencePercent = Math.round(confidence * 100);
    const t = this.designTokens;

    return {
      type: 'confidence-indicator',
      html: `
        <div class="confidence-indicator" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]};">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: ${t.spacing[3]};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">${label}</div>
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${confidenceColor}; font-weight: ${t.typography.fontWeight.bold};">${confidencePercent}%</div>
          </div>
          <div style="width: 100%; height: 4px; background: ${this.theme.background.tertiary}; border-radius: ${t.radius.full}; overflow: hidden;">
            <div style="height: 100%; width: ${confidencePercent}%; background: linear-gradient(90deg, ${confidenceColor} 0%, ${this.getConfidenceColor(Math.min(confidence + 0.2, 1))} 100%); transition: width 0.3s;"></div>
          </div>
        </div>
      `,
      metadata: {
        confidence,
        confidencePercent,
        label,
        color: confidenceColor,
      },
    };
  }

  generateLiveIntelligenceBadge(status = 'active', timestamp = null) {
    const statusConfig = {
      active: { color: this.designTokens.colors.success, label: 'Live', pulse: true },
      updated: { color: this.designTokens.colors.accent[500], label: 'Updated', pulse: false },
      stale: { color: this.designTokens.colors.warning, label: 'Stale', pulse: false },
      offline: { color: this.designTokens.colors.critical, label: 'Offline', pulse: false },
    };

    const config = statusConfig[status] || statusConfig.offline;
    const timeString = timestamp ? new Date(timestamp).toLocaleTimeString() : 'Unknown';
    const t = this.designTokens;

    return {
      type: 'live-intelligence-badge',
      html: `
        <div class="live-badge" style="display: inline-flex; align-items: center; gap: ${t.spacing[2]}; background: ${config.color}20; border: 1px solid ${config.color}; border-radius: ${t.radius.full}; padding: ${t.spacing[2]} ${t.spacing[3]};">
          <div style="width: 8px; height: 8px; border-radius: 50%; background: ${config.color}; ${config.pulse ? 'animation: pulse 2s infinite;' : ''}"></div>
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${config.color}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase;">
            ${config.label}
          </div>
          ${timestamp ? `<div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-left: ${t.spacing[1]};">${timeString}</div>` : ''}
        </div>
      `,
      metadata: {
        status,
        label: config.label,
        color: config.color,
        timestamp,
      },
    };
  }

  generateDetectionReadinessWidget(enhancement = {}) {
    const {
      detectionCoverage = 0,
      coverageDetails = { edrs: 0, siem: 0, ndr: 0, unknown: 0 },
    } = enhancement.presentationEnhancements?.coverPage?.sections?.threatInformation || {};

    const t = this.designTokens;
    const detectionSystems = [
      { label: 'EDR/XDR', coverage: coverageDetails.edrs || 0, icon: '▲' },
      { label: 'SIEM', coverage: coverageDetails.siem || 0, icon: '◉' },
      { label: 'NDR/NPD', coverage: coverageDetails.ndr || 0, icon: '⧉' },
    ];

    const detectionHTML = detectionSystems.map(system => {
      const percent = Math.round(system.coverage * 100);
      return `
        <div style="margin-bottom: ${t.spacing[3]};">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: ${t.spacing[2]};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">${system.icon} ${system.label}</div>
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold};">${percent}%</div>
          </div>
          <div style="height: 3px; background: ${this.theme.background.tertiary}; border-radius: ${t.radius.full}; overflow: hidden;">
            <div style="height: 100%; width: ${percent}%; background: ${this.getStatusColor(percent > 70 ? 'success' : percent > 40 ? 'warning' : 'critical')};"></div>
          </div>
        </div>
      `;
    }).join('');

    return {
      type: 'detection-readiness-widget',
      html: `
        <div class="detection-readiness" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[4]}; letter-spacing: 0.5px;">Detection Coverage</div>
          <div style="font-size: ${t.typography.fontSize.lg}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold}; margin-bottom: ${t.spacing[4]};">
            ${Math.round(detectionCoverage * 100)}% Covered
          </div>
          ${detectionHTML}
        </div>
      `,
      metadata: {
        overallCoverage: Math.round(detectionCoverage * 100),
        systems: detectionSystems.map(s => ({ label: s.label, coverage: Math.round(s.coverage * 100) })),
      },
    };
  }

  generateEvidenceCounter(evidence = []) {
    const totalEvidence = evidence.length;
    const byType = {};

    for (const item of evidence) {
      const type = item.type || 'unknown';
      byType[type] = (byType[type] || 0) + 1;
    }

    const t = this.designTokens;
    const typeElements = Object.entries(byType).map(([type, count]) => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: ${t.spacing[2]}; border-bottom: 1px solid ${this.theme.border.primary};">
        <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: capitalize;">${type}</div>
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold}; font-family: ${t.typography.fontFamily.mono};">${count}</div>
      </div>
    `).join('');

    return {
      type: 'evidence-counter',
      html: `
        <div class="evidence-counter" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[4]}; min-width: 180px;">
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[3]}; letter-spacing: 0.5px;">Evidence Items</div>
          <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold}; font-family: ${t.typography.fontFamily.mono}; margin-bottom: ${t.spacing[3]};">${totalEvidence}</div>
          <div style="border-top: 1px solid ${this.theme.border.primary}; padding-top: ${t.spacing[3]};">
            ${typeElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.xs + ';">No evidence available</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalEvidence,
        byType,
      },
    };
  }

  generateIOCCounter(iocs = []) {
    const totalIOCs = iocs.length;
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

    for (const ioc of iocs) {
      const severity = ioc.severity || 'MEDIUM';
      if (severity in bySeverity) {
        bySeverity[severity]++;
      }
    }

    const t = this.designTokens;
    const severityElements = Object.entries(bySeverity)
      .filter(([, count]) => count > 0)
      .map(([severity, count]) => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: ${t.spacing[2]}; border-bottom: 1px solid ${this.theme.border.primary};">
          <div style="display: flex; align-items: center; gap: ${t.spacing[2]};">
            <div style="width: 8px; height: 8px; border-radius: 50%; background: ${this.getSeverityColor(severity)};"></div>
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">${severity}</div>
          </div>
          <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold}; font-family: ${t.typography.fontFamily.mono};">${count}</div>
        </div>
      `).join('');

    return {
      type: 'ioc-counter',
      html: `
        <div class="ioc-counter" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[4]}; min-width: 180px;">
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[3]}; letter-spacing: 0.5px;">IOC Count</div>
          <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${t.colors.critical}; font-weight: ${t.typography.fontWeight.bold}; font-family: ${t.typography.fontFamily.mono}; margin-bottom: ${t.spacing[3]};">${totalIOCs}</div>
          <div style="border-top: 1px solid ${this.theme.border.primary}; padding-top: ${t.spacing[3]};">
            ${severityElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.xs + ';">No IOCs available</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalIOCs,
        bySeverity,
      },
    };
  }

  generateSOCDashboard(product = {}, investigation = {}, enhancement = {}) {
    const threatHeader = this.generateThreatCommandHeader(investigation);
    const executiveRibbon = this.generateExecutiveCommandRibbon(investigation);
    const metricsRibbon = this.generateSOCMetricsRibbon(enhancement);
    const threatScoreWidget = this.generateThreatScoreWidget(investigation, enhancement);
    const riskIndicator = this.generateRiskIndicator(investigation.severity || 'MEDIUM');
    const confidenceIndicator = this.generateConfidenceIndicator(investigation.confidence || 0);
    const liveIntelligence = this.generateLiveIntelligenceBadge('active', new Date().toISOString());
    const detectionReadiness = this.generateDetectionReadinessWidget(enhancement);
    const evidenceCounter = this.generateEvidenceCounter(investigation.findings || []);
    const iocCounter = this.generateIOCCounter(investigation.iocs || []);
    const t = this.designTokens;

    return {
      type: 'soc-command-center-dashboard',
      html: `
        <div class="soc-command-center" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; min-height: 100vh;">
          ${threatHeader.html}
          ${executiveRibbon.html}
          ${metricsRibbon.html}
          <div style="padding: ${t.spacing[8]};">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
              ${threatScoreWidget.html}
              ${detectionReadiness.html}
              <div style="display: flex; flex-direction: column; gap: ${t.spacing[4]};">
                ${riskIndicator.html}
                ${confidenceIndicator.html}
              </div>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
              ${evidenceCounter.html}
              ${iocCounter.html}
            </div>
            <div style="display: flex; justify-content: flex-start; gap: ${t.spacing[4]};">
              ${liveIntelligence.html}
            </div>
          </div>
        </div>
      `,
      components: {
        threatHeader,
        executiveRibbon,
        metricsRibbon,
        threatScoreWidget,
        riskIndicator,
        confidenceIndicator,
        liveIntelligence,
        detectionReadiness,
        evidenceCounter,
        iocCounter,
      },
      metadata: {
        productId: product.id,
        threatLevel: investigation.severity || 'UNKNOWN',
        threatActors: (investigation.threatActors || []).map(a => a.name || a),
        totalEvidence: (investigation.findings || []).length,
        totalIOCs: (investigation.iocs || []).length,
        generatedAt: new Date().toISOString(),
      },
    };
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

  getConfidenceColor(confidence) {
    const t = this.designTokens;
    if (confidence >= 0.8) return t.colors.success;
    if (confidence >= 0.6) return t.colors.accent[500];
    if (confidence >= 0.4) return t.colors.warning;
    return t.colors.critical;
  }

  getStatusColor(status) {
    const t = this.designTokens;
    const statusMap = {
      success: t.colors.success,
      warning: t.colors.warning,
      critical: t.colors.critical,
      info: t.colors.accent[500],
    };
    return statusMap[status] || t.colors.accent[500];
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

module.exports = { SentinelApexSOCCommandCenter };
