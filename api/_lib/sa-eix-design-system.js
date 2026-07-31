'use strict';

class SentinelApexEIXDesignSystem {
  constructor(brandConfig = {}) {
    this.brandConfig = brandConfig;
    this.tokens = this.generateDesignTokens();
    this.components = new Map();
    this.themes = this.generateThemes();
  }

  generateDesignTokens() {
    return {
      // Typography
      typography: {
        fontFamily: {
          heading: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
          body: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
          mono: "'JetBrains Mono', 'Courier New', monospace",
        },
        fontSize: {
          xs: '11px',
          sm: '12px',
          base: '14px',
          md: '16px',
          lg: '18px',
          xl: '20px',
          '2xl': '24px',
          '3xl': '28px',
          '4xl': '32px',
          '5xl': '40px',
        },
        fontWeight: {
          light: 300,
          normal: 400,
          medium: 500,
          semibold: 600,
          bold: 700,
          extrabold: 800,
        },
        lineHeight: {
          tight: 1.2,
          normal: 1.5,
          relaxed: 1.75,
          loose: 2,
        },
      },

      // Color System
      colors: {
        primary: {
          50: '#F0F4F8',
          100: '#D9E2EC',
          200: '#B2CCE0',
          300: '#8CB5D4',
          400: '#6B9FC8',
          500: '#4A89BC',
          600: '#0A3A5C',
          700: '#082E4A',
          800: '#062238',
          900: '#051B2C',
        },
        secondary: {
          50: '#F0F5FA',
          100: '#D9E5F2',
          200: '#B2CDE5',
          300: '#8BB5D8',
          400: '#6B9DCB',
          500: '#1B5E8E',
          600: '#154B75',
          700: '#0F385C',
          800: '#0A2543',
          900: '#052A2A',
        },
        accent: {
          50: '#FFF5EB',
          100: '#FDE7D0',
          200: '#FBD0A1',
          300: '#F9B872',
          400: '#F7A043',
          500: '#FF6B35',
          600: '#E55C2B',
          700: '#CC4D21',
          800: '#B33E17',
          900: '#9A2F0D',
        },
        success: '#2ECC71',
        warning: '#F39C12',
        critical: '#E74C3C',
        neutral: {
          50: '#F8F9FA',
          100: '#E9ECEF',
          200: '#DEE2E6',
          300: '#CED4DA',
          400: '#ADB5BD',
          500: '#6C757D',
          600: '#495057',
          700: '#343A40',
          800: '#212529',
          900: '#0F1419',
        },
      },

      // Spacing
      spacing: {
        0: '0',
        1: '4px',
        2: '8px',
        3: '12px',
        4: '16px',
        5: '20px',
        6: '24px',
        8: '32px',
        10: '40px',
        12: '48px',
        16: '64px',
        20: '80px',
      },

      // Border Radius
      radius: {
        none: '0',
        sm: '4px',
        md: '6px',
        lg: '8px',
        xl: '12px',
        '2xl': '16px',
        full: '9999px',
      },

      // Shadows
      shadow: {
        none: 'none',
        sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
      },

      // Z-Index
      zIndex: {
        hide: -1,
        base: 0,
        dropdown: 1000,
        sticky: 1020,
        fixed: 1030,
        backdrop: 1040,
        offcanvas: 1050,
        modal: 1060,
        popover: 1070,
        tooltip: 1080,
      },

      // Breakpoints
      breakpoints: {
        xs: '320px',
        sm: '640px',
        md: '768px',
        lg: '1024px',
        xl: '1280px',
        '2xl': '1536px',
      },
    };
  }

  generateThemes() {
    return {
      dark: {
        background: {
          primary: '#0D1117',
          secondary: '#161B22',
          tertiary: '#21262D',
          surface: '#1C2128',
        },
        text: {
          primary: '#C9D1D9',
          secondary: '#8B949E',
          tertiary: '#6E7681',
          inverse: '#0D1117',
        },
        border: {
          primary: '#30363D',
          secondary: '#21262D',
        },
      },
      light: {
        background: {
          primary: '#FFFFFF',
          secondary: '#F6F8FB',
          tertiary: '#EAEEF2',
          surface: '#FFFFFF',
        },
        text: {
          primary: '#24292F',
          secondary: '#57606A',
          tertiary: '#6E7781',
          inverse: '#FFFFFF',
        },
        border: {
          primary: '#D0D7DE',
          secondary: '#EAEEF2',
        },
      },
    };
  }

  // Component Generators

  generateKPICard(title, value, metric, status = 'normal') {
    const statusColor = this.getStatusColor(status);
    return {
      type: 'kpi-card',
      title,
      value,
      metric,
      status,
      statusColor,
      html: `
        <div class="kpi-card kpi-card--${status}">
          <div class="kpi-header">
            <h3 class="kpi-title">${this.escapeHtml(title)}</h3>
            <span class="kpi-status" style="color: ${statusColor}">●</span>
          </div>
          <div class="kpi-value">${this.escapeHtml(String(value))}</div>
          <div class="kpi-metric">${this.escapeHtml(metric)}</div>
        </div>
      `,
    };
  }

  generateRiskGauge(label, value, max = 100) {
    const percentage = Math.min((value / max) * 100, 100);
    const color = this.getRiskColor(percentage);
    return {
      type: 'risk-gauge',
      label,
      value,
      percentage,
      html: `
        <div class="risk-gauge">
          <div class="gauge-label">${this.escapeHtml(label)}</div>
          <div class="gauge-container">
            <svg viewBox="0 0 200 100" class="gauge-svg">
              <path d="M 20 80 A 60 60 0 0 1 180 80" fill="none" stroke="#30363D" stroke-width="8"/>
              <path d="M 20 80 A 60 60 0 0 1 ${20 + (160 * percentage / 100)} 80" fill="none" stroke="${color}" stroke-width="8"/>
              <text x="100" y="75" text-anchor="middle" font-size="24" font-weight="bold">${Math.round(value)}</text>
            </svg>
          </div>
        </div>
      `,
    };
  }

  generateEvidenceCard(evidence) {
    const { type, value, severity, confidence, validated } = evidence;
    return {
      type: 'evidence-card',
      evidence,
      html: `
        <div class="evidence-card">
          <div class="evidence-type">${this.escapeHtml(type)}</div>
          <div class="evidence-value" style="font-family: monospace">${this.escapeHtml(value)}</div>
          <div class="evidence-meta">
            <span class="severity" style="color: ${this.getSeverityColor(severity)}">${this.escapeHtml(severity)}</span>
            <span class="confidence">${Math.round(confidence * 100)}%</span>
            ${validated ? '<span class="validated">✓</span>' : ''}
          </div>
        </div>
      `,
    };
  }

  generateThreatCard(threat) {
    const { name, severity, confidence, status } = threat;
    return {
      type: 'threat-card',
      threat,
      html: `
        <div class="threat-card threat-card--${status || 'active'}">
          <div class="threat-header">
            <h4 class="threat-name">${this.escapeHtml(name)}</h4>
            <span class="threat-severity" style="color: ${this.getSeverityColor(severity)}">${severity}</span>
          </div>
          <div class="threat-confidence">Confidence: ${Math.round(confidence * 100)}%</div>
          <div class="threat-status">${this.escapeHtml(status || 'Active')}</div>
        </div>
      `,
    };
  }

  generateCallout(type, content, icon = null) {
    const iconMap = {
      info: 'ℹ️',
      warning: '⚠️',
      critical: '🔴',
      success: '✓',
    };
    return {
      type: 'callout',
      calloutType: type,
      html: `
        <div class="callout callout--${type}">
          <div class="callout-icon">${icon || iconMap[type] || ''}</div>
          <div class="callout-content">${this.escapeHtml(content)}</div>
        </div>
      `,
    };
  }

  generateTable(columns, rows, options = {}) {
    const { striped = true, bordered = true } = options;
    let html = `<table class="data-table ${striped ? 'striped' : ''} ${bordered ? 'bordered' : ''}">`;
    html += '<thead><tr>';
    for (const col of columns) {
      html += `<th>${this.escapeHtml(col)}</th>`;
    }
    html += '</tr></thead>';
    html += '<tbody>';
    for (const row of rows) {
      html += '<tr>';
      for (const cell of row) {
        html += `<td>${this.escapeHtml(String(cell))}</td>`;
      }
      html += '</tr>';
    }
    html += '</tbody></table>';
    return { type: 'table', html };
  }

  generateChart(type, data, options = {}) {
    const { title = '', height = 300 } = options;
    return {
      type: 'chart',
      chartType: type,
      data,
      html: `
        <div class="chart-container" style="height: ${height}px">
          <h4>${this.escapeHtml(title)}</h4>
          <div class="chart-placeholder">[${type} chart - ready for D3/Recharts integration]</div>
        </div>
      `,
    };
  }

  generateMitreHeatmap(tactics) {
    let html = '<div class="mitre-heatmap"><table class="mitre-matrix">';
    html += '<thead><tr>';
    for (const tactic of Object.keys(tactics)) {
      html += `<th>${this.escapeHtml(tactic)}</th>`;
    }
    html += '</tr></thead>';
    html += '<tbody>';

    const techniques = new Set();
    for (const tacticTechs of Object.values(tactics)) {
      if (Array.isArray(tacticTechs)) {
        tacticTechs.forEach(t => techniques.add(t.technique || t));
      }
    }

    for (const technique of Array.from(techniques).slice(0, 10)) {
      html += '<tr>';
      for (const tactic of Object.keys(tactics)) {
        const tacticTechs = tactics[tactic];
        const hasTechnique = Array.isArray(tacticTechs) && tacticTechs.some(t => (t.technique || t) === technique);
        html += `<td class="mitre-cell ${hasTechnique ? 'covered' : ''}">${hasTechnique ? '✓' : ''}</td>`;
      }
      html += '</tr>';
    }

    html += '</tbody></table></div>';
    return { type: 'mitre-heatmap', html };
  }

  generateComponentCSS(theme = 'dark') {
    const themeVars = this.themes[theme];
    return `
    /* KPI Card */
    .kpi-card {
      background: ${themeVars.background.secondary};
      border: 1px solid ${themeVars.border.primary};
      border-radius: ${this.tokens.radius.lg};
      padding: ${this.tokens.spacing[4]};
      margin-bottom: ${this.tokens.spacing[4]};
    }

    .kpi-card--normal { border-left: 4px solid ${this.tokens.colors.primary[500]}; }
    .kpi-card--warning { border-left: 4px solid ${this.tokens.colors.warning}; }
    .kpi-card--critical { border-left: 4px solid ${this.tokens.colors.critical}; }
    .kpi-card--success { border-left: 4px solid ${this.tokens.colors.success}; }

    .kpi-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: ${this.tokens.spacing[2]};
    }

    .kpi-title {
      margin: 0;
      font-size: ${this.tokens.typography.fontSize.sm};
      font-weight: ${this.tokens.typography.fontWeight.semibold};
      color: ${themeVars.text.secondary};
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .kpi-value {
      font-size: ${this.tokens.typography.fontSize['2xl']};
      font-weight: ${this.tokens.typography.fontWeight.bold};
      color: ${themeVars.text.primary};
      margin-bottom: ${this.tokens.spacing[1]};
    }

    .kpi-metric {
      font-size: ${this.tokens.typography.fontSize.sm};
      color: ${themeVars.text.tertiary};
    }

    /* Risk Gauge */
    .risk-gauge {
      padding: ${this.tokens.spacing[4]};
      margin-bottom: ${this.tokens.spacing[4]};
    }

    .gauge-label {
      font-size: ${this.tokens.typography.fontSize.md};
      font-weight: ${this.tokens.typography.fontWeight.medium};
      color: ${themeVars.text.primary};
      margin-bottom: ${this.tokens.spacing[2]};
    }

    .gauge-container {
      max-width: 300px;
    }

    .gauge-svg {
      width: 100%;
      height: auto;
    }

    /* Evidence Card */
    .evidence-card {
      background: ${themeVars.background.tertiary};
      border: 1px solid ${themeVars.border.secondary};
      border-radius: ${this.tokens.radius.md};
      padding: ${this.tokens.spacing[3]};
      margin-bottom: ${this.tokens.spacing[2]};
      font-size: ${this.tokens.typography.fontSize.sm};
    }

    .evidence-type {
      color: ${themeVars.text.secondary};
      font-weight: ${this.tokens.typography.fontWeight.semibold};
      margin-bottom: ${this.tokens.spacing[1]};
      text-transform: uppercase;
      font-size: 10px;
    }

    .evidence-value {
      color: ${themeVars.text.primary};
      word-break: break-all;
      margin-bottom: ${this.tokens.spacing[2]};
      background: ${themeVars.background.primary};
      padding: ${this.tokens.spacing[2]};
      border-radius: ${this.tokens.radius.sm};
      font-size: ${this.tokens.typography.fontSize.xs};
    }

    .evidence-meta {
      display: flex;
      gap: ${this.tokens.spacing[2]};
      font-size: ${this.tokens.typography.fontSize.xs};
    }

    .evidence-meta .severity,
    .evidence-meta .confidence,
    .evidence-meta .validated {
      font-weight: ${this.tokens.typography.fontWeight.semibold};
    }

    /* Threat Card */
    .threat-card {
      background: ${themeVars.background.secondary};
      border: 1px solid ${themeVars.border.primary};
      border-radius: ${this.tokens.radius.lg};
      padding: ${this.tokens.spacing[4]};
      margin-bottom: ${this.tokens.spacing[4]};
    }

    .threat-card--active { border-left: 4px solid ${this.tokens.colors.critical}; }
    .threat-card--resolved { border-left: 4px solid ${this.tokens.colors.success}; }
    .threat-card--monitoring { border-left: 4px solid ${this.tokens.colors.warning}; }

    .threat-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: ${this.tokens.spacing[2]};
    }

    .threat-name {
      margin: 0;
      font-size: ${this.tokens.typography.fontSize.lg};
      font-weight: ${this.tokens.typography.fontWeight.semibold};
      color: ${themeVars.text.primary};
    }

    .threat-severity {
      font-weight: ${this.tokens.typography.fontWeight.bold};
      font-size: ${this.tokens.typography.fontSize.md};
    }

    .threat-confidence {
      color: ${themeVars.text.secondary};
      font-size: ${this.tokens.typography.fontSize.sm};
      margin-bottom: ${this.tokens.spacing[1]};
    }

    .threat-status {
      color: ${themeVars.text.tertiary};
      font-size: ${this.tokens.typography.fontSize.sm};
    }

    /* Callout */
    .callout {
      display: flex;
      gap: ${this.tokens.spacing[3]};
      padding: ${this.tokens.spacing[4]};
      border-radius: ${this.tokens.radius.lg};
      margin-bottom: ${this.tokens.spacing[4]};
      border-left: 4px solid;
    }

    .callout--info {
      background: rgba(59, 130, 246, 0.1);
      border-left-color: #3B82F6;
      color: #1E40AF;
    }

    .callout--warning {
      background: rgba(243, 156, 18, 0.1);
      border-left-color: ${this.tokens.colors.warning};
      color: #7C2D12;
    }

    .callout--critical {
      background: rgba(220, 38, 38, 0.1);
      border-left-color: ${this.tokens.colors.critical};
      color: #7F1D1D;
    }

    .callout--success {
      background: rgba(34, 197, 94, 0.1);
      border-left-color: ${this.tokens.colors.success};
      color: #166534;
    }

    .callout-icon {
      flex-shrink: 0;
      font-size: ${this.tokens.typography.fontSize.lg};
    }

    .callout-content {
      flex: 1;
    }

    /* Data Table */
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: ${this.tokens.typography.fontSize.sm};
    }

    .data-table th {
      background: ${themeVars.background.tertiary};
      color: ${themeVars.text.primary};
      padding: ${this.tokens.spacing[3]};
      text-align: left;
      font-weight: ${this.tokens.typography.fontWeight.semibold};
      border-bottom: 2px solid ${themeVars.border.primary};
    }

    .data-table td {
      padding: ${this.tokens.spacing[3]};
      color: ${themeVars.text.secondary};
      border-bottom: 1px solid ${themeVars.border.secondary};
    }

    .data-table.striped tbody tr:nth-child(odd) {
      background: ${themeVars.background.tertiary};
    }

    .data-table.bordered {
      border: 1px solid ${themeVars.border.primary};
      border-radius: ${this.tokens.radius.lg};
      overflow: hidden;
    }

    /* Chart */
    .chart-container {
      background: ${themeVars.background.secondary};
      border: 1px solid ${themeVars.border.primary};
      border-radius: ${this.tokens.radius.lg};
      padding: ${this.tokens.spacing[4]};
      margin-bottom: ${this.tokens.spacing[4]};
    }

    .chart-container h4 {
      margin-top: 0;
      margin-bottom: ${this.tokens.spacing[3]};
      color: ${themeVars.text.primary};
    }

    .chart-placeholder {
      display: flex;
      align-items: center;
      justify-content: center;
      height: 200px;
      color: ${themeVars.text.tertiary};
      background: ${themeVars.background.primary};
      border-radius: ${this.tokens.radius.md};
    }

    /* MITRE Heatmap */
    .mitre-heatmap {
      overflow-x: auto;
      margin-bottom: ${this.tokens.spacing[4]};
    }

    .mitre-matrix {
      width: 100%;
      border-collapse: collapse;
      font-size: ${this.tokens.typography.fontSize.xs};
    }

    .mitre-matrix th {
      background: ${themeVars.background.tertiary};
      padding: ${this.tokens.spacing[2]};
      color: ${themeVars.text.primary};
      text-align: center;
      font-weight: ${this.tokens.typography.fontWeight.semibold};
    }

    .mitre-cell {
      width: 40px;
      height: 40px;
      border: 1px solid ${themeVars.border.secondary};
      text-align: center;
      vertical-align: middle;
      background: ${themeVars.background.tertiary};
    }

    .mitre-cell.covered {
      background: ${this.tokens.colors.primary[600]};
      color: white;
      font-weight: bold;
    }
    `;
  }

  // Utility Methods

  getStatusColor(status) {
    const colors = {
      normal: this.tokens.colors.primary[500],
      warning: this.tokens.colors.warning,
      critical: this.tokens.colors.critical,
      success: this.tokens.colors.success,
    };
    return colors[status] || colors.normal;
  }

  getSeverityColor(severity) {
    const colors = {
      CRITICAL: this.tokens.colors.critical,
      HIGH: '#E67E22',
      MEDIUM: this.tokens.colors.warning,
      LOW: this.tokens.colors.success,
      INFO: '#3B82F6',
    };
    return colors[String(severity).toUpperCase()] || this.tokens.colors.neutral[500];
  }

  getRiskColor(percentage) {
    if (percentage >= 80) return this.tokens.colors.critical;
    if (percentage >= 60) return '#E67E22';
    if (percentage >= 40) return this.tokens.colors.warning;
    return this.tokens.colors.success;
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

module.exports = { SentinelApexEIXDesignSystem };
