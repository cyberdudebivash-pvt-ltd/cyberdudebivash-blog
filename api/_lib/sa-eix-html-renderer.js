'use strict';

class SentinelApexEIXHTMLRenderer {
  constructor(brandingConfig = {}) {
    const defaults = this.getDefaultBranding();
    this.brandingConfig = {
      ...defaults,
      ...brandingConfig,
      colors: { ...defaults.colors, ...((brandingConfig && brandingConfig.colors) || {}) },
      typography: { ...defaults.typography, ...((brandingConfig && brandingConfig.typography) || {}) },
    };
    this.templates = new Map();
    this.cssCache = new Map();
  }

  getDefaultBranding() {
    return {
      name: 'Sentinel APEX',
      colors: {
        primary: '#0A3A5C',
        secondary: '#1B5E8E',
        accent: '#FF6B35',
        success: '#2ECC71',
        warning: '#F39C12',
        critical: '#E74C3C',
        neutral: '#34495E',
        light: '#ECF0F1',
        dark: '#2C3E50',
      },
      typography: {
        heading: 'Inter, -apple-system, sans-serif',
        body: 'Inter, -apple-system, sans-serif',
        mono: 'JetBrains Mono, monospace',
      },
    };
  }

  renderEnhancedReport(enhancement, options = {}) {
    const { theme = 'dark', mode = 'executive', responsive = true } = options;

    let html = '';

    if (enhancement.presentationEnhancements.coverPage) {
      html += this.renderCoverPage(enhancement.presentationEnhancements.coverPage);
    }

    if (enhancement.presentationEnhancements.dashboardHeader) {
      html += this.renderDashboardHeader(enhancement.presentationEnhancements.dashboardHeader);
    }

    if (enhancement.presentationEnhancements.executiveCards) {
      html += this.renderExecutiveCards(enhancement.presentationEnhancements.executiveCards);
    }

    if (enhancement.presentationEnhancements.evidenceGallery) {
      html += this.renderEvidenceGallery(enhancement.presentationEnhancements.evidenceGallery);
    }

    if (enhancement.presentationEnhancements.interactiveDiagrams) {
      html += this.renderDiagrams(enhancement.presentationEnhancements.interactiveDiagrams);
    }

    if (enhancement.presentationEnhancements.decisionCenter) {
      html += this.renderDecisionCenter(enhancement.presentationEnhancements.decisionCenter, mode);
    }

    const css = this.generateCSS(theme, responsive);
    return this.wrapInDocument(html, css, theme);
  }

  renderCoverPage(coverPage) {
    const header = coverPage.sections.header;
    const threatInfo = coverPage.sections.threatInformation;

    let html = `
    <section class="cover-page" data-section="cover">
      <div class="cover-container">
        <div class="cover-header">
          <div class="cover-badge">${header.classification}</div>
          <h1 class="cover-title">${this.escapeHtml(header.title)}</h1>
          <p class="cover-subtitle">${this.escapeHtml(header.subtitle || '')}</p>
        </div>

        <div class="cover-threat-metrics">
          <div class="threat-score-box">
            <div class="score-value" style="color: ${this.getThreatColor(header.threatScore)}">
              ${header.threatScore}
            </div>
            <div class="score-label">Threat Score</div>
          </div>

          <div class="metric-box">
            <div class="metric-label">Severity</div>
            <div class="metric-value" style="color: ${this.getThreatLevelColor(header.threatLevel)}">
              ${header.threatLevel}
            </div>
          </div>

          <div class="metric-box">
            <div class="metric-label">Confidence</div>
            <div class="metric-value">${Math.round((threatInfo.confidence || 0) * 100)}%</div>
          </div>

          <div class="metric-box">
            <div class="metric-label">Detection Coverage</div>
            <div class="metric-value">${Math.round(threatInfo.detectionCoverage || 0)}%</div>
          </div>
        </div>

        <div class="cover-business-impact">
          <h3>Business Impact</h3>
          <p>${this.escapeHtml(threatInfo.businessImpact)}</p>
          <p>Operational Risk: <strong>${threatInfo.operationalRisk}</strong></p>
        </div>

        ${this.renderCoverThreatActors(coverPage.sections)}
        ${this.renderCoverIndustries(coverPage.sections)}
        ${this.renderCoverKeyMetrics(coverPage.sections.keyMetrics)}
      </div>
    </section>
    `;

    return html;
  }

  renderCoverThreatActors(sections) {
    if (!sections.threatActors || sections.threatActors.length === 0) return '';

    let html = '<div class="cover-threat-actors"><h3>Threat Actors</h3><div class="actor-list">';
    for (const actor of sections.threatActors.slice(0, 5)) {
      html += `<span class="actor-badge">${this.escapeHtml(actor.name)}</span>`;
    }
    html += '</div></div>';
    return html;
  }

  renderCoverIndustries(sections) {
    if (!sections.affectedIndustries || sections.affectedIndustries.length === 0) return '';

    let html = '<div class="cover-industries"><h3>Affected Industries</h3><div class="industry-list">';
    for (const industry of sections.affectedIndustries.slice(0, 5)) {
      html += `<span class="industry-tag">${this.escapeHtml(industry)}</span>`;
    }
    html += '</div></div>';
    return html;
  }

  renderCoverKeyMetrics(metrics) {
    return `
    <div class="cover-metrics-summary">
      <div class="metric"><span class="label">Findings:</span> <span class="value">${metrics.findingsCount}</span></div>
      <div class="metric"><span class="label">IOCs:</span> <span class="value">${metrics.iocsCount}</span></div>
      <div class="metric"><span class="label">Infrastructure:</span> <span class="value">${metrics.infrastructureCount}</span></div>
      <div class="metric"><span class="label">Techniques:</span> <span class="value">${metrics.techniquesCount}</span></div>
    </div>
    `;
  }

  renderDashboardHeader(dashboard) {
    let html = '<section class="dashboard-header" data-section="dashboard">';
    html += '<div class="dashboard-title"><h2>Operational Intelligence Dashboard</h2></div>';
    html += '<div class="widgets-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))">';

    for (const widget of dashboard.widgets) {
      html += `
      <div class="widget" data-widget="${widget.name}">
        <div class="widget-icon">${this.getWidgetIcon(widget.icon)}</div>
        <div class="widget-value" style="color: ${widget.color || '#FFF'}">${this.escapeHtml(String(widget.value))}</div>
        <div class="widget-label">${this.escapeHtml(widget.name)}</div>
      </div>
      `;
    }

    html += '</div></section>';
    return html;
  }

  renderExecutiveCards(cards) {
    if (!Array.isArray(cards) || cards.length === 0) return '';

    let html = '<section class="executive-cards" data-section="cards">';
    html += '<div class="cards-grid">';

    for (const card of cards) {
      const colorClass = this.getCategoryColorClass(card.category);
      html += `
      <div class="card ${colorClass}" data-card="${card.category}">
        <div class="card-header">
          <h3 class="card-title">${this.escapeHtml(card.title)}</h3>
          <span class="card-icon">${this.getCardIcon(card.icon)}</span>
        </div>
        <div class="card-content">
          ${this.renderCardContent(card.content)}
        </div>
      </div>
      `;
    }

    html += '</div></section>';
    return html;
  }

  renderCardContent(content) {
    if (!content) return '';

    let html = '';
    for (const [key, value] of Object.entries(content)) {
      if (Array.isArray(value)) {
        html += `<div class="card-field"><strong>${this.humanizeKey(key)}:</strong> ${value.join(', ')}</div>`;
      } else if (typeof value === 'object') {
        html += `<div class="card-field"><strong>${this.humanizeKey(key)}:</strong> ${JSON.stringify(value)}</div>`;
      } else {
        html += `<div class="card-field"><strong>${this.humanizeKey(key)}:</strong> ${this.escapeHtml(String(value))}</div>`;
      }
    }
    return html;
  }

  renderEvidenceGallery(gallery) {
    if (!gallery.sections || gallery.sections.length === 0) return '';

    let html = '<section class="evidence-gallery" data-section="evidence">';
    html += '<div class="gallery-header"><h2>Evidence Gallery</h2></div>';

    for (const section of gallery.sections) {
      html += `
      <div class="gallery-section" data-section="${section.title}">
        <div class="section-header">
          <h3 class="section-title">${this.escapeHtml(section.title)}</h3>
          <span class="section-count">${section.count} items</span>
        </div>
        <div class="section-items">
          ${this.renderGalleryItems(section.items, section.title)}
        </div>
      </div>
      `;
    }

    html += '</section>';
    return html;
  }

  renderGalleryItems(items, sectionType) {
    if (!Array.isArray(items) || items.length === 0) return '<p class="empty-state">No items</p>';

    let html = '';
    for (const item of items.slice(0, 10)) {
      html += '<div class="gallery-item">';

      if (sectionType.includes('Finding')) {
        html += `
        <div class="item-content">
          <div class="item-statement">${this.escapeHtml(item.statement || '')}</div>
          <div class="item-meta">
            <span class="severity" style="color: ${this.getSeverityColor(item.severity)}">${item.severity}</span>
            <span class="confidence">${Math.round((item.confidence || 0) * 100)}%</span>
          </div>
        </div>
        `;
      } else if (sectionType.includes('Indicator')) {
        html += `
        <div class="item-content">
          <div class="item-value" style="font-family: monospace">${this.escapeHtml(item.value)}</div>
          <div class="item-type">${item.type}</div>
          <div class="item-severity" style="color: ${this.getSeverityColor(item.severity)}">${item.severity}</div>
        </div>
        `;
      } else if (sectionType.includes('Technique')) {
        html += `
        <div class="item-content">
          <div class="item-technique">${this.escapeHtml(item.technique || '')}</div>
          <div class="item-tactic">${this.escapeHtml(item.tactic || '')}</div>
        </div>
        `;
      } else {
        html += `<div class="item-content">${JSON.stringify(item)}</div>`;
      }

      html += '</div>';
    }

    if (items.length > 10) {
      html += `<p class="items-truncated">+${items.length - 10} more items</p>`;
    }

    return html;
  }

  renderDiagrams(diagramsData) {
    if (!diagramsData.diagrams || diagramsData.diagrams.length === 0) return '';

    let html = '<section class="diagrams-section" data-section="diagrams">';
    html += '<div class="diagrams-header"><h2>Intelligence Visualizations</h2></div>';

    for (const diagram of diagramsData.diagrams) {
      html += `
      <div class="diagram-container" data-diagram="${diagram.type}">
        <h3 class="diagram-title">${this.escapeHtml(diagram.title)}</h3>
        <div class="diagram-placeholder">
          <p class="placeholder-text">[${diagram.type} diagram - placeholder for SVG/D3 rendering]</p>
          <pre style="font-size: 12px; max-height: 200px; overflow: auto">${this.escapeHtml(JSON.stringify(diagram, null, 2))}</pre>
        </div>
      </div>
      `;
    }

    html += '</section>';
    return html;
  }

  renderDecisionCenter(decisionCenter, mode = 'executive') {
    let html = '<section class="decision-center" data-section="decisions">';
    html += '<div class="decision-header"><h2>Executive Decision Center</h2></div>';
    html += '<div class="decisions-grid">';

    for (const [audienceKey, audienceData] of Object.entries(decisionCenter.audiences)) {
      html += `
      <div class="audience-panel" data-audience="${audienceKey}">
        <div class="audience-title">${this.escapeHtml(audienceData.title)} Decisions</div>

        <div class="decisions-list">
          <h4>Required Decisions</h4>
          <ul>
            ${audienceData.decisions.map(d => `<li>${this.escapeHtml(d)}</li>`).join('')}
          </ul>
        </div>

        <div class="metrics-list">
          <h4>Key Metrics</h4>
          <table class="metrics-table">
            ${audienceData.metrics.map(m => `
            <tr>
              <td class="metric-name">${this.escapeHtml(m.label)}</td>
              <td class="metric-value">${this.escapeHtml(String(m.value))}</td>
            </tr>
            `).join('')}
          </table>
        </div>
      </div>
      `;
    }

    html += '</div></section>';
    return html;
  }

  generateCSS(theme = 'dark', responsive = true) {
    const cacheKey = `${theme}-${responsive}`;
    if (this.cssCache.has(cacheKey)) {
      return this.cssCache.get(cacheKey);
    }

    const isDark = theme === 'dark';
    const bgColor = isDark ? '#0D1117' : '#FFFFFF';
    const fgColor = isDark ? '#C9D1D9' : '#2C3E50';
    const borderColor = isDark ? '#30363D' : '#E1E4E8';
    const cardBg = isDark ? '#161B22' : '#F8F9FA';

    const css = `
    :root {
      --primary-color: ${this.brandingConfig.colors.primary};
      --secondary-color: ${this.brandingConfig.colors.secondary};
      --accent-color: ${this.brandingConfig.colors.accent};
      --success-color: ${this.brandingConfig.colors.success};
      --warning-color: ${this.brandingConfig.colors.warning};
      --critical-color: ${this.brandingConfig.colors.critical};
      --bg-color: ${bgColor};
      --fg-color: ${fgColor};
      --border-color: ${borderColor};
      --card-bg: ${cardBg};
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    html, body {
      background-color: var(--bg-color);
      color: var(--fg-color);
      font-family: ${this.brandingConfig.typography.body};
      line-height: 1.6;
      font-size: 14px;
    }

    section {
      padding: 2rem;
      border-bottom: 1px solid var(--border-color);
      margin-bottom: 2rem;
    }

    h1, h2, h3, h4, h5, h6 {
      font-family: ${this.brandingConfig.typography.heading};
      font-weight: 600;
      margin-bottom: 1rem;
      line-height: 1.2;
    }

    h1 { font-size: 2.5rem; margin-top: 2rem; }
    h2 { font-size: 1.8rem; margin-top: 1.5rem; }
    h3 { font-size: 1.3rem; margin-top: 1rem; }
    h4 { font-size: 1.1rem; }

    /* Cover Page Styles */
    .cover-page {
      background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
      color: #FFF;
      padding: 4rem 2rem;
      text-align: center;
      border: none;
      margin: 0;
    }

    .cover-container {
      max-width: 900px;
      margin: 0 auto;
    }

    .cover-header {
      margin-bottom: 3rem;
    }

    .cover-badge {
      display: inline-block;
      background: rgba(255, 255, 255, 0.2);
      padding: 0.5rem 1rem;
      border-radius: 20px;
      font-size: 0.9rem;
      margin-bottom: 1rem;
    }

    .cover-title {
      color: #FFF;
      font-size: 3rem;
      margin-bottom: 0.5rem;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }

    .cover-threat-metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 2rem;
      margin: 2rem 0;
    }

    .threat-score-box, .metric-box {
      background: rgba(255, 255, 255, 0.1);
      padding: 1.5rem;
      border-radius: 10px;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }

    .score-value {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }

    .score-label, .metric-label {
      font-size: 0.9rem;
      opacity: 0.8;
      text-transform: uppercase;
    }

    .metric-value {
      font-size: 1.5rem;
      font-weight: 600;
      margin-top: 0.5rem;
    }

    /* Dashboard Styles */
    .dashboard-header {
      background: var(--card-bg);
    }

    .widgets-grid {
      display: grid;
      gap: 1rem;
      margin-top: 1.5rem;
    }

    .widget {
      background: var(--bg-color);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1.5rem;
      text-align: center;
      transition: all 0.2s;
    }

    .widget:hover {
      border-color: var(--accent-color);
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }

    .widget-value {
      font-size: 1.5rem;
      font-weight: 700;
      margin: 0.5rem 0;
      font-family: ${this.brandingConfig.typography.mono};
    }

    .widget-label {
      font-size: 0.85rem;
      opacity: 0.7;
      text-transform: uppercase;
    }

    /* Cards Styles */
    .executive-cards {
      background: transparent;
    }

    .cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.5rem;
      margin-top: 1.5rem;
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-left: 4px solid var(--primary-color);
      border-radius: 8px;
      padding: 1.5rem;
      transition: all 0.3s;
    }

    .card.threat-summary {
      border-left-color: var(--critical-color);
    }

    .card.business-impact {
      border-left-color: var(--warning-color);
    }

    .card:hover {
      transform: translateY(-4px);
      box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border-color);
    }

    .card-title {
      margin: 0;
      font-size: 1.1rem;
    }

    .card-field {
      margin: 0.75rem 0;
      font-size: 0.95rem;
    }

    .card-field strong {
      color: var(--primary-color);
      margin-right: 0.5rem;
    }

    /* Evidence Gallery Styles */
    .evidence-gallery {
      background: var(--card-bg);
    }

    .gallery-section {
      margin-bottom: 2rem;
      padding: 1.5rem;
      background: var(--bg-color);
      border: 1px solid var(--border-color);
      border-radius: 8px;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }

    .section-title {
      margin: 0;
    }

    .section-count {
      background: var(--accent-color);
      color: #FFF;
      padding: 0.25rem 0.75rem;
      border-radius: 20px;
      font-size: 0.85rem;
      font-weight: 600;
    }

    .section-items {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 1rem;
    }

    .gallery-item {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 1rem;
      font-size: 0.9rem;
    }

    .item-value {
      word-break: break-all;
      margin: 0.5rem 0;
    }

    /* Decision Center Styles */
    .decision-center {
      background: transparent;
    }

    .decisions-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1.5rem;
      margin-top: 1.5rem;
    }

    .audience-panel {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1.5rem;
    }

    .audience-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--primary-color);
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 2px solid var(--accent-color);
    }

    .decisions-list ul, .metrics-list {
      margin-bottom: 1.5rem;
    }

    .decisions-list h4, .metrics-list h4 {
      font-size: 1rem;
      margin-bottom: 0.75rem;
    }

    .decisions-list ul {
      list-style: none;
    }

    .decisions-list li {
      padding: 0.5rem 0;
      padding-left: 1.5rem;
      position: relative;
    }

    .decisions-list li:before {
      content: '▸';
      position: absolute;
      left: 0;
      color: var(--accent-color);
      font-weight: bold;
    }

    .metrics-table {
      width: 100%;
      font-size: 0.9rem;
    }

    .metrics-table td {
      padding: 0.5rem;
      border-bottom: 1px solid var(--border-color);
    }

    .metric-name {
      font-weight: 500;
    }

    .metric-value {
      text-align: right;
      font-family: ${this.brandingConfig.typography.mono};
    }

    /* Utility Styles */
    .empty-state {
      text-align: center;
      opacity: 0.6;
      padding: 2rem;
    }

    .diagram-placeholder {
      background: var(--bg-color);
      border: 2px dashed var(--border-color);
      border-radius: 8px;
      padding: 2rem;
      text-align: center;
      margin-top: 1rem;
    }

    .placeholder-text {
      color: var(--accent-color);
      margin-bottom: 1rem;
    }

    code {
      background: var(--bg-color);
      padding: 0.2rem 0.4rem;
      border-radius: 3px;
      font-family: ${this.brandingConfig.typography.mono};
      font-size: 0.9em;
    }

    /* Print Styles */
    @media print {
      html, body {
        background: #FFF;
        color: #000;
      }

      section {
        page-break-inside: avoid;
        border-bottom: 1px solid #CCC;
      }

      .widget:hover, .card:hover {
        box-shadow: none;
        transform: none;
      }
    }

    /* Responsive Styles */
    ${responsive ? `
    @media (max-width: 1024px) {
      .cards-grid, .decisions-grid {
        grid-template-columns: 1fr;
      }

      .cover-threat-metrics {
        grid-template-columns: repeat(2, 1fr);
      }

      h1 { font-size: 2rem; }
      h2 { font-size: 1.5rem; }
    }

    @media (max-width: 640px) {
      section {
        padding: 1rem;
      }

      .cover-page {
        padding: 2rem 1rem;
      }

      .cover-title {
        font-size: 2rem;
      }

      .cover-threat-metrics {
        grid-template-columns: repeat(2, 1fr);
        gap: 1rem;
      }

      .widgets-grid {
        grid-template-columns: 1fr;
      }

      .section-items {
        grid-template-columns: 1fr;
      }

      h1 { font-size: 1.5rem; }
      h2 { font-size: 1.2rem; }
      h3 { font-size: 1rem; }
    }
    ` : ''}
    `;

    this.cssCache.set(cacheKey, css);
    return css;
  }

  wrapInDocument(html, css, theme = 'dark') {
    return `<!DOCTYPE html>
<html lang="en" data-theme="${theme}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel APEX Intelligence Report</title>
  <style>
    ${css}
  </style>
</head>
<body>
  <div class="report-container">
    ${html}
  </div>
  <script>
    // Dark mode toggle functionality
    document.addEventListener('DOMContentLoaded', function() {
      const theme = localStorage.getItem('sa-eix-theme') || 'dark';
      document.documentElement.setAttribute('data-theme', theme);
    });
  </script>
</body>
</html>`;
  }

  // Utility Methods

  escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  getThreatColor(score) {
    if (score >= 80) return '#E74C3C';
    if (score >= 60) return '#E67E22';
    if (score >= 40) return '#F39C12';
    return '#2ECC71';
  }

  getThreatLevelColor(level) {
    const colors = {
      CRITICAL: '#E74C3C',
      HIGH: '#E67E22',
      MEDIUM: '#F39C12',
      LOW: '#2ECC71',
    };
    return colors[level] || '#95A5A6';
  }

  getSeverityColor(severity) {
    const colors = {
      critical: '#E74C3C',
      high: '#E67E22',
      medium: '#F39C12',
      low: '#2ECC71',
      info: '#3498DB',
    };
    return colors[String(severity).toLowerCase()] || '#95A5A6';
  }

  getWidgetIcon(iconName) {
    const icons = {
      alert: '⚠️',
      'check-circle': '✓',
      'trending-up': '📈',
      activity: '📊',
      shield: '🛡️',
      grid: '◻️',
      'book-open': '📖',
      check: '✔️',
    };
    return icons[iconName] || '•';
  }

  getCardIcon(iconName) {
    const icons = {
      'alert-triangle': '⚠️',
      'bar-chart-2': '📊',
      zap: '⚡',
      layers: '📚',
      globe: '🌍',
    };
    return icons[iconName] || '📌';
  }

  getCategoryColorClass(category) {
    const classes = {
      'threat-summary': 'threat-summary',
      'business-impact': 'business-impact',
      'executive-actions': 'executive-actions',
      'sector-risk': 'sector-risk',
      'regional-risk': 'regional-risk',
    };
    return classes[category] || '';
  }

  humanizeKey(key) {
    return key
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .trim();
  }
}

module.exports = { SentinelApexEIXHTMLRenderer };
