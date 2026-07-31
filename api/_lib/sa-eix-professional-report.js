'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexProfessionalReport {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateReportCover(title = '', subtitle = '', metadata = {}) {
    const t = this.designTokens;

    const coverDate = metadata.date || new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });

    return {
      type: 'report-cover',
      html: `
        <div class="report-cover" style="background: linear-gradient(135deg, ${this.theme.background.primary} 0%, ${this.theme.background.secondary} 100%); padding: ${t.spacing[12]} ${t.spacing[8]}; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body};">

          <div style="border-top: 4px solid ${t.colors.primary[500]}; border-bottom: 4px solid ${t.colors.primary[500]}; padding: ${t.spacing[8]} 0; max-width: 600px; margin-bottom: ${t.spacing[8]};">
            <h1 style="font-size: ${t.typography.fontSize['5xl']}; font-weight: ${t.typography.fontWeight.bold}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">
              ${this.escapeHtml(title)}
            </h1>
            ${subtitle ? `
              <div style="font-size: ${t.typography.fontSize.xl}; color: ${this.theme.text.secondary}; margin: 0;">
                ${this.escapeHtml(subtitle)}
              </div>
            ` : ''}
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]}; width: 100%; max-width: 600px;">
            ${metadata.client ? `
              <div>
                <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Client</div>
                <div style="font-size: ${t.typography.fontSize.base}; font-weight: ${t.typography.fontWeight.semibold};">
                  ${this.escapeHtml(metadata.client)}
                </div>
              </div>
            ` : ''}
            <div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Date</div>
              <div style="font-size: ${t.typography.fontSize.base}; font-weight: ${t.typography.fontWeight.semibold};">
                ${coverDate}
              </div>
            </div>
            ${metadata.classification ? `
              <div>
                <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Classification</div>
                <div style="font-size: ${t.typography.fontSize.base}; font-weight: ${t.typography.fontWeight.semibold}; color: ${t.colors.warning};">
                  ${this.escapeHtml(metadata.classification)}
                </div>
              </div>
            ` : ''}
          </div>

          <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; margin-top: auto;">
            Confidential - CYBERDUDEBIVASH® SENTINEL APEX
          </div>
        </div>
      `,
      metadata: {
        title,
        subtitle,
        date: coverDate,
        client: metadata.client || 'Undisclosed',
        classification: metadata.classification || 'Confidential',
      },
    };
  }

  generateExecutiveSummary(summary = '', keyFindings = []) {
    const t = this.designTokens;

    const findingsHTML = (keyFindings || []).slice(0, 5).map((finding) => `
      <div style="display: flex; gap: ${t.spacing[3]}; margin-bottom: ${t.spacing[3]};">
        <div style="color: ${t.colors.critical}; font-weight: bold; flex-shrink: 0;">●</div>
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; line-height: 1.6;">
          ${this.escapeHtml(finding)}
        </div>
      </div>
    `).join('');

    return {
      type: 'executive-summary',
      html: `
        <div class="executive-summary" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h2 style="font-size: ${t.typography.fontSize['2xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading}; border-bottom: 2px solid ${t.colors.primary[500]}; padding-bottom: ${t.spacing[3]};">Executive Summary</h2>

          ${summary ? `
            <p style="font-size: ${t.typography.fontSize.base}; color: ${this.theme.text.secondary}; line-height: 1.8; margin: 0 0 ${t.spacing[4]} 0;">
              ${this.escapeHtml(summary)}
            </p>
          ` : ''}

          ${findingsHTML ? `
            <div style="margin-top: ${t.spacing[4]};">
              <h4 style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase; color: ${this.theme.text.secondary}; margin: 0 0 ${t.spacing[2]} 0;">Key Findings</h4>
              ${findingsHTML}
            </div>
          ` : ''}
        </div>
      `,
      metadata: {
        summary: summary.substring(0, 100),
        keyFindingsCount: (keyFindings || []).length,
        displayedFindings: Math.min((keyFindings || []).length, 5),
      },
    };
  }

  generateFindingsSection(findings = []) {
    const t = this.designTokens;

    const findingElements = (findings || []).slice(0, 8).map((finding, idx) => {
      const severityColor = this.getSeverityColor(finding.severity || 'medium');

      return `
        <div style="background: ${this.theme.background.primary}; border-left: 4px solid ${severityColor}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]}; margin-bottom: ${t.spacing[3]};">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: ${t.spacing[2]};">
            <h4 style="font-size: ${t.typography.fontSize.base}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0;">
              ${this.escapeHtml(finding.title || `Finding ${idx + 1}`)}
            </h4>
            <div style="background: ${severityColor}20; color: ${severityColor}; padding: ${t.spacing[1]} ${t.spacing[2]}; border-radius: ${t.radius.md}; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase;">
              ${(finding.severity || 'medium').toUpperCase()}
            </div>
          </div>
          <p style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; margin: 0 0 ${t.spacing[2]} 0; line-height: 1.6;">
            ${this.escapeHtml(finding.description || '')}
          </p>
          ${finding.impact ? `
            <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">
              <strong>Impact:</strong> ${this.escapeHtml(finding.impact)}
            </div>
          ` : ''}
        </div>
      `;
    }).join('');

    return {
      type: 'findings-section',
      html: `
        <div class="findings-section" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h2 style="font-size: ${t.typography.fontSize['2xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading}; border-bottom: 2px solid ${t.colors.warning}; padding-bottom: ${t.spacing[3]};">Key Findings</h2>

          <div>
            ${findingElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No findings to display</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalFindings: (findings || []).length,
        displayedFindings: Math.min((findings || []).length, 8),
        criticalCount: (findings || []).filter(f => f.severity === 'critical').length,
        highCount: (findings || []).filter(f => f.severity === 'high').length,
      },
    };
  }

  generateRecommendations(recommendations = []) {
    const t = this.designTokens;

    const recElements = (recommendations || []).slice(0, 6).map((rec, idx) => {
      const priorityColor = this.getPriorityColor(rec.priority || 'medium');

      return `
        <div style="background: ${this.theme.background.primary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]}; margin-bottom: ${t.spacing[3]};">
          <div style="display: flex; align-items: flex-start; gap: ${t.spacing[3]}; margin-bottom: ${t.spacing[2]};">
            <div style="background: ${priorityColor}; color: white; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0;">
              ${idx + 1}
            </div>
            <div style="flex: 1;">
              <h4 style="font-size: ${t.typography.fontSize.base}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[1]} 0;">
                ${this.escapeHtml(rec.title || `Recommendation ${idx + 1}`)}
              </h4>
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${priorityColor}; font-weight: ${t.typography.fontWeight.semibold}; text-transform: uppercase;">
                Priority: ${(rec.priority || 'medium').toUpperCase()}
              </div>
            </div>
          </div>
          <p style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; margin: 0; line-height: 1.6;">
            ${this.escapeHtml(rec.description || '')}
          </p>
        </div>
      `;
    }).join('');

    return {
      type: 'recommendations',
      html: `
        <div class="recommendations" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h2 style="font-size: ${t.typography.fontSize['2xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading}; border-bottom: 2px solid ${t.colors.success}; padding-bottom: ${t.spacing[3]};">Recommendations</h2>

          <div>
            ${recElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No recommendations to display</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalRecommendations: (recommendations || []).length,
        displayedRecommendations: Math.min((recommendations || []).length, 6),
        criticalCount: (recommendations || []).filter(r => r.priority === 'critical').length,
        highCount: (recommendations || []).filter(r => r.priority === 'high').length,
      },
    };
  }

  generateReportMetadata(metadata = {}) {
    const t = this.designTokens;

    const metadataItems = [
      { label: 'Report ID', value: metadata.reportId || 'N/A' },
      { label: 'Prepared By', value: metadata.preparedBy || 'CYBERDUDEBIVASH SENTINEL APEX' },
      { label: 'Reviewed By', value: metadata.reviewedBy || 'Security Team' },
      { label: 'Valid Until', value: metadata.validUntil || '90 days from issue date' },
    ];

    const itemsHTML = metadataItems.map(item => `
      <div style="display: flex; justify-content: space-between; padding: ${t.spacing[2]} 0; border-bottom: 1px solid ${this.theme.border.secondary};">
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; font-weight: ${t.typography.fontWeight.semibold};">
          ${item.label}
        </div>
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary};">
          ${this.escapeHtml(item.value)}
        </div>
      </div>
    `).join('');

    return {
      type: 'report-metadata',
      html: `
        <div class="report-metadata" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[4]};">
          <h4 style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin: 0 0 ${t.spacing[3]} 0;">Report Information</h4>
          <div>
            ${itemsHTML}
          </div>
        </div>
      `,
      metadata,
    };
  }

  generateProfessionalReport(reportConfig = {}) {
    const cover = this.generateReportCover(
      reportConfig.title || 'Security Assessment Report',
      reportConfig.subtitle || 'Enterprise Threat Intelligence',
      reportConfig.metadata || {}
    );

    const summary = this.generateExecutiveSummary(
      reportConfig.summary || '',
      reportConfig.keyFindings || []
    );

    const findings = this.generateFindingsSection(reportConfig.findings || []);
    const recommendations = this.generateRecommendations(reportConfig.recommendations || []);
    const reportMetadata = this.generateReportMetadata(reportConfig.metadata || {});

    const t = this.designTokens;

    return {
      type: 'professional-report',
      html: `
        <div class="professional-report" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body};">
          ${cover.html}

          <div style="padding: ${t.spacing[8]}; max-width: 900px; margin: 0 auto;">
            <div style="margin-bottom: ${t.spacing[8]};">
              ${summary.html}
            </div>

            <div style="margin-bottom: ${t.spacing[8]};">
              ${findings.html}
            </div>

            <div style="margin-bottom: ${t.spacing[8]};">
              ${recommendations.html}
            </div>

            <div style="margin-bottom: ${t.spacing[8]};">
              ${reportMetadata.html}
            </div>

            <div style="text-align: center; padding-top: ${t.spacing[6]}; border-top: 1px solid ${this.theme.border.secondary}; color: ${this.theme.text.secondary}; font-size: ${t.typography.fontSize.xs};">
              <p style="margin: 0; margin-bottom: ${t.spacing[2]};">
                © CYBERDUDEBIVASH® SENTINEL APEX — Enterprise Cybersecurity Intelligence
              </p>
              <p style="margin: 0;">
                This document is confidential and intended only for authorized recipients.
              </p>
            </div>
          </div>
        </div>
      `,
      components: {
        cover,
        summary,
        findings,
        recommendations,
        reportMetadata,
      },
      metadata: {
        title: reportConfig.title || 'Security Assessment Report',
        generatedAt: new Date().toISOString(),
        findingsCount: (reportConfig.findings || []).length,
        recommendationsCount: (reportConfig.recommendations || []).length,
      },
    };
  }

  getSeverityColor(severity) {
    const t = this.designTokens;
    const severityMap = {
      critical: t.colors.critical,
      high: t.colors.warning,
      medium: t.colors.accent[500],
      low: t.colors.success,
    };
    return severityMap[severity] || t.colors.accent[500];
  }

  getPriorityColor(priority) {
    const t = this.designTokens;
    const priorityMap = {
      critical: t.colors.critical,
      high: t.colors.warning,
      medium: t.colors.accent[500],
      low: t.colors.success,
    };
    return priorityMap[priority] || t.colors.accent[500];
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

module.exports = { SentinelApexProfessionalReport };
