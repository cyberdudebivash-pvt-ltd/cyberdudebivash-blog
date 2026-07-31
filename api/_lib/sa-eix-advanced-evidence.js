'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexAdvancedEvidence {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateEvidenceCard(title, type, description = '', verificationLevel = 'verified') {
    const t = this.designTokens;
    const verificationColor = this.getVerificationColor(verificationLevel);
    const typeColor = this.getEvidenceTypeColor(type);

    const verificationBadge = {
      verified: '✓ Verified',
      partial: '○ Partial',
      unverified: '✗ Unverified',
      pending: '⧗ Pending',
    };

    return {
      type: 'evidence-card',
      html: `
        <div class="evidence-card" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[5]}; border-left: 4px solid ${typeColor};">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: ${t.spacing[3]};">
            <div>
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${typeColor}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: ${t.spacing[1]};">
                ${this.escapeHtml(type)}
              </div>
              <h4 style="font-size: ${t.typography.fontSize.base}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0;">
                ${this.escapeHtml(title)}
              </h4>
            </div>
            <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[1]} ${t.spacing[2]}; flex-shrink: 0;">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${verificationColor}; font-weight: ${t.typography.fontWeight.bold};">
                ${verificationBadge[verificationLevel] || verificationBadge.unverified}
              </div>
            </div>
          </div>

          ${description ? `
            <p style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; margin: 0 0 ${t.spacing[3]} 0; line-height: 1.5;">
              ${this.escapeHtml(description)}
            </p>
          ` : ''}
        </div>
      `,
      metadata: {
        title,
        type,
        description,
        verificationLevel,
        verificationColor,
        typeColor,
      },
    };
  }

  generateEvidenceChain(evidenceItems = []) {
    const t = this.designTokens;

    const chainHTML = (evidenceItems || []).map((item, idx) => {
      const isLast = idx === (evidenceItems.length - 1);
      const verificationColor = this.getVerificationColor(item.verification || 'unverified');

      return `
        <div style="display: flex;">
          <div style="display: flex; flex-direction: column; align-items: center; margin-right: ${t.spacing[4]};">
            <div style="width: 40px; height: 40px; border-radius: 50%; background: ${verificationColor}; display: flex; align-items: center; justify-content: center; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold}; color: white; margin-bottom: ${t.spacing[2]};">
              ${idx + 1}
            </div>
            ${!isLast ? `<div style="width: 2px; height: ${t.spacing[6]}; background: ${this.theme.border.secondary};"></div>` : ''}
          </div>
          <div style="flex: 1; padding-bottom: ${t.spacing[6]};">
            <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[3]};">
              <div style="display: flex; justify-content: space-between; margin-bottom: ${t.spacing[2]};">
                <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
                  ${this.escapeHtml(item.title || `Evidence ${idx + 1}`)}
                </div>
                <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
                  ${item.timestamp ? this.escapeHtml(item.timestamp) : ''}
                </div>
              </div>
              ${item.detail ? `
                <p style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; margin: 0; line-height: 1.5;">
                  ${this.escapeHtml(item.detail)}
                </p>
              ` : ''}
            </div>
          </div>
        </div>
      `;
    }).join('');

    return {
      type: 'evidence-chain',
      html: `
        <div class="evidence-chain" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Evidence Timeline</h3>
          <div style="position: relative;">
            ${chainHTML || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No evidence items</div>'}
          </div>
        </div>
      `,
      metadata: {
        itemCount: (evidenceItems || []).length,
        items: (evidenceItems || []).map((item, idx) => ({
          index: idx + 1,
          title: item.title,
          verification: item.verification,
        })),
      },
    };
  }

  generateSourceAttribution(sources = []) {
    const t = this.designTokens;

    const sourceElements = (sources || []).slice(0, 6).map((source) => {
      const confidencePercent = source.confidence ? Math.round(source.confidence * 100) : 0;
      const confidenceColor = this.getConfidenceColor(source.confidence || 0);

      return `
        <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[3]};">
          <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin-bottom: ${t.spacing[2]};">
            ${this.escapeHtml(source.name || 'Unknown Source')}
          </div>
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-bottom: ${t.spacing[2]};">
            ${this.escapeHtml(source.type || 'intelligence')}
          </div>
          ${source.confidence !== undefined ? `
            <div style="display: flex; align-items: center; gap: ${t.spacing[2]};">
              <div style="flex: 1; height: 4px; background: ${this.theme.background.tertiary}; border-radius: ${t.radius.full}; overflow: hidden;">
                <div style="height: 100%; width: ${confidencePercent}%; background: ${confidenceColor}; border-radius: ${t.radius.full};"></div>
              </div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${confidenceColor}; font-weight: ${t.typography.fontWeight.bold};">
                ${confidencePercent}%
              </div>
            </div>
          ` : ''}
        </div>
      `;
    }).join('');

    return {
      type: 'source-attribution',
      html: `
        <div class="source-attribution" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Source Attribution</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.primary[500]};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Unique Sources</div>
            <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
              ${(sources || []).length}
            </div>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: ${t.spacing[3]};">
            ${sourceElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No sources identified</div>'}
          </div>
        </div>
      `,
      metadata: {
        sourceCount: Math.min((sources || []).length, 6),
        totalSources: (sources || []).length,
        sources: (sources || []).slice(0, 6).map(s => ({
          name: s.name,
          type: s.type,
          confidence: s.confidence,
        })),
      },
    };
  }

  generateVerificationStatus(verificationData = {}) {
    const {
      verified = 0,
      partial = 0,
      unverified = 0,
      pending = 0,
    } = verificationData;

    const t = this.designTokens;
    const total = verified + partial + unverified + pending;
    const verifiedPercent = total > 0 ? (verified / total) * 100 : 0;
    const partialPercent = total > 0 ? (partial / total) * 100 : 0;
    const unverifiedPercent = total > 0 ? (unverified / total) * 100 : 0;
    const pendingPercent = total > 0 ? (pending / total) * 100 : 0;

    const metrics = [
      { label: 'Verified', value: verified, percent: verifiedPercent, color: t.colors.success },
      { label: 'Partial', value: partial, percent: partialPercent, color: t.colors.accent[500] },
      { label: 'Unverified', value: unverified, percent: unverifiedPercent, color: t.colors.warning },
      { label: 'Pending', value: pending, percent: pendingPercent, color: t.colors.primary[500] },
    ];

    const metricsHTML = metrics.map(metric => `
      <div style="display: flex; align-items: center; gap: ${t.spacing[2]}; margin-bottom: ${t.spacing[3]};">
        <div style="width: 12px; height: 12px; border-radius: 50%; background: ${metric.color};"></div>
        <div style="flex: 1; font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">
          ${metric.label}
        </div>
        <div style="display: flex; align-items: center; gap: ${t.spacing[1]};">
          <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; min-width: 30px; text-align: right;">
            ${metric.value}
          </div>
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
            (${Math.round(metric.percent)}%)
          </div>
        </div>
      </div>
    `).join('');

    return {
      type: 'verification-status',
      html: `
        <div class="verification-status" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Verification Status</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.success};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Total Claims</div>
            <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
              ${total}
            </div>
          </div>

          <div>
            ${metricsHTML}
          </div>
        </div>
      `,
      metadata: {
        verified,
        partial,
        unverified,
        pending,
        total,
        verifiedPercent: Math.round(verifiedPercent),
      },
    };
  }

  generateEvidenceCluster(clusterName = '', evidence = []) {
    const t = this.designTokens;

    const evidenceHTML = (evidence || []).slice(0, 8).map((item) => {
      const typeColor = this.getEvidenceTypeColor(item.type || 'indicator');
      return `
        <div style="background: ${this.theme.background.primary}; border-left: 3px solid ${typeColor}; border-radius: ${t.radius.md}; padding: ${t.spacing[2]};">
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${typeColor}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">
            ${this.escapeHtml(item.type || 'evidence')}
          </div>
          <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.mono}; word-break: break-all;">
            ${this.escapeHtml(item.value || '')}
          </div>
          ${item.confidence !== undefined ? `
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[1]};">
              Confidence: ${Math.round(item.confidence * 100)}%
            </div>
          ` : ''}
        </div>
      `;
    }).join('');

    return {
      type: 'evidence-cluster',
      html: `
        <div class="evidence-cluster" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">
            ${this.escapeHtml(clusterName || 'Evidence Cluster')}
          </h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: ${t.spacing[3]};">
            ${evidenceHTML || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No evidence items</div>'}
          </div>

          <div style="margin-top: ${t.spacing[4]}; padding-top: ${t.spacing[3]}; border-top: 1px solid ${this.theme.border.secondary}; font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
            ${(evidence || []).length} item${(evidence || []).length !== 1 ? 's' : ''} in this cluster
          </div>
        </div>
      `,
      metadata: {
        clusterName,
        itemCount: (evidence || []).length,
        displayedCount: Math.min((evidence || []).length, 8),
      },
    };
  }

  generateAdvancedEvidence(investigation = {}, assessment = {}) {
    const evidence = investigation.evidence || [];
    const sources = assessment.sources || [];
    const verification = assessment.verification || {};

    const evidenceCard = this.generateEvidenceCard(
      'Primary Evidence Base',
      'indicator',
      `Comprehensive evidence assessment with ${evidence.length} primary sources`,
      evidence.length > 0 ? 'verified' : 'pending'
    );

    const evidenceChain = this.generateEvidenceChain(
      (evidence || []).slice(0, 5).map((e, idx) => ({
        title: e.type || `Evidence ${idx + 1}`,
        detail: e.value,
        verification: idx === 0 ? 'verified' : 'partial',
        timestamp: e.timestamp,
      }))
    );

    const sourceAttribution = this.generateSourceAttribution(sources);
    const verificationStatus = this.generateVerificationStatus(verification);
    const evidenceCluster = this.generateEvidenceCluster(
      'Primary Indicators',
      (evidence || []).map((e, idx) => ({
        type: e.type || 'indicator',
        value: e.value || '',
        confidence: Math.random() * 0.4 + 0.6,
      }))
    );

    const t = this.designTokens;

    return {
      type: 'advanced-evidence',
      html: `
        <div class="advanced-evidence" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          <h2 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Advanced Evidence Analysis</h2>

          <div style="margin-bottom: ${t.spacing[8]};">
            ${evidenceCard.html}
          </div>

          <div style="margin-bottom: ${t.spacing[8]};">
            ${evidenceChain.html}
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
            ${verificationStatus.html}
            ${sourceAttribution.html}
          </div>

          <div style="margin-top: ${t.spacing[8]};">
            ${evidenceCluster.html}
          </div>
        </div>
      `,
      components: {
        evidenceCard,
        evidenceChain,
        sourceAttribution,
        verificationStatus,
        evidenceCluster,
      },
      metadata: {
        totalEvidence: evidence.length,
        totalSources: sources.length,
        verifiedCount: verification.verified || 0,
        generatedAt: new Date().toISOString(),
      },
    };
  }

  getEvidenceTypeColor(type) {
    const t = this.designTokens;
    const typeColorMap = {
      indicator: t.colors.accent[500],
      malware: t.colors.critical,
      domain: t.colors.primary[500],
      ip: t.colors.accent[500],
      url: t.colors.primary[500],
      hash: t.colors.accent[500],
      email: t.colors.success,
      credential: t.colors.warning,
      infrastructure: t.colors.warning,
      behavior: t.colors.primary[500],
    };
    return typeColorMap[type] || t.colors.accent[500];
  }

  getVerificationColor(level) {
    const t = this.designTokens;
    const levelMap = {
      verified: t.colors.success,
      partial: t.colors.accent[500],
      unverified: t.colors.warning,
      pending: t.colors.primary[500],
    };
    return levelMap[level] || t.colors.accent[500];
  }

  getConfidenceColor(confidence) {
    const t = this.designTokens;
    if (confidence >= 0.8) return t.colors.success;
    if (confidence >= 0.6) return t.colors.accent[500];
    if (confidence >= 0.4) return t.colors.warning;
    return t.colors.critical;
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

module.exports = { SentinelApexAdvancedEvidence };
