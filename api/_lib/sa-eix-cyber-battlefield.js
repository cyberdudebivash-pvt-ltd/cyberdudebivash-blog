'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexCyberBattlefield {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateAttackSurface(assets = []) {
    const t = this.designTokens;

    const assetsByStatus = {
      compromised: (assets || []).filter(a => a.status === 'compromised').length,
      exposed: (assets || []).filter(a => a.status === 'exposed').length,
      vulnerable: (assets || []).filter(a => a.status === 'vulnerable').length,
      protected: (assets || []).filter(a => a.status === 'protected').length,
    };

    const statusMetrics = [
      { label: 'Compromised', count: assetsByStatus.compromised, color: t.colors.critical },
      { label: 'Exposed', count: assetsByStatus.exposed, color: t.colors.warning },
      { label: 'Vulnerable', count: assetsByStatus.vulnerable, color: t.colors.accent[500] },
      { label: 'Protected', count: assetsByStatus.protected, color: t.colors.success },
    ];

    const statusHTML = statusMetrics.map(status => `
      <div style="display: flex; align-items: center; gap: ${t.spacing[2]}; padding: ${t.spacing[2]} 0; border-bottom: 1px solid ${this.theme.border.secondary};">
        <div style="display: flex; align-items: center; gap: ${t.spacing[2]}; flex: 1;">
          <div style="width: 8px; height: 8px; border-radius: 50%; background: ${status.color};"></div>
          <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary};">
            ${status.label}
          </div>
        </div>
        <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
          ${status.count}
        </div>
      </div>
    `).join('');

    const totalAssets = (assets || []).length;
    const riskPercent = totalAssets > 0 ? ((assetsByStatus.compromised + assetsByStatus.exposed) / totalAssets) * 100 : 0;

    return {
      type: 'attack-surface',
      html: `
        <div class="attack-surface" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Attack Surface</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.critical};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Assets at Risk</div>
            <div style="font-size: ${t.typography.fontSize['3xl']}; color: ${t.colors.critical}; font-weight: ${t.typography.fontWeight.bold};">
              ${totalAssets}
            </div>
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[1]};">
              ${Math.round(riskPercent)}% critical risk
            </div>
          </div>

          <div>
            ${statusHTML}
          </div>
        </div>
      `,
      metadata: {
        totalAssets,
        compromised: assetsByStatus.compromised,
        exposed: assetsByStatus.exposed,
        vulnerable: assetsByStatus.vulnerable,
        protected: assetsByStatus.protected,
        riskPercent: Math.round(riskPercent),
      },
    };
  }

  generateNetworkTopology(nodes = []) {
    const t = this.designTokens;

    const nodesByType = {};
    (nodes || []).forEach(node => {
      const type = node.type || 'unknown';
      nodesByType[type] = (nodesByType[type] || 0) + 1;
    });

    const nodeTypeHTML = Object.entries(nodesByType).map(([type, count]) => `
      <div style="display: flex; align-items: center; gap: ${t.spacing[2]}; margin-bottom: ${t.spacing[2]};">
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; flex: 1;">
          ${this.escapeHtml(type)}
        </div>
        <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
          ${count}
        </div>
      </div>
    `).join('');

    const totalNodes = (nodes || []).length;
    const criticalNodes = (nodes || []).filter(n => n.criticality === 'critical').length;

    return {
      type: 'network-topology',
      html: `
        <div class="network-topology" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Network Topology</h3>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: ${t.spacing[4]}; margin-bottom: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.primary[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Total Nodes</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${totalNodes}
              </div>
            </div>
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.critical};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Critical</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.critical}; font-weight: ${t.typography.fontWeight.bold};">
                ${criticalNodes}
              </div>
            </div>
          </div>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md};">
            <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin-bottom: ${t.spacing[2]};">Node Types</div>
            ${nodeTypeHTML}
          </div>
        </div>
      `,
      metadata: {
        totalNodes,
        criticalNodes,
        nodeTypes: Object.keys(nodesByType),
        nodeDistribution: nodesByType,
      },
    };
  }

  generateKillChain(techniques = []) {
    const t = this.designTokens;

    const tacticMap = {};
    (techniques || []).forEach(tech => {
      const tactic = tech.tactic || 'initial-access';
      if (!tacticMap[tactic]) {
        tacticMap[tactic] = [];
      }
      tacticMap[tactic].push(tech);
    });

    const tactics = [
      'reconnaissance',
      'resource-development',
      'initial-access',
      'execution',
      'persistence',
      'privilege-escalation',
      'defense-evasion',
      'credential-access',
      'discovery',
      'lateral-movement',
      'collection',
      'command-and-control',
      'exfiltration',
      'impact',
    ];

    const chainHTML = tactics.map((tactic, idx) => {
      const techniques = tacticMap[tactic] || [];
      const isLast = idx === tactics.length - 1;

      return `
        <div style="display: flex;">
          <div style="display: flex; flex-direction: column; align-items: center; margin-right: ${t.spacing[3]};">
            <div style="width: 32px; height: 32px; border-radius: 50%; background: ${techniques.length > 0 ? t.colors.critical : this.theme.background.tertiary}; display: flex; align-items: center; justify-content: center; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold}; color: white; margin-bottom: ${t.spacing[2]};">
              ${techniques.length}
            </div>
            ${!isLast ? `<div style="width: 2px; height: ${t.spacing[8]}; background: ${this.theme.border.secondary};"></div>` : ''}
          </div>
          <div style="flex: 1; padding-bottom: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[3]};">
              <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; text-transform: capitalize; margin-bottom: ${t.spacing[2]};">
                ${tactic.replace(/-/g, ' ')}
              </div>
              ${techniques.length > 0 ? `
                <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
                  ${techniques.map(t => this.escapeHtml(t.name || t.id || 'technique')).join(', ')}
                </div>
              ` : `
                <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
                  No techniques detected
                </div>
              `}
            </div>
          </div>
        </div>
      `;
    }).join('');

    const totalTechniques = (techniques || []).length;

    return {
      type: 'kill-chain',
      html: `
        <div class="kill-chain" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Kill Chain (MITRE ATT&CK)</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.critical};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">Observed Techniques</div>
            <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
              ${totalTechniques}
            </div>
          </div>

          <div style="position: relative;">
            ${chainHTML}
          </div>
        </div>
      `,
      metadata: {
        totalTechniques,
        tacticsObserved: Object.keys(tacticMap).length,
        techniquesByTactic: tacticMap,
      },
    };
  }

  generateImpactZones(zones = []) {
    const t = this.designTokens;

    const zoneElements = (zones || []).slice(0, 6).map((zone) => {
      const severity = zone.severity || 'medium';
      const severityColor = this.getSeverityColor(severity);
      const affectedCount = zone.affectedCount || 0;

      return `
        <div style="background: ${this.theme.background.primary}; border-left: 4px solid ${severityColor}; border-radius: ${t.radius.md}; padding: ${t.spacing[3]};">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: ${t.spacing[2]};">
            <div>
              <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary};">
                ${this.escapeHtml(zone.name || 'Zone')}
              </div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
                ${this.escapeHtml(zone.type || 'unknown')}
              </div>
            </div>
            <div style="text-align: right;">
              <div style="font-size: ${t.typography.fontSize.sm}; font-weight: ${t.typography.fontWeight.bold}; color: ${severityColor};">
                ${severity.toUpperCase()}
              </div>
            </div>
          </div>
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
            ${affectedCount} asset${affectedCount !== 1 ? 's' : ''} affected
          </div>
        </div>
      `;
    }).join('');

    const totalZones = (zones || []).length;
    const criticalZones = (zones || []).filter(z => z.severity === 'critical').length;

    return {
      type: 'impact-zones',
      html: `
        <div class="impact-zones" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Impact Zones</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[3]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; display: grid; grid-template-columns: 1fr 1fr; gap: ${t.spacing[3]};">
            <div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Total Zones</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.bold};">
                ${totalZones}
              </div>
            </div>
            <div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[1]};">Critical</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.critical}; font-weight: ${t.typography.fontWeight.bold};">
                ${criticalZones}
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: ${t.spacing[3]};">
            ${zoneElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + ';">No impact zones identified</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalZones,
        criticalZones,
        displayedZones: Math.min((zones || []).length, 6),
        zones: (zones || []).slice(0, 6).map(z => ({
          name: z.name,
          type: z.type,
          severity: z.severity,
        })),
      },
    };
  }

  generateCyberBattlefield(investigation = {}, campaign = {}) {
    const attackSurface = this.generateAttackSurface(investigation.assets || []);
    const networkTopology = this.generateNetworkTopology(investigation.nodes || []);
    const killChain = this.generateKillChain(campaign.techniques || []);
    const impactZones = this.generateImpactZones(investigation.impactZones || []);

    const t = this.designTokens;

    return {
      type: 'cyber-battlefield',
      html: `
        <div class="cyber-battlefield" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          <h2 style="font-size: ${t.typography.fontSize['3xl']}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[6]} 0; font-family: ${t.typography.fontFamily.heading};">Cyber Battlefield Analysis</h2>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: ${t.spacing[6]}; margin-bottom: ${t.spacing[8]};">
            ${attackSurface.html}
            ${networkTopology.html}
          </div>

          <div style="margin-bottom: ${t.spacing[8]};">
            ${killChain.html}
          </div>

          <div>
            ${impactZones.html}
          </div>
        </div>
      `,
      components: {
        attackSurface,
        networkTopology,
        killChain,
        impactZones,
      },
      metadata: {
        totalAssets: investigation.assets ? (investigation.assets || []).length : 0,
        totalNodes: investigation.nodes ? (investigation.nodes || []).length : 0,
        totalTechniques: campaign.techniques ? (campaign.techniques || []).length : 0,
        impactZoneCount: investigation.impactZones ? (investigation.impactZones || []).length : 0,
        generatedAt: new Date().toISOString(),
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

module.exports = { SentinelApexCyberBattlefield };
