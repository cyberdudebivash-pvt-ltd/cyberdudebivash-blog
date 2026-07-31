'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexCTIDashboards {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
    this.theme = this.designSystem.themes.dark;
  }

  generateThreatLandscape(investigation = {}) {
    const {
      threatActors = [],
      campaigns = [],
      targetedSectors = [],
      infrastructure = [],
      mitreTechniques = [],
      severity = 'UNKNOWN',
    } = investigation;

    const t = this.designTokens;

    return {
      type: 'threat-landscape',
      html: `
        <div class="threat-landscape" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Threat Landscape</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: ${t.spacing[4]}; margin-bottom: ${t.spacing[6]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${this.getSeverityColor(severity)};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Overall Severity</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${this.getSeverityColor(severity)}; font-weight: ${t.typography.fontWeight.bold};">${severity}</div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.accent[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Threat Actors</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold};">${threatActors.length}</div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.primary[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Active Campaigns</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.primary[500]}; font-weight: ${t.typography.fontWeight.bold};">${campaigns.length}</div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.warning};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Target Sectors</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.warning}; font-weight: ${t.typography.fontWeight.bold};">${targetedSectors.length}</div>
            </div>
          </div>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.success};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Target Sectors Details</div>
            <div style="display: flex; flex-wrap: wrap; gap: ${t.spacing[2]};">
              ${(targetedSectors || []).map(sector => `
                <span style="background: ${t.colors.success}20; color: ${t.colors.success}; padding: ${t.spacing[2]} ${t.spacing[3]}; border-radius: ${t.radius.sm}; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.semibold}; text-transform: capitalize;">
                  ${this.escapeHtml(sector)}
                </span>
              `).join('')}
            </div>
          </div>
        </div>
      `,
      metadata: {
        severity,
        threatActorCount: threatActors.length,
        campaignCount: campaigns.length,
        sectorCount: targetedSectors.length,
        targetSectors: targetedSectors,
      },
    };
  }

  generateCampaignStatus(campaigns = []) {
    const t = this.designTokens;

    const campaignElements = (campaigns || []).map((campaign, idx) => {
      const startDate = campaign.startDate || campaign.date || 'Unknown';
      const status = campaign.status || (idx % 2 === 0 ? 'Active' : 'Ongoing');
      const statusColor = status === 'Active' ? t.colors.critical : status === 'Ongoing' ? t.colors.warning : t.colors.accent[500];

      return `
        <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]}; margin-bottom: ${t.spacing[3]};">
          <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: ${t.spacing[3]};">
            <div>
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold}; font-family: ${t.typography.fontFamily.heading};">
                ${this.escapeHtml(campaign.name || 'Unnamed Campaign')}
              </div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[1]};">
                Started: ${this.escapeHtml(startDate)}
              </div>
            </div>
            <span style="background: ${statusColor}20; color: ${statusColor}; padding: ${t.spacing[1]} ${t.spacing[2]}; border-radius: ${t.radius.sm}; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase;">
              ${status}
            </span>
          </div>
          ${campaign.description ? `
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; line-height: ${t.typography.lineHeight.normal};">
              ${this.escapeHtml(campaign.description)}
            </div>
          ` : ''}
        </div>
      `;
    }).join('');

    return {
      type: 'campaign-status',
      html: `
        <div class="campaign-status" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Campaign Status</h3>
          ${campaignElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + '; text-align: center; padding: ' + t.spacing[4] + ';">No campaigns identified</div>'}
        </div>
      `,
      metadata: {
        totalCampaigns: campaigns.length,
        campaigns: campaigns.map(c => ({ name: c.name, status: c.status || 'Active' })),
      },
    };
  }

  generateThreatActorActivity(threatActors = []) {
    const t = this.designTokens;

    const actorElements = (threatActors || []).map(actor => {
      const confidence = actor.confidence || 0;
      const confidencePercent = Math.round(confidence * 100);
      const activityStatus = actor.active ? 'Active' : 'Inactive';
      const statusColor = actor.active ? t.colors.critical : t.colors.success;

      return `
        <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]}; margin-bottom: ${t.spacing[3]};">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: ${t.spacing[3]};">
            <div style="flex: 1;">
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold};">
                ${this.escapeHtml(actor.name || 'Unknown Actor')}
              </div>
              ${actor.aliases ? `
                <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[1]};">
                  aka: ${this.escapeHtml(actor.aliases.join(', '))}
                </div>
              ` : ''}
            </div>
            <span style="background: ${statusColor}20; color: ${statusColor}; padding: ${t.spacing[1]} ${t.spacing[2]}; border-radius: ${t.radius.sm}; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold}; text-transform: uppercase;">
              ${activityStatus}
            </span>
          </div>

          <div style="margin-bottom: ${t.spacing[3]};">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: ${t.spacing[2]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase;">Confidence</div>
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold};">${confidencePercent}%</div>
            </div>
            <div style="height: 4px; background: ${this.theme.background.tertiary}; border-radius: ${t.radius.full}; overflow: hidden;">
              <div style="height: 100%; width: ${confidencePercent}%; background: linear-gradient(90deg, ${this.getConfidenceColor(confidence)} 0%, ${this.getConfidenceColor(Math.min(confidence + 0.2, 1))} 100%);"></div>
            </div>
          </div>

          ${actor.origin ? `
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
              <strong>Origin:</strong> ${this.escapeHtml(actor.origin)}
            </div>
          ` : ''}
          ${actor.targetSectors ? `
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[2]};">
              <strong>Targets:</strong> ${this.escapeHtml(actor.targetSectors.join(', '))}
            </div>
          ` : ''}
        </div>
      `;
    }).join('');

    return {
      type: 'threat-actor-activity',
      html: `
        <div class="threat-actor-activity" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Threat Actor Activity</h3>
          ${actorElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + '; text-align: center; padding: ' + t.spacing[4] + ';">No threat actors identified</div>'}
        </div>
      `,
      metadata: {
        totalActors: threatActors.length,
        activeActors: (threatActors || []).filter(a => a.active).length,
        actors: threatActors.map(a => ({ name: a.name, confidence: a.confidence })),
      },
    };
  }

  generateVictimDistribution(investigation = {}) {
    const {
      targetedSectors = [],
      targetedCountries = [],
      targetedOrganizations = [],
    } = investigation;

    const t = this.designTokens;
    const sectorCount = targetedSectors.length;
    const countryCount = targetedCountries ? targetedCountries.length : 0;
    const orgCount = targetedOrganizations ? targetedOrganizations.length : 0;

    return {
      type: 'victim-distribution',
      html: `
        <div class="victim-distribution" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Victim Distribution</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: ${t.spacing[4]}; margin-bottom: ${t.spacing[6]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.accent[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Target Sectors</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold};">${sectorCount}</div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.primary[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Target Countries</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.primary[500]}; font-weight: ${t.typography.fontWeight.bold};">${countryCount}</div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.warning};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Organizations</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.warning}; font-weight: ${t.typography.fontWeight.bold};">${orgCount}</div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: ${t.spacing[4]};">
            ${sectorCount > 0 ? `
              <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md};">
                <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[3]}; font-weight: ${t.typography.fontWeight.semibold};">Sectors</div>
                <div style="display: flex; flex-wrap: wrap; gap: ${t.spacing[2]};">
                  ${(targetedSectors || []).map(sector => `
                    <span style="background: ${t.colors.accent[500]}20; color: ${t.colors.accent[500]}; padding: ${t.spacing[2]} ${t.spacing[3]}; border-radius: ${t.radius.sm}; font-size: ${t.typography.fontSize.xs}; text-transform: capitalize;">
                      ${this.escapeHtml(sector)}
                    </span>
                  `).join('')}
                </div>
              </div>
            ` : ''}

            ${countryCount > 0 ? `
              <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md};">
                <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[3]}; font-weight: ${t.typography.fontWeight.semibold};">Countries</div>
                <div style="display: flex; flex-wrap: wrap; gap: ${t.spacing[2]};">
                  ${(targetedCountries || []).map(country => `
                    <span style="background: ${t.colors.primary[500]}20; color: ${t.colors.primary[500]}; padding: ${t.spacing[2]} ${t.spacing[3]}; border-radius: ${t.radius.sm}; font-size: ${t.typography.fontSize.xs}; text-transform: capitalize;">
                      ${this.escapeHtml(country)}
                    </span>
                  `).join('')}
                </div>
              </div>
            ` : ''}
          </div>
        </div>
      `,
      metadata: {
        targetSectorCount: sectorCount,
        targetCountryCount: countryCount,
        targetOrgCount: orgCount,
        sectors: targetedSectors,
        countries: targetedCountries,
      },
    };
  }

  generateInfrastructureSummary(infrastructure = []) {
    const t = this.designTokens;

    const byType = {};
    for (const item of infrastructure) {
      const type = item.type || 'unknown';
      byType[type] = (byType[type] || 0) + 1;
    }

    const typeElements = Object.entries(byType).map(([type, count]) => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: ${t.spacing[3]}; border-bottom: 1px solid ${this.theme.border.secondary};">
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; text-transform: capitalize; font-weight: ${t.typography.fontWeight.semibold};">
          ${this.escapeHtml(type)}
        </div>
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold}; font-family: ${t.typography.fontFamily.mono};">
          ${count}
        </div>
      </div>
    `).join('');

    return {
      type: 'infrastructure-summary',
      html: `
        <div class="infrastructure-summary" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Infrastructure Summary</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: ${t.spacing[4]}; margin-bottom: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.primary[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Total Nodes</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.primary[500]}; font-weight: ${t.typography.fontWeight.bold};">${infrastructure.length}</div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.accent[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Unique Types</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold};">${Object.keys(byType).length}</div>
            </div>
          </div>

          <div style="background: ${this.theme.background.primary}; border-radius: ${t.radius.md}; overflow: hidden;">
            ${typeElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + '; padding: ' + t.spacing[4] + '; text-align: center;">No infrastructure nodes identified</div>'}
          </div>
        </div>
      `,
      metadata: {
        totalNodes: infrastructure.length,
        typeCount: Object.keys(byType).length,
        byType,
      },
    };
  }

  generateMalwareSummary(malware = []) {
    const t = this.designTokens;

    const malwareElements = (malware || []).map(item => {
      const name = item.name || 'Unknown Malware';
      const type = item.type || 'unknown';
      const family = item.family || 'unclassified';

      return `
        <div style="background: ${this.theme.background.primary}; border: 1px solid ${this.theme.border.secondary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]}; margin-bottom: ${t.spacing[3]};">
          <div style="display: flex; justify-content: space-between; align-items: start;">
            <div>
              <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold};">
                ${this.escapeHtml(name)}
              </div>
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; margin-top: ${t.spacing[1]};">
                Type: <strong>${this.escapeHtml(type)}</strong> | Family: <strong>${this.escapeHtml(family)}</strong>
              </div>
            </div>
            <span style="background: ${t.colors.critical}20; color: ${t.colors.critical}; padding: ${t.spacing[1]} ${t.spacing[2]}; border-radius: ${t.radius.sm}; font-size: ${t.typography.fontSize.xs}; font-weight: ${t.typography.fontWeight.bold};">
              DETECTED
            </span>
          </div>
        </div>
      `;
    }).join('');

    return {
      type: 'malware-summary',
      html: `
        <div class="malware-summary" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Malware Summary</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.critical};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Total Malware Families</div>
            <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.critical}; font-weight: ${t.typography.fontWeight.bold};">${malware.length}</div>
          </div>

          ${malwareElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + '; text-align: center; padding: ' + t.spacing[4] + ';">No malware identified</div>'}
        </div>
      `,
      metadata: {
        totalMalware: malware.length,
        malwareList: malware.map(m => ({ name: m.name, type: m.type, family: m.family })),
      },
    };
  }

  generateMITRECoverage(mitreTechniques = []) {
    const t = this.designTokens;

    const byTactic = {};
    for (const technique of mitreTechniques || []) {
      const tactic = technique.tactic || 'Unknown';
      if (!byTactic[tactic]) {
        byTactic[tactic] = [];
      }
      byTactic[tactic].push(technique.technique || technique);
    }

    const tacticElements = Object.entries(byTactic).map(([tactic, techniques]) => `
      <div style="background: ${this.theme.background.primary}; border-radius: ${t.radius.md}; padding: ${t.spacing[4]}; margin-bottom: ${t.spacing[3]};">
        <div style="font-size: ${t.typography.fontSize.sm}; color: ${this.theme.text.primary}; font-weight: ${t.typography.fontWeight.semibold}; margin-bottom: ${t.spacing[2]};">
          ${this.escapeHtml(tactic)}
        </div>
        <div style="display: flex; flex-wrap: wrap; gap: ${t.spacing[2]};">
          ${techniques.map(technique => `
            <span style="background: ${t.colors.accent[500]}20; color: ${t.colors.accent[500]}; padding: ${t.spacing[1]} ${t.spacing[2]}; border-radius: ${t.radius.sm}; font-size: ${t.typography.fontSize.xs};">
              ${this.escapeHtml(technique)}
            </span>
          `).join('')}
        </div>
      </div>
    `).join('');

    return {
      type: 'mitre-coverage',
      html: `
        <div class="mitre-coverage" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">MITRE ATT&CK Coverage</h3>

          <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; margin-bottom: ${t.spacing[4]}; border-left: 4px solid ${t.colors.accent[500]};">
            <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Tactics Covered</div>
            <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold};">${Object.keys(byTactic).length}</div>
          </div>

          ${tacticElements || '<div style="color: ' + this.theme.text.secondary + '; font-size: ' + t.typography.fontSize.sm + '; text-align: center; padding: ' + t.spacing[4] + ';">No MITRE techniques identified</div>'}
        </div>
      `,
      metadata: {
        tacticCount: Object.keys(byTactic).length,
        techniqueCount: mitreTechniques.length,
        byTactic,
      },
    };
  }

  generateEvidenceStatus(evidence = []) {
    const t = this.designTokens;

    const byStatus = { verified: 0, suspected: 0, unconfirmed: 0, contradicted: 0 };
    for (const item of evidence) {
      const status = item.status || 'unconfirmed';
      if (status in byStatus) {
        byStatus[status]++;
      } else {
        byStatus.unconfirmed++;
      }
    }

    const statusColors = {
      verified: t.colors.success,
      suspected: t.colors.warning,
      unconfirmed: t.colors.accent[500],
      contradicted: t.colors.critical,
    };

    const statusElements = Object.entries(byStatus)
      .filter(([, count]) => count > 0)
      .map(([status, count]) => `
        <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${statusColors[status] || t.colors.accent[500]};">
          <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">${status}</div>
          <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${statusColors[status] || t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold};">${count}</div>
        </div>
      `).join('');

    return {
      type: 'evidence-status',
      html: `
        <div class="evidence-status" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]}; margin-bottom: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Evidence Status</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.primary[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Total Evidence</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.primary[500]}; font-weight: ${t.typography.fontWeight.bold};">${evidence.length}</div>
            </div>
            ${statusElements}
          </div>
        </div>
      `,
      metadata: {
        totalEvidence: evidence.length,
        byStatus,
      },
    };
  }

  generatePublicationQuality(metadata = {}) {
    const {
      quality = 'high',
      lastUpdated = null,
      sources = 0,
      verifiedClaims = 0,
    } = metadata;

    const t = this.designTokens;
    const qualityColor = quality === 'high' ? t.colors.success : quality === 'medium' ? t.colors.warning : t.colors.critical;

    return {
      type: 'publication-quality',
      html: `
        <div class="publication-quality" style="background: ${this.theme.background.secondary}; border: 1px solid ${this.theme.border.primary}; border-radius: ${t.radius.lg}; padding: ${t.spacing[6]};">
          <h3 style="font-size: ${t.typography.fontSize.lg}; font-weight: ${t.typography.fontWeight.bold}; color: ${this.theme.text.primary}; margin: 0 0 ${t.spacing[4]} 0; font-family: ${t.typography.fontFamily.heading};">Publication Quality</h3>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: ${t.spacing[4]};">
            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${qualityColor};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Quality Rating</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${qualityColor}; font-weight: ${t.typography.fontWeight.bold}; text-transform: capitalize;">
                ${quality}
              </div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.accent[500]};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Sources</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.accent[500]}; font-weight: ${t.typography.fontWeight.bold};">
                ${sources}
              </div>
            </div>

            <div style="background: ${this.theme.background.primary}; padding: ${t.spacing[4]}; border-radius: ${t.radius.md}; border-left: 4px solid ${t.colors.success};">
              <div style="font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary}; text-transform: uppercase; margin-bottom: ${t.spacing[2]};">Verified Claims</div>
              <div style="font-size: ${t.typography.fontSize['2xl']}; color: ${t.colors.success}; font-weight: ${t.typography.fontWeight.bold};">
                ${verifiedClaims}
              </div>
            </div>
          </div>

          ${lastUpdated ? `
            <div style="margin-top: ${t.spacing[4]}; font-size: ${t.typography.fontSize.xs}; color: ${this.theme.text.secondary};">
              Last Updated: ${this.escapeHtml(lastUpdated)}
            </div>
          ` : ''}
        </div>
      `,
      metadata: {
        quality,
        sources,
        verifiedClaims,
        lastUpdated,
      },
    };
  }

  generateEnterpriseCTIDashboard(product = {}, investigation = {}) {
    const threatLandscape = this.generateThreatLandscape(investigation);
    const campaignStatus = this.generateCampaignStatus(investigation.campaigns);
    const threatActorActivity = this.generateThreatActorActivity(investigation.threatActors);
    const victimDistribution = this.generateVictimDistribution(investigation);
    const infrastructureSummary = this.generateInfrastructureSummary(investigation.infrastructure);
    const malwareSummary = this.generateMalwareSummary(investigation.malware);
    const mitreCoverage = this.generateMITRECoverage(investigation.mitreTechniques);
    const evidenceStatus = this.generateEvidenceStatus(investigation.findings);
    const publicationQuality = this.generatePublicationQuality(investigation.metadata);
    const t = this.designTokens;

    return {
      type: 'enterprise-cti-dashboard',
      html: `
        <div class="enterprise-cti-dashboard" style="background: ${this.theme.background.primary}; color: ${this.theme.text.primary}; font-family: ${t.typography.fontFamily.body}; padding: ${t.spacing[8]};">
          ${threatLandscape.html}
          ${campaignStatus.html}
          ${threatActorActivity.html}
          ${victimDistribution.html}
          ${infrastructureSummary.html}
          ${malwareSummary.html}
          ${mitreCoverage.html}
          ${evidenceStatus.html}
          ${publicationQuality.html}
        </div>
      `,
      components: {
        threatLandscape,
        campaignStatus,
        threatActorActivity,
        victimDistribution,
        infrastructureSummary,
        malwareSummary,
        mitreCoverage,
        evidenceStatus,
        publicationQuality,
      },
      metadata: {
        productId: product.id,
        investigation: investigation.id,
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

module.exports = { SentinelApexCTIDashboards };
