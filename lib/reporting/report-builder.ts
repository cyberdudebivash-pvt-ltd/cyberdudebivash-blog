/**
 * Report Builder
 * Assembles report sections with validation and evidence tracking
 */

import type {
  MalwareFamily,
  MitreTechnique,
  IOC,
  Evidence,
  Campaign,
  ThreatActor,
} from '../intelligence/schema';
import { aggregateConfidence, formatConfidenceLevel } from './confidence';
import type { Citation } from './references';
import { generateCitations } from './references';

export interface ReportSection {
  title: string;
  content: string;
  confidence: string;
  evidence: Evidence[];
  isEmpty: boolean;
}

export interface MalwareReport {
  id: string;
  title: string;
  sections: Record<string, ReportSection>;
  metadata: Record<string, unknown>;
  citations: Citation[];
  generatedAt: string;
}

export class ReportBuilder {
  private malware: MalwareFamily;
  private sections: Map<string, ReportSection> = new Map();
  private citations: Citation[] = [];

  constructor(malware: MalwareFamily) {
    this.malware = malware;
    this.citations = generateCitations(malware.references);
  }

  addSection(
    key: string,
    title: string,
    content: string,
    evidence: Evidence[],
    isEmpty: boolean = false
  ): this {
    const confidence = evidence.length > 0 ? aggregateConfidence(evidence.map(e => e.confidence)) : 'LOW';
    this.sections.set(key, {
      title,
      content,
      confidence,
      evidence,
      isEmpty,
    });
    return this;
  }

  buildExecutiveSummary(): this {
    const summary = this.malware.description || 'No summary available';
    const isEmpty = !summary;
    this.addSection('executive_summary', 'Executive Summary', summary, [this.malware.evidence], isEmpty);
    return this;
  }

  buildThreatOverview(): this {
    const threats: string[] = [];
    if (this.malware.known_victims && this.malware.known_victims.length > 0) {
      threats.push(`**Known Victims:** ${this.malware.known_victims.join(', ')}`);
    }
    if (this.malware.target_industries && this.malware.target_industries.length > 0) {
      threats.push(`**Target Industries:** ${this.malware.target_industries.join(', ')}`);
    }
    if (this.malware.target_regions && this.malware.target_regions.length > 0) {
      threats.push(`**Target Regions:** ${this.malware.target_regions.join(', ')}`);
    }
    const content = threats.length > 0 ? threats.join('\n\n') : 'Insufficient data';
    this.addSection(
      'threat_overview',
      'Threat Overview',
      content,
      this.malware.target_industries ? [this.malware.evidence] : [],
      !this.malware.target_industries || this.malware.target_industries.length === 0
    );
    return this;
  }

  buildTechnicalAnalysis(): this {
    const details: string[] = [];
    if (this.malware.language) details.push(`**Language:** ${this.malware.language}`);
    if (this.malware.compiler) details.push(`**Compiler:** ${this.malware.compiler}`);
    if (this.malware.packer) details.push(`**Packer:** ${this.malware.packer}`);
    if (this.malware.encryption) details.push(`**Encryption:** ${this.malware.encryption}`);
    if (this.malware.obfuscation) details.push(`**Obfuscation:** ${this.malware.obfuscation}`);

    const content = details.length > 0 ? details.join('\n\n') : 'Technical details not yet analyzed';
    this.addSection(
      'technical_analysis',
      'Technical Analysis',
      content,
      [this.malware.evidence],
      details.length === 0
    );
    return this;
  }

  buildMitreMappings(): this {
    if (this.malware.mitre_techniques.length === 0) {
      this.addSection('mitre_mapping', 'MITRE ATT&CK Mapping', 'No techniques mapped', [], true);
      return this;
    }

    const techniques = this.malware.mitre_techniques
      .map((t: MitreTechnique) => `- **${t.technique_id}** (${t.tactic}): ${t.name}`)
      .join('\n');

    this.addSection(
      'mitre_mapping',
      'MITRE ATT&CK Mapping',
      techniques,
      this.malware.mitre_techniques.map((t: MitreTechnique) => t.evidence),
      false
    );
    return this;
  }

  buildIOCIntelligence(): this {
    if (this.malware.iocs.length === 0) {
      this.addSection('ioc_intelligence', 'IOC Intelligence', 'No IOCs recorded', [], true);
      return this;
    }

    const iocsByType = this.malware.iocs.reduce(
      (acc, ioc: IOC) => {
        if (!acc[ioc.type]) acc[ioc.type] = [];
        acc[ioc.type].push(ioc);
        return acc;
      },
      {} as Record<string, IOC[]>
    );

    const content = Object.entries(iocsByType)
      .map(([type, iocs]) => {
        const list = iocs.map((ioc: IOC) => `- \`${ioc.value}\` (${ioc.confidence})`).join('\n');
        return `**${type.toUpperCase()}**\n${list}`;
      })
      .join('\n\n');

    this.addSection(
      'ioc_intelligence',
      'IOC Intelligence',
      content,
      this.malware.iocs.map((ioc: IOC) => ioc.evidence),
      false
    );
    return this;
  }

  buildDetectionEngineering(): this {
    const content =
      this.malware.platforms && this.malware.platforms.length > 0
        ? `Detection rules should target: ${this.malware.platforms.join(', ')}`
        : 'Detection platform requirements to be determined';

    this.addSection(
      'detection_engineering',
      'Detection Engineering',
      content,
      [this.malware.evidence],
      !this.malware.platforms || this.malware.platforms.length === 0
    );
    return this;
  }

  buildThreatActorAttribution(): this {
    if (!this.malware.threat_actors || this.malware.threat_actors.length === 0) {
      this.addSection('threat_actor_attribution', 'Threat Actor Attribution', 'Attribution pending', [], true);
      return this;
    }

    const content = `Attributed to: ${this.malware.threat_actors.join(', ')}`;
    this.addSection('threat_actor_attribution', 'Threat Actor Attribution', content, [this.malware.evidence], false);
    return this;
  }

  buildCampaignAnalysis(): this {
    if (!this.malware.campaigns || this.malware.campaigns.length === 0) {
      this.addSection('campaign_analysis', 'Campaign Analysis', 'No campaigns linked', [], true);
      return this;
    }

    const content = `Associated campaigns: ${this.malware.campaigns.join(', ')}`;
    this.addSection('campaign_analysis', 'Campaign Analysis', content, [this.malware.evidence], false);
    return this;
  }

  buildRecommendations(): this {
    const recommendations: string[] = [
      '1. Implement endpoint detection rules for known IOCs',
      '2. Monitor for command and control activity',
      '3. Maintain situational awareness for variant activity',
      '4. Review incident response procedures',
    ];

    this.addSection(
      'recommendations',
      'Recommendations',
      recommendations.join('\n'),
      [this.malware.evidence],
      false
    );
    return this;
  }

  build(): MalwareReport {
    return {
      id: this.malware.id,
      title: `${this.malware.name} - Malware Intelligence Report`,
      sections: Object.fromEntries(this.sections),
      metadata: {
        malware_id: this.malware.id,
        malware_name: this.malware.name,
        malware_type: this.malware.type,
        confidence: this.malware.confidence,
      },
      citations: this.citations,
      generatedAt: new Date().toISOString(),
    };
  }
}
