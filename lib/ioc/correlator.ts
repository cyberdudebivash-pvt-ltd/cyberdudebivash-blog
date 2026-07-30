/**
 * IOC Correlation Engine
 * Correlates IOCs with malware families, campaigns, threat actors, techniques, detection rules
 */

import type { MalwareFamily, Campaign, ThreatActor, MitreTechnique } from '../intelligence/schema';
import type { IOCCorrelationResult } from './types';

export class CorrelationEngine {
  private malwareFamilies: Map<string, MalwareFamily> = new Map();
  private campaigns: Map<string, Campaign> = new Map();
  private threatActors: Map<string, ThreatActor> = new Map();
  private techniques: Map<string, MitreTechnique> = new Map();

  loadMalwareFamilies(families: MalwareFamily[]): void {
    for (const family of families) {
      this.malwareFamilies.set(family.id, family);
    }
  }

  loadCampaigns(campaigns: Campaign[]): void {
    for (const campaign of campaigns) {
      this.campaigns.set(campaign.id, campaign);
    }
  }

  loadThreatActors(actors: ThreatActor[]): void {
    for (const actor of actors) {
      this.threatActors.set(actor.id, actor);
    }
  }

  correlate(iocValue: string, iocType: string): IOCCorrelationResult {
    const correlatedMalware = this.findCorrelatedMalware(iocValue, iocType);
    const correlatedCampaigns = this.findCorrelatedCampaigns(correlatedMalware);
    const correlatedActors = this.findCorrelatedActors(correlatedMalware, correlatedCampaigns);
    const correlatedTechniques = this.findCorrelatedTechniques(correlatedMalware);

    const confidenceScore =
      (correlatedMalware.length * 2 + correlatedCampaigns.length + correlatedActors.length) /
      (correlatedMalware.length + correlatedCampaigns.length + correlatedActors.length + 1);

    return {
      ioc_id: iocValue,
      correlated_malware: correlatedMalware,
      correlated_campaigns: correlatedCampaigns,
      correlated_threat_actors: correlatedActors,
      correlated_techniques: correlatedTechniques,
      correlated_reports: [],
      confidence_score: Math.min(1.0, confidenceScore),
    };
  }

  private findCorrelatedMalware(iocValue: string, iocType: string): string[] {
    const correlated: string[] = [];

    for (const [familyId, family] of this.malwareFamilies) {
      // Check if IOC is in family's IOCs
      const iocMatch = family.iocs.some(ioc => ioc.value === iocValue || ioc.normalized === iocValue);

      // Check if IOC is in any variant's IOCs
      const variantMatch = family.variants.some(variant =>
        variant.iocs.some(ioc => ioc.value === iocValue || ioc.normalized === iocValue)
      );

      if (iocMatch || variantMatch) {
        correlated.push(familyId);
      }
    }

    return correlated;
  }

  private findCorrelatedCampaigns(malwareIds: string[]): string[] {
    const correlated = new Set<string>();

    for (const malwareId of malwareIds) {
      const family = this.malwareFamilies.get(malwareId);
      if (family && family.campaigns) {
        family.campaigns.forEach(id => correlated.add(id));
      }
    }

    return Array.from(correlated);
  }

  private findCorrelatedActors(malwareIds: string[], campaignIds: string[]): string[] {
    const correlated = new Set<string>();

    // From malware
    for (const malwareId of malwareIds) {
      const family = this.malwareFamilies.get(malwareId);
      if (family && family.threat_actors) {
        family.threat_actors.forEach(id => correlated.add(id));
      }
    }

    // From campaigns
    for (const campaignId of campaignIds) {
      const campaign = this.campaigns.get(campaignId);
      if (campaign && campaign.threat_actors) {
        campaign.threat_actors.forEach(id => correlated.add(id));
      }
    }

    return Array.from(correlated);
  }

  private findCorrelatedTechniques(malwareIds: string[]): string[] {
    const correlated = new Set<string>();

    for (const malwareId of malwareIds) {
      const family = this.malwareFamilies.get(malwareId);
      if (family) {
        family.mitre_techniques.forEach(technique => correlated.add(technique.technique_id));
      }
    }

    return Array.from(correlated);
  }

  getCorrelationGraph(iocValue: string): {
    ioc: string;
    malware: Array<{ id: string; name: string }>;
    campaigns: Array<{ id: string; name: string }>;
    actors: Array<{ id: string; name: string }>;
    techniques: string[];
  } {
    const correlation = this.correlate(iocValue, 'unknown');

    return {
      ioc: iocValue,
      malware: correlation.correlated_malware
        .map(id => this.malwareFamilies.get(id))
        .filter((f): f is MalwareFamily => f !== undefined)
        .map(f => ({ id: f.id, name: f.name })),
      campaigns: correlation.correlated_campaigns
        .map(id => this.campaigns.get(id))
        .filter((c): c is Campaign => c !== undefined)
        .map(c => ({ id: c.id, name: c.name })),
      actors: correlation.correlated_threat_actors
        .map(id => this.threatActors.get(id))
        .filter((a): a is ThreatActor => a !== undefined)
        .map(a => ({ id: a.id, name: a.name })),
      techniques: correlation.correlated_techniques,
    };
  }
}

export function createCorrelationEngine(): CorrelationEngine {
  return new CorrelationEngine();
}
