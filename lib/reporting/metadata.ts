/**
 * Report Metadata Generation
 * Creates machine-readable metadata for reports (for APIs, SEO, filtering)
 */

import type { MalwareFamily, MitreTechnique } from '../intelligence/schema';

export interface MalwareReportMetadata {
  id: string;
  title: string;
  description: string;
  slug: string;
  canonical?: string;
  malware_family: string;
  malware_aliases: string[];
  malware_type: string;
  platforms: string[];
  mitre_techniques: string[];
  mitre_tactics: string[];
  threat_actors: string[];
  campaigns: string[];
  cves: string[];
  target_industries: string[];
  target_regions: string[];
  confidence: string;
  severity: string;
  first_observed?: string;
  last_observed?: string;
  last_updated: string;
  published_at: string;
  analyst?: string;
  tags: string[];
}

export function generateMetadata(malware: MalwareFamily): MalwareReportMetadata {
  const tactics = Array.from(new Set(malware.mitre_techniques.map((t: MitreTechnique) => t.tactic)));
  const techniques = malware.mitre_techniques.map((t: MitreTechnique) => t.technique_id);

  return {
    id: `report-${malware.id}`,
    title: `${malware.name} Malware Intelligence Report`,
    description: malware.description || `Comprehensive threat intelligence report on ${malware.name}`,
    slug: `malware-reports/${malware.id}`,
    malware_family: malware.id,
    malware_aliases: malware.aliases,
    malware_type: malware.type,
    platforms: malware.platforms,
    mitre_techniques: techniques,
    mitre_tactics: tactics,
    threat_actors: malware.threat_actors || [],
    campaigns: malware.campaigns || [],
    cves: malware.related_cves || [],
    target_industries: malware.target_industries || [],
    target_regions: malware.target_regions || [],
    confidence: malware.confidence,
    severity: malware.confidence === 'HIGH' ? 'CRITICAL' : 'HIGH',
    first_observed: malware.first_observed,
    last_observed: malware.last_observed,
    last_updated: malware.updated_at,
    published_at: new Date().toISOString(),
    analyst: malware.analyst,
    tags: [
      malware.type,
      ...malware.platforms,
      ...tactics,
      ...(malware.target_industries || []),
    ],
  };
}

export function metadataToFrontmatter(metadata: MalwareReportMetadata): Record<string, unknown> {
  return {
    title: metadata.title,
    description: metadata.description,
    slug: metadata.slug,
    canonical: metadata.canonical,
    malware_family: metadata.malware_family,
    malware_aliases: metadata.malware_aliases,
    malware_type: metadata.malware_type,
    platforms: metadata.platforms,
    mitre_techniques: metadata.mitre_techniques,
    mitre_tactics: metadata.mitre_tactics,
    threat_actors: metadata.threat_actors,
    campaigns: metadata.campaigns,
    cves: metadata.cves,
    target_industries: metadata.target_industries,
    target_regions: metadata.target_regions,
    confidence: metadata.confidence,
    severity: metadata.severity,
    first_observed: metadata.first_observed,
    last_observed: metadata.last_observed,
    last_updated: metadata.last_updated,
    published_at: metadata.published_at,
    analyst: metadata.analyst,
    tags: metadata.tags,
  };
}
