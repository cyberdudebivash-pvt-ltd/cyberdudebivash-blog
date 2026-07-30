/**
 * SEO & Front Matter Generation
 * Generates blog-compatible front matter and SEO metadata
 */

import type { MalwareReportMetadata } from './metadata';

export interface Frontmatter {
  title: string;
  description: string;
  slug: string;
  published_at: string;
  updated_at: string;
  canonical?: string;
  tags: string[];
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
  tlp?: string;
  author?: string;
}

export function generateFrontmatter(metadata: MalwareReportMetadata): Frontmatter {
  return {
    title: metadata.title,
    description: metadata.description,
    slug: metadata.slug,
    published_at: metadata.published_at,
    updated_at: metadata.last_updated,
    canonical: metadata.canonical,
    tags: metadata.tags,
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
    tlp: 'TLP:GREEN',
    author: metadata.analyst || 'SENTINEL APEX Intelligence Division',
  };
}

export function formatFrontmatterYAML(frontmatter: Frontmatter): string {
  const lines: string[] = ['---'];

  const formatValue = (v: unknown): string => {
    if (typeof v === 'string') return `"${v.replace(/"/g, '\\"')}"`;
    if (Array.isArray(v)) return `[${v.map(i => formatValue(i)).join(', ')}]`;
    return String(v);
  };

  Object.entries(frontmatter).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      if (Array.isArray(value)) {
        lines.push(`${key}:`);
        value.forEach(item => {
          lines.push(`  - ${formatValue(item)}`);
        });
      } else {
        lines.push(`${key}: ${formatValue(value)}`);
      }
    }
  });

  lines.push('---');
  return lines.join('\n');
}

export interface SEOMetadata {
  og_title: string;
  og_description: string;
  og_type: string;
  og_url: string;
  twitter_card: string;
  twitter_title: string;
  twitter_description: string;
  keywords: string[];
  author: string;
}

export function generateSEOMetadata(metadata: MalwareReportMetadata): SEOMetadata {
  const keywords: string[] = [
    metadata.malware_family,
    metadata.malware_type,
    'malware analysis',
    'threat intelligence',
    'cybersecurity',
    ...metadata.mitre_techniques,
    ...metadata.threat_actors,
    ...metadata.target_industries,
  ].filter((k): k is string => k !== null && k !== undefined);

  return {
    og_title: metadata.title,
    og_description: metadata.description,
    og_type: 'article',
    og_url: metadata.canonical || `https://blog.cyberdudebivash.in/${metadata.slug}`,
    twitter_card: 'summary_large_image',
    twitter_title: metadata.title,
    twitter_description: metadata.description,
    keywords: [...new Set(keywords)],
    author: 'CYBERDUDEBIVASH® SENTINEL APEX',
  };
}

export function generateStructuredData(metadata: MalwareReportMetadata): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: metadata.title,
    description: metadata.description,
    datePublished: metadata.published_at,
    dateModified: metadata.last_updated,
    author: {
      '@type': 'Organization',
      name: 'CYBERDUDEBIVASH® SENTINEL APEX',
    },
    keywords: metadata.tags.join(', '),
    articleBody: `Intelligence report on ${metadata.malware_family}`,
  };
}
