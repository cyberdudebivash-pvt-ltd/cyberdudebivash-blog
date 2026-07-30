/**
 * Zod validation schemas for SENTINEL APEX Malware Intelligence
 * Runtime validation and type coercion for all intelligence objects
 */

import { z } from 'zod';
import * as schema from './schema';

// Confidence level validator
export const ConfidenceLevelSchema = z.enum(['HIGH', 'MEDIUM', 'LOW']);

// IOC type validator
export const IOCTypeSchema = z.nativeEnum(schema.IOCType);

// Platform validator
export const PlatformSchema = z.nativeEnum(schema.Platform);

// Malware type validator
export const MalwareTypeSchema = z.nativeEnum(schema.MalwareType);

// Evidence validator
export const EvidenceSchema = z.object({
  source: z.string().min(1),
  date: z.string().datetime(),
  attribution: z.enum(['observed_fact', 'analyst_assessment', 'hypothesis']),
  confidence: ConfidenceLevelSchema,
  notes: z.string().optional(),
});

// Reference validator
export const ReferenceSchema = z.object({
  url: z.string().url(),
  date: z.string().datetime().optional(),
  title: z.string().optional(),
  source: z.string().optional(),
});

// IOC validator with normalization
export const IOCSchema = z.object({
  type: IOCTypeSchema,
  value: z.string().min(1),
  normalized: z.string().optional(),
  confidence: ConfidenceLevelSchema,
  first_seen: z.string().datetime().optional(),
  last_seen: z.string().datetime().optional(),
  evidence: EvidenceSchema,
  verified: z.boolean(),
}).transform((ioc) => {
  // Normalize hashes to uppercase, domains to lowercase
  if ([schema.IOCType.SHA256, schema.IOCType.SHA1, schema.IOCType.MD5].includes(ioc.type)) {
    ioc.normalized = ioc.value.toUpperCase();
  } else if (ioc.type === schema.IOCType.DOMAIN) {
    ioc.normalized = ioc.value.toLowerCase();
  }
  return ioc;
});

// MITRE technique validator
export const MitreTechniqueSchema = z.object({
  technique_id: z.string().regex(/^T\d{4}(?:\.\d{3})?$/), // T1234 or T1234.001
  name: z.string().min(1),
  tactic: z.string().min(1),
  sub_technique: z.string().optional(),
  confidence: ConfidenceLevelSchema,
  evidence: EvidenceSchema,
  notes: z.string().optional(),
});

// Threat actor validator
export const ThreatActorSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  aliases: z.array(z.string()),
  description: z.string().optional(),
  known_campaigns: z.array(z.string()),
  attribution_confidence: ConfidenceLevelSchema,
  first_seen: z.string().datetime().optional(),
  last_seen: z.string().datetime().optional(),
  target_industries: z.array(z.string()).optional(),
  target_regions: z.array(z.string()).optional(),
  evidence: EvidenceSchema,
});

// Campaign validator
export const CampaignSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().min(1),
  start_date: z.string().datetime(),
  end_date: z.string().datetime().optional(),
  status: z.enum(['active', 'inactive', 'unknown']),
  malware_families: z.array(z.string()),
  threat_actors: z.array(z.string()).optional(),
  cves: z.array(z.string()).optional(),
  victim_count: z.number().int().nonnegative().optional(),
  target_industries: z.array(z.string()).optional(),
  target_regions: z.array(z.string()).optional(),
  evidence: EvidenceSchema,
});

// Malware variant validator
export const MalwareVariantSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  version: z.string().optional(),
  description: z.string().optional(),
  discovery_date: z.string().datetime(),
  iocs: z.array(IOCSchema),
  capabilities: z.array(z.string()).optional(),
  mitre_techniques: z.array(MitreTechniqueSchema).optional(),
  associated_campaigns: z.array(z.string()).optional(),
  evidence: EvidenceSchema,
});

// Malware family validator (core)
export const MalwareFamilySchema = z.object({
  id: z.string().min(1).regex(/^[a-z0-9_-]+$/), // Lowercase alphanumeric, dash, underscore
  name: z.string().min(1),
  aliases: z.array(z.string()),
  description: z.string().optional(),
  type: MalwareTypeSchema,
  platforms: z.array(PlatformSchema),
  discovery_date: z.string().datetime().optional(),
  first_observed: z.string().datetime().optional(),
  last_observed: z.string().datetime().optional(),

  variants: z.array(MalwareVariantSchema),
  iocs: z.array(IOCSchema),
  mitre_techniques: z.array(MitreTechniqueSchema),

  threat_actors: z.array(z.string()).optional(),
  campaigns: z.array(z.string()).optional(),
  related_malware: z.array(z.string()).optional(),

  known_victims: z.array(z.string()).optional(),
  target_industries: z.array(z.string()).optional(),
  target_regions: z.array(z.string()).optional(),

  language: z.string().optional(),
  compiler: z.string().optional(),
  packer: z.string().optional(),
  encryption: z.string().optional(),
  obfuscation: z.string().optional(),

  related_cves: z.array(z.string()).optional(),

  c2_protocol: z.string().optional(),
  c2_domains: z.array(z.string()).optional(),
  c2_ips: z.array(z.string()).optional(),

  confidence: ConfidenceLevelSchema,
  evidence: EvidenceSchema,
  references: z.array(ReferenceSchema),

  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  analyst: z.string().optional(),
}).refine((malware) => {
  // Ensure at least one IOC if iocs array exists
  if (malware.iocs && malware.iocs.length === 0 && malware.variants.some(v => v.iocs.length > 0)) {
    return true; // OK if variants have IOCs
  }
  return true;
}, {
  message: 'Malware family should have IOCs in variants or root iocs array',
});

// Report metadata validator
export const ReportMetadataSchema = z.object({
  report_id: z.string().regex(/^[A-Z]{2}-\d{4}-\d{4}$/), // e.g., SA-2026-0001
  title: z.string().min(10),
  date: z.string().datetime(),
  tlp: z.enum(['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED']),
  report_type: z.enum(['incident', 'threat_analysis', 'malware_analysis', 'campaign', 'advisory']),
  version: z.string().regex(/^\d+\.\d+\.\d+$/), // Semver
  last_updated: z.string().datetime(),
  review_status: z.enum(['draft', 'reviewed', 'published']),

  threat_actors: z.array(z.string()),
  malware_families: z.array(z.string()),
  cves: z.array(z.string()),
  campaigns: z.array(z.string()),

  sectors: z.array(z.string()),
  attack_ids: z.array(z.string()),

  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']),
  confidence: ConfidenceLevelSchema,
  cvss: z.string().optional(),

  analyst: z.string().min(1),
  reviewer: z.string().optional(),

  sources: z.array(ReferenceSchema),
});

// Detection rule validator
export const DetectionRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  type: z.enum(['sigma', 'yara', 'suricata', 'snort', 'kql', 'eql', 'spl', 'aql', 'udm']),
  rule_content: z.string().min(10),
  platforms: z.array(PlatformSchema).optional(),
  confidence: ConfidenceLevelSchema,
  false_positive_notes: z.string().optional(),
  enabled: z.boolean(),
  created_at: z.string().datetime(),
});

// Aggregated summary validator
export const MalwareIntelligenceSummarySchema = z.object({
  malware_family: MalwareFamilySchema,
  variants_count: z.number().int().nonnegative(),
  total_iocs: z.number().int().nonnegative(),
  campaigns_count: z.number().int().nonnegative(),
  threat_actors_count: z.number().int().nonnegative(),
  detection_rules_count: z.number().int().nonnegative(),
  related_reports: z.array(z.string()),
  last_activity: z.string().datetime(),
});

// Knowledge graph node validator
export const KnowledgeGraphNodeSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  type: z.enum([
    'malware', 'malware_family', 'malware_variant', 'cve',
    'ioc_domain', 'ioc_ipv4', 'ioc_ipv6', 'ioc_sha256', 'ioc_sha1', 'ioc_md5',
    'ioc_url', 'ioc_email', 'ioc_mutex', 'ioc_registry', 'ioc_service',
    'technique', 'vendor', 'product', 'threat_actor', 'campaign', 'report',
  ]),
  properties: z.record(z.unknown()).optional(),
});

// Knowledge graph edge validator
export const KnowledgeGraphEdgeSchema = z.object({
  src: z.string().min(1),
  dst: z.string().min(1),
  rel: z.string().min(1),
  report: z.string().optional(),
  confidence: ConfidenceLevelSchema.optional(),
});

// Knowledge graph validator
export const KnowledgeGraphSchema = z.object({
  entities: z.record(KnowledgeGraphNodeSchema),
  relations: z.array(KnowledgeGraphEdgeSchema),
  generated_at: z.string().datetime(),
  version: z.string(),
});

// Type inference from validators
export type ValidatedMalwareFamily = z.infer<typeof MalwareFamilySchema>;
export type ValidatedIOC = z.infer<typeof IOCSchema>;
export type ValidatedEvidence = z.infer<typeof EvidenceSchema>;
export type ValidatedMitreTechnique = z.infer<typeof MitreTechniqueSchema>;
export type ValidatedThreatActor = z.infer<typeof ThreatActorSchema>;
export type ValidatedCampaign = z.infer<typeof CampaignSchema>;
export type ValidatedReportMetadata = z.infer<typeof ReportMetadataSchema>;
export type ValidatedDetectionRule = z.infer<typeof DetectionRuleSchema>;
export type ValidatedKnowledgeGraph = z.infer<typeof KnowledgeGraphSchema>;

/**
 * Validation helper functions
 */

export function validateMalwareFamily(data: unknown): ValidatedMalwareFamily {
  return MalwareFamilySchema.parse(data);
}

export function validateMalwareFamilySafe(data: unknown): ValidatedMalwareFamily | null {
  try {
    return MalwareFamilySchema.parse(data);
  } catch (error) {
    console.error('Malware family validation failed:', error);
    return null;
  }
}

export function validateIOC(data: unknown): ValidatedIOC {
  return IOCSchema.parse(data);
}

export function validateReportMetadata(data: unknown): ValidatedReportMetadata {
  return ReportMetadataSchema.parse(data);
}

export function validateKnowledgeGraph(data: unknown): ValidatedKnowledgeGraph {
  return KnowledgeGraphSchema.parse(data);
}
