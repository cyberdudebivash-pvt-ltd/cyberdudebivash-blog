/**
 * SENTINEL APEX Malware Intelligence Data Model
 * Canonical schema for malware families, IOCs, threat actors, campaigns, and evidence attribution
 */

// Confidence levels for all assessments
export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';

// IOC types supported by Sentinel APEX
export enum IOCType {
  SHA256 = 'sha256',
  SHA1 = 'sha1',
  MD5 = 'md5',
  DOMAIN = 'domain',
  IPV4 = 'ipv4',
  IPV6 = 'ipv6',
  URL = 'url',
  EMAIL = 'email',
  MUTEX = 'mutex',
  REGISTRY = 'registry',
  SERVICE = 'service',
  PROCESS = 'process',
  FILE_PATH = 'file_path',
  CERTIFICATE = 'certificate',
  JA3 = 'ja3',
  JA4 = 'ja4',
  USER_AGENT = 'user_agent',
  TLS_FINGERPRINT = 'tls_fingerprint',
}

// Malware platforms
export enum Platform {
  WINDOWS = 'windows',
  LINUX = 'linux',
  MACOS = 'macos',
  ANDROID = 'android',
  IOS = 'ios',
  CLOUD = 'cloud',
  CONTAINER = 'container',
  ICS = 'ics',
  OT = 'ot',
  IOT = 'iot',
}

// Malware types/families
export enum MalwareType {
  RANSOMWARE = 'ransomware',
  STEALER = 'stealer',
  LOADER = 'loader',
  DOWNLOADER = 'downloader',
  DROPPER = 'dropper',
  ROOTKIT = 'rootkit',
  BACKDOOR = 'backdoor',
  BANKING_TROJAN = 'banking_trojan',
  REMOTE_ACCESS_TROJAN = 'remote_access_trojan',
  INFORMATION_STEALER = 'information_stealer',
  BOTNET = 'botnet',
  SPYWARE = 'spyware',
  ADWARE = 'adware',
  WORM = 'worm',
  CRYPTOMINER = 'cryptominer',
  FILELESS = 'fileless',
  LIVING_OFF_THE_LAND = 'living_off_the_land',
  BOOTKIT = 'bootkit',
  UEFI_MALWARE = 'uefi_malware',
  APT_MALWARE = 'apt_malware',
  AI_MALWARE = 'ai_malware',
}

// Evidence source
export interface Evidence {
  source: string; // e.g., "CISA KEV", "vendor advisory", "VirusTotal", "honeypot telemetry"
  date: string; // ISO 8601
  attribution: 'observed_fact' | 'analyst_assessment' | 'hypothesis';
  confidence: ConfidenceLevel;
  notes?: string;
}

// Reference/source for intelligence
export interface Reference {
  url: string;
  date?: string; // ISO 8601
  title?: string;
  source?: string; // e.g., "NVD", "SecurityWeek", "GitHub"
}

// IOC object
export interface IOC {
  type: IOCType;
  value: string;
  normalized?: string; // lowercase for domains, uppercase for hashes
  confidence: ConfidenceLevel;
  first_seen?: string; // ISO 8601
  last_seen?: string; // ISO 8601
  evidence: Evidence;
  verified: boolean;
}

// MITRE ATT&CK technique mapping
export interface MitreTechnique {
  technique_id: string; // e.g., "T1027"
  name: string; // e.g., "Obfuscated Files or Information"
  tactic: string; // e.g., "defense_evasion"
  sub_technique?: string; // e.g., "T1027.001"
  confidence: ConfidenceLevel;
  evidence: Evidence;
  notes?: string;
}

// Threat actor/group
export interface ThreatActor {
  id: string; // e.g., "ta-lazarus", "apt28"
  name: string; // e.g., "Lazarus Group", "APT28"
  aliases: string[]; // e.g., ["HIDDEN COBRA", "DPRK Hackers"]
  description?: string;
  known_campaigns: string[]; // Campaign IDs
  attribution_confidence: ConfidenceLevel;
  first_seen?: string; // ISO 8601
  last_seen?: string; // ISO 8601
  target_industries?: string[]; // e.g., ["Finance", "Government"]
  target_regions?: string[]; // e.g., ["US", "EU"]
  evidence: Evidence;
}

// Campaign
export interface Campaign {
  id: string; // e.g., "2026-sharepoint-wave"
  name: string; // e.g., "SharePoint Exploitation Wave"
  description: string;
  start_date: string; // ISO 8601
  end_date?: string; // ISO 8601
  status: 'active' | 'inactive' | 'unknown';
  malware_families: string[]; // Malware family IDs
  threat_actors?: string[]; // Threat actor IDs
  cves?: string[]; // CVE IDs
  victim_count?: number;
  target_industries?: string[];
  target_regions?: string[];
  evidence: Evidence;
}

// Malware variant
export interface MalwareVariant {
  id: string; // e.g., "qilin-v2.0"
  name: string; // e.g., "Qilin v2.0"
  version?: string; // e.g., "2.0"
  description?: string;
  discovery_date: string; // ISO 8601
  iocs: IOC[];
  capabilities?: string[]; // e.g., ["encryption", "exfiltration", "lateral_movement"]
  mitre_techniques?: MitreTechnique[];
  associated_campaigns?: string[]; // Campaign IDs
  evidence: Evidence;
}

// Malware family (core object)
export interface MalwareFamily {
  id: string; // e.g., "qilin", "lockbit"
  name: string; // e.g., "Qilin"
  aliases: string[]; // e.g., ["Qilin Ransomware", "ChaCha Ransomware"]
  description?: string;
  type: MalwareType;
  platforms: Platform[];
  discovery_date?: string; // ISO 8601
  first_observed?: string; // ISO 8601
  last_observed?: string; // ISO 8601

  // Variants
  variants: MalwareVariant[];

  // IOCs associated with family (aggregated from variants)
  iocs: IOC[];

  // MITRE ATT&CK
  mitre_techniques: MitreTechnique[];

  // Attribution
  threat_actors?: string[]; // Threat actor IDs
  campaigns?: string[]; // Campaign IDs
  related_malware?: string[]; // Other malware family IDs

  // Incident details
  known_victims?: string[]; // Organization names (not PII)
  target_industries?: string[]; // e.g., ["Finance", "Healthcare", "Government"]
  target_regions?: string[]; // Country codes

  // Technical details
  language?: string; // Development language if known
  compiler?: string; // e.g., "MSVC", "GCC"
  packer?: string; // e.g., "UPX", "Themida"
  encryption?: string; // Encryption algorithm if known
  obfuscation?: string; // Obfuscation technique if known

  // CVEs exploited by this malware
  related_cves?: string[]; // CVE IDs

  // Infrastructure
  c2_protocol?: string; // e.g., "HTTP", "HTTPS", "DNS", "Tor"
  c2_domains?: string[];
  c2_ips?: string[];

  // Confidence and evidence
  confidence: ConfidenceLevel;
  evidence: Evidence;
  references: Reference[];

  // Metadata
  created_at: string; // ISO 8601, when added to Sentinel APEX
  updated_at: string; // ISO 8601, last update
  analyst?: string; // Analyst who created/updated
}

// Detection rule metadata
export interface DetectionRule {
  id: string; // e.g., "sigma-qilin-encryption"
  name: string;
  type: 'sigma' | 'yara' | 'suricata' | 'snort' | 'kql' | 'eql' | 'spl' | 'aql' | 'udm'; // Detection engine type
  rule_content: string; // The actual rule (YAML, etc.)
  platforms?: Platform[]; // Platforms this rule applies to
  confidence: ConfidenceLevel;
  false_positive_notes?: string;
  enabled: boolean;
  created_at: string; // ISO 8601
}

// Report metadata (extends YAML front-matter)
export interface ReportMetadata {
  report_id: string; // e.g., "SA-2026-0001"
  title: string;
  date: string; // ISO 8601
  tlp: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
  report_type: 'incident' | 'threat_analysis' | 'malware_analysis' | 'campaign' | 'advisory';
  version: string; // Semver
  last_updated: string; // ISO 8601
  review_status: 'draft' | 'reviewed' | 'published';

  // Content associations
  threat_actors: string[]; // Threat actor IDs
  malware_families: string[]; // Malware family IDs
  cves: string[]; // CVE IDs
  campaigns: string[]; // Campaign IDs

  // Classifications
  sectors: string[]; // Affected industries
  attack_ids: string[]; // MITRE ATT&CK technique IDs

  // Severity/confidence
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: ConfidenceLevel;
  cvss?: string; // CVSS vector or score

  // Attribution
  analyst: string;
  reviewer?: string;

  // Sources
  sources: Reference[];
}

// Aggregated malware intelligence for API/dashboard
export interface MalwareIntelligenceSummary {
  malware_family: MalwareFamily;
  variants_count: number;
  total_iocs: number;
  campaigns_count: number;
  threat_actors_count: number;
  detection_rules_count: number;
  related_reports: string[]; // Report IDs
  last_activity: string; // ISO 8601
}

// Knowledge graph node types (mirrors existing knowledge-graph.json entities)
export type KnowledgeGraphEntityType =
  | 'malware'
  | 'malware_family'
  | 'malware_variant'
  | 'cve'
  | 'ioc_domain'
  | 'ioc_ipv4'
  | 'ioc_ipv6'
  | 'ioc_sha256'
  | 'ioc_sha1'
  | 'ioc_md5'
  | 'ioc_url'
  | 'ioc_email'
  | 'ioc_mutex'
  | 'ioc_registry'
  | 'ioc_service'
  | 'technique'
  | 'vendor'
  | 'product'
  | 'threat_actor'
  | 'campaign'
  | 'report';

// Knowledge graph node
export interface KnowledgeGraphNode {
  id: string; // e.g., "malware:qilin", "cve:CVE-2026-0257"
  name: string;
  type: KnowledgeGraphEntityType;
  properties?: Record<string, unknown>;
}

// Knowledge graph edge
export interface KnowledgeGraphEdge {
  src: string; // Node ID
  dst: string; // Node ID
  rel: string; // Relationship type (e.g., "mentions", "references", "maps_to", "exploits", "observed")
  report?: string; // Report ID if applicable
  confidence?: ConfidenceLevel;
}

// Knowledge graph
export interface KnowledgeGraph {
  entities: Record<string, KnowledgeGraphNode>;
  relations: KnowledgeGraphEdge[];
  generated_at: string; // ISO 8601
  version: string; // Graph schema version
}
