/**
 * SENTINEL APEX Detection Engineering Schema
 * Core type definitions for Sigma, YARA, Suricata, SIEM rule generation
 */

import { z } from 'zod';

// ============================================================================
// ENUMS
// ============================================================================

export enum DetectionFormat {
  SIGMA = 'sigma',
  YARA = 'yara',
  SURICATA = 'suricata',
  SPLUNK = 'splunk',
  ELK = 'elk',
  SENTINEL = 'sentinel',
  ARCSIGHT = 'arcsight',
}

export enum RuleSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFORMATIONAL = 'informational',
}

export enum DetectionBehavior {
  NETWORK_COMMUNICATION = 'network_communication',
  FILE_ACTIVITY = 'file_activity',
  REGISTRY_MODIFICATION = 'registry_modification',
  PROCESS_EXECUTION = 'process_execution',
  LATERAL_MOVEMENT = 'lateral_movement',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  CREDENTIAL_THEFT = 'credential_theft',
  DATA_EXFILTRATION = 'data_exfiltration',
  PERSISTENCE = 'persistence',
  DEFENSE_EVASION = 'defense_evasion',
}

// ============================================================================
// SIGMA TYPES
// ============================================================================

export interface SigmaLogsource {
  category?: string;
  product?: string;
  service?: string;
}

export interface SigmaDetectionField {
  [key: string]: string | string[] | Record<string, string | string[]>;
}

export interface SigmaDetection {
  [key: string]: SigmaDetectionField | string[];
  condition: string | string[];
}

export interface SigmaRule {
  title: string;
  id: string;
  status: 'experimental' | 'test' | 'stable' | 'deprecated';
  description: string;
  author: string;
  date: string;
  modified?: string;
  logsource: SigmaLogsource;
  detection: SigmaDetection;
  falsepositives?: string[];
  level: RuleSeverity;
  references?: string[];
  tags?: string[];
}

// ============================================================================
// YARA TYPES
// ============================================================================

export interface YaraString {
  name: string;
  pattern: string;
  isRegex?: boolean;
  isWide?: boolean;
  isCaseInsensitive?: boolean;
}

export interface YaraMetadata {
  [key: string]: string | number | boolean;
}

export interface YaraRule {
  name: string;
  scope?: 'private' | 'public';
  metadata: YaraMetadata;
  strings: YaraString[];
  condition: string;
}

// ============================================================================
// SURICATA TYPES
// ============================================================================

export interface SuricataFlow {
  direction: 'to_server' | 'to_client' | 'both';
  homeNet: 'HOME_NET' | 'EXTERNAL_NET' | 'any';
  port?: string | number;
}

export interface SuricataContent {
  pattern: string;
  offset?: number;
  depth?: number;
  distance?: number;
  within?: number;
  fastPattern?: boolean;
  caseSensitive?: boolean;
}

export interface SuricataRule {
  action: 'alert' | 'drop' | 'reject' | 'rejectsrc' | 'pass';
  protocol: 'tcp' | 'udp' | 'icmp' | 'ip' | 'http' | 'tls';
  sourceIp: string;
  sourcePort: string | number;
  direction: '->' | '<>';
  destIp: string;
  destPort: string | number;
  msg: string;
  flow?: SuricataFlow;
  content?: SuricataContent[];
  pcre?: string;
  classtype?: string;
  sid: string | number;
  rev?: number;
  reference?: string[];
}

// ============================================================================
// SIEM RULE TYPES
// ============================================================================

export interface SEMRuleField {
  name: string;
  value: string | string[];
  operator?: 'equals' | 'contains' | 'startswith' | 'endswith' | 'regex';
}

export interface SEMRule {
  name: string;
  description: string;
  source: 'splunk' | 'elk' | 'sentinel' | 'arcsight';
  eventType: string;
  fields: SEMRuleField[];
  threshold?: {
    operator: 'greater_than' | 'less_than' | 'equals';
    value: number;
    timeWindow: string;
  };
  severity: RuleSeverity;
}

// ============================================================================
// UNIFIED DETECTION RULE
// ============================================================================

export interface RuleMetadata {
  linkedMalware: string[];
  linkedTechniques: string[];
  linkedIOCs: string[];
  linkedCampaigns?: string[];
  linkedActors?: string[];
  coverage?: number;
  fpRate?: number;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  author: string;
  date: string;
  severity: RuleSeverity;
  formats: {
    sigma?: SigmaRule;
    yara?: YaraRule;
    suricata?: SuricataRule[];
    siem?: SEMRule[];
  };
  metadata: RuleMetadata;
  behaviors: DetectionBehavior[];
  falsePositives?: string[];
  references?: string[];
  enabled: boolean;
  tags: string[];
}

export interface DetectionRuleCollection {
  name: string;
  description: string;
  author: string;
  date: string;
  rules: DetectionRule[];
  metadata: {
    totalRules: number;
    malwareFamilies: string[];
    techniques: string[];
    iocCount: number;
  };
}

// ============================================================================
// DETECTION GENERATION REQUEST/RESPONSE
// ============================================================================

export interface GenerateDetectionRequest {
  iocType: string;
  iocValue: string;
  malwareId?: string;
  techniques?: string[];
  formats?: DetectionFormat[];
  severity?: RuleSeverity;
}

export interface GenerateDetectionResponse {
  rules: DetectionRule[];
  coverage: number;
  timestamp: string;
}

export interface DetectionRuleExport {
  format: DetectionFormat;
  rules: DetectionRule[];
  content: string;
  mimeType: string;
}

// ============================================================================
// DETECTION SEARCH QUERY
// ============================================================================

export interface DetectionSearchQuery {
  malwareId?: string;
  technique?: string;
  iocValue?: string;
  severity?: RuleSeverity;
  behavior?: DetectionBehavior;
  format?: DetectionFormat;
  limit?: number;
  offset?: number;
}

// ============================================================================
// DETECTION OPTIMIZATION
// ============================================================================

export interface DeduplicationResult {
  originalCount: number;
  deduplicatedCount: number;
  mergedRules: DetectionRule[];
  redundantRules: DetectionRule[];
  confidence: number;
}

export interface OptimizationMetrics {
  totalRules: number;
  redundantRules: number;
  averageCoverage: number;
  averageFPRate: number;
  recommendations: string[];
}

// ============================================================================
// VALIDATION TYPES
// ============================================================================

export interface RuleValidationError {
  rule: string;
  format: DetectionFormat;
  error: string;
  field?: string;
  severity: 'error' | 'warning';
}

export interface RuleValidationResult {
  valid: boolean;
  errors: RuleValidationError[];
  warnings: RuleValidationError[];
}
