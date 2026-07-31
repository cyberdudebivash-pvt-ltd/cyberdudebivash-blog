/**
 * Sigma Rule Generator
 * Generates Sigma YAML detection rules from IOCs and MITRE techniques
 */

import { v4 as uuidv4 } from 'uuid';
import type { SigmaRule, SigmaDetection } from '../schema';
import { RuleSeverity } from '../schema';
import type { IOCType } from '../../intelligence/schema';

// ============================================================================
// SIGMA RULE GENERATION
// ============================================================================

export interface SigmaGeneratorOptions {
  severity?: RuleSeverity;
  techniques?: string[];
  malwareId?: string;
  falsePositiveRate?: number;
}

export function generateSigmaFromIOC(
  iocType: IOCType,
  iocValue: string,
  malwareName: string,
  options?: SigmaGeneratorOptions
): SigmaRule {
  const severity = options?.severity || RuleSeverity.HIGH;
  const techniques = options?.techniques || [];
  const malwareId = options?.malwareId || malwareName.toLowerCase();

  // Generate base title and description
  const title = generateTitle(iocType, iocValue, malwareName);
  const description = generateDescription(iocType, iocValue, malwareName, techniques);

  // Generate logsource based on IOC type
  const logsource = generateLogsource(iocType);

  // Generate detection patterns
  const detection = generateDetection(iocType, iocValue);

  // Generate tags
  const tags = generateTags(iocType, malwareId, techniques);

  const rule: SigmaRule = {
    title,
    id: uuidv4(),
    status: 'experimental',
    description,
    author: 'SENTINEL APEX Detection Engineering',
    date: new Date().toISOString().split('T')[0],
    logsource,
    detection,
    level: severity,
    tags,
    references: [
      `https://mitre-attack.github.io`,
      `https://www.cyberdudebivash.in`,
    ],
    falsepositives: generateFalsePositives(iocType),
  };

  return rule;
}

// ============================================================================
// SIGMA TITLE GENERATION
// ============================================================================

function generateTitle(iocType: IOCType, iocValue: string, malwareName: string): string {
  const titleMap: Record<string, string> = {
    sha256: `Detection of ${malwareName} - SHA256 Hash Match`,
    sha1: `Detection of ${malwareName} - SHA1 Hash Match`,
    md5: `Detection of ${malwareName} - MD5 Hash Match`,
    domain: `Detection of ${malwareName} - C2 Domain Communication`,
    ipv4: `Detection of ${malwareName} - C2 IPv4 Communication`,
    ipv6: `Detection of ${malwareName} - C2 IPv6 Communication`,
    url: `Detection of ${malwareName} - Malicious URL Access`,
    email: `Detection of ${malwareName} - Associated Email Address`,
    registry: `Detection of ${malwareName} - Registry Persistence`,
    file_path: `Detection of ${malwareName} - Suspicious File Path`,
    mutex: `Detection of ${malwareName} - Mutex Creation`,
    service: `Detection of ${malwareName} - Service Installation`,
    process: `Detection of ${malwareName} - Process Execution`,
    ja3: `Detection of ${malwareName} - TLS Fingerprint Match`,
    ja4: `Detection of ${malwareName} - TLS/QUIC Fingerprint Match`,
    certificate: `Detection of ${malwareName} - Certificate Hash`,
    user_agent: `Detection of ${malwareName} - User Agent Signature`,
    tls_fingerprint: `Detection of ${malwareName} - TLS Fingerprint Match`,
  };

  return titleMap[iocType] || `Detection of ${malwareName} - ${iocType}`;
}

// ============================================================================
// SIGMA DESCRIPTION GENERATION
// ============================================================================

function generateDescription(
  iocType: IOCType,
  iocValue: string,
  malwareName: string,
  techniques: string[]
): string {
  const descriptions: Record<string, string> = {
    sha256: `Detects execution of ${malwareName} malware based on known file hash (SHA256). This rule identifies attempts to run the malware executable.`,
    sha1: `Detects execution of ${malwareName} malware based on known file hash (SHA1). This rule identifies attempts to run the malware executable.`,
    md5: `Detects execution of ${malwareName} malware based on known file hash (MD5). This rule identifies attempts to run the malware executable.`,
    domain: `Detects network connections to known ${malwareName} command and control (C2) infrastructure. Monitors for DNS queries and connection attempts to ${iocValue}.`,
    ipv4: `Detects network connections to known ${malwareName} command and control infrastructure. Monitors for connections to ${iocValue}.`,
    ipv6: `Detects network connections to known ${malwareName} IPv6 command and control infrastructure. Monitors for connections to ${iocValue}.`,
    url: `Detects HTTP/HTTPS requests to known malicious URLs associated with ${malwareName}. May indicate malware callback, exploitation, or lateral movement.`,
    email: `Detects ${malwareName} spear-phishing and distribution campaigns using the email address ${iocValue}.`,
    registry: `Detects ${malwareName} persistence mechanisms through registry modification. Monitors for creation/modification of known registry keys.`,
    file_path: `Detects ${malwareName} based on suspicious file paths used for staging or execution.`,
    mutex: `Detects ${malwareName} process execution by monitoring for creation of known mutex objects used for single-instance enforcement.`,
    service: `Detects ${malwareName} persistence through Windows service installation with known service names.`,
    process: `Detects ${malwareName} process execution through known process names or command lines.`,
    ja3: `Detects ${malwareName} TLS communications based on fingerprinting. Monitors for known TLS client signatures.`,
    ja4: `Detects ${malwareName} TLS/QUIC communications based on fingerprinting.`,
    certificate: `Detects ${malwareName} HTTPS communications using known certificate hashes.`,
    user_agent: `Detects ${malwareName} HTTP communications using known user agent strings.`,
    tls_fingerprint: `Detects ${malwareName} TLS communications using fingerprint patterns.`,
  };

  let desc = descriptions[iocType] || `Detects ${malwareName} based on ${iocType} indicator.`;

  if (techniques.length > 0) {
    desc += ` Associated MITRE ATT&CK techniques: ${techniques.join(', ')}.`;
  }

  return desc;
}

// ============================================================================
// SIGMA LOGSOURCE GENERATION
// ============================================================================

function generateLogsource(iocType: IOCType) {
  const logsourceMap: Record<string, { category: string; product?: string; service?: string }> = {
    sha256: { category: 'process_creation', product: 'windows' },
    sha1: { category: 'process_creation', product: 'windows' },
    md5: { category: 'process_creation', product: 'windows' },
    domain: { category: 'dns_query', product: 'windows' },
    ipv4: { category: 'network_connection', product: 'windows' },
    ipv6: { category: 'network_connection', product: 'windows' },
    url: { category: 'web_application_firewall' },
    email: { category: 'email_security' },
    registry: { category: 'registry_set', product: 'windows' },
    file_path: { category: 'file_event', product: 'windows' },
    mutex: { category: 'process_creation', product: 'windows' },
    service: { category: 'service_installation', product: 'windows' },
    process: { category: 'process_creation', product: 'windows' },
    ja3: { category: 'network_connection', product: 'zeek' },
    ja4: { category: 'network_connection', product: 'zeek' },
    certificate: { category: 'network_connection' },
    user_agent: { category: 'web_application_firewall' },
    tls_fingerprint: { category: 'network_connection' },
  };

  return logsourceMap[iocType] || { category: 'process_creation', product: 'windows' };
}

// ============================================================================
// SIGMA DETECTION PATTERN GENERATION
// ============================================================================

function generateDetection(iocType: IOCType, iocValue: string): SigmaDetection {
  const detectionMap: Record<IOCType, SigmaDetection> = {
    sha256: {
      process_creation: {
        Hashes: iocValue.toUpperCase(),
      },
      condition: 'process_creation',
    },
    sha1: {
      process_creation: {
        Hashes: iocValue.toUpperCase(),
      },
      condition: 'process_creation',
    },
    md5: {
      process_creation: {
        Hashes: iocValue.toUpperCase(),
      },
      condition: 'process_creation',
    },
    domain: {
      dns_query: {
        QueryName: iocValue.toLowerCase(),
      },
      condition: 'dns_query',
    },
    ipv4: {
      network_connection: {
        DestinationIp: iocValue,
      },
      condition: 'network_connection',
    },
    ipv6: {
      network_connection: {
        DestinationIp: iocValue,
      },
      condition: 'network_connection',
    },
    url: {
      http_request: {
        c_uri: iocValue,
      },
      condition: 'http_request',
    },
    email: {
      email_event: {
        sender: iocValue.toLowerCase(),
      },
      condition: 'email_event',
    },
    registry: {
      registry_set: {
        TargetObject: iocValue.toUpperCase(),
      },
      condition: 'registry_set',
    },
    file_path: {
      file_event: {
        TargetFilename: iocValue,
      },
      condition: 'file_event',
    },
    mutex: {
      process_creation: {
        CommandLine: iocValue,
      },
      condition: 'process_creation',
    },
    service: {
      service_installation: {
        ServiceName: iocValue,
      },
      condition: 'service_installation',
    },
    process: {
      process_creation: {
        Image: iocValue,
      },
      condition: 'process_creation',
    },
    ja3: {
      network_connection: {
        tls_ja3: iocValue,
      },
      condition: 'network_connection',
    },
    ja4: {
      network_connection: {
        tls_ja4: iocValue,
      },
      condition: 'network_connection',
    },
    certificate: {
      network_connection: {
        certificate_sha1: iocValue.toUpperCase(),
      },
      condition: 'network_connection',
    },
    user_agent: {
      http_request: {
        User_Agent: iocValue,
      },
      condition: 'http_request',
    },
    tls_fingerprint: {
      network_connection: {
        tls_fingerprint: iocValue.toUpperCase(),
      },
      condition: 'network_connection',
    },
  };

  return detectionMap[iocType] || { selection: { field: iocValue }, condition: 'selection' };
}

// ============================================================================
// SIGMA TAG GENERATION
// ============================================================================

function generateTags(iocType: IOCType, malwareId: string, techniques: string[]): string[] {
  const baseTags = [
    'malware',
    'detection',
    malwareId,
    `ioc_type_${iocType}`,
    'sentinel_apex',
  ];

  // Add technique tags
  if (techniques.length > 0) {
    baseTags.push(...techniques.map(t => `attack_${t.toLowerCase().replace('.', '_')}`));
  }

  // Add behavior-based tags
  const behaviorTags: Record<string, string[]> = {
    sha256: ['execution', 'binary'],
    sha1: ['execution', 'binary'],
    md5: ['execution', 'binary'],
    domain: ['c2', 'network', 'dns'],
    ipv4: ['c2', 'network'],
    ipv6: ['c2', 'network'],
    url: ['c2', 'network', 'web'],
    email: ['phishing', 'initial_access'],
    registry: ['persistence', 'defense_evasion'],
    file_path: ['execution', 'binary'],
    mutex: ['execution', 'process'],
    service: ['persistence', 'execution'],
    process: ['execution', 'process'],
    ja3: ['c2', 'network', 'tls'],
    ja4: ['c2', 'network', 'tls'],
    certificate: ['c2', 'network', 'tls'],
    user_agent: ['c2', 'network', 'http'],
    tls_fingerprint: ['c2', 'network', 'tls'],
  };

  baseTags.push(...(behaviorTags[iocType] || []));

  return Array.from(new Set(baseTags)).sort();
}

// ============================================================================
// FALSE POSITIVE GENERATION
// ============================================================================

function generateFalsePositives(iocType: IOCType): string[] {
  const fpMap: Record<string, string[]> = {
    sha256: ['Legitimate software updates', 'Development tools', 'Antivirus false positives'],
    sha1: ['Legitimate software updates', 'Development tools', 'Antivirus false positives'],
    md5: ['Legitimate software updates', 'Development tools', 'Antivirus false positives'],
    domain: ['Legitimate third-party integrations', 'Shared CDN usage', 'DNS analytics services'],
    ipv4: ['Legitimate cloud services', 'Shared hosting providers', 'VPN services'],
    ipv6: ['Legitimate cloud services', 'Shared hosting providers', 'VPN services'],
    url: ['Legitimate business applications', 'CDN URLs', 'Analytics platforms'],
    email: ['Spoofed addresses', 'Legitimate domain variations', 'Internal testing accounts'],
    registry: ['Legitimate software installation', 'Administrative scripts'],
    file_path: ['Common installation paths', 'Shared directories'],
    mutex: ['Legitimate application mutexes', 'Third-party software'],
    service: ['Third-party services', 'Administrative tools'],
    process: ['Legitimate process names', 'System processes'],
    ja3: ['Legitimate TLS clients', 'Browser variations'],
    ja4: ['Legitimate TLS clients', 'QUIC implementations'],
    certificate: ['Legitimate certificate sharing', 'Wildcard certificates'],
    user_agent: ['Legitimate browser variants', 'Corporate proxies'],
    tls_fingerprint: ['Legitimate TLS clients', 'Common implementations'],
  };

  return fpMap[iocType] || [];
}

// ============================================================================
// BATCH SIGMA GENERATION
// ============================================================================

export interface IOCForGeneration {
  type: IOCType;
  value: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  evidence?: string;
}

export function generateSigmaRuleSet(
  malwareName: string,
  iocs: IOCForGeneration[],
  options?: SigmaGeneratorOptions
): SigmaRule[] {
  return iocs
    .filter(ioc => ioc.confidence === 'HIGH' || ioc.confidence === 'MEDIUM')
    .map(ioc => generateSigmaFromIOC(ioc.type, ioc.value, malwareName, options));
}
