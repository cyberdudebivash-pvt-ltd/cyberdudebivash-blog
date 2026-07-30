/**
 * Suricata Rule Generator
 * Generates Suricata IDS/IPS rules for network detection
 */

import type { SuricataRule, SuricataContent, SuricataFlow } from '../schema';
import { RuleSeverity } from '../schema';
import type { IOCType } from '../../intelligence/schema';

let sidCounter = 1000000;

// ============================================================================
// SURICATA RULE GENERATION
// ============================================================================

export interface SuricataGeneratorOptions {
  severity?: RuleSeverity;
  direction?: '->' | '<>';
  classType?: string;
}

export function generateSuricataFromIOC(
  iocType: IOCType,
  iocValue: string,
  malwareName: string,
  options?: SuricataGeneratorOptions
): SuricataRule[] {
  const severity = options?.severity || RuleSeverity.HIGH;
  const direction = options?.direction || '->';
  const classType = options?.classType || 'attempted-recon';

  const rules: SuricataRule[] = [];

  switch (iocType) {
    case 'domain':
    case 'ipv4':
    case 'ipv6':
      rules.push(...generateNetworkRules(iocType, iocValue, malwareName, severity, direction, classType));
      break;

    case 'url':
      rules.push(...generateHTTPRules(iocValue, malwareName, severity, classType));
      break;

    case 'user_agent':
      rules.push(...generateUserAgentRules(iocValue, malwareName, severity, classType));
      break;

    case 'ja3':
      rules.push(...generateJA3Rules(iocValue, malwareName, severity, classType));
      break;

    default:
      // Fallback for other types
      rules.push(generateBasicRule(iocValue, malwareName, severity, classType));
  }

  return rules;
}

// ============================================================================
// NETWORK RULE GENERATION
// ============================================================================

function generateNetworkRules(
  iocType: IOCType,
  iocValue: string,
  malwareName: string,
  severity: RuleSeverity,
  direction: '->' | '<>',
  classType: string
): SuricataRule[] {
  const rules: SuricataRule[] = [];

  if (iocType === 'ipv4' || iocType === 'ipv6') {
    // Inbound connection from C2
    rules.push({
      action: 'alert',
      protocol: 'tcp',
      sourceIp: iocValue,
      sourcePort: 'any',
      direction: direction,
      destIp: 'HOME_NET',
      destPort: 'any',
      msg: `${malwareName} - C2 Communication from ${iocValue}`,
      classtype: classType,
      sid: generateSID(),
      rev: 1,
      reference: [
        `https://www.cyberdudebivash.in`,
        `https://mitre-attack.github.io`,
      ],
    });

    // Outbound connection to C2
    rules.push({
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: direction,
      destIp: iocValue,
      destPort: 'any',
      msg: `${malwareName} - Outbound C2 Communication to ${iocValue}`,
      classtype: classType,
      sid: generateSID(),
      rev: 1,
    });

    // DNS to C2 domain (if applicable)
    if (iocType === 'ipv4') {
      rules.push({
        action: 'alert',
        protocol: 'udp',
        sourceIp: 'HOME_NET',
        sourcePort: 'any',
        direction: direction,
        destIp: iocValue,
        destPort: 53,
        msg: `${malwareName} - DNS Query to C2 Hosting ${iocValue}`,
        classtype: 'dns',
        sid: generateSID(),
        rev: 1,
      });
    }
  } else if (iocType === 'domain') {
    // DNS query to malicious domain
    const dnsRule: SuricataRule = {
      action: 'alert',
      protocol: 'udp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: direction,
      destIp: 'any',
      destPort: 53,
      msg: `${malwareName} - DNS Query to C2 Domain ${iocValue}`,
      content: [
        {
          pattern: iocValue.toLowerCase(),
          caseSensitive: false,
        },
      ],
      classtype: 'dns',
      sid: generateSID(),
      rev: 1,
    };
    rules.push(dnsRule);

    // HTTP request to domain on common ports
    for (const port of [80, 8080, 8888, 3128]) {
      rules.push({
        action: 'alert',
        protocol: 'tcp',
        sourceIp: 'HOME_NET',
        sourcePort: 'any',
        direction: direction,
        destIp: 'EXTERNAL_NET',
        destPort: port,
        msg: `${malwareName} - HTTP C2 Communication to ${iocValue}:${port}`,
        content: [
          {
            pattern: `Host: ${iocValue}`,
            caseSensitive: false,
          },
        ],
        classtype: 'attempted-recon',
        sid: generateSID(),
        rev: 1,
      });
    }

    // HTTPS request to domain
    rules.push({
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: direction,
      destIp: 'EXTERNAL_NET',
      destPort: 443,
      msg: `${malwareName} - HTTPS C2 Communication to ${iocValue}`,
      classtype: 'attempted-recon',
      sid: generateSID(),
      rev: 1,
    });
  }

  return rules;
}

// ============================================================================
// HTTP RULE GENERATION
// ============================================================================

function generateHTTPRules(url: string, malwareName: string, severity: RuleSeverity, classType: string): SuricataRule[] {
  const rules: SuricataRule[] = [];

  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname + (urlObj.search || '');
    const port = urlObj.protocol === 'https:' ? 443 : 80;

    rules.push({
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: '->',
      destIp: 'EXTERNAL_NET',
      destPort: port,
      msg: `${malwareName} - Malicious URL Access ${url}`,
      content: [
        {
          pattern: `GET ${path}`,
        },
      ],
      classtype: classType,
      sid: generateSID(),
      rev: 1,
    });

    rules.push({
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: '->',
      destIp: 'EXTERNAL_NET',
      destPort: port,
      msg: `${malwareName} - Malicious POST Request to ${url}`,
      content: [
        {
          pattern: `POST ${path}`,
        },
      ],
      classtype: classType,
      sid: generateSID(),
      rev: 1,
    });
  } catch (e) {
    // Fallback for relative URLs
    rules.push(generateBasicRule(url, malwareName, severity, classType));
  }

  return rules;
}

// ============================================================================
// USER AGENT RULE GENERATION
// ============================================================================

function generateUserAgentRules(
  userAgent: string,
  malwareName: string,
  severity: RuleSeverity,
  classType: string
): SuricataRule[] {
  return [
    {
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: '->',
      destIp: 'EXTERNAL_NET',
      destPort: 80,
      msg: `${malwareName} - HTTP Request with Known User-Agent ${userAgent}`,
      content: [
        {
          pattern: `User-Agent: ${userAgent}`,
          caseSensitive: false,
        },
      ],
      classtype: classType,
      sid: generateSID(),
      rev: 1,
    },
    {
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: '->',
      destIp: 'EXTERNAL_NET',
      destPort: 443,
      msg: `${malwareName} - HTTPS Request with Known User-Agent`,
      content: [
        {
          pattern: userAgent,
          caseSensitive: false,
        },
      ],
      classtype: classType,
      sid: generateSID(),
      rev: 1,
    },
  ];
}

// ============================================================================
// JA3 FINGERPRINT RULE GENERATION
// ============================================================================

function generateJA3Rules(ja3Value: string, malwareName: string, severity: RuleSeverity, classType: string): SuricataRule[] {
  return [
    {
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'HOME_NET',
      sourcePort: 'any',
      direction: '->',
      destIp: 'EXTERNAL_NET',
      destPort: 443,
      msg: `${malwareName} - TLS Fingerprint Match (JA3)`,
      pcre: `/JA3=${ja3Value}/i`,
      classtype: classType,
      sid: generateSID(),
      rev: 1,
    },
  ];
}

// ============================================================================
// BASIC RULE GENERATION
// ============================================================================

function generateBasicRule(
  iocValue: string,
  malwareName: string,
  severity: RuleSeverity,
  classType: string
): SuricataRule {
  return {
    action: 'alert',
    protocol: 'tcp',
    sourceIp: 'any',
    sourcePort: 'any',
    direction: '->',
    destIp: 'any',
    destPort: 'any',
    msg: `${malwareName} - IOC Detection: ${iocValue}`,
    content: [
      {
        pattern: iocValue,
        caseSensitive: false,
      },
    ],
    classtype: classType,
    sid: generateSID(),
    rev: 1,
  };
}

// ============================================================================
// SID MANAGEMENT
// ============================================================================

function generateSID(): number {
  return sidCounter++;
}

// ============================================================================
// BATCH SURICATA GENERATION
// ============================================================================

export interface IOCForSuricataGeneration {
  type: IOCType;
  value: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export function generateSuricataRuleSet(
  malwareName: string,
  iocs: IOCForSuricataGeneration[],
  options?: SuricataGeneratorOptions
): SuricataRule[] {
  const allRules: SuricataRule[] = [];

  for (const ioc of iocs) {
    if (ioc.confidence === 'HIGH' || ioc.confidence === 'MEDIUM') {
      const rules = generateSuricataFromIOC(ioc.type, ioc.value, malwareName, options);
      allRules.push(...rules);
    }
  }

  return allRules;
}

// ============================================================================
// SURICATA RULE FORMATTING
// ============================================================================

export function formatSuricataRule(rule: SuricataRule): string {
  let ruleStr = `${rule.action} ${rule.protocol} ${rule.sourceIp} ${rule.sourcePort} ${rule.direction} ${rule.destIp} ${rule.destPort} `;
  ruleStr += `(msg:"${rule.msg}";`;

  if (rule.flow) {
    ruleStr += ` flow:${rule.flow.direction},established;`;
  }

  if (rule.content && rule.content.length > 0) {
    for (const content of rule.content) {
      ruleStr += ` content:"${content.pattern}";`;
      if (content.caseSensitive === false) {
        ruleStr += ' nocase;';
      }
    }
  }

  if (rule.pcre) {
    ruleStr += ` pcre:"${rule.pcre}";`;
  }

  if (rule.classtype) {
    ruleStr += ` classtype:${rule.classtype};`;
  }

  ruleStr += ` sid:${rule.sid}; rev:${rule.rev || 1};`;

  if (rule.reference && rule.reference.length > 0) {
    ruleStr += ` reference:`;
    ruleStr += rule.reference.map(ref => `url,${ref}`).join(',');
    ruleStr += ';';
  }

  ruleStr += ')';

  return ruleStr;
}
