/**
 * SIEM Rule Generator
 * Generates Splunk SPL, ELK, Sentinel KQL, ArcSight AEL rules
 */

import type { SEMRule } from '../schema';
import { RuleSeverity } from '../schema';
import type { IOCType } from '../../intelligence/schema';

// ============================================================================
// SIEM RULE GENERATION
// ============================================================================

export interface SEMGeneratorOptions {
  severity?: RuleSeverity;
  timeWindow?: string;
  threshold?: number;
}

export function generateSEMRuleFromIOC(
  iocType: IOCType,
  iocValue: string,
  malwareName: string,
  options?: SEMGeneratorOptions
): SEMRule[] {
  const severity = options?.severity || RuleSeverity.HIGH;
  const timeWindow = options?.timeWindow || '10m';
  const threshold = options?.threshold || 1;

  const rules: SEMRule[] = [];

  // Generate Splunk search
  rules.push(generateSplunkRule(iocType, iocValue, malwareName, severity));

  // Generate ELK query
  rules.push(generateELKRule(iocType, iocValue, malwareName, severity));

  // Generate Sentinel KQL
  rules.push(generateSentinelRule(iocType, iocValue, malwareName, severity, timeWindow));

  // Generate ArcSight AEL
  rules.push(generateArcSightRule(iocType, iocValue, malwareName, severity));

  return rules;
}

// ============================================================================
// SPLUNK SPL GENERATOR
// ============================================================================

function generateSplunkRule(iocType: IOCType, iocValue: string, malwareName: string, severity: RuleSeverity): SEMRule {
  let searchQuery = generateSplunkSearch(iocType, iocValue);

  const rule: SEMRule = {
    name: `Splunk: ${malwareName} - ${iocType} Detection`,
    description: `Splunk search for ${malwareName} detection using ${iocType} indicator`,
    source: 'splunk',
    eventType: 'splunk_search',
    fields: [
      {
        name: 'search',
        value: searchQuery,
      },
    ],
    threshold: {
      operator: 'greater_than',
      value: 0,
      timeWindow: '10m',
    },
    severity,
  };

  return rule;
}

function generateSplunkSearch(iocType: IOCType, iocValue: string): string {
  const searches: Record<string, string> = {
    sha256: `index=main (process_hash="${iocValue}" OR md5="${iocValue}" OR sha1="${iocValue}" OR sha256="${iocValue}") | stats count by host, user, process_name`,
    sha1: `index=main (md5="${iocValue}" OR sha1="${iocValue}" OR sha256="${iocValue}") | stats count by host, user`,
    md5: `index=main (md5="${iocValue}" OR sha1="${iocValue}" OR sha256="${iocValue}") | stats count by host, user`,
    domain: `index=main dns_query="${iocValue}" OR dest="${iocValue}" OR url="*${iocValue}*" | stats count by src_ip, host, query`,
    ipv4: `index=main dest="${iocValue}" OR src="${iocValue}" | stats count by src_ip, dest_ip, dest_port, protocol`,
    ipv6: `index=main dest="${iocValue}" OR src="${iocValue}" | stats count by src_ip, dest_ip`,
    url: `index=main url="${iocValue}" OR uri="${iocValue}" | stats count by src_ip, dest_ip, http_method`,
    email: `index=main src_user="*${iocValue}*" OR sender="*${iocValue}*" OR email="*${iocValue}*" | stats count by src_user, dest_user`,
    registry: `index=main object="${iocValue}" OR process_name="*${iocValue}*" | stats count by host, user, process_name`,
    file_path: `index=main file_path="${iocValue}" | stats count by host, user, process_name`,
    mutex: `index=main mutex="${iocValue}" | stats count by host, process_name`,
    service: `index=main service="${iocValue}" | stats count by host, user`,
    process: `index=main process_name="${iocValue}" | stats count by host, user`,
    ja3: `index=main tls_ja3="${iocValue}" | stats count by src_ip, dest_ip, dest_port`,
    ja4: `index=main tls_ja4="${iocValue}" | stats count by src_ip, dest_ip`,
    certificate: `index=main certificate_fingerprint="${iocValue}" | stats count by src_ip, dest_ip`,
    user_agent: `index=main http_user_agent="*${iocValue}*" | stats count by src_ip, dest_ip, http_method`,
    tls_fingerprint: `index=main tls_fingerprint="${iocValue}" | stats count by src_ip, dest_ip`,
  };

  return searches[iocType] || `index=main "${iocValue}" | stats count by host`;
}

// ============================================================================
// ELASTICSEARCH/KIBANA GENERATOR
// ============================================================================

function generateELKRule(iocType: IOCType, iocValue: string, malwareName: string, severity: RuleSeverity): SEMRule {
  const query = generateELKQuery(iocType, iocValue);

  const rule: SEMRule = {
    name: `Elasticsearch: ${malwareName} - ${iocType} Detection`,
    description: `Elasticsearch/Kibana query for ${malwareName} detection`,
    source: 'elk',
    eventType: 'elasticsearch_query',
    fields: [
      {
        name: 'query',
        value: query,
      },
    ],
    severity,
  };

  return rule;
}

function generateELKQuery(iocType: IOCType, iocValue: string): string {
  const queries: Record<string, string> = {
    sha256: `{ "bool": { "must": [ { "match": { "file.hash.sha256": "${iocValue.toUpperCase()}" } } ] } }`,
    sha1: `{ "bool": { "must": [ { "match": { "file.hash.sha1": "${iocValue.toUpperCase()}" } } ] } }`,
    md5: `{ "bool": { "must": [ { "match": { "file.hash.md5": "${iocValue.toUpperCase()}" } } ] } }`,
    domain: `{ "bool": { "should": [ { "match": { "dns.question.name": "${iocValue.toLowerCase()}" } }, { "match": { "destination.domain": "${iocValue.toLowerCase()}" } }, { "match": { "url.domain": "${iocValue.toLowerCase()}" } } ] } }`,
    ipv4: `{ "bool": { "should": [ { "match": { "destination.ip": "${iocValue}" } }, { "match": { "source.ip": "${iocValue}" } } ] } }`,
    ipv6: `{ "bool": { "should": [ { "match": { "destination.ip": "${iocValue}" } }, { "match": { "source.ip": "${iocValue}" } } ] } }`,
    url: `{ "bool": { "must": [ { "match": { "url.full": "${iocValue}" } } ] } }`,
    email: `{ "bool": { "should": [ { "match": { "email.sender.address": "${iocValue.toLowerCase()}" } }, { "match": { "email.recipient": "${iocValue.toLowerCase()}" } } ] } }`,
    registry: `{ "bool": { "must": [ { "match": { "registry.path": "${iocValue.toUpperCase()}" } } ] } }`,
    file_path: `{ "bool": { "must": [ { "match": { "file.path": "${iocValue}" } } ] } }`,
    mutex: `{ "bool": { "must": [ { "match": { "process.mutex": "${iocValue}" } } ] } }`,
    service: `{ "bool": { "must": [ { "match": { "service.name": "${iocValue}" } } ] } }`,
    process: `{ "bool": { "must": [ { "match": { "process.name": "${iocValue}" } } ] } }`,
    ja3: `{ "bool": { "must": [ { "match": { "tls.fingerprints.ja3.hash": "${iocValue}" } } ] } }`,
    ja4: `{ "bool": { "must": [ { "match": { "tls.fingerprints.ja4.hash": "${iocValue}" } } ] } }`,
    certificate: `{ "bool": { "must": [ { "match": { "tls.server.certificate.fingerprint.sha1": "${iocValue.toUpperCase()}" } } ] } }`,
    user_agent: `{ "bool": { "must": [ { "match": { "http.request.header.user-agent": "${iocValue}" } } ] } }`,
    tls_fingerprint: `{ "bool": { "must": [ { "match": { "tls.fingerprint": "${iocValue}" } } ] } }`,
  };

  return queries[iocType] || `{ "bool": { "must": [ { "match_phrase": { "message": "${iocValue}" } } ] } }`;
}

// ============================================================================
// AZURE SENTINEL KQL GENERATOR
// ============================================================================

function generateSentinelRule(
  iocType: IOCType,
  iocValue: string,
  malwareName: string,
  severity: RuleSeverity,
  timeWindow: string
): SEMRule {
  const kqlQuery = generateSentinelKQL(iocType, iocValue);

  const rule: SEMRule = {
    name: `Azure Sentinel: ${malwareName} - ${iocType} Detection`,
    description: `Azure Sentinel KQL query for ${malwareName} detection`,
    source: 'sentinel',
    eventType: 'kql_query',
    fields: [
      {
        name: 'query',
        value: kqlQuery,
      },
    ],
    threshold: {
      operator: 'greater_than',
      value: 0,
      timeWindow,
    },
    severity,
  };

  return rule;
}

function generateSentinelKQL(iocType: IOCType, iocValue: string): string {
  const queries: Record<string, string> = {
    sha256: `SecurityEvent | where EventID == 23 and SHA256 == "${iocValue.toUpperCase()}" | summarize count() by Computer, Account`,
    sha1: `SecurityEvent | where EventID == 23 and SHA1 == "${iocValue.toUpperCase()}" | summarize count() by Computer`,
    md5: `SecurityEvent | where EventID == 23 and MD5 == "${iocValue.toUpperCase()}" | summarize count() by Computer`,
    domain: `let domains = dynamic(["${iocValue.toLowerCase()}"]); (CommonSecurityLog | where RequestURL has_any (domains)) | summarize count() by SourceIP, DestinationIP`,
    ipv4: `CommonSecurityLog | where DestinationIP == "${iocValue}" or SourceIP == "${iocValue}" | summarize count() by SourceIP, DestinationIP, DestinationPort`,
    ipv6: `CommonSecurityLog | where DestinationIP == "${iocValue}" or SourceIP == "${iocValue}" | summarize count() by SourceIP, DestinationIP`,
    url: `CommonSecurityLog | where RequestURL contains "${iocValue}" | summarize count() by SourceIP, RequestURL`,
    email: `OfficeActivity | where UserId contains "${iocValue.toLowerCase()}" or Sender contains "${iocValue.toLowerCase()}" | summarize count() by UserId`,
    registry: `SecurityEvent | where EventID == 13 and ObjectName contains "${iocValue.toUpperCase()}" | summarize count() by Computer, Account`,
    file_path: `FileCreateEvents | where FolderPath contains "${iocValue}" | summarize count() by Computer`,
    mutex: `ProcessCreationTime | where CommandLine contains "${iocValue}" | summarize count() by Computer, InitiatingProcessCommandLine`,
    service: `SecurityEvent | where EventID == 7045 and ServiceName == "${iocValue}" | summarize count() by Computer`,
    process: `ProcessCreationTime | where CommandLine contains "${iocValue}" | summarize count() by Computer`,
    ja3: `CommonSecurityLog | where DeviceCustomString1 == "${iocValue}" | summarize count() by SourceIP, DestinationIP`,
    ja4: `CommonSecurityLog | where DeviceCustomString2 == "${iocValue}" | summarize count() by SourceIP, DestinationIP`,
    certificate: `CommonSecurityLog | where CertificateHash == "${iocValue.toUpperCase()}" | summarize count() by SourceIP, DestinationIP`,
    user_agent: `CommonSecurityLog | where RequestUserAgent == "${iocValue}" | summarize count() by SourceIP, DestinationIP`,
    tls_fingerprint: `CommonSecurityLog | where TLSFingerprint == "${iocValue.toUpperCase()}" | summarize count() by SourceIP, DestinationIP`,
  };

  return queries[iocType] || `CommonSecurityLog | where RequestURL contains "${iocValue}" | summarize count() by SourceIP`;
}

// ============================================================================
// ARCSIGHT AEL GENERATOR
// ============================================================================

function generateArcSightRule(iocType: IOCType, iocValue: string, malwareName: string, severity: RuleSeverity): SEMRule {
  const aelRule = generateArcSightAEL(iocType, iocValue);

  const rule: SEMRule = {
    name: `ArcSight: ${malwareName} - ${iocType} Detection`,
    description: `ArcSight ESM rule for ${malwareName} detection`,
    source: 'arcsight',
    eventType: 'arcsight_rule',
    fields: [
      {
        name: 'rule',
        value: aelRule,
      },
    ],
    severity,
  };

  return rule;
}

function generateArcSightAEL(iocType: IOCType, iocValue: string): string {
  const rules: Record<string, string> = {
    sha256: `fileHash matches "${iocValue.toUpperCase()}"`,
    sha1: `fileHash matches "${iocValue.toUpperCase()}"`,
    md5: `fileHash matches "${iocValue.toUpperCase()}"`,
    domain: `destinationAddress matches "${iocValue.toLowerCase()}" OR requestUrl contains "${iocValue.toLowerCase()}"`,
    ipv4: `destinationAddress = "${iocValue}" OR sourceAddress = "${iocValue}"`,
    ipv6: `destinationAddress = "${iocValue}" OR sourceAddress = "${iocValue}"`,
    url: `requestUrl matches "${iocValue}"`,
    email: `sender matches "${iocValue.toLowerCase()}" OR recipient matches "${iocValue.toLowerCase()}"`,
    registry: `destinationUserName matches "${iocValue.toUpperCase()}"`,
    file_path: `filePath contains "${iocValue}"`,
    mutex: `deviceCustomString1 matches "${iocValue}"`,
    service: `deviceCustomString1 matches "${iocValue}"`,
    process: `deviceCustomString2 matches "${iocValue}"`,
    ja3: `deviceCustomString3 matches "${iocValue}"`,
    ja4: `deviceCustomString4 matches "${iocValue}"`,
    certificate: `deviceCustomString5 matches "${iocValue.toUpperCase()}"`,
    user_agent: `request contains "${iocValue}"`,
    tls_fingerprint: `deviceCustomString6 matches "${iocValue}"`,
  };

  return rules[iocType] || `message matches "${iocValue}"`;
}

// ============================================================================
// BATCH SIEM GENERATION
// ============================================================================

export interface IOCForSEMGeneration {
  type: IOCType;
  value: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export function generateSEMRuleSet(
  malwareName: string,
  iocs: IOCForSEMGeneration[],
  options?: SEMGeneratorOptions
): SEMRule[] {
  const allRules: SEMRule[] = [];

  for (const ioc of iocs) {
    if (ioc.confidence === 'HIGH' || ioc.confidence === 'MEDIUM') {
      const rules = generateSEMRuleFromIOC(ioc.type, ioc.value, malwareName, options);
      allRules.push(...rules);
    }
  }

  return allRules;
}
