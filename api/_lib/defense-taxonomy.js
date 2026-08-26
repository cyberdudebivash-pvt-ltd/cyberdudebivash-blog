'use strict';
/**
 * SENTINEL APEX -- Customer Telemetry & Environment-Aware Defense Coverage
 * Fabric v1: static technology + telemetry-source vocabulary.
 *
 * Reuses, rather than re-declares, two already-canonical vocabularies (see
 * docs/audits/SENTINEL-APEX-CUSTOMER-DEFENSE-CONTEXT-INVENTORY-V1.md):
 *
 *   - Normalized telemetry concepts (`process_creation`, `process_access`,
 *     `registry_set`, `network`) come from detection-intelligence.js's own
 *     TELEMETRY_REQUIREMENTS -- not redeclared here.
 *   - Microsoft Sentinel/Defender XDR's real Advanced Hunting table names
 *     (DeviceProcessEvents/DeviceEvents/DeviceRegistryEvents) and Splunk's
 *     CIM data model names come from detection-engine.js's FIELD_MAP
 *     (_kql_table/_splunk_dm) -- the same constants the format generators
 *     themselves compile against, imported directly so this file cannot
 *     drift from what a detection's `kql`/`splunk` format actually targets.
 *
 * Everything else here (per-vendor telemetry source labels for providers
 * FIELD_MAP has no opinion on, e.g. CrowdStrike Falcon, SentinelOne) is new,
 * hand-curated vocabulary. Per mandate Phase 54/55 ("do not map fields
 * without evidence" / "mark unsupported/partial where uncertain"): a
 * provider entry only gets a `fields` array when this platform has genuine
 * confidence in the exact column names (documented, stable, public vendor
 * schema); otherwise `fields: null` with `confidence: 'general'` --
 * honestly labeled as a source-existence-only mapping, never guessed field
 * names dressed up as certainty.
 */

const detectionEngine = require('../../Sentinel-APEX/engine-node/detection-engine');
const { TELEMETRY_REQUIREMENTS } = require('./detection-intelligence');

const SCHEMA_VERSION = '1.0';

const TECHNOLOGY_CATEGORIES = Object.freeze(['siem', 'edr_xdr', 'cloud', 'endpoint_telemetry', 'os']);

// CUSTOM_UNMAPPED sentinel (mandate Phase 35): "Other / Not listed" is
// always selectable in any category without pretending compatibility
// exists for it. Never treated as a format or telemetry-source match.
const CUSTOM_UNMAPPED_ID = 'other';

// detection_format: the FORMAT_CAPABILITY_MATRIX key (detection-intelligence.js)
// this SIEM technology's query language corresponds to -- null means this
// platform has no validated generator/structural-validator for that
// vendor's query language today (Elastic/QRadar/Chronicle), so a customer
// on that SIEM alone can never reach READY, only a disclosed
// Sigma-portable note (mandate Phase 26).
const TECHNOLOGIES = Object.freeze({
  'microsoft-sentinel':         { category: 'siem',    label: 'Microsoft Sentinel',              detection_format: 'kql' },
  'splunk-enterprise-security': { category: 'siem',    label: 'Splunk Enterprise Security',       detection_format: 'splunk' },
  'elastic-security':           { category: 'siem',    label: 'Elastic Security',                 detection_format: null },
  'qradar':                     { category: 'siem',    label: 'IBM QRadar',                       detection_format: null },
  'google-secops':              { category: 'siem',    label: 'Google SecOps (Chronicle)',        detection_format: null },

  'microsoft-defender-xdr':     { category: 'edr_xdr', label: 'Microsoft Defender XDR' },
  'crowdstrike-falcon':         { category: 'edr_xdr', label: 'CrowdStrike Falcon' },
  'sentinelone':                { category: 'edr_xdr', label: 'SentinelOne' },

  aws:                          { category: 'cloud',   label: 'Amazon Web Services' },
  azure:                        { category: 'cloud',   label: 'Microsoft Azure' },
  gcp:                          { category: 'cloud',   label: 'Google Cloud Platform' },

  sysmon:                       { category: 'endpoint_telemetry', label: 'Sysmon' },
  'windows-security-events':    { category: 'endpoint_telemetry', label: 'Windows Security Event Log' },
  'linux-auditd':                { category: 'endpoint_telemetry', label: 'Linux auditd' },

  windows:                      { category: 'os', label: 'Windows' },
  linux:                        { category: 'os', label: 'Linux' },
});

function technologyOptionsFor(category) {
  return Object.entries(TECHNOLOGIES)
    .filter(([, t]) => t.category === category)
    .map(([id, t]) => ({ id, label: t.label }))
    .concat([{ id: CUSTOM_UNMAPPED_ID, label: 'Other / Not listed' }]);
}

function isKnownTechnology(category, technologyId) {
  if (technologyId === CUSTOM_UNMAPPED_ID) return true;
  const t = TECHNOLOGIES[technologyId];
  return !!t && t.category === category;
}

function preferredFormatFor(technologyId) {
  const t = TECHNOLOGIES[technologyId];
  return (t && t.detection_format) || null;
}

/* ─────────────────── Provider telemetry source labels ───────────────────
 * Keyed by the SAME data_source strings TELEMETRY_REQUIREMENTS already
 * uses. `_kql_table`/`_splunk_dm` values for the 3 data sources
 * detectionEngine.REGISTRY actually builds against are read directly off
 * FIELD_MAP -- never re-typed by hand. */
const FM = detectionEngine.FIELD_MAP;

function fieldMapSource(dataSource, kind) {
  const entry = FM && FM[dataSource];
  if (!entry) return null;
  return kind === 'kql' ? entry._kql_table : kind === 'splunk' ? entry._splunk_dm : entry._osquery_table;
}

const PROVIDER_TELEMETRY_SOURCES = Object.freeze({
  process_creation: [
    { technology_id: 'microsoft-defender-xdr', source_label: fieldMapSource('process_creation', 'kql'), fields: ['FileName', 'ProcessCommandLine', 'InitiatingProcessFolderPath'], confidence: 'documented' },
    { technology_id: 'sysmon',                 source_label: 'Sysmon Event ID 1 (Process Creation)', fields: ['Image', 'CommandLine', 'ParentImage'], confidence: 'documented' },
    { technology_id: 'windows-security-events', source_label: 'Windows Security Event ID 4688 (Process Creation, with command-line auditing enabled)', fields: ['NewProcessName', 'CommandLine', 'ParentProcessName'], confidence: 'documented' },
    { technology_id: 'splunk-enterprise-security', source_label: `Splunk CIM ${fieldMapSource('process_creation', 'splunk')} data model`, fields: null, confidence: 'general' },
    { technology_id: 'crowdstrike-falcon',      source_label: 'CrowdStrike Falcon process-creation telemetry (Falcon Data Replicator / Advanced Event Search)', fields: null, confidence: 'general' },
    { technology_id: 'sentinelone',             source_label: 'SentinelOne process-creation telemetry (Deep Visibility)', fields: null, confidence: 'general' },
    { technology_id: 'linux-auditd',            source_label: 'Linux auditd execve records', fields: ['exe', 'comm'], confidence: 'documented' },
  ],
  process_access: [
    { technology_id: 'microsoft-defender-xdr', source_label: `Microsoft Defender XDR ${fieldMapSource('process_access', 'kql')} (process-access events)`, fields: null, confidence: 'general' },
    { technology_id: 'sysmon',                 source_label: 'Sysmon Event ID 10 (Process Access)', fields: ['TargetImage', 'GrantedAccess'], confidence: 'documented' },
    { technology_id: 'crowdstrike-falcon',      source_label: 'CrowdStrike Falcon process-access telemetry', fields: null, confidence: 'general' },
    { technology_id: 'sentinelone',             source_label: 'SentinelOne process-access telemetry (Deep Visibility)', fields: null, confidence: 'general' },
  ],
  registry_set: [
    { technology_id: 'microsoft-defender-xdr', source_label: fieldMapSource('registry_set', 'kql'), fields: ['RegistryKey', 'InitiatingProcessFolderPath'], confidence: 'documented' },
    { technology_id: 'sysmon',                 source_label: 'Sysmon Event ID 13 (Registry Value Set)', fields: ['TargetObject', 'Image'], confidence: 'documented' },
    { technology_id: 'windows-security-events', source_label: 'Windows Security Event ID 4657 (Registry Value Modified, requires object-access SACL auditing)', fields: null, confidence: 'general' },
    { technology_id: 'splunk-enterprise-security', source_label: `Splunk CIM ${fieldMapSource('registry_set', 'splunk')} data model`, fields: null, confidence: 'general' },
  ],
  network: [
    { technology_id: 'microsoft-defender-xdr', source_label: 'Microsoft Defender XDR DeviceNetworkEvents', fields: null, confidence: 'general' },
    { technology_id: 'sysmon',                 source_label: 'Sysmon Event ID 3 (Network Connection)', fields: null, confidence: 'general' },
    { technology_id: 'aws',                    source_label: 'AWS VPC Flow Logs / CloudTrail network events', fields: null, confidence: 'general' },
    { technology_id: 'azure',                  source_label: 'Azure NSG Flow Logs', fields: null, confidence: 'general' },
    { technology_id: 'crowdstrike-falcon',      source_label: 'CrowdStrike Falcon network telemetry', fields: null, confidence: 'general' },
  ],
});

/**
 * Suggested telemetry sources for a data source gap, scoped to the
 * technologies the customer actually declared (mandate Phase 43: "Do not
 * recommend vendor sources to customers not using that vendor"). Falls back
 * to the full, technology-agnostic list only when the customer has declared
 * no relevant (edr_xdr/endpoint_telemetry/cloud) technology at all, so the
 * gap is still explained rather than shown as a dead end.
 */
function suggestedSourcesFor(dataSource, declaredTechnologyIds) {
  const all = PROVIDER_TELEMETRY_SOURCES[dataSource] || [];
  if (!declaredTechnologyIds || declaredTechnologyIds.length === 0) return all;
  const declared = new Set(declaredTechnologyIds);
  const scoped = all.filter(s => declared.has(s.technology_id));
  return scoped.length > 0 ? scoped : all;
}

const TELEMETRY_STATUS_VALUES = Object.freeze(['AVAILABLE', 'PARTIALLY_AVAILABLE', 'NOT_AVAILABLE', 'UNKNOWN']);
const DATA_SOURCES = Object.freeze(Object.keys(TELEMETRY_REQUIREMENTS));

module.exports = {
  SCHEMA_VERSION,
  TECHNOLOGY_CATEGORIES,
  TECHNOLOGIES,
  CUSTOM_UNMAPPED_ID,
  DATA_SOURCES,
  TELEMETRY_STATUS_VALUES,
  PROVIDER_TELEMETRY_SOURCES,
  technologyOptionsFor,
  isKnownTechnology,
  preferredFormatFor,
  suggestedSourcesFor,
};
