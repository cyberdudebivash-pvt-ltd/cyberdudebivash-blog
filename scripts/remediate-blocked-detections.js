#!/usr/bin/env node
/**
 * SENTINEL APEX — Detection Integrity Remediation v1
 *
 * One-time, evidence-based remediation for the two real canonical detection
 * rules PR #145's Review Queue surfaced as BLOCKED. See
 * docs/audits/SENTINEL-APEX-READONLY-SIEM-HUNTING-CONNECTORS-V1-CERTIFICATION.md
 * §3 for the full root-cause evidence trail this script implements.
 *
 * 9a5467dc8ae03f68 (T1547.001, "Registry Run Key Persistence From
 * User-Writable Path", currently v1.0.9): genuine, provable metadata defect
 * -- data_source is stored as "process_creation" but the rule's own Sigma
 * content declares logsource.category: registry_set and references
 * TargetObject (a registry field, absent from process_creation's known
 * fields, present in registry_set's). Real CVE-2026-54550 backing,
 * structurally valid, fixtures pass. FIX: correct data_source to
 * "registry_set" via a normal storeRule() call -- a new, immutable version,
 * never mutating the broken v1.0.9 snapshot. All other content (Sigma/KQL/
 * Splunk/OSQuery/description/level/source refs) is carried forward
 * VERBATIM, unchanged, to avoid losing any real content in the process.
 *
 * fbc0da003ab2d073 (T1059.001, "Suspicious PowerShell Execution", v1.0.0):
 * incomplete test/seed content with zero real evidentiary backing --
 * source.articles references "TEST-001", confirmed absent from the entire
 * real intelligence corpus (grepped: 0 matches in api/intel/**, reports-
 * index.json, threat-graph.json); source.iocs is an RFC1918 placeholder
 * ("10.0.0.1"); the Sigma content itself is missing 3 mandatory fields
 * (title, a properly-shaped logsource object, detection.condition) and
 * data_source is an empty string. There is no genuine detection logic here
 * to correct -- writing "fixed" Sigma content would be fabrication, which
 * this tranche's own mandate explicitly forbids. REVOKE: this rule was
 * never real, shippable detection content.
 *
 * Dry-run by default; --apply to write. Idempotent: running twice with
 * --apply is safe (the second run's storeRule() call would bump the
 * version again with identical content -- harmless but unnecessary, so
 * this script checks current state first and skips work already done).
 *
 * Usage:
 *   node scripts/remediate-blocked-detections.js [--apply] [--verbose]
 */
'use strict';

const detectionRules = require('../api/_lib/detection-rules');
const detectionIntelligence = require('../api/_lib/detection-intelligence');

const FIX_RULE_ID = '9a5467dc8ae03f68';
const FIX_CORRECTED_DATA_SOURCE = 'registry_set';
const REVOKE_RULE_ID = 'fbc0da003ab2d073';

function canonicalStatusFor(rule) {
  return detectionIntelligence.toCanonicalDetectionObject(rule, { attackEvidenceState: 'UNKNOWN' });
}

async function main() {
  const args = process.argv.slice(2);
  const apply = args.includes('--apply');
  const verbose = args.includes('--verbose');

  const store = detectionRules.loadCanonical();

  const fixRule = store.rules.find(r => r.id === FIX_RULE_ID);
  const revokeRule = store.rules.find(r => r.id === REVOKE_RULE_ID);

  if (!fixRule) throw new Error(`Expected rule ${FIX_RULE_ID} not found in canonical store.`);
  if (!revokeRule) throw new Error(`Expected rule ${REVOKE_RULE_ID} not found in canonical store.`);

  console.log('[REMEDIATE] Current state:');
  console.log(`  ${FIX_RULE_ID}: data_source="${fixRule.data_source}", version=${fixRule.governance.version}, status=${canonicalStatusFor(fixRule).status}`);
  console.log(`  ${REVOKE_RULE_ID}: governance.status="${revokeRule.governance.status}", version=${revokeRule.governance.version}, canonical_status=${canonicalStatusFor(revokeRule).status}`);

  const fixAlreadyApplied = fixRule.data_source === FIX_CORRECTED_DATA_SOURCE;
  const revokeAlreadyApplied = revokeRule.governance.status === 'REVOKED';

  if (fixAlreadyApplied && revokeAlreadyApplied) {
    console.log('[REMEDIATE] Both remediations already applied. Nothing to do.');
    return;
  }

  if (!apply) {
    console.log('\n[REMEDIATE] Dry run only. Planned actions:');
    if (!fixAlreadyApplied) console.log(`  - ${FIX_RULE_ID}: storeRule() with corrected data_source "${FIX_CORRECTED_DATA_SOURCE}" (all other content unchanged) -> new version`);
    if (!revokeAlreadyApplied) console.log(`  - ${REVOKE_RULE_ID}: updateRuleStatus(..., 'REVOKED', ...) -- no content change, no version bump`);
    console.log('\nRe-run with --apply to write.');
    return;
  }

  if (!fixAlreadyApplied) {
    // Reconstruct the FULL existing ruleSpec verbatim, correcting only
    // data_source -- storeRule() builds its canonicalRule entirely from
    // this argument, so anything omitted here would be silently dropped
    // from the new version (exactly the kind of content loss this whole
    // tranche exists to prevent).
    const ruleSpec = {
      technique_id: fixRule.technique_id,
      title: fixRule.title,
      level: fixRule.level,
      description: fixRule.description,
      data_source: FIX_CORRECTED_DATA_SOURCE,
      sigma: fixRule.platforms.sigma,
      kql: fixRule.platforms.kql,
      splunk: fixRule.platforms.splunk,
      osquery: fixRule.platforms.osquery,
      suricata: fixRule.suricata,
    };
    const sourceMetadata = {
      confidence: fixRule.governance.confidence,
      iocs: fixRule.source.iocs,
      articles: fixRule.source.articles,
      campaigns: fixRule.source.campaigns,
      evidence: fixRule.source.evidence,
      change: 'Corrected data_source metadata from "process_creation" to "registry_set". The rule\'s own Sigma logsource has always declared category: registry_set and referenced TargetObject (a registry field), which is not a recognized process_creation field -- this was a genuine, provable metadata defect from generation time, not a content change. No detection logic (Sigma/KQL/Splunk/OSQuery) was altered. See docs/audits/SENTINEL-APEX-READONLY-SIEM-HUNTING-CONNECTORS-V1-CERTIFICATION.md for the full evidence trail.',
      author: 'detection-integrity-remediation-v1',
    };
    const updated = detectionRules.storeRule(ruleSpec, sourceMetadata);
    const newStatus = canonicalStatusFor(updated);
    console.log(`[REMEDIATE] ${FIX_RULE_ID}: stored new version ${updated.governance.version} (data_source now "${updated.data_source}"). New canonical status: ${newStatus.status} (reasons: ${JSON.stringify(newStatus.lifecycle_reasons)})`);
    if (verbose) console.log(JSON.stringify(newStatus.validation.telemetry, null, 2));
  } else {
    console.log(`[REMEDIATE] ${FIX_RULE_ID}: fix already applied, skipping.`);
  }

  if (!revokeAlreadyApplied) {
    const revoked = detectionRules.updateRuleStatus(REVOKE_RULE_ID, 'REVOKED', {
      author: 'detection-integrity-remediation-v1',
      comment: 'Revoked: content is incomplete test/seed data, never real shippable detection logic. Sigma is missing 3 mandatory fields (title, a properly-shaped logsource object, detection.condition); data_source is an empty string; source.articles references "TEST-001", confirmed absent from the entire real intelligence corpus; source.iocs is an RFC1918 placeholder address. No genuine threat-intelligence evidence exists to construct a real, non-fabricated corrected detection -- see docs/audits/SENTINEL-APEX-READONLY-SIEM-HUNTING-CONNECTORS-V1-CERTIFICATION.md for the full evidence trail.',
    });
    console.log(`[REMEDIATE] ${REVOKE_RULE_ID}: governance.status now "${revoked.governance.status}".`);
  } else {
    console.log(`[REMEDIATE] ${REVOKE_RULE_ID}: revoke already applied, skipping.`);
  }

  console.log('\n[REMEDIATE] Done.');
}

main().catch(err => {
  console.error('[REMEDIATE] Fatal error:', err.message);
  process.exitCode = 1;
});
