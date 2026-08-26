'use strict';
/**
 * SENTINEL APEX -- Deterministic Detection Compatibility + Customer-Specific
 * Defense Coverage Engine (Customer Telemetry & Environment-Aware Defense
 * Coverage Fabric v1).
 *
 * Wraps, never replaces, the two already-canonical engines this feature
 * depends on:
 *   - detection-intelligence.js#computeCoverage()  (GLOBAL, entity-scoped
 *     ATT&CK-to-detection coverage -- untouched, called as-is)
 *   - detection-engine.js#REGISTRY / FIELD_MAP     (which data source and
 *     real vendor table each buildable technique's detection targets)
 *
 * No LLM anywhere in this file (mandate Phase 19/61/111): every state is a
 * deterministic function of (detection, profile). No detection is ever
 * generated here to "fit" a customer's profile (mandate Phase 63/64) --
 * this module only evaluates EXISTING RELEASED detections against a
 * profile; the release gate that produced RELEASED already ran,
 * unmodified, in detection-intelligence.js.
 */

const detectionEngine = require('../../Sentinel-APEX/engine-node/detection-engine');
const detectionIntelligence = require('./detection-intelligence');
const detectionRules = require('./detection-rules');
const taxonomy = require('./defense-taxonomy');

const COMPATIBILITY_STATES = Object.freeze([
  'READY', 'PARTIALLY_READY', 'TELEMETRY_GAP', 'UNSUPPORTED_PLATFORM', 'UNKNOWN', 'NO_VALIDATED_DETECTION',
]);

/* ───────────────────────── profile helpers ───────────────────────── */

function siemTechnologiesOf(profile) {
  return (profile?.technologies || []).filter(t => t.category === 'siem' && t.technology_id !== taxonomy.CUSTOM_UNMAPPED_ID);
}

// EDR/XDR, endpoint-agent, and cloud technologies are the ones that can
// plausibly supply telemetry (mandate Phase 12's "Endpoint telemetry"
// category) -- SIEM/OS technologies never appear as a suggested_sources
// entry (a SIEM ingests telemetry, it does not produce it; OS is
// descriptive context, not a telemetry provider in this taxonomy).
function relevantTelemetryTechnologyIds(profile) {
  return (profile?.technologies || [])
    .filter(t => ['edr_xdr', 'endpoint_telemetry', 'cloud'].includes(t.category) && t.technology_id !== taxonomy.CUSTOM_UNMAPPED_ID)
    .map(t => t.technology_id);
}

function telemetryStatusFor(profile, dataSource) {
  return (profile && profile.telemetry && profile.telemetry[dataSource]) || 'UNKNOWN';
}

// The real, per-technique requirement: technique -> REGISTRY's own
// data_source. Always length 1 today (every buildable technique targets
// exactly one data source -- see the inventory doc §3's disclosed
// limitation), but written generically so a future multi-data-source
// detection is handled correctly without this function changing.
function requirementsFor(canonicalDetection) {
  return (canonicalDetection.attack || [])
    .map(a => {
      const reg = detectionEngine.REGISTRY[a.id];
      return reg ? { technique_id: a.id, data_source: reg.data_source } : null;
    })
    .filter(Boolean);
}

/**
 * Rolls up one or more per-data-source telemetry statuses into a single
 * telemetry-availability verdict. Mirrors the mandate's own two worked
 * examples exactly (Phase 21: 2 requirements, 1 available -> partially
 * available; Phase 22: 1 requirement, not available -> gap):
 *   all AVAILABLE                      -> FULLY_AVAILABLE
 *   some (but not all) AVAILABLE/PARTIAL -> PARTIALLY_AVAILABLE
 *   all UNKNOWN                        -> UNKNOWN
 *   none AVAILABLE, at least one NOT_AVAILABLE (rest UNKNOWN/NOT_AVAILABLE) -> GAP
 */
function rollupTelemetryStatus(statuses) {
  if (!statuses.length) return 'UNKNOWN';
  if (statuses.every(s => s === 'AVAILABLE')) return 'FULLY_AVAILABLE';
  if (statuses.some(s => s === 'AVAILABLE' || s === 'PARTIALLY_AVAILABLE')) return 'PARTIALLY_AVAILABLE';
  if (statuses.every(s => s === 'UNKNOWN')) return 'UNKNOWN';
  if (statuses.some(s => s === 'NOT_AVAILABLE')) return 'GAP';
  return 'UNKNOWN';
}

/**
 * Evaluates whether ONE already-RELEASED canonical detection fits a
 * customer's Defense Profile. Format/platform compatibility is checked
 * first and short-circuits (mandate Phase 92): a customer whose declared
 * SIEM cannot run this detection in any released format never reaches a
 * telemetry verdict for it. Sigma existing alone is never silently
 * upgraded to a native-format match (mandate Phase 26).
 */
function evaluateDetectionCompatibility(canonicalDetection, profile) {
  if (!canonicalDetection || canonicalDetection.status !== 'RELEASED') {
    return {
      status: 'NO_VALIDATED_DETECTION', format_used: null, sigma_portable: false, missing_telemetry: [],
      explanation: 'This detection has not passed full validation and release gating yet.',
    };
  }

  const availableFormats = Object.keys(canonicalDetection.formats || {});
  const siemTechs = siemTechnologiesOf(profile);

  if (siemTechs.length === 0) {
    return {
      status: 'UNKNOWN', format_used: null, sigma_portable: availableFormats.includes('sigma'), missing_telemetry: [],
      explanation: 'No SIEM / detection platform is configured in your Defense Profile, so format compatibility cannot be determined.',
    };
  }

  const preferredFormats = siemTechs.map(t => taxonomy.preferredFormatFor(t.technology_id)).filter(Boolean);
  const matchedFormat = preferredFormats.find(f => availableFormats.includes(f));
  const siemLabel = siemTechs.map(t => t.label).join(' / ');

  if (!matchedFormat) {
    const sigmaPortable = availableFormats.includes('sigma');
    return {
      status: 'UNSUPPORTED_PLATFORM', format_used: null, sigma_portable: sigmaPortable, missing_telemetry: [],
      explanation: sigmaPortable
        ? `No native ${siemLabel} format is available for this detection. A portable Sigma source exists, but converting it to your platform's native query language has not been done -- it is not automatically treated as ready.`
        : `No detection format compatible with your configured SIEM (${siemLabel}) is currently available for this detection.`,
    };
  }

  const relevantTechIds = relevantTelemetryTechnologyIds(profile);
  const dataSources = [...new Set(requirementsFor(canonicalDetection).map(r => r.data_source))];
  const statuses = dataSources.map(ds => telemetryStatusFor(profile, ds));
  const rollup = rollupTelemetryStatus(statuses);
  const labelFor = (ds) => (detectionIntelligence.TELEMETRY_REQUIREMENTS[ds] || {}).source_label || ds;

  const missing = dataSources
    .filter(ds => telemetryStatusFor(profile, ds) !== 'AVAILABLE')
    .map(ds => ({
      data_source: ds,
      source_label: labelFor(ds),
      status: telemetryStatusFor(profile, ds),
      suggested_sources: taxonomy.suggestedSourcesFor(ds, relevantTechIds),
    }));

  if (rollup === 'FULLY_AVAILABLE') {
    return {
      status: 'READY', format_used: matchedFormat, sigma_portable: availableFormats.includes('sigma'), missing_telemetry: [],
      explanation: `Your configured ${siemLabel} environment includes the required ${dataSources.map(labelFor).join(', ')} telemetry.`,
    };
  }
  if (rollup === 'PARTIALLY_AVAILABLE') {
    return {
      status: 'PARTIALLY_READY', format_used: matchedFormat, sigma_portable: availableFormats.includes('sigma'), missing_telemetry: missing,
      explanation: 'Some, but not all, of the telemetry this detection requires is available in your Defense Profile.',
    };
  }
  if (rollup === 'GAP') {
    return {
      status: 'TELEMETRY_GAP', format_used: matchedFormat, sigma_portable: availableFormats.includes('sigma'), missing_telemetry: missing,
      explanation: `This detection requires ${missing.map(m => m.source_label).join(', ')}, which ${missing.length === 1 ? 'is' : 'are'} not currently marked available in your Defense Profile.`,
    };
  }
  return {
    status: 'UNKNOWN', format_used: matchedFormat, sigma_portable: availableFormats.includes('sigma'), missing_telemetry: missing,
    explanation: "Telemetry availability has not been configured for this detection's required data source(s).",
  };
}

function recommendationFor(t) {
  switch (t.customer_status) {
    case 'READY':
      return t.recommended_detection
        ? `Deploy-ready: use the ${t.customer_format_used} format from detection ${t.recommended_detection.detection_id}.`
        : 'Deploy-ready.';
    case 'PARTIALLY_READY':
      return 'Partially ready -- configure the missing telemetry below to reach full readiness.';
    case 'TELEMETRY_GAP': {
      const sources = (t.customer_missing_telemetry || []).flatMap(m => (m.suggested_sources || []).map(s => s.source_label)).filter(Boolean);
      return sources.length
        ? `Configure an available telemetry source for this technique before relying on this detection (e.g. ${sources.slice(0, 3).join(', ')}).`
        : "Configure telemetry for this technique's required data source before relying on this detection.";
    }
    case 'UNSUPPORTED_PLATFORM':
      return t.customer_sigma_portable
        ? 'A portable Sigma detection exists but has no native format for your configured SIEM. Manual conversion or a compatible SIEM would be required.'
        : 'No detection format compatible with your configured SIEM is currently available for this technique.';
    case 'UNKNOWN':
      return "Telemetry availability has not been configured for this technique's required data source.";
    case 'NO_VALIDATED_DETECTION':
      return 'No validated detection currently exists for this technique.';
    case 'UNKNOWN_PROFILE':
      return 'Configure your Defense Profile to see environment-specific detection readiness for this technique.';
    default:
      return '';
  }
}

const COMPAT_PRIORITY = ['READY', 'PARTIALLY_READY', 'TELEMETRY_GAP', 'UNKNOWN', 'UNSUPPORTED_PLATFORM'];

/**
 * Customer-specific defense coverage for one CVE/campaign. Wraps the
 * unmodified global coverage engine and adds a per-technique compatibility
 * rollup against the caller's Defense Profile. `profile` may be null
 * (mandate Phase 37's safe default) -- global coverage is still fully
 * returned, only the customer dimension degrades to UNKNOWN_PROFILE.
 */
function computeCustomerCoverage({ attackContext, entityType, entityId, profile }) {
  const globalCoverage = detectionIntelligence.computeCoverage({ attackContext, entityType, entityId });

  if (!profile) {
    const techniques = globalCoverage.techniques.map(t => ({
      ...t, customer_status: 'UNKNOWN_PROFILE', customer_explanation: null,
      customer_format_used: null, customer_missing_telemetry: [], customer_sigma_portable: false,
      recommended_detection: null, recommendation: recommendationFor({ customer_status: 'UNKNOWN_PROFILE' }),
    }));
    return {
      ...globalCoverage, profile_configured: false, techniques,
      customer_summary: { ready: 0, partial: 0, telemetry_gap: 0, unsupported_platform: 0, unknown: 0, unknown_profile: techniques.length, no_validated_detection: 0 },
    };
  }

  const techniques = globalCoverage.techniques.map(t => {
    if (t.status === 'NO_VALIDATED_DETECTION' || t.status === 'UNSUPPORTED_TELEMETRY') {
      // Platform-has-no-rule is never conflated with customer-lacks-telemetry
      // (mandate Phase 94) -- this technique has no eligible detection at
      // all, independent of anyone's environment.
      const base = { ...t, customer_status: 'NO_VALIDATED_DETECTION', customer_explanation: 'No validated detection currently exists for this technique -- independent of your environment.', customer_format_used: null, customer_missing_telemetry: [], customer_sigma_portable: false, recommended_detection: null };
      return { ...base, recommendation: recommendationFor(base) };
    }

    const releasedDetections = (t.rule_ids || [])
      .map(id => detectionRules.getRule(id))
      .filter(Boolean)
      .map(r => detectionIntelligence.toCanonicalDetectionObject(r, { attackEvidenceState: t.evidence_state }))
      .filter(d => d.status === 'RELEASED');

    if (releasedDetections.length === 0) {
      const base = { ...t, customer_status: 'NO_VALIDATED_DETECTION', customer_explanation: 'A detection exists for this technique but has not yet passed full validation and release gating.', customer_format_used: null, customer_missing_telemetry: [], customer_sigma_portable: false, recommended_detection: null };
      return { ...base, recommendation: recommendationFor(base) };
    }

    const evaluated = releasedDetections.map(d => ({ detection: d, compat: evaluateDetectionCompatibility(d, profile) }));
    let best = null;
    for (const status of COMPAT_PRIORITY) {
      best = evaluated.find(e => e.compat.status === status);
      if (best) break;
    }
    if (!best) best = evaluated[0];

    const base = {
      ...t,
      customer_status: best.compat.status,
      customer_explanation: best.compat.explanation,
      customer_format_used: best.compat.format_used,
      customer_missing_telemetry: best.compat.missing_telemetry || [],
      customer_sigma_portable: !!best.compat.sigma_portable,
      recommended_detection: best.compat.status === 'READY' || best.compat.status === 'PARTIALLY_READY'
        ? { detection_id: best.detection.detection_id, format: best.compat.format_used }
        : null,
    };
    return { ...base, recommendation: recommendationFor(base) };
  });

  const count = (s) => techniques.filter(t => t.customer_status === s).length;
  return {
    ...globalCoverage,
    profile_configured: true,
    techniques,
    customer_summary: {
      ready: count('READY'),
      partial: count('PARTIALLY_READY'),
      telemetry_gap: count('TELEMETRY_GAP'),
      unsupported_platform: count('UNSUPPORTED_PLATFORM'),
      unknown: count('UNKNOWN'),
      unknown_profile: 0,
      no_validated_detection: count('NO_VALIDATED_DETECTION'),
    },
  };
}

module.exports = {
  COMPATIBILITY_STATES,
  rollupTelemetryStatus,
  evaluateDetectionCompatibility,
  computeCustomerCoverage,
  recommendationFor,
};
