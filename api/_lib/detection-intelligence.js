'use strict';
/**
 * SENTINEL APEX -- Threat-to-Defense Fabric v1
 *
 * Turns evidence-backed intelligence (CVE/Campaign dossiers, already
 * ATT&CK-evidence-graded) into detection coverage, opportunity assessment,
 * and validated detection artifacts -- WITHOUT building a second detection
 * truth store. This module is a computed orchestration layer over two
 * already-canonical systems (see docs/audits/
 * SENTINEL-APEX-DETECTION-CAPABILITY-INVENTORY-V1.md for the full
 * reuse-before-build evidence):
 *
 *   - api/_lib/detection-rules.js        (canonical detection-rule STORE)
 *   - Sentinel-APEX/engine-node/detection-engine.js + the Python parity
 *     port (canonical detection GENERATOR -- REGISTRY, format builders,
 *     structural validators -- called here unchanged, never re-implemented)
 *
 * ATT&CK evidence linkage is likewise reused, not re-derived: this module
 * classifies evidence quality from the `source`/`via` fields the dossier's
 * own buildAttackContext() already attaches (linked_report = hand-authored,
 * negation-aware attack_mapper.py output; linked_actor = curated, static
 * ttps[]) -- it never re-scans raw text for technique keywords itself.
 *
 * Nothing here is persisted as a second store. Coverage/opportunity/
 * validation are computed fresh per call, exactly like intelligence-
 * dossier.js's own "not canonical storage" design -- deleting this file
 * and re-deriving its output from the two canonical systems above always
 * reproduces the same result.
 */

const yaml = require('js-yaml');
const detectionEngine = require('../../Sentinel-APEX/engine-node/detection-engine');
const detectionRules = require('./detection-rules');

/* ───────────────────────── Vocabularies ───────────────────────── */

const SCHEMA_VERSION = '1.0';

// Reconciles with, does not compete against, the already-certified 9-state
// vocabulary in Sentinel-APEX/engine/sentinel_engine/reportx/
// detection_validation.py (a report-prose honesty gate, a different layer
// -- see inventory doc Section 2.8). This is the rule-lifecycle vocabulary
// the mandate's Phase 6 asks for.
const LIFECYCLE_STATES = Object.freeze([
  'DRAFT', 'GENERATED', 'STRUCTURALLY_VALIDATED', 'BEHAVIORALLY_VALIDATED',
  'REVIEW_REQUIRED', 'RELEASED', 'DEPRECATED', 'REVOKED',
]);

const BLOCK_REASONS = Object.freeze([
  'MISSING_EVIDENCE', 'UNSUPPORTED_TELEMETRY', 'INVALID_QUERY', 'INVALID_LOGSOURCE',
  'POSITIVE_FIXTURE_FAILED', 'NEGATIVE_FIXTURE_MATCHED', 'ATTACK_MAPPING_UNCERTAIN',
  'UNSUPPORTED_FORMAT',
]);

const ATTACK_EVIDENCE_STATES = Object.freeze([
  'DIRECT_OBSERVATION', 'SOURCE_ATTRIBUTED', 'INFERRED', 'PROFILE_DERIVED', 'UNKNOWN',
]);

const DETECTION_OPPORTUNITY = Object.freeze([
  'DETECTION_AVAILABLE', 'DETECTION_GENERATABLE', 'INSUFFICIENT_EVIDENCE',
  'INSUFFICIENT_TELEMETRY', 'LOW_SIGNAL', 'UNSUPPORTED',
]);

const COVERAGE_STATUS = Object.freeze([
  'COVERED', 'PARTIALLY_COVERED', 'UNSUPPORTED_TELEMETRY', 'NO_VALIDATED_DETECTION',
]);

// Evidence-based, per docs/audits/SENTINEL-APEX-DETECTION-CAPABILITY-
// INVENTORY-V1.md Section 2.3/2.8. Sigma alone has a real fixture
// evaluator (see evaluateSigmaCondition below); KQL/Splunk/OSQuery/
// Suricata have real structural validators (reused from detection-engine.js
// unchanged) but no behavioral-fixture engine exists for them yet -- an
// honest, disclosed gap, not silently claimed as covered. Elastic/QRadar/
// YARA have no validated generator anywhere in this codebase's live path
// (api/_lib/detection-export-engine.js produces unvalidated output from a
// different, unrelated data shape -- not reused, see inventory doc 2.5) so
// they are honestly UNSUPPORTED, never advertised.
const FORMAT_CAPABILITY_MATRIX = Object.freeze({
  sigma:    { generate: true,  structural_validate: true,  fixture_validate: true,  release: true,  maturity: 'Production Ready' },
  kql:      { generate: true,  structural_validate: true,  fixture_validate: false, release: true,  maturity: 'Production Ready With Limitations' },
  splunk:   { generate: true,  structural_validate: true,  fixture_validate: false, release: true,  maturity: 'Production Ready With Limitations' },
  osquery:  { generate: true,  structural_validate: true,  fixture_validate: false, release: true,  maturity: 'Production Ready With Limitations' },
  suricata: { generate: true,  structural_validate: true,  fixture_validate: false, release: true,  maturity: 'Production Ready With Limitations' },
  elastic:  { generate: false, structural_validate: false, fixture_validate: false, release: false, maturity: 'Unsupported' },
  qradar:   { generate: false, structural_validate: false, fixture_validate: false, release: false, maturity: 'Unsupported' },
  yara:     { generate: false, structural_validate: false, fixture_validate: false, release: false, maturity: 'Unsupported' },
});

const SUPPORTED_FORMATS = Object.freeze(Object.keys(FORMAT_CAPABILITY_MATRIX).filter(f => FORMAT_CAPABILITY_MATRIX[f].generate));

// Keyed by the same data_source vocabulary detection_specs.py/
// detection-engine.js's REGISTRY already uses -- documents an existing
// vocabulary, does not invent a new one. `known_fields` is the superset a
// technique on this data source MAY reference (per REGISTRY's own
// FIELD_MAP); a specific rule's actual *required* fields are derived from
// what its own selection logic references (see requiredFieldsFromSigma
// below), never asserted as a fixed list independent of the rule -- a
// rule generated against a narrower field set (e.g. T1204.002 uses only
// ParentImage/Image, never CommandLine) must not be penalized for not
// using every field another technique on the same data source happens to
// need.
const TELEMETRY_REQUIREMENTS = Object.freeze({
  process_creation: {
    platform: 'windows',
    source_label: 'Windows Process Creation (Sysmon Event ID 1, or Windows Security 4688 with command-line auditing enabled)',
    known_fields: ['Image', 'CommandLine', 'ParentImage'],
    optional_fields: ['User', 'Hashes', 'IntegrityLevel'],
  },
  process_access: {
    platform: 'windows',
    source_label: 'Windows Process Access (Sysmon Event ID 10)',
    known_fields: ['TargetImage', 'GrantedAccess'],
    optional_fields: ['SourceImage', 'CallTrace'],
  },
  registry_set: {
    platform: 'windows',
    source_label: 'Windows Registry Modification (Sysmon Event ID 13)',
    known_fields: ['TargetObject', 'Image'],
    optional_fields: ['Details'],
  },
  network: {
    platform: 'network',
    source_label: 'Network/DNS/Proxy telemetry (firewall, DNS resolver, or proxy logs)',
    known_fields: ['src_ip', 'dest_ip_or_domain'],
    optional_fields: ['dest_port', 'protocol'],
  },
});
const DEFAULT_TELEMETRY_REQUIREMENT = Object.freeze({
  platform: 'unknown',
  source_label: 'Not documented for this data source.',
  known_fields: [],
  optional_fields: [],
});

function telemetryRequirementsFor(dataSource, { requiredFields } = {}) {
  const base = TELEMETRY_REQUIREMENTS[dataSource] || DEFAULT_TELEMETRY_REQUIREMENT;
  return { ...base, required_fields: requiredFields || base.known_fields };
}

/**
 * Extracts the actual field names a parsed Sigma rule's selection/filter
 * blocks reference (the `|modifier` prefix stripped) -- the real,
 * rule-specific telemetry requirement, not a generic per-data-source
 * guess.
 */
function requiredFieldsFromSigma(parsedSigma) {
  const detection = parsedSigma?.detection || {};
  const fields = new Set();
  for (const [blockName, block] of Object.entries(detection)) {
    if (blockName === 'condition' || !block || typeof block !== 'object') continue;
    for (const key of Object.keys(block)) fields.add(key.split('|')[0]);
  }
  return [...fields];
}

// General, non-technique-specific guidance only -- deliberately never
// claims measured/zero false positives (mandate Phase 29/70).
const GENERAL_FALSE_POSITIVE_GUIDANCE = Object.freeze([
  'GENERAL FALSE-POSITIVE CONSIDERATIONS (not a measured false-positive rate):',
  'Validate this logic against your own environment baseline before enabling in blocking mode.',
  'Legitimate administrative tooling and authorized security testing can trigger process/command-line-based detections.',
  'Tune scope (host groups, user groups, time windows) to your environment before broad deployment.',
]);

/* ───────────────────────── ATT&CK evidence linkage (reused, not re-derived) ─── */

/**
 * Classifies the evidence quality of one ATT&CK technique entry already
 * produced by intelligence-dossier.js's buildAttackContext(). Never infers
 * evidence quality from raw text itself -- that mapping already happened,
 * with negation-awareness, in the offline attack_mapper.py that produced
 * a linked report's attack_ids[], or is a curated ThreatActor ttps[] entry.
 */
function classifyAttackEvidence(techniqueEntry) {
  if (!techniqueEntry || !techniqueEntry.source) return 'UNKNOWN';
  if (techniqueEntry.source === 'linked_report') return 'SOURCE_ATTRIBUTED';
  if (techniqueEntry.source === 'linked_actor') return 'PROFILE_DERIVED';
  return 'UNKNOWN';
}

/* ───────────────────────── Detection opportunity engine ───────────────────── */

/**
 * Decides whether a detection should even be attempted for a technique,
 * before any generation happens (mandate Phase 11). Never generates for
 * every ATT&CK ID -- only the canonical generator's own buildable set.
 */
function assessOpportunity(techniqueId, { hasReleasedRule = false } = {}) {
  if (!detectionEngine.isValidTechniqueId(techniqueId)) {
    return {
      opportunity: 'UNSUPPORTED',
      reason: `"${techniqueId}" is not a recognized ATT&CK technique in this platform's curated registry.`,
    };
  }
  if (hasReleasedRule) {
    return { opportunity: 'DETECTION_AVAILABLE', reason: 'A released detection already exists for this technique.' };
  }
  const buildable = detectionEngine.buildableTechniques(); // returns a Set, not an Array
  if (buildable.has(techniqueId)) {
    return {
      opportunity: 'DETECTION_GENERATABLE',
      reason: 'A detection spec exists for this technique in the canonical generator registry and can be built.',
    };
  }
  return {
    opportunity: 'INSUFFICIENT_TELEMETRY',
    reason: `"${techniqueId}" is a recognized technique, but no detection spec exists yet in the canonical generator registry (buildableTechniques()).`,
  };
}

/* ───────────────────────── L2: Sigma structural validation ────────────────── */

function validateSigmaStructural(sigmaYamlText) {
  const errors = [];
  let parsed;
  try {
    parsed = yaml.load(sigmaYamlText);
  } catch (e) {
    return { pass: false, errors: [`YAML parse error: ${e.message}`], parsed: null };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { pass: false, errors: ['Parsed Sigma content is not a YAML mapping.'], parsed: null };
  }
  if (!parsed.title) errors.push('Missing required field: title');
  if (!parsed.logsource || typeof parsed.logsource !== 'object') errors.push('Missing or invalid required field: logsource');
  if (!parsed.detection || typeof parsed.detection !== 'object') {
    errors.push('Missing or invalid required field: detection');
  } else if (!parsed.detection.condition) {
    errors.push('Missing required field: detection.condition');
  }
  return { pass: errors.length === 0, errors, parsed: errors.length === 0 ? parsed : null };
}

/* ───────────────────── L4/L5: mini Sigma selection/condition evaluator ──────
 *
 * Deliberately scoped, not a general Sigma implementation: supports the
 * exact modifiers and condition grammar this platform's own canonical
 * generator (detection_builder.py's to_sigma()) actually emits --
 * |endswith / |startswith / |contains / bare equality, list values as OR,
 * multiple keys in one block as AND, and "A and B" / "A or B" / "not X"
 * condition tokens (the negate=True -> "selection and not filter_N" shape
 * detection_builder.py generates for T1547.001). An unsupported condition
 * grammar fails closed (returns false / "cannot verify"), never claims a
 * match it cannot actually compute.
 */

function matchValue(candidate, actual, modifier) {
  const a = String(actual).toLowerCase();
  // YAML 1.1 (js-yaml's default schema) parses an unquoted "0x1410"-style
  // literal as the NUMBER 5136, not the string "0x1410" -- a real,
  // verified gotcha in the canonical generator's own Sigma output (e.g.
  // T1003.001's GrantedAccess|contains values), since access-mask/hex
  // telemetry fields are conventionally hex-string-shaped. Compare
  // against both the decimal and re-hexed forms so a synthetic event
  // using the hex-string convention still matches correctly.
  const candidateForms = [String(candidate).toLowerCase()];
  if (typeof candidate === 'number' && Number.isInteger(candidate)) {
    candidateForms.push('0x' + candidate.toString(16).toLowerCase());
  }
  return candidateForms.some(c => {
    switch (modifier) {
      case 'endswith':   return a.endsWith(c);
      case 'startswith': return a.startsWith(c);
      case 'contains':   return a.includes(c);
      case undefined:    return a === c;
      default:           return false; // unrecognized modifier -- fail closed
    }
  });
}

function matchOneField(rawKey, expected, event) {
  const sep = rawKey.indexOf('|');
  const fieldName = sep === -1 ? rawKey : rawKey.slice(0, sep);
  const modifier = sep === -1 ? undefined : rawKey.slice(sep + 1);
  const actual = event[fieldName];
  if (actual === undefined || actual === null) return false;
  const candidates = Array.isArray(expected) ? expected : [expected];
  return candidates.some(candidate => matchValue(candidate, actual, modifier));
}

function evaluateSelectionBlock(block, event) {
  if (!block || typeof block !== 'object') return false;
  return Object.entries(block).every(([key, expected]) => matchOneField(key, expected, event));
}

function evaluateSigmaCondition(parsedSigma, event) {
  const detection = parsedSigma.detection || {};
  const condition = String(detection.condition || '').trim();
  const blockNames = Object.keys(detection).filter(k => k !== 'condition');
  const blockResults = {};
  for (const name of blockNames) blockResults[name] = evaluateSelectionBlock(detection[name], event);

  const resolveToken = (token) => {
    const t = token.trim();
    if (t.startsWith('not ')) {
      const inner = t.slice(4).trim();
      return Object.prototype.hasOwnProperty.call(blockResults, inner) ? !blockResults[inner] : null;
    }
    return Object.prototype.hasOwnProperty.call(blockResults, t) ? blockResults[t] : null;
  };

  if (Object.prototype.hasOwnProperty.call(blockResults, condition)) return blockResults[condition];
  if (condition.includes(' and ')) {
    const parts = condition.split(' and ').map(resolveToken);
    if (parts.some(p => p === null)) return false;
    return parts.every(Boolean);
  }
  if (condition.includes(' or ')) {
    const parts = condition.split(' or ').map(resolveToken);
    if (parts.some(p => p === null)) return false;
    return parts.some(Boolean);
  }
  return false; // unsupported condition grammar -- cannot verify, fail closed
}

/* ───────────────────────── Fixture framework ───────────────────────────────
 *
 * Field names/values below are taken directly from the canonical
 * generator's own spec (Sentinel-APEX/engine/sentinel_engine/
 * detection_specs.py REGISTRY), so a fixture is guaranteed to exercise the
 * real matcher logic that spec's Sigma output encodes -- not a guess.
 * Telemetry only: no command is ever executed, no malicious payload is
 * generated, these are static field/value JSON objects representing what
 * an EDR/Sysmon event would look like.
 */

const FIXTURE_SPECS = Object.freeze({
  'T1059.001': {
    positive: { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -EncodedCommand SQBFAFgA' },
    negative: { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -File deploy.ps1' },
    edge: [
      { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE', CommandLine: 'PowerShell.exe -enc dGVzdA==' },
      { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
      { Image: '', CommandLine: '' },
    ],
  },
  'T1204.002': {
    positive: { ParentImage: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
    negative: { ParentImage: 'C:\\Windows\\explorer.exe', Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
    edge: [
      { ParentImage: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE' },
      { ParentImage: 'c:\\program files\\microsoft office\\root\\office16\\excel.exe', Image: 'C:\\Windows\\System32\\cmd.exe' },
    ],
  },
  T1490: {
    positive: { CommandLine: 'vssadmin delete shadows /all /quiet' },
    negative: { CommandLine: 'vssadmin list shadows' },
    edge: [{ CommandLine: '' }],
  },
  'T1547.001': {
    positive: { TargetObject: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater', Image: 'C:\\Users\\Public\\evil.exe' },
    negative: { TargetObject: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive', Image: 'C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe' },
    edge: [{ TargetObject: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X' }],
  },
  'T1003.001': {
    positive: { TargetImage: 'C:\\Windows\\System32\\lsass.exe', GrantedAccess: '0x1410' },
    negative: { TargetImage: 'C:\\Windows\\System32\\lsass.exe', GrantedAccess: '0x0400' },
    edge: [{ TargetImage: 'C:\\Windows\\System32\\lsass.exe' }],
  },
  'T1218.005': {
    positive: { Image: 'C:\\Windows\\System32\\mshta.exe', CommandLine: 'mshta.exe javascript:eval("x")' },
    negative: { Image: 'C:\\Windows\\System32\\mshta.exe', CommandLine: 'mshta.exe C:\\Users\\admin\\local-help.hta' },
    edge: [{ Image: 'C:\\Windows\\System32\\MSHTA.EXE', CommandLine: 'mshta http://example.com/a.hta' }],
  },
});

function fixturesFor(techniqueId) {
  return FIXTURE_SPECS[techniqueId] || null;
}

/**
 * Runs the positive/negative/edge fixture suite for a Sigma rule tied to a
 * known technique. Returns null (not applicable) when no curated fixture
 * exists for the technique -- never fabricates a fixture, and never claims
 * fixture_validate for a technique this table doesn't cover.
 */
function runSigmaFixtureSuite(parsedSigma, techniqueId) {
  const fixtures = fixturesFor(techniqueId);
  if (!fixtures) return null;
  const positiveMatch = evaluateSigmaCondition(parsedSigma, fixtures.positive);
  const negativeMatch = evaluateSigmaCondition(parsedSigma, fixtures.negative);
  const edgeResults = (fixtures.edge || []).map(ev => {
    try {
      return { event: ev, matched: evaluateSigmaCondition(parsedSigma, ev), crashed: false };
    } catch (e) {
      return { event: ev, matched: null, crashed: true, error: e.message };
    }
  });
  return {
    positive_fixture: { pass: positiveMatch === true, matched: positiveMatch },
    negative_fixture: { pass: negativeMatch === false, matched: negativeMatch },
    edge_fixtures: edgeResults,
  };
}

/* ───────────────────────── L1-L7 validation truth model ───────────────────── */

/**
 * Runs the full, honest validation truth model for one stored detection
 * record + a specific technique context. Never collapses to a single
 * VALIDATED=true/false -- each level is reported independently, and L6/L7
 * are always explicitly "not verified" since this environment has no real
 * SIEM/customer-production execution capability.
 */
function runValidation(storedRule) {
  const techniqueId = storedRule.technique_id;
  const result = {
    schema: { level: 'L1', pass: !!(storedRule.id && storedRule.technique_id && storedRule.title) },
    structural: { level: 'L2', pass: true, per_format: {} },
    telemetry: { level: 'L3', pass: true, missing_fields: [] },
    positive_fixture: { level: 'L4', pass: null, note: 'Not applicable for this technique or format.' },
    negative_fixture: { level: 'L5', pass: null, note: 'Not applicable for this technique or format.' },
    real_execution: { level: 'L6', pass: null, note: 'Not verified -- no real SIEM execution available in this environment.' },
    customer_production: { level: 'L7', pass: null, note: 'Not verified -- requires live customer deployment telemetry, not available to this platform.' },
  };

  // L2: structural, per populated format.
  const platforms = storedRule.platforms || {};
  let parsedSigma = null;
  if (platforms.sigma) {
    const sigmaCheck = validateSigmaStructural(platforms.sigma);
    result.structural.per_format.sigma = { pass: sigmaCheck.pass, errors: sigmaCheck.errors };
    if (!sigmaCheck.pass) result.structural.pass = false;
    parsedSigma = sigmaCheck.parsed;
  }
  if (platforms.kql) {
    const errs = detectionEngine.validateKql(platforms.kql);
    result.structural.per_format.kql = { pass: errs.length === 0, errors: errs };
    if (errs.length) result.structural.pass = false;
  }
  if (platforms.splunk) {
    const errs = detectionEngine.validateSplunk(platforms.splunk);
    result.structural.per_format.splunk = { pass: errs.length === 0, errors: errs };
    if (errs.length) result.structural.pass = false;
  }
  if (platforms.osquery) {
    const errs = detectionEngine.validateOsquery(platforms.osquery);
    result.structural.per_format.osquery = { pass: errs.length === 0, errors: errs };
    if (errs.length) result.structural.pass = false;
  }
  if (Array.isArray(storedRule.suricata) && storedRule.suricata.length) {
    const errs = storedRule.suricata.flatMap(rule => detectionEngine.validateSuricata(rule));
    result.structural.per_format.suricata = { pass: errs.length === 0, errors: errs };
    if (errs.length) result.structural.pass = false;
  }

  // L3: telemetry -- does the record declare a known data_source, and is
  // every field the rule's own selection logic actually references a
  // recognized field for that data source? This catches a real defect
  // (an unrecognized/typo'd field, or a data source this platform hasn't
  // documented telemetry for) -- it deliberately does NOT require a rule
  // to use every field another technique on the same data source happens
  // to need (see the DetectionSpec REGISTRY: T1204.002 only ever
  // references ParentImage/Image, never CommandLine, and must not be
  // penalized for that).
  const knownDataSource = !!TELEMETRY_REQUIREMENTS[storedRule.data_source];
  if (parsedSigma) {
    result.telemetry.fields_referenced = requiredFieldsFromSigma(parsedSigma);
    const req = telemetryRequirementsFor(storedRule.data_source);
    const recognized = new Set([...req.known_fields, ...req.optional_fields]);
    const unrecognized = knownDataSource ? result.telemetry.fields_referenced.filter(f => !recognized.has(f)) : result.telemetry.fields_referenced;
    result.telemetry.pass = knownDataSource && unrecognized.length === 0;
    result.telemetry.missing_fields = knownDataSource ? unrecognized : ['(data_source not documented)'];
  } else {
    result.telemetry.fields_referenced = [];
    result.telemetry.pass = knownDataSource;
    result.telemetry.missing_fields = knownDataSource ? [] : ['(data_source not documented)'];
  }

  // L4/L5: fixture suite, Sigma only (the only format with a real evaluator).
  if (parsedSigma && result.structural.pass) {
    const fixtureResult = runSigmaFixtureSuite(parsedSigma, techniqueId);
    if (fixtureResult) {
      result.positive_fixture = { level: 'L4', ...fixtureResult.positive_fixture };
      result.negative_fixture = { level: 'L5', ...fixtureResult.negative_fixture };
      result.edge_fixtures = fixtureResult.edge_fixtures;
    }
  }

  return result;
}

/* ───────────────────────── Release gate + block reasons ───────────────────── */

/**
 * Evaluates whether a stored rule may be marked RELEASED. Requires threat
 * linkage, a non-UNKNOWN ATT&CK evidence basis, and every populated
 * validation level to pass. Never releases an unvalidated generated rule
 * (mandate Phase 49).
 */
function evaluateReleaseGate(storedRule, validation, attackEvidenceState) {
  const reasons = [];

  const hasLinkage = (storedRule.source?.articles?.length > 0) || (storedRule.source?.campaigns?.length > 0);
  if (!hasLinkage) reasons.push('MISSING_EVIDENCE');

  if (attackEvidenceState === 'UNKNOWN') reasons.push('ATTACK_MAPPING_UNCERTAIN');

  if (!validation.schema.pass) reasons.push('MISSING_EVIDENCE');
  if (!validation.structural.pass) reasons.push('INVALID_QUERY');

  const platforms = storedRule.platforms || {};
  if (platforms.sigma) {
    const sigmaStruct = validation.structural.per_format.sigma;
    if (sigmaStruct && !sigmaStruct.pass && sigmaStruct.errors.some(e => /logsource/i.test(e))) {
      reasons.push('INVALID_LOGSOURCE');
    }
  }

  if (validation.telemetry.pass === false) reasons.push('UNSUPPORTED_TELEMETRY');

  if (validation.positive_fixture.pass === false) reasons.push('POSITIVE_FIXTURE_FAILED');
  if (validation.negative_fixture.pass === false) reasons.push('NEGATIVE_FIXTURE_MATCHED');

  const declaredFormats = Object.keys(platforms).filter(f => platforms[f]).concat(
    (storedRule.suricata || []).length ? ['suricata'] : []
  );
  const unsupportedFormat = declaredFormats.find(f => !FORMAT_CAPABILITY_MATRIX[f] || !FORMAT_CAPABILITY_MATRIX[f].release);
  if (unsupportedFormat) reasons.push('UNSUPPORTED_FORMAT');

  const uniqueReasons = [...new Set(reasons)];
  if (uniqueReasons.length === 0) {
    return { status: 'RELEASED', reasons: [] };
  }
  // A structural or fixture failure blocks outright; anything else
  // (missing evidence, uncertain ATT&CK basis) is review-required, not an
  // automatic hard block -- an analyst can supply the missing linkage.
  const hardBlockers = ['INVALID_QUERY', 'INVALID_LOGSOURCE', 'POSITIVE_FIXTURE_FAILED', 'NEGATIVE_FIXTURE_MATCHED', 'UNSUPPORTED_FORMAT', 'UNSUPPORTED_TELEMETRY'];
  const status = uniqueReasons.some(r => hardBlockers.includes(r)) ? 'BLOCKED' : 'REVIEW_REQUIRED';
  return { status, reasons: uniqueReasons };
}

function falsePositiveGuidanceFor(_techniqueId) {
  // Curated per-technique guidance is a natural future extension; today
  // every technique gets the same honestly-labeled general guidance
  // rather than fabricated technique-specific false-positive rates.
  return [...GENERAL_FALSE_POSITIVE_GUIDANCE];
}

/* ───────────────────────── Canonical Detection Object projection ──────────── */

const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/i;

/**
 * Projects an existing stored rule (api/_lib/detection-rules.js's shape)
 * into the mandate's richer canonical Detection Object -- computed at read
 * time, the storage format itself is untouched.
 */
const MANUAL_LIFECYCLE_OVERRIDES = Object.freeze(['DEPRECATED', 'REVOKED']);

function toCanonicalDetectionObject(storedRule, { attackEvidenceState = 'UNKNOWN' } = {}) {
  const validation = runValidation(storedRule);
  const gate = evaluateReleaseGate(storedRule, validation, attackEvidenceState);
  // DEPRECATED/REVOKED are analyst decisions, not something the release
  // gate can compute from validation math -- reuses the existing,
  // unchanged detection-rules.js#updateRuleStatus() write path (mandate
  // Phase 51-52). An explicit manual status always overrides the
  // computed gate result; history of the transition is already preserved
  // by updateRuleStatus()'s own history[] append.
  const manualStatus = storedRule.governance?.status;
  const effectiveGate = MANUAL_LIFECYCLE_OVERRIDES.includes(manualStatus)
    ? { status: manualStatus, reasons: gate.reasons }
    : gate;
  const cves = (storedRule.source?.articles || []).filter(a => CVE_ID_RE.test(a));
  const formats = {};
  const platforms = storedRule.platforms || {};
  for (const fmt of ['sigma', 'kql', 'splunk', 'osquery']) {
    if (platforms[fmt]) formats[fmt] = { content: platforms[fmt], maturity: FORMAT_CAPABILITY_MATRIX[fmt].maturity };
  }
  if (Array.isArray(storedRule.suricata) && storedRule.suricata.length) {
    formats.suricata = { content: storedRule.suricata, maturity: FORMAT_CAPABILITY_MATRIX.suricata.maturity };
  }

  return {
    schema_version: SCHEMA_VERSION,
    detection_id: storedRule.id,
    version: storedRule.governance?.version || '1.0.0',
    name: storedRule.title,
    status: effectiveGate.status,
    lifecycle_reasons: effectiveGate.reasons,

    threat_context: {
      cves,
      campaigns: storedRule.source?.campaigns || [],
      actors: [],
      reports: [],
    },

    attack: [{ id: storedRule.technique_id, evidence_state: attackEvidenceState }],
    formats,
    telemetry_requirements: telemetryRequirementsFor(storedRule.data_source, {
      requiredFields: validation.telemetry.fields_referenced?.length ? validation.telemetry.fields_referenced : undefined,
    }),
    validation,
    false_positive_guidance: falsePositiveGuidanceFor(storedRule.technique_id),
    evidence_refs: storedRule.source?.iocs || [],
    source_refs: storedRule.source?.articles || [],

    created_at: storedRule.governance?.created_at || null,
    updated_at: storedRule.governance?.updated_at || null,
  };
}

/* ───────────────────────── Coverage engine ─────────────────────────────────
 *
 * Consumes attack_context.techniques[] as already produced by
 * intelligence-dossier.js's buildAttackContext() (evidence-graded, source-
 * attributed) -- does not re-derive ATT&CK linkage. Cross-references the
 * canonical store by technique_id, further scoped to this entity's own CVE/
 * campaign ID where the linkage exists, so a rule generated for a
 * different, unrelated CVE that happens to share a technique is not
 * miscounted as "this entity's" coverage.
 */
function computeCoverage({ attackContext, entityType, entityId }) {
  const techniques = (attackContext?.techniques || []);
  const seen = new Set();
  const perTechnique = [];

  for (const t of techniques) {
    if (seen.has(t.id)) continue;
    seen.add(t.id);

    const evidenceState = classifyAttackEvidence(t);
    const allRulesForTechnique = detectionRules.getRulesByTechnique(t.id) || [];
    const entityRules = entityType === 'cve'
      ? allRulesForTechnique.filter(r => (r.source?.articles || []).includes(entityId))
      : entityType === 'campaign'
        ? allRulesForTechnique.filter(r => (r.source?.campaigns || []).includes(entityId))
        : [];
    // Fall back to technique-level rules (not entity-scoped) only when no
    // entity-scoped rule exists, and marked as such -- never silently
    // presented as if it were specific to this CVE/campaign.
    const usedEntityScoped = entityRules.length > 0;
    const candidateRules = usedEntityScoped ? entityRules : allRulesForTechnique;

    const opportunity = assessOpportunity(t.id, { hasReleasedRule: candidateRules.length > 0 });

    let status;
    let ruleIds = [];
    if (candidateRules.length === 0) {
      status = opportunity.opportunity === 'UNSUPPORTED' || opportunity.opportunity === 'INSUFFICIENT_TELEMETRY'
        ? 'UNSUPPORTED_TELEMETRY'
        : 'NO_VALIDATED_DETECTION';
    } else {
      const classified = candidateRules.map(r => toCanonicalDetectionObject(r, { attackEvidenceState: evidenceState }));
      const released = classified.filter(d => d.status === 'RELEASED');
      const reviewRequired = classified.filter(d => d.status === 'REVIEW_REQUIRED');
      ruleIds = classified.map(d => d.detection_id);
      if (released.length > 0) status = 'COVERED';
      else if (reviewRequired.length > 0) status = 'PARTIALLY_COVERED';
      else status = 'NO_VALIDATED_DETECTION';
    }

    perTechnique.push({
      id: t.id,
      evidence_state: evidenceState,
      opportunity: opportunity.opportunity,
      status,
      rule_ids: ruleIds,
      entity_scoped: usedEntityScoped,
    });
  }

  const validated = perTechnique.filter(t => t.status === 'COVERED').length;
  const reviewRequired = perTechnique.filter(t => t.status === 'PARTIALLY_COVERED').length;
  const uncovered = perTechnique.filter(t => t.status === 'NO_VALIDATED_DETECTION' || t.status === 'UNSUPPORTED_TELEMETRY').length;

  return {
    entity_type: entityType,
    entity_id: entityId,
    observed_techniques: perTechnique.length,
    validated,
    review_required: reviewRequired,
    uncovered,
    techniques: perTechnique,
  };
}

/**
 * Builds the CVE/Campaign dossier's "detections" section from an already-
 * computed attack_context (mandate Phase 34). Replaces
 * intelligence-dossier.js's prior always-unavailable stub. Still honestly
 * reports available:false when there is truly nothing to show -- never
 * fabricates coverage.
 */
function buildDossierDetectionsSection(attackContext, entityType, entityId) {
  if (!attackContext || attackContext.status === 'not_established' || !(attackContext.techniques || []).length) {
    return {
      available: false,
      formats: [],
      coverage: null,
      note: 'No detection artifact currently available for this record.',
    };
  }
  const coverage = computeCoverage({ attackContext, entityType, entityId });
  const availableFormats = new Set();
  for (const t of coverage.techniques) {
    for (const ruleId of t.rule_ids) {
      const rule = detectionRules.getRule(ruleId);
      if (!rule) continue;
      for (const fmt of Object.keys(rule.platforms || {})) if (rule.platforms[fmt]) availableFormats.add(fmt);
      if ((rule.suricata || []).length) availableFormats.add('suricata');
    }
  }
  return {
    available: coverage.validated > 0 || coverage.review_required > 0,
    formats: [...availableFormats],
    coverage: {
      observed_techniques: coverage.observed_techniques,
      validated: coverage.validated,
      review_required: coverage.review_required,
      uncovered: coverage.uncovered,
    },
    note: (coverage.validated + coverage.review_required) === 0
      ? 'No validated detection currently available for this record\u2019s observed ATT&CK techniques.'
      : null,
  };
}

/* ───────────────────────── Detection pack manifest ─────────────────────────── */

const crypto = require('crypto');

function sha256(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

/**
 * Builds a detection pack manifest for an entity -- only RELEASED
 * detections are eligible (mandate Phase 43). Never includes an empty or
 * generated-but-unvalidated rule.
 */
function buildDetectionPack({ attackContext, entityType, entityId }) {
  const coverage = computeCoverage({ attackContext, entityType, entityId });
  const detectionIds = new Set();
  for (const t of coverage.techniques) for (const id of t.rule_ids) detectionIds.add(id);

  const detections = [];
  for (const id of detectionIds) {
    const rule = detectionRules.getRule(id);
    if (!rule) continue;
    const evidenceState = coverage.techniques.find(t => t.rule_ids.includes(id))?.evidence_state || 'UNKNOWN';
    const canonical = toCanonicalDetectionObject(rule, { attackEvidenceState: evidenceState });
    if (canonical.status !== 'RELEASED') continue; // packs contain only eligible (released) detections
    detections.push({
      detection_id: canonical.detection_id,
      version: canonical.version,
      technique: rule.technique_id,
      formats: Object.keys(canonical.formats),
      validation_status: canonical.status,
      hashes: Object.fromEntries(Object.entries(canonical.formats).map(([fmt, f]) => [fmt, sha256(typeof f.content === 'string' ? f.content : JSON.stringify(f.content))])),
    });
  }

  return {
    pack_id: `pack_${entityType}_${sha256(entityId).slice(0, 16)}`,
    entity: { type: entityType, id: entityId },
    generated_at: new Date().toISOString(),
    detection_count: detections.length,
    detections,
  };
}

/* ───────────────────────── Drop guard (Phase 32) ─────────────────────────── */

/**
 * Reusable, tested primitive guarding against an unexplained catastrophic
 * collapse in a detection count between two observations -- the same
 * discipline the campaign-delivery-integrity fix established. Not wired to
 * a persisted index file in this tranche (coverage/index are computed
 * per-request, matching the dossier/search precedent -- see certification
 * doc), but available and tested for a future batch/index-persistence
 * path.
 */
function checkDropGuard(previousCount, newCount, { minAbsolute = 5, maxDropRatio = 0.5 } = {}) {
  if (previousCount < minAbsolute) return { blocked: false, reason: null };
  if (newCount >= previousCount) return { blocked: false, reason: null };
  const dropRatio = (previousCount - newCount) / previousCount;
  if (dropRatio > maxDropRatio) {
    return {
      blocked: true,
      reason: `Detection count dropped from ${previousCount} to ${newCount} (${Math.round(dropRatio * 100)}%), exceeding the ${Math.round(maxDropRatio * 100)}% guard threshold.`,
    };
  }
  return { blocked: false, reason: null };
}

/* ───────────────────────── Exports ─────────────────────────────────────── */

module.exports = {
  SCHEMA_VERSION,
  LIFECYCLE_STATES,
  BLOCK_REASONS,
  ATTACK_EVIDENCE_STATES,
  DETECTION_OPPORTUNITY,
  COVERAGE_STATUS,
  FORMAT_CAPABILITY_MATRIX,
  SUPPORTED_FORMATS,
  TELEMETRY_REQUIREMENTS,
  telemetryRequirementsFor,

  classifyAttackEvidence,
  assessOpportunity,

  validateSigmaStructural,
  evaluateSigmaCondition,
  runSigmaFixtureSuite,
  fixturesFor,
  runValidation,
  evaluateReleaseGate,
  falsePositiveGuidanceFor,

  toCanonicalDetectionObject,
  computeCoverage,
  buildDossierDetectionsSection,
  buildDetectionPack,
  checkDropGuard,
};
