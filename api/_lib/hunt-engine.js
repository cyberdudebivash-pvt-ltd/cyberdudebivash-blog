'use strict';
/**
 * SENTINEL APEX — Threat Hunting Workspace Engine
 *
 * Composes the already-certified canonical detection store
 * (detection-rules.js / detection-intelligence.js), the customer
 * defense-compatibility engine (defense-profile-store.js /
 * defense-compatibility.js), the deployment state machine
 * (deployment-store.js), and the CVE/Campaign/Actor/IOC dossier
 * accessors (intel.js) with hunt-store.js / detection-feedback-store.js
 * — never re-implements any of them. See
 * docs/audits/SENTINEL-APEX-HUNTING-WORKSPACE-CAPABILITY-INVENTORY-V1.md
 * for why none of the existing internal SOC Workbench modules were reused
 * as the storage layer instead.
 *
 * No autonomous investigation authority lives here: hypothesis generation
 * is a deterministic template, never an unverified claim of fact, and this
 * module never determines a finding's classification, sets a disposition,
 * or closes/reopens a hunt without an explicit, human-attributed call
 * (createdBy / actor is always required, never defaulted to "system").
 */

const huntStore = require('./hunt-store');
const feedbackStore = require('./detection-feedback-store');
const detectionRules = require('./detection-rules');
const detectionIntelligence = require('./detection-intelligence');
const defenseProfileStore = require('./defense-profile-store');
const defenseCompatibility = require('./defense-compatibility');
const deploymentStore = require('./deployment-store');
const intel = require('./intel');

const LIVE_DEPLOYMENT_STATES = new Set(['DEPLOYED', 'VERIFYING', 'VERIFIED', 'DRIFTED', 'UPDATE_REQUIRED']);

/** Resolves a detection_id into the same canonical, release-gated object
 *  deployment-engine.js already relies on — never a second computation of
 *  RELEASED/BLOCKED/REVIEW_REQUIRED. attackContextTechniques, when supplied
 *  fresh from a dossier, lets classifyAttackEvidence() grade the match the
 *  same way the deployment engine does; when unavailable (e.g. re-checking
 *  readiness later from stored refs alone, with no evidence-source metadata
 *  persisted) it safely defaults to an honest 'UNKNOWN' evidence grade
 *  rather than fabricating one. */
function resolveCanonicalDetection(detectionId, attackContextTechniques) {
  const storedRule = detectionRules.getRule(detectionId);
  if (!storedRule) return null;
  const matched = (attackContextTechniques || []).find((t) => t && t.id === storedRule.technique_id);
  const attackEvidenceState = detectionIntelligence.classifyAttackEvidence(matched);
  return detectionIntelligence.toCanonicalDetectionObject(storedRule, { attackEvidenceState });
}

/** Deterministic hypothesis draft — Threat -> ATT&CK -> Detection ->
 *  Telemetry, per the mandate. Always hedged ("may be present", "testable
 *  hypothesis"), never framed as an established fact. An LLM may later
 *  improve wording only, never add unsupported claims — no such wiring
 *  exists in this tranche (deliberately out of scope, see the
 *  certification doc). */
function generateHypothesis({ threatLabel, techniqueIds, detectionName }) {
  const techPart = (techniqueIds || []).filter(Boolean).length
    ? (techniqueIds || []).filter(Boolean).join(', ')
    : 'an undetermined technique';
  const detectionPart = detectionName ? ` Candidate detection logic modeled on "${detectionName}" may help surface it.` : '';
  return (
    `Activity consistent with ${threatLabel} may be present in this environment, ` +
    `evidenced by behavior mapped to ATT&CK technique(s) ${techPart}.${detectionPart} ` +
    `This is a testable hypothesis to investigate against available telemetry, not a confirmed finding.`
  );
}

function resolveThreatContext(entityType, entityId) {
  if (!entityType || !entityId) return { found: false, label: null, techniques: [] };
  if (entityType === 'cve' || entityType === 'campaign') {
    const { found, dossier } = intel.getDossierAPI(entityType, entityId, 'enterprise');
    if (!found || !dossier) return { found: false, label: entityId, techniques: [] };
    return { found: true, label: dossier.title || dossier.name || entityId, techniques: dossier.attack_context?.techniques || [] };
  }
  if (entityType === 'threat_actor') {
    const { found, actor } = intel.getActorDetailAPI(entityId);
    return { found: !!found, label: (found && actor && actor.name) || entityId, techniques: [] };
  }
  if (entityType === 'ioc') {
    const { found, ioc } = intel.getIocDetailAPI(entityId);
    return { found: !!found, label: (found && ioc && ioc.name) || entityId, techniques: [] };
  }
  return { found: false, label: entityId, techniques: [] };
}

async function createHuntFromContext(ownerId, { title, entityType, entityId, detectionId, priority, createdBy }) {
  const threatContext = resolveThreatContext(entityType, entityId);
  const canonicalDetection = detectionId ? resolveCanonicalDetection(detectionId, threatContext.techniques) : null;
  const techniqueIds = canonicalDetection
    ? canonicalDetection.attack.map((a) => a.id).filter(Boolean)
    : threatContext.techniques.map((t) => t.id).filter(Boolean);

  const hypothesis = generateHypothesis({
    threatLabel: threatContext.label || entityId || 'the supplied context',
    techniqueIds,
    detectionName: canonicalDetection ? canonicalDetection.name : null,
  });

  const hypothesisSource = detectionId ? 'DETECTION_DERIVED' : threatContext.found ? 'INTELLIGENCE_DERIVED' : 'ANALYST_CREATED';

  const row = await huntStore.createHunt(ownerId, {
    title: title || `Hunt: ${threatContext.label || entityId || 'untitled'}`,
    hypothesis,
    hypothesisSource,
    priority,
    createdBy,
  });
  const huntId = row.hunt_id;

  if (entityType && entityId && huntStore.REF_KINDS.includes(entityType)) {
    await huntStore.addRef(huntId, entityType, entityId);
  }
  for (const techId of techniqueIds) await huntStore.addRef(huntId, 'attack_technique', techId);
  if (detectionId) await huntStore.addRef(huntId, 'detection', detectionId);

  await huntStore.appendTimeline(
    huntId,
    'HUNT_CREATED',
    `Hunt created from ${entityType || 'analyst input'}${entityId ? ' ' + entityId : ''}.`,
    createdBy
  );

  return huntStore.toPublicHunt(row);
}

const PRIMARY_ENTITY_REF_KINDS = ['cve', 'campaign', 'threat_actor', 'ioc'];

/** A hunt's "primary" threat entity — the CVE/Campaign/Actor/IOC it was
 *  opened against, if any. Re-deriving evidence-graded ATT&CK attribution
 *  later (readiness/maturity checks, possibly long after hunt creation)
 *  requires fetching the SAME live dossier fresh again, exactly like
 *  deployment-engine.js#recomputeDeployability() always re-fetches
 *  getDossierAPI() by (entity_type, entity_id) rather than trusting a
 *  cached techniques list — RELEASED/BLOCKED is contextual to a specific
 *  entity's evidence, not a bare property of the detection rule alone. */
function derivePrimaryEntityRef(refs) {
  const ref = (refs || []).find((r) => PRIMARY_ENTITY_REF_KINDS.includes(r.ref_kind));
  return ref ? { entityType: ref.ref_kind, entityId: ref.ref_id } : null;
}

/** The real, evidence-graded ATT&CK techniques for a hunt's own primary
 *  entity, freshly re-fetched every call (never cached/persisted) — the
 *  single shared derivation computeHuntReadiness and the add-query API
 *  handler both use, so a hunt's linked CVE/campaign context is honored
 *  consistently everywhere a detection is re-evaluated for this hunt. */
async function resolveHuntAttackContext(huntId) {
  const refs = await huntStore.listRefs(huntId);
  const entityRef = derivePrimaryEntityRef(refs);
  return entityRef ? resolveThreatContext(entityRef.entityType, entityRef.entityId).techniques : [];
}

/** Hunt-level telemetry readiness — computed fresh on every call from the
 *  hunt's linked detections against the owner's Defense Profile, never
 *  persisted (matching this platform's "coverage is never stored"
 *  discipline — see the Source-of-Truth Matrix). */
async function computeHuntReadiness(ownerId, huntId) {
  const refs = await huntStore.listRefs(huntId);
  const detectionIds = refs.filter((r) => r.ref_kind === 'detection').map((r) => r.ref_id);
  if (!detectionIds.length) return { readiness: 'UNKNOWN', per_detection: [] };

  const attackContextTechniques = await resolveHuntAttackContext(huntId);

  const { profile } = await defenseProfileStore.getProfile(ownerId);
  const perDetection = [];
  for (const detectionId of detectionIds) {
    const canonical = resolveCanonicalDetection(detectionId, attackContextTechniques);
    if (!canonical || canonical.status !== 'RELEASED') {
      perDetection.push({ detection_id: detectionId, status: 'NO_VALIDATED_DETECTION' });
      continue;
    }
    const result = defenseCompatibility.evaluateDetectionCompatibility(canonical, profile);
    perDetection.push({ detection_id: detectionId, ...result });
  }

  const statuses = perDetection.map((d) => d.status);
  let readiness = 'UNKNOWN';
  if (statuses.length && statuses.every((s) => s === 'READY')) readiness = 'READY';
  else if (statuses.some((s) => s === 'READY' || s === 'PARTIALLY_READY')) readiness = 'PARTIALLY_READY';
  else if (statuses.some((s) => s === 'TELEMETRY_GAP')) readiness = 'TELEMETRY_GAP';
  else if (statuses.length && statuses.every((s) => s === 'UNSUPPORTED_PLATFORM' || s === 'NO_VALIDATED_DETECTION')) readiness = 'UNSUPPORTED';

  return { readiness, per_detection: perDetection };
}

/** Surfaces each linked detection's REAL current lifecycle status
 *  (RELEASED/DEPRECATED/REVOKED/...) and any deployment(s) this owner has
 *  for it, including drift — never re-derives either, only reads them.
 *  A REVOKED detection or a DRIFTED deployment is surfaced as-is, exactly
 *  as the mandate requires: never hidden, never silently reconciled. */
async function resolveDeploymentLinkage(ownerId, huntId) {
  const refs = await huntStore.listRefs(huntId);
  const detectionIds = refs.filter((r) => r.ref_kind === 'detection').map((r) => r.ref_id);
  if (!detectionIds.length) return [];

  const deployments = await deploymentStore.listDeployments(ownerId);
  return detectionIds.map((detectionId) => {
    const canonical = resolveCanonicalDetection(detectionId, []);
    const matches = deployments.filter((d) => d.detection_id === detectionId);
    return {
      detection_id: detectionId,
      detection_status: canonical ? canonical.status : 'UNKNOWN',
      deployments: matches.map((d) => ({ deployment_id: d.deployment_id, state: d.state, connector_id: d.connector_id })),
    };
  });
}

/** Coverage maturity extension — additive on top of the existing
 *  Compatibility states, never replacing them, never claiming "guaranteed
 *  coverage": AVAILABLE -> ENVIRONMENT_COMPATIBLE -> DEPLOYED ->
 *  OBSERVED_SIGNAL -> ANALYST_VALIDATED. Computed fresh every call, same
 *  discipline as computeHuntReadiness above.
 *
 *  entityRef ({entityType, entityId}), when supplied, lets RELEASED/BLOCKED
 *  be evaluated with real, freshly-fetched evidence attribution for that
 *  specific CVE/campaign/actor/IOC (same contextual pattern deployment-
 *  engine.js and defense-compatibility.js already use — see
 *  derivePrimaryEntityRef's header). Without it, evidence defaults to
 *  UNKNOWN, which is an honest floor, not a wrong answer: a detection
 *  whose release genuinely depends on entity-specific attribution will
 *  correctly show as not yet AVAILABLE until evaluated in that entity's
 *  context, rather than silently guessing. */
async function computeDetectionMaturity(ownerId, detectionId, entityRef) {
  const attackContextTechniques = entityRef ? resolveThreatContext(entityRef.entityType, entityRef.entityId).techniques : [];
  const canonical = resolveCanonicalDetection(detectionId, attackContextTechniques);
  if (!canonical || canonical.status !== 'RELEASED') return 'NOT_AVAILABLE';
  let maturity = 'AVAILABLE';

  const { profile } = await defenseProfileStore.getProfile(ownerId);
  const compat = defenseCompatibility.evaluateDetectionCompatibility(canonical, profile);
  if (compat.status === 'READY' || compat.status === 'PARTIALLY_READY') maturity = 'ENVIRONMENT_COMPATIBLE';

  const deployments = await deploymentStore.listDeployments(ownerId);
  const hasLiveDeployment = deployments.some((d) => d.detection_id === detectionId && LIVE_DEPLOYMENT_STATES.has(d.state));
  if (hasLiveDeployment) maturity = 'DEPLOYED';

  const referencingHuntIds = await huntStore.listHuntIdsReferencing('detection', detectionId);
  let ownedHuntIds = [];
  for (const huntId of referencingHuntIds) {
    const row = await huntStore.getHuntRaw(ownerId, huntId); // naturally tenant-scoped: only matches this owner's own hunts
    if (row) ownedHuntIds.push(huntId);
  }

  if (ownedHuntIds.length) {
    for (const huntId of ownedHuntIds) {
      const observations = await huntStore.listObservations(huntId);
      if (observations.length) { maturity = 'OBSERVED_SIGNAL'; break; }
    }
  }

  let analystValidated = false;
  for (const huntId of ownedHuntIds) {
    const findings = await huntStore.listFindings(huntId);
    if (findings.some((f) => f.classification === 'CONFIRMED_MALICIOUS')) { analystValidated = true; break; }
  }
  if (!analystValidated) {
    const feedback = await feedbackStore.listFeedbackForOwner(ownerId, { detectionId });
    if (feedback.some((f) => f.classification === 'TRUE_POSITIVE')) analystValidated = true;
  }
  if (analystValidated) maturity = 'ANALYST_VALIDATED';

  return maturity;
}

/** CONFIRMED_MALICIOUS is a strong claim — the mandate requires it be
 *  backed by linked evidence, never asserted bare. */
async function addFindingWithValidation(ownerId, huntId, { classification, confidence, summary, evidenceRefs, createdBy }) {
  const { hunt, error } = await huntStore.getHunt(ownerId, huntId);
  if (error) return { error };
  if (classification === 'CONFIRMED_MALICIOUS' && (!evidenceRefs || !evidenceRefs.length)) {
    return { error: 'EVIDENCE_REQUIRED', message: 'CONFIRMED_MALICIOUS findings require at least one linked evidence_id.' };
  }
  const findingId = await huntStore.addFinding(huntId, { classification, confidence, summary, evidenceRefs, createdBy });
  await huntStore.appendTimeline(huntId, 'FINDING_ADDED', `Finding recorded: ${classification} (${confidence}).`, createdBy);
  return { finding_id: findingId, hunt };
}

/** Disposition is the one terminal act that closes a hunt. CONFIRMED_THREAT
 *  requires the hunt already carry at least one finding or evidence link —
 *  a strong outcome may never rest on the disposition summary text alone.
 *  Disposition fields are a single slot, not a version history (mirrors
 *  the deployment engine's own disclosed one-level-undo simplification) —
 *  the full history of every disposition-set and reopen event lives in
 *  hunt_timeline instead, which is append-only and never overwritten. */
async function setDisposition(ownerId, huntId, { disposition, summary, actor }) {
  const { hunt, error } = await huntStore.getHunt(ownerId, huntId);
  if (error) return { error };
  if (!summary || !actor) return { error: 'DISPOSITION_INCOMPLETE', message: 'A disposition requires both a summary and an attributed analyst identity.' };

  if (disposition === 'CONFIRMED_THREAT') {
    const [findings, evidence] = await Promise.all([huntStore.listFindings(huntId), huntStore.listEvidence(huntId)]);
    if (!findings.length && !evidence.length) {
      return { error: 'EVIDENCE_REQUIRED', message: 'CONFIRMED_THREAT requires at least one linked finding or evidence record.' };
    }
  }

  const nowIso = new Date().toISOString();
  await huntStore.updateHunt(huntId, {
    status: 'CLOSED',
    disposition,
    disposition_summary: summary,
    disposition_by: actor,
    disposition_at: nowIso,
    closed_at: nowIso,
  });
  await huntStore.appendTimeline(huntId, 'DISPOSITION_SET', `Hunt closed with disposition ${disposition}: ${summary}`, actor);
  return huntStore.getHunt(ownerId, huntId);
}

async function reopenHunt(ownerId, huntId, { reason, actor }) {
  const { hunt, error } = await huntStore.getHunt(ownerId, huntId);
  if (error) return { error };
  if (hunt.status !== 'CLOSED') return { error: 'NOT_CLOSED', message: 'Only a closed hunt can be reopened.' };
  if (!actor) return { error: 'ACTOR_REQUIRED', message: 'Reopening a hunt requires an attributed analyst identity.' };

  await huntStore.updateHunt(huntId, { status: 'ACTIVE', closed_at: null });
  await huntStore.appendTimeline(huntId, 'HUNT_REOPENED', reason ? `Hunt reopened: ${reason}` : 'Hunt reopened.', actor);
  return huntStore.getHunt(ownerId, huntId);
}

/** Detection feedback may optionally reference a hunt or a deployment —
 *  both are independently ownership-checked here (never trusted from the
 *  request body) before the reference is persisted, since detection_
 *  feedback.hunt_id/deployment_id are the one place a caller could
 *  otherwise attach feedback to another tenant's hunt or deployment. */
async function submitDetectionFeedback(ownerId, { detectionId, huntId, deploymentId, classification, summary, createdBy }) {
  const storedRule = detectionRules.getRule(detectionId);
  if (!storedRule) return { error: 'NOT_FOUND', message: 'No detection found.' };
  const detectionVersion = storedRule.governance?.version || '1.0.0';

  if (huntId) {
    const { error } = await huntStore.getHunt(ownerId, huntId);
    if (error) return { error: 'NOT_FOUND', message: 'No hunt found.' };
  }
  if (deploymentId) {
    const { error } = await deploymentStore.getDeployment(ownerId, deploymentId);
    if (error) return { error: 'NOT_FOUND', message: 'No deployment found.' };
  }

  const feedbackId = await feedbackStore.submitFeedback(ownerId, {
    detectionId, detectionVersion, huntId, deploymentId, classification, summary, createdBy,
  });
  if (huntId) {
    await huntStore.appendTimeline(huntId, 'FEEDBACK_SUBMITTED', `Detection feedback submitted: ${classification}.`, createdBy);
  }
  return { feedback_id: feedbackId, detection_version: detectionVersion };
}

module.exports = {
  resolveCanonicalDetection,
  generateHypothesis,
  resolveThreatContext,
  derivePrimaryEntityRef,
  resolveHuntAttackContext,
  createHuntFromContext,
  computeHuntReadiness,
  resolveDeploymentLinkage,
  computeDetectionMaturity,
  addFindingWithValidation,
  setDisposition,
  reopenHunt,
  submitDetectionFeedback,
};
