'use strict';
/**
 * SENTINEL APEX — Controlled SIEM Deployment Engine v1
 *
 * Orchestrates the full lifecycle mandated by the Controlled SIEM
 * Deployment Gateway task: GENERATE -> RELEASE GATE -> COMPATIBILITY ->
 * PREVIEW -> EXPLICIT APPROVAL -> DEPLOY -> READ-BACK -> VERIFY, plus
 * update/rollback/disable. This file is pure orchestration: it calls
 * already-canonical engines (detection-rules.js, detection-intelligence.js,
 * defense-compatibility.js, defense-profile-store.js via `getDossierAPI`)
 * for every fact about a detection or a customer's environment, and calls
 * connector-registry.js for every fact about a remote SIEM. It never
 * re-derives detection lifecycle or compatibility logic itself.
 *
 * ── Approval-hash design (Sections 14/15/95) ──────────────────────────
 * This design never accepts a client-supplied deployment PAYLOAD at all —
 * `intent.query` always comes from the server's own canonical detection
 * store (or, for a rollback, from this platform's own previously-recorded
 * snapshot — see below), never from a request body. The "approval hash"
 * therefore protects against a different, but equivalent, attack: the
 * TRUTH the server derives the intent from changing between approve and
 * execute (a new detection version released, a connector's target_config
 * edited, or someone directly enabling a checkbox that was left off at
 * approval time). desired_hash is always *recomputed* fresh at approve
 * time and again at execute time from current authoritative state; a
 * mismatch between the approved hash and the execute-time hash blocks
 * execution exactly as Section 95 requires — it is just never possible
 * for a client to smuggle a *different* query into an already-approved
 * deployment_id, because the client never controls query content in the
 * first place.
 *
 * ── Rollback design (Sections 51-55, 101) ─────────────────────────────
 * detection-rules.js#storeRule() overwrites a rule's format content in
 * place on every new version — history[] records only version/timestamp/
 * change metadata, never a content snapshot (verified by direct reading
 * of that file before this was designed). This platform's OWN deployment
 * record is therefore the only place a previously-deployed version's
 * exact content survives. `detection_deployments.deployed_intent_snapshot`
 * always holds what is (or was about to become) live; on a successful
 * UPDATE it is rotated into `previous_intent_snapshot` first (Section 53:
 * "restore prior version" — ONE level of undo, matching the mandate's own
 * "Deploy v1 -> Update v2 -> Rollback to v1" test scenario exactly, not an
 * arbitrary version stack). Rollback therefore does not re-run the full
 * release/compatibility gate against the historical version (the
 * canonical store cannot reproduce that version's original content to
 * re-validate) — it does check the detection has not since been REVOKED
 * (Section 114) before allowing old content back onto a customer's SIEM.
 * This limitation is disclosed, not silently assumed away.
 */

const crypto = require('crypto');
const detectionRules = require('./detection-rules');
const detectionIntelligence = require('./detection-intelligence');
const defenseCompatibility = require('./defense-compatibility');
const defenseProfileStore = require('./defense-profile-store');
const { getDossierAPI } = require('./intel');
const connectorStore = require('./siem-connector-store');
const deploymentStore = require('./deployment-store');
const taxonomy = require('./siem-connector-taxonomy');
const { getConnectorModule } = require('./connectors/connector-registry');
const { ConnectorError } = require('./connectors/connector-contract');

function sha256(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

/** Stable regardless of object key order — an explicit, fixed field list,
 *  not a generic canonical-JSON algorithm (Section 46/47: remote
 *  normalization is the CONNECTOR's job via toCanonicalObserved(); this
 *  function only needs to hash whatever shape it's given consistently). */
function canonicalizeForHash({ query, severity, enabled, techniques }) {
  return JSON.stringify({
    query: String(query || '').trim(),
    severity: String(severity || ''),
    enabled: !!enabled,
    techniques: [...(techniques || [])].map(String).sort(),
  });
}

/* ───────────────────────── eligibility recheck ───────────────────────── */

/**
 * Recomputes, from scratch, whether `detectionId` (in the context of
 * `entityType`/`entityId`) is currently deployable: RELEASED (not
 * REVIEW_REQUIRED/BLOCKED/DEPRECATED/REVOKED) AND compatibility READY
 * against the caller's Defense Profile. Called at preview, at approve,
 * and again immediately before execute (Sections 36/37/81/82) — never
 * cached across calls, since the whole point is to catch a change that
 * happened in between.
 */
async function recomputeDeployability({ detectionId, entityType, entityId, ownerId, tier }) {
  const rawRule = detectionRules.getRule(detectionId);
  if (!rawRule) return { eligible: false, blockReason: 'DETECTION_NOT_FOUND' };

  const { found, dossier, unsupported } = getDossierAPI(entityType, entityId, tier);
  if (unsupported) return { eligible: false, blockReason: 'UNSUPPORTED_ENTITY_TYPE' };
  if (!found) return { eligible: false, blockReason: 'ENTITY_NOT_FOUND' };

  const techEntry = (dossier.attack_context?.techniques || []).find(t => t.id === rawRule.technique_id);
  const evidenceState = detectionIntelligence.classifyAttackEvidence(techEntry);
  const canonical = detectionIntelligence.toCanonicalDetectionObject(rawRule, { attackEvidenceState: evidenceState });

  if (canonical.status !== 'RELEASED') {
    return { eligible: false, blockReason: 'DETECTION_NOT_RELEASED', canonical, rawRule };
  }

  const { profile } = await defenseProfileStore.getProfile(ownerId);
  const compat = defenseCompatibility.evaluateDetectionCompatibility(canonical, profile);
  if (compat.status !== 'READY') {
    return { eligible: false, blockReason: 'COMPATIBILITY_NOT_READY', canonical, compat, rawRule };
  }

  return { eligible: true, canonical, compat, rawRule };
}

function buildLiveIntent({ deploymentRow, rawRule, canonical, compat, enabled }) {
  return {
    remote_resource_name: deploymentRow.remote_resource_name,
    detection_id: rawRule.id,
    detection_version: canonical.version,
    title: rawRule.title,
    description: rawRule.description || '',
    technique_id: rawRule.technique_id,
    severity_raw: rawRule.level,
    format: compat.format_used,
    query: canonical.formats[compat.format_used].content,
    enabled: !!enabled,
  };
}

async function connectorAndModuleFor(ownerId, connectorId) {
  const safeResult = await connectorStore.getConnectorSafe(ownerId, connectorId);
  if (safeResult.error) return { error: safeResult.error, message: safeResult.message };
  if (safeResult.connector.disabled) return { error: 'CONNECTOR_DISABLED', message: 'This connector has been disconnected.' };
  const platformDef = taxonomy.KNOWN_PLATFORMS[safeResult.connector.platform];
  const module_ = getConnectorModule(safeResult.connector.platform);
  if (!platformDef || !module_) return { error: 'PLATFORM_NOT_IMPLEMENTED', message: 'This connector platform is not implemented.' };
  return { connector: safeResult.connector, module: module_, capabilities: platformDef.capabilities };
}

/* ───────────────────────── preview ───────────────────────── */

async function previewDeployment({ ownerId, tier, connectorId, detectionId, entityType, entityId, enabledRequested = false }) {
  const cm = await connectorAndModuleFor(ownerId, connectorId);
  if (cm.error) return { blocked: true, reason: cm.error, message: cm.message };
  if (!cm.capabilities.deploy_supported) return { blocked: true, reason: 'PLATFORM_NOT_IMPLEMENTED', message: 'This connector platform does not support deployment.' };

  const eligibility = await recomputeDeployability({ detectionId, entityType, entityId, ownerId, tier });
  if (!eligibility.eligible) {
    return { blocked: true, reason: eligibility.blockReason, canonical: eligibility.canonical || null, compat: eligibility.compat || null };
  }
  const { canonical, compat, rawRule } = eligibility;

  const existing = await deploymentStore.findActiveDeployment(ownerId, connectorId, detectionId, entityType, entityId);
  const row = existing || await deploymentStore.createDraftDeployment(ownerId, {
    connectorId, detectionId, detectionVersion: canonical.version, entityType, entityId, format: compat.format_used,
  });

  const pendingAction = row.deployed_intent_snapshot ? 'UPDATE' : 'DEPLOY';
  const intent = buildLiveIntent({ deploymentRow: row, rawRule, canonical, compat, enabled: enabledRequested });
  const desired = cm.module.toCanonicalObserved(intent);
  const desiredHash = sha256(canonicalizeForHash(desired));

  await deploymentStore.updateDeployment(row.deployment_id, {
    state: 'PREVIEWED',
    detection_version: canonical.version,
    format: compat.format_used,
    desired_hash: desiredHash,
    enabled_desired: enabledRequested ? 1 : 0,
    pending_action: pendingAction,
  });

  // Read-only remote lookup so the preview can honestly show CREATE vs
  // UPDATE and a real diff — never mutates anything (Section 34/85).
  let existingRemote = { found: false, observed: null };
  const credResult = await connectorStore.getConnectorWithCredential(ownerId, connectorId);
  if (!credResult.error) {
    try {
      existingRemote = await cm.module.readBack(credResult.connector, row.remote_resource_name);
    } catch (_) {
      // A failed read-only lookup must not block preview from rendering —
      // the customer still sees the intended change; connectivity issues
      // surface clearly at "Test Connection" and at execute time instead.
    }
  }

  deploymentStore.appendDeploymentAudit('PREVIEW_CREATED', { owner: ownerId, deploymentId: row.deployment_id, detectionId, connectorId }).catch(() => {});

  return {
    blocked: false,
    deployment_id: row.deployment_id,
    action: existingRemote.found ? 'UPDATE' : 'CREATE',
    target: { platform: cm.connector.platform, name: cm.connector.name, target_config: cm.connector.target_config },
    resource_name: row.remote_resource_name,
    detection_id: detectionId,
    detection_version: canonical.version,
    attack: canonical.attack,
    severity: rawRule.level,
    format: compat.format_used,
    query: intent.query,
    enabled: enabledRequested,
    telemetry_requirements: canonical.telemetry_requirements,
    validation_status: canonical.status,
    compatibility: compat,
    diff: existingRemote.found ? { current: existingRemote.observed, proposed: desired } : null,
    rollback_available: !!row.previous_intent_snapshot,
  };
}

/* ───────────────────────── approval (server-side) ───────────────────────── */

async function approveDeployment({ ownerId, tier, deploymentId, enabledRequested }) {
  const row = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);
  if (!row) return { blocked: true, reason: 'NOT_FOUND' };
  if (!['PREVIEWED', 'APPROVAL_REQUIRED', 'FAILED_RETRYABLE'].includes(row.state)) {
    return { blocked: true, reason: 'INVALID_STATE_FOR_APPROVAL', state: row.state };
  }

  const cm = await connectorAndModuleFor(ownerId, row.connector_id);
  if (cm.error) return { blocked: true, reason: cm.error, message: cm.message };

  const enabled = enabledRequested === undefined ? !!row.enabled_desired : !!enabledRequested;
  let desiredHash;
  let canonicalVersion = row.detection_version;

  if (row.pending_action === 'ROLLBACK') {
    if (!row.previous_intent_snapshot) return { blocked: true, reason: 'NO_ROLLBACK_SNAPSHOT' };
    const rawRule = detectionRules.getRule(row.detection_id);
    if (rawRule && rawRule.governance && rawRule.governance.status === 'REVOKED') {
      return { blocked: true, reason: 'DETECTION_REVOKED' };
    }
    const snapshot = JSON.parse(row.previous_intent_snapshot);
    canonicalVersion = snapshot.detection_version;
    desiredHash = sha256(canonicalizeForHash(cm.module.toCanonicalObserved(snapshot)));
  } else {
    const eligibility = await recomputeDeployability({ detectionId: row.detection_id, entityType: row.entity_type, entityId: row.entity_id, ownerId, tier });
    if (!eligibility.eligible) {
      await deploymentStore.updateDeployment(deploymentId, { state: 'APPROVAL_REQUIRED' });
      return { blocked: true, reason: eligibility.blockReason };
    }
    const intent = buildLiveIntent({ deploymentRow: row, rawRule: eligibility.rawRule, canonical: eligibility.canonical, compat: eligibility.compat, enabled });
    canonicalVersion = eligibility.canonical.version;
    desiredHash = sha256(canonicalizeForHash(cm.module.toCanonicalObserved(intent)));
  }

  const targetConfigHash = sha256(JSON.stringify(cm.connector.target_config));
  const nowIso = new Date().toISOString();

  await deploymentStore.updateDeployment(deploymentId, {
    state: 'APPROVED',
    detection_version: canonicalVersion,
    desired_hash: desiredHash,
    enabled_desired: enabled ? 1 : 0,
    approved_at: nowIso,
  });
  await deploymentStore.recordApproval(deploymentId, ownerId, {
    detectionVersion: canonicalVersion, connectorId: row.connector_id, targetConfigHash, approvedHash: desiredHash, enabledRequested: enabled,
  });
  deploymentStore.appendDeploymentAudit('DEPLOYMENT_APPROVED', { owner: ownerId, deploymentId, action: row.pending_action }).catch(() => {});

  const updated = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);
  return { blocked: false, deployment: deploymentStore.toPublicDeployment(updated) };
}

/* ───────────────────────── execute (idempotent, reconciling) ───────────────────────── */

async function executeDeployment({ ownerId, tier, deploymentId }) {
  const preClaim = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);
  if (!preClaim) return { blocked: true, reason: 'NOT_FOUND' };

  // Atomic claim (Section 98): a plain SELECT-then-branch would race under
  // real concurrency — two simultaneous execute calls could both observe
  // state === 'APPROVED' before either writes 'DEPLOYING'. Only the caller
  // that actually wins this UPDATE...WHERE state IN (...) proceeds to
  // touch the connector; a losing concurrent call returns immediately
  // without making any remote call at all, guaranteeing one semantic
  // remote deployment regardless of how many requests race.
  const { claimed } = await deploymentStore.claimForExecution(deploymentId);
  if (!claimed) {
    return { blocked: true, reason: 'INVALID_STATE_FOR_EXECUTE', state: preClaim.state };
  }
  const row = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);

  const approval = await deploymentStore.getLatestApproval(deploymentId);
  if (!approval) return { blocked: true, reason: 'NO_APPROVAL_ON_RECORD' };

  const cm = await connectorAndModuleFor(ownerId, row.connector_id);
  if (cm.error) return { blocked: true, reason: cm.error, message: cm.message };

  // ── Immediate pre-flight recheck (Sections 81-83, 96-97) ──
  let intent;
  if (row.pending_action === 'ROLLBACK') {
    if (!row.previous_intent_snapshot) return { blocked: true, reason: 'NO_ROLLBACK_SNAPSHOT' };
    const rawRule = detectionRules.getRule(row.detection_id);
    if (rawRule && rawRule.governance && rawRule.governance.status === 'REVOKED') {
      return { blocked: true, reason: 'DETECTION_REVOKED' };
    }
    intent = JSON.parse(row.previous_intent_snapshot);
  } else {
    const eligibility = await recomputeDeployability({ detectionId: row.detection_id, entityType: row.entity_type, entityId: row.entity_id, ownerId, tier });
    if (!eligibility.eligible) {
      await deploymentStore.updateDeployment(deploymentId, { state: 'APPROVAL_REQUIRED' });
      deploymentStore.appendDeploymentAudit('DEPLOYMENT_FAILED', { owner: ownerId, deploymentId, reason: eligibility.blockReason }).catch(() => {});
      return { blocked: true, reason: eligibility.blockReason };
    }
    intent = buildLiveIntent({ deploymentRow: row, rawRule: eligibility.rawRule, canonical: eligibility.canonical, compat: eligibility.compat, enabled: !!row.enabled_desired });
  }

  // ── Approval-hash + target-config-hash verification (Sections 14/15/95) ──
  const currentHash = sha256(canonicalizeForHash(cm.module.toCanonicalObserved(intent)));
  const currentTargetHash = sha256(JSON.stringify(cm.connector.target_config));
  if (currentHash !== approval.approved_hash) {
    await deploymentStore.updateDeployment(deploymentId, { state: 'APPROVAL_REQUIRED' });
    deploymentStore.appendDeploymentAudit('DEPLOYMENT_FAILED', { owner: ownerId, deploymentId, reason: 'APPROVAL_HASH_MISMATCH' }).catch(() => {});
    return { blocked: true, reason: 'APPROVAL_HASH_MISMATCH' };
  }
  if (currentTargetHash !== approval.target_config_hash) {
    await deploymentStore.updateDeployment(deploymentId, { state: 'APPROVAL_REQUIRED' });
    deploymentStore.appendDeploymentAudit('DEPLOYMENT_FAILED', { owner: ownerId, deploymentId, reason: 'TARGET_CONFIG_CHANGED' }).catch(() => {});
    return { blocked: true, reason: 'TARGET_CONFIG_CHANGED' };
  }

  // ── Dispatch (idempotent upsert, with ambiguous-failure reconciliation) ──
  // Note: state is already 'DEPLOYING', set atomically by the claim above.
  const credResult = await connectorStore.getConnectorWithCredential(ownerId, row.connector_id);
  if (credResult.error) return { blocked: true, reason: credResult.error, message: credResult.message };

  const startedAt = new Date().toISOString();
  const attemptAction = row.pending_action === 'UPDATE' ? 'UPDATE' : (row.pending_action === 'ROLLBACK' ? 'ROLLBACK' : 'DEPLOY');
  let deployResult;
  let attemptAlreadyRecorded = false;
  try {
    deployResult = await cm.module.deploy(credResult.connector, intent);
  } catch (e) {
    // Ambiguous-create reconciliation (Section 43/99): before declaring
    // failure, check whether the remote mutation actually landed anyway
    // (e.g. the response was lost after a real create/update succeeded).
    let reconciled = null;
    try {
      reconciled = await cm.module.readBack(credResult.connector, row.remote_resource_name);
    } catch (_) { /* reconciliation attempt itself failed -- fall through to the original error */ }

    if (reconciled && reconciled.found) {
      const desiredCanonical = cm.module.toCanonicalObserved(intent);
      const matches = sha256(canonicalizeForHash(desiredCanonical)) === sha256(canonicalizeForHash(reconciled.observed));
      if (matches) {
        deployResult = { remote_resource_id: reconciled.raw?.id || row.remote_resource_name, remote_etag: reconciled.etag, raw: reconciled.raw };
        await deploymentStore.recordAttempt(deploymentId, { action: attemptAction, result: 'SUCCESS', errorCode: 'RECONCILED_AFTER_AMBIGUOUS_ERROR', startedAt, finishedAt: new Date().toISOString() });
        attemptAlreadyRecorded = true;
      }
    }
    if (!deployResult) {
      const isConnErr = e instanceof ConnectorError;
      const retryable = isConnErr ? e.retryable : true;
      await deploymentStore.recordAttempt(deploymentId, {
        action: attemptAction,
        result: retryable ? 'FAILED_RETRYABLE' : 'FAILED_TERMINAL',
        errorCode: isConnErr ? e.code : 'UNKNOWN_ERROR', httpStatus: isConnErr ? e.httpStatus : null,
        startedAt, finishedAt: new Date().toISOString(),
      });
      await deploymentStore.updateDeployment(deploymentId, {
        state: retryable ? 'FAILED_RETRYABLE' : 'FAILED_TERMINAL',
        last_error: JSON.stringify({ code: isConnErr ? e.code : 'UNKNOWN_ERROR', message: e.message }),
      });
      deploymentStore.appendDeploymentAudit('DEPLOYMENT_FAILED', { owner: ownerId, deploymentId, code: isConnErr ? e.code : 'UNKNOWN_ERROR' }).catch(() => {});
      return { blocked: false, deployment: deploymentStore.toPublicDeployment(await deploymentStore.getDeploymentRaw(ownerId, deploymentId)) };
    }
  }
  if (!attemptAlreadyRecorded) {
    await deploymentStore.recordAttempt(deploymentId, { action: attemptAction, result: 'SUCCESS', startedAt, finishedAt: new Date().toISOString() });
  }

  // Persisted (not merely transient) so a process interruption between
  // here and the read-back below leaves the row honestly at DEPLOYED —
  // "remote resource created, not yet independently verified" — rather
  // than stuck at APPROVED/DEPLOYING or silently advanced to VERIFIED
  // without ever having been read back.
  await deploymentStore.updateDeployment(deploymentId, {
    state: 'DEPLOYED',
    remote_resource_id: deployResult.remote_resource_id,
    remote_etag: deployResult.remote_etag,
    deployed_at: new Date().toISOString(),
  });
  await deploymentStore.updateDeployment(deploymentId, { state: 'VERIFYING' });

  return verifyAfterDeploy({ ownerId, deploymentId, connector: credResult.connector, module: cm.module, intent, pendingAction: row.pending_action });
}

async function verifyAfterDeploy({ ownerId, deploymentId, connector, module: connectorModule, intent, pendingAction }) {
  const row = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);
  const startedAt = new Date().toISOString();
  let readBackResult;
  try {
    readBackResult = await connectorModule.readBack(connector, row.remote_resource_name);
  } catch (e) {
    await deploymentStore.recordAttempt(deploymentId, { action: 'READBACK', result: 'FAILED_RETRYABLE', errorCode: e.code || 'UNKNOWN_ERROR', startedAt, finishedAt: new Date().toISOString() });
    await deploymentStore.updateDeployment(deploymentId, { state: 'FAILED_RETRYABLE', last_error: JSON.stringify({ code: 'READBACK_FAILED', message: e.message }) });
    return { blocked: false, deployment: deploymentStore.toPublicDeployment(await deploymentStore.getDeploymentRaw(ownerId, deploymentId)) };
  }

  const desired = connectorModule.toCanonicalObserved(intent);
  const desiredHash = sha256(canonicalizeForHash(desired));
  const observedHash = readBackResult.found ? sha256(canonicalizeForHash(readBackResult.observed)) : null;
  await deploymentStore.recordAttempt(deploymentId, { action: 'READBACK', result: readBackResult.found ? 'SUCCESS' : 'FAILED_RETRYABLE', startedAt, finishedAt: new Date().toISOString() });

  if (!readBackResult.found || desiredHash !== observedHash) {
    await deploymentStore.updateDeployment(deploymentId, {
      state: 'FAILED_RETRYABLE',
      observed_hash: observedHash,
      last_error: JSON.stringify({ code: 'READBACK_MISMATCH', message: readBackResult.found ? 'Remote state does not match what was deployed.' : 'Remote resource not found immediately after deployment.' }),
    });
    deploymentStore.appendDeploymentAudit('DEPLOYMENT_FAILED', { owner: ownerId, deploymentId, code: 'READBACK_MISMATCH' }).catch(() => {});
    return { blocked: false, deployment: deploymentStore.toPublicDeployment(await deploymentStore.getDeploymentRaw(ownerId, deploymentId)) };
  }

  // Verified. Rotate content snapshots per the update/rollback design.
  const fields = {
    state: 'VERIFIED', observed_hash: observedHash, verified_at: new Date().toISOString(), pending_action: null,
  };
  if (pendingAction === 'ROLLBACK') {
    fields.deployed_intent_snapshot = JSON.stringify(intent);
    fields.previous_intent_snapshot = null; // consumed -- one level of undo
  } else {
    fields.previous_intent_snapshot = row.deployed_intent_snapshot; // may be null on first DEPLOY -- fine, means "no rollback target yet"
    fields.deployed_intent_snapshot = JSON.stringify(intent);
  }
  await deploymentStore.updateDeployment(deploymentId, fields);
  deploymentStore.appendDeploymentAudit('DEPLOYMENT_VERIFIED', { owner: ownerId, deploymentId, action: pendingAction }).catch(() => {});

  return { blocked: false, deployment: deploymentStore.toPublicDeployment(await deploymentStore.getDeploymentRaw(ownerId, deploymentId)) };
}

/* ───────────────────────── on-demand verification / drift check ───────────────────────── */

async function verifyDeployment({ ownerId, deploymentId }) {
  const row = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);
  if (!row) return { blocked: true, reason: 'NOT_FOUND' };
  // 'DEPLOYED' included so a process interruption between a successful
  // deploy() and its automatic read-back can be resumed on demand rather
  // than leaving the deployment stuck.
  if (!['VERIFIED', 'DRIFTED', 'DEPLOYED'].includes(row.state)) return { blocked: true, reason: 'NOT_YET_DEPLOYED' };

  const cm = await connectorAndModuleFor(ownerId, row.connector_id);
  if (cm.error) return { blocked: true, reason: cm.error, message: cm.message };
  const credResult = await connectorStore.getConnectorWithCredential(ownerId, row.connector_id);
  if (credResult.error) return { blocked: true, reason: credResult.error, message: credResult.message };

  const startedAt = new Date().toISOString();
  const readBackResult = await cm.module.readBack(credResult.connector, row.remote_resource_name);
  await deploymentStore.recordAttempt(deploymentId, { action: 'RECONCILE', result: readBackResult.found ? 'SUCCESS' : 'FAILED_RETRYABLE', startedAt, finishedAt: new Date().toISOString() });

  const observedHash = readBackResult.found ? sha256(canonicalizeForHash(readBackResult.observed)) : null;
  const desiredHash = row.deployed_intent_snapshot
    ? sha256(canonicalizeForHash(cm.module.toCanonicalObserved(JSON.parse(row.deployed_intent_snapshot))))
    : row.desired_hash;
  if (!readBackResult.found || observedHash !== desiredHash) {
    // Never auto-overwrite (Section 48/49): surface DRIFTED, leave the
    // remote resource exactly as found.
    await deploymentStore.updateDeployment(deploymentId, { state: 'DRIFTED', observed_hash: observedHash });
    deploymentStore.appendDeploymentAudit('DRIFT_DETECTED', { owner: ownerId, deploymentId }).catch(() => {});
    return { blocked: false, deployment: deploymentStore.toPublicDeployment(await deploymentStore.getDeploymentRaw(ownerId, deploymentId)) };
  }
  await deploymentStore.updateDeployment(deploymentId, { state: 'VERIFIED', observed_hash: observedHash, verified_at: new Date().toISOString() });
  return { blocked: false, deployment: deploymentStore.toPublicDeployment(await deploymentStore.getDeploymentRaw(ownerId, deploymentId)) };
}

/* ───────────────────────── rollback ───────────────────────── */

async function previewRollback({ ownerId, deploymentId }) {
  const row = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);
  if (!row) return { blocked: true, reason: 'NOT_FOUND' };
  if (!row.previous_intent_snapshot) return { blocked: true, reason: 'NO_ROLLBACK_TARGET' };

  const rawRule = detectionRules.getRule(row.detection_id);
  if (rawRule && rawRule.governance && rawRule.governance.status === 'REVOKED') {
    return { blocked: true, reason: 'DETECTION_REVOKED' };
  }
  const cm = await connectorAndModuleFor(ownerId, row.connector_id);
  if (cm.error) return { blocked: true, reason: cm.error, message: cm.message };

  const snapshot = JSON.parse(row.previous_intent_snapshot);
  const desired = cm.module.toCanonicalObserved(snapshot);
  const desiredHash = sha256(canonicalizeForHash(desired));

  await deploymentStore.updateDeployment(deploymentId, {
    state: 'APPROVAL_REQUIRED', pending_action: 'ROLLBACK', desired_hash: desiredHash,
  });

  const currentIntent = row.deployed_intent_snapshot ? JSON.parse(row.deployed_intent_snapshot) : null;
  return {
    blocked: false,
    deployment_id: deploymentId,
    action: 'ROLLBACK',
    resource_name: row.remote_resource_name,
    from_version: currentIntent?.detection_version || row.detection_version,
    to_version: snapshot.detection_version,
    query: snapshot.query,
    diff: { from: currentIntent, to: snapshot },
  };
}

/* ───────────────────────── disable (Section 35/56) ───────────────────────── */

async function disableDeployment({ ownerId, deploymentId }) {
  const row = await deploymentStore.getDeploymentRaw(ownerId, deploymentId);
  if (!row) return { blocked: true, reason: 'NOT_FOUND' };
  if (!['VERIFIED', 'DRIFTED', 'FAILED_RETRYABLE'].includes(row.state)) return { blocked: true, reason: 'INVALID_STATE_FOR_DISABLE', state: row.state };

  const cm = await connectorAndModuleFor(ownerId, row.connector_id);
  if (cm.error) return { blocked: true, reason: cm.error, message: cm.message };
  if (!cm.capabilities.disable_supported) return { blocked: true, reason: 'DISABLE_NOT_SUPPORTED' };
  const credResult = await connectorStore.getConnectorWithCredential(ownerId, row.connector_id);
  if (credResult.error) return { blocked: true, reason: credResult.error, message: credResult.message };

  const startedAt = new Date().toISOString();
  try {
    await cm.module.disable(credResult.connector, row.remote_resource_name);
  } catch (e) {
    await deploymentStore.recordAttempt(deploymentId, { action: 'DISABLE', result: 'FAILED_RETRYABLE', errorCode: e.code || 'UNKNOWN_ERROR', startedAt, finishedAt: new Date().toISOString() });
    return { blocked: false, error: true, message: e.message };
  }
  await deploymentStore.recordAttempt(deploymentId, { action: 'DISABLE', result: 'SUCCESS', startedAt, finishedAt: new Date().toISOString() });
  await deploymentStore.updateDeployment(deploymentId, { state: 'DISABLED' });
  deploymentStore.appendDeploymentAudit('DEPLOYMENT_DISABLED', { owner: ownerId, deploymentId }).catch(() => {});
  return { blocked: false, deployment: deploymentStore.toPublicDeployment(await deploymentStore.getDeploymentRaw(ownerId, deploymentId)) };
}

module.exports = {
  recomputeDeployability,
  previewDeployment,
  approveDeployment,
  executeDeployment,
  verifyDeployment,
  previewRollback,
  disableDeployment,
  // exported for direct unit testing
  canonicalizeForHash,
  sha256,
};
