'use strict';

/**
 * System 5 adapter for ReportX (ReportX Section 44 / rollout runbook Phase 3).
 *
 * Per the operator's hybrid-architecture decision: System 3
 * (Sentinel-APEX/engine/sentinel_engine/reportx/, Python) is the sole
 * canonical evidence/claim truth model. System 5 (this file and the rest of
 * api/_lib/) is the commercial product-composition layer and MUST consume
 * System 3's validated output -- it must never recompute an EpistemicState,
 * a CorroborationState, or a commercial-readiness control result. Every
 * value this module exposes is read directly from the JSON artifact
 * produced by `python3 cli.py reportx-gate <bundle.json> --export out.json`
 * (see sentinel_engine.reportx.bundle_io.export_report_json) -- nothing
 * here re-derives or re-judges anything System 3 already decided.
 *
 * This module does not replace any existing engine (product-composition-
 * engine.js, evidence-traceability-engine.js, ...); it is a new, additive
 * read-only consumer, per the Architecture Preservation Rule.
 */

const fs = require('fs');

const REQUIRED_TOP_LEVEL_KEYS = ['bundle', 'commercial_readiness'];

class ReportXBundle {
  constructor(raw) {
    for (const key of REQUIRED_TOP_LEVEL_KEYS) {
      if (!(key in raw)) {
        throw new Error(`ReportXBundle: exported artifact is missing required key "${key}" -- ` +
          'was this produced by `reportx-gate --export`, or was it hand-edited?');
      }
    }
    this._raw = raw;
  }

  // ---- Identity ----

  get reportId() {
    return this._raw.bundle.report_id;
  }

  get isPremiumTier() {
    return Boolean(this._raw.bundle.is_premium_tier);
  }

  // ---- Evidence graph (read-only) ----

  getSources() {
    return this._raw.bundle.sources;
  }

  getSource(sourceId) {
    return this._raw.bundle.sources.find(s => s.source_id === sourceId) || null;
  }

  getEvidence() {
    return this._raw.bundle.evidence;
  }

  getClaims() {
    return this._raw.bundle.claims;
  }

  getClaim(claimId) {
    return this._raw.bundle.claims.find(c => c.claim_id === claimId) || null;
  }

  /** Claims whose observed_vs_context is OBSERVED -- incident-specific, not general actor background. */
  getIncidentSpecificClaims() {
    return this._raw.bundle.claims.filter(c => c.observed_vs_context === 'OBSERVED');
  }

  /** Claims whose observed_vs_context is CONTEXT -- actor-historical/general background. */
  getActorContextClaims() {
    return this._raw.bundle.claims.filter(c => c.observed_vs_context === 'CONTEXT');
  }

  // ---- Threat products (schema-isolated) ----

  getThreatProducts() {
    return this._raw.bundle.threat_products;
  }

  /** Convenience accessor for the common single-product case (every
   * golden ransomware fixture in this repo has exactly one). Returns null
   * if there are zero or more than one -- callers needing multi-product
   * bundles should use getThreatProducts() directly rather than guessing
   * which one this method would have picked. */
  getPrimaryThreatProduct() {
    const products = this._raw.bundle.threat_products;
    return products.length === 1 ? products[0] : null;
  }

  // ---- Commercial-readiness gate (already computed by System 3 -- read only) ----

  getControlResults() {
    return this._raw.commercial_readiness.controls;
  }

  getControlResult(controlId) {
    return this._raw.commercial_readiness.controls.find(c => c.control_id === controlId) || null;
  }

  getPassCount() {
    return this._raw.commercial_readiness.pass_count;
  }

  getTotalControlCount() {
    return this._raw.commercial_readiness.total_count;
  }

  getVerdict() {
    return this._raw.commercial_readiness.verdict;
  }

  isCommercialReady() {
    return this._raw.commercial_readiness.verdict === 'COMMERCIAL-READY';
  }

  getFailingControls() {
    return this._raw.commercial_readiness.controls.filter(c => c.status !== 'PASS');
  }

  // ---- Bridge into the existing product-composition shape ----

  /**
   * Maps this validated ReportX bundle into the loosely-typed
   * "investigation"-shaped object api/_lib/product-composition-engine.js's
   * existing compose*() methods already consume (investigation.title,
   * .findings, .threatActors, etc.) -- so a ReportX-backed report can flow
   * through the SAME, unmodified ProductCompositionEngine every other
   * intelligence product already uses (Principle 4: reuse before build).
   *
   * This is a best-effort compatibility bridge, not a full re-expression
   * of the evidence graph -- it necessarily flattens epistemic nuance
   * (EpistemicState, CorroborationState, threat-schema isolation) that
   * the investigation shape has no fields for. Anything beyond executive/
   * technical product composition should read the validated data directly
   * via this class's other accessors, not through this bridge.
   */
  toInvestigationShape() {
    const product = this.getPrimaryThreatProduct();
    const victim = product && product.threat_type === 'RANSOMWARE_VICTIM_CLAIM'
      ? product.victim_observation : null;
    const actorContext = product && product.threat_type === 'RANSOMWARE_VICTIM_CLAIM'
      ? product.actor_context : null;

    const findings = this._raw.bundle.claims.map(claim => ({
      statement: claim.text,
      severity: _severityForClaim(claim),
      confidence: (claim.confidence || 'LOW').toLowerCase(),
      businessImpact: undefined,
      evidence: (claim.evidence_refs || []).map(eid => {
        const ev = this._raw.bundle.evidence.find(e => e.evidence_id === eid);
        return ev ? ev.excerpt : eid;
      }),
      // Preserves the epistemic status alongside the flattened severity,
      // rather than discarding it -- a caller inspecting findings can
      // still see the real ReportX status without recomputing it.
      reportXStatus: claim.status,
      reportXClaimId: claim.claim_id,
    }));

    return {
      id: this.reportId,
      title: victim && victim.victim_name
        ? `${victim.group_named_by_source || 'Unknown actor'} / ${victim.victim_name}`
        : this.reportId,
      description: victim && victim.claimed_data_description
        ? victim.claimed_data_description
        : '',
      severity: 'MEDIUM', // ReportX's evidence model has no direct severity field; left at a
                           // neutral default rather than inferring one System 3 never asserted.
      classification: this.isPremiumTier ? 'TLP:AMBER' : 'TLP:CLEAR',
      threatActors: victim && victim.group_named_by_source
        ? [{
          name: victim.group_named_by_source,
          aliases: (actorContext && actorContext.actor_aliases) || [],
          origin: undefined,
          firstSeen: undefined,
          lastSeen: undefined,
          description: (actorContext && actorContext.sectors && actorContext.sectors.length)
            ? `Historically observed across: ${actorContext.sectors.join(', ')}`
            : undefined,
        }]
        : [],
      findings,
      iocs: [], // No golden fixture in this repo has populated IOC claims; left empty
                // rather than fabricated -- see observed_incident_ioc_claim_ids upstream.
      timeline: (victim && victim.claim_date)
        ? [{ timestamp: victim.claim_date, event: 'Leak-site claim posted', severity: 'INFO' }]
        : [],
      sources: this._raw.bundle.sources.map(s => s.source_id),
      // Non-standard field the existing engine's methods don't read, but
      // kept attached so a caller with this adapter's context can still
      // reach the full gate result from the mapped object without a
      // second lookup.
      reportXGate: {
        verdict: this.getVerdict(),
        passCount: this.getPassCount(),
        totalCount: this.getTotalControlCount(),
      },
    };
  }
}

function _severityForClaim(claim) {
  // A coarse, explicit mapping -- not an inference about real-world
  // severity, just a bridge onto the existing findings-severity field's
  // vocabulary ('critical'|'high'|...) so extractKeyRisks() in
  // product-composition-engine.js (which filters on this field) works
  // unmodified against ReportX-derived findings.
  const highImpact = ['EXPLOITATION', 'DATA_THEFT', 'RANSOM_PAYMENT', 'BUSINESS_IMPACT'];
  if (highImpact.includes(claim.claim_type) && claim.status === 'CONFIRMED') return 'critical';
  if (highImpact.includes(claim.claim_type)) return 'high';
  return 'medium';
}

/** Loads a bundle from an already-parsed object or a JSON string. */
function loadReportXBundle(source) {
  const raw = typeof source === 'string' ? JSON.parse(source) : source;
  return new ReportXBundle(raw);
}

/** Loads a bundle from a file path (the output of `reportx-gate --export`). */
function loadReportXBundleFromFile(filePath) {
  return loadReportXBundle(fs.readFileSync(filePath, 'utf8'));
}

module.exports = { ReportXBundle, loadReportXBundle, loadReportXBundleFromFile };
