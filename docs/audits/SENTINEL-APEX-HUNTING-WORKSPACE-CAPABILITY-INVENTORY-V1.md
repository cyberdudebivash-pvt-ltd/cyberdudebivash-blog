# SENTINEL APEX — Threat Hunting Workspace: Reuse-Before-Build Capability Inventory v1

**Date:** 2026-08-29
**Scope:** Reuse-before-build audit preceding the Threat Hunting Workspace, Analyst Investigation Fabric, Detection Feedback Intelligence & Defensive Outcome Loop v1 tranche, per Principle 4 (Reuse Before Build) and Section 0 Level 4 (Reuse) of this repository's governance constitution. Performed by direct, full reads of every candidate file — not assumed from names or prior-session memory.

---

## 1. Executive finding

A **fully-built, working SOC investigation/case/evidence/timeline/graph system already exists** in this repository (`api/_lib/investigation-manager.js`, `case-manager.js`, `evidence-manager.js`, `timeline-engine.js`, `graph-engine.js` + friends, `analysis-manager.js`), exposed via `api/v1/workbench/*` and `api/v1/analysis/*`, with a working UI (`workbench.html`). **None of it can be reused as the persistence layer for the new customer-facing Hunt capability**, for two independent, evidence-based reasons:

1. **Tenancy/identity mismatch.** Every one of these systems is gated by `analyst-auth.js`'s `X-Analyst-Key` (an internal SOC-analyst credential pool via the `ANALYST_KEYS` env var) — not `authenticate()`'s customer API-key/`userId` model every other customer-facing store in this platform uses (connectors, deployments, watchlists, defense profiles). There is no `owner_id` concept anywhere in `InvestigationManager`/`CaseManager`. A hunt tied to a specific customer's own detections, deployments, and defense profile cannot be built on a system with zero customer-tenancy dimension without inventing a bolt-on ownership layer on top of someone else's ID scheme — which is a worse outcome than building the right-shaped table from the start.
2. **Runtime-policy conflict.** `docs/architecture/PRODUCTION-RUNTIME-POLICY.md` §1 is an active, dated, operator-issued policy: *"No Upstash Redis production dependency for new capability."* The entire Investigation/Case/Evidence/Graph/Analysis stack is Redis-only (confirmed: zero D1 tables reference any of it — see §4 below). Extending it would be a direct, avoidable violation of an explicit architectural policy that outranks the ordinary "prefer reuse" preference — Section 0's Level 1 (Correctness, defined here as correctly honoring the platform's own governing constraints) sits above Level 4 (Reuse). New hunt persistence goes on Cloudflare D1, in the same `sentinel-apex-core` database as every other customer-facing store shipped since the Cloudflare-Only Runtime Completion v2 tranche.

This mirrors, and is directly licensed by, an already-documented precedent: `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`'s existing row for "SOC Workbench intelligence objects" already states it is *"a **deliberately separate** system... Redis-persisted (not file-persisted), analyst-curated (not automated bot ingestion)... Not customer-facing by design."* The new Hunt capability belongs in the same category as Connectors/Deployments/Watchlists/Defense Profiles (D1, `owner_id`-scoped, customer-facing) — not in the SOC-Workbench category. No new precedent is being set here; an existing one is being followed correctly.

**What genuinely is reused, unchanged:** the canonical detection store and release gate, the customer defense-compatibility engine, the deployment-state machine, the CVE/Campaign/Actor/IOC dossier accessors, and — most importantly — the exact 4-point router/route-table/vercel.json registration pattern and the `fake-d1.js` fixture-extension pattern this platform has now used three times (watchlists, defense profiles, SIEM deployment gateway).

---

## 2. Capability matrix

| Capability | Existing? | Production reachable? | Reusable for Hunt Workspace? | Gap / Decision |
|---|---|---|---|---|
| Investigation lifecycle (OPEN/IN_PROGRESS/PENDING_REVIEW/CLOSED/ARCHIVED) | Yes — `investigation-manager.js` | Yes, internal-analyst-only (`api/v1/workbench/investigations`) | **No** — wrong tenancy (no `owner_id`), wrong auth (`X-Analyst-Key`), wrong storage (Redis, policy-barred for new capability) | Build new `hunts` table on D1, own status vocabulary (DRAFT/READY/ACTIVE/PAUSED/AWAITING_EVIDENCE/ANALYSIS_COMPLETE/CLOSED per mandate) |
| Case management (OPEN→EVIDENCE_COLLECTION→ANALYSIS→DECISION→CLOSURE→CLOSED, notes, tasks, decisions) | Yes — `case-manager.js` | Yes, internal-analyst-only, no list-all endpoint (lookup by ID only) | **No** (same reasons) — but its `addDecision()` is a useful reference pattern for what a disposition record looks like | Hunt disposition modeled as columns on `hunts` (one terminal act, not a recurring sub-resource); a hunt's own optional `linked_case_reference` is a plain analyst-entered pointer, not automated cross-system promotion (see §6) |
| Evidence tracking (13 typed evidence records, MITRE-mapping helper, graph-entity linking, tagging) | Yes — `evidence-manager.js` | Yes, internal-analyst-only | **No** (same reasons); the type taxonomy is heavier than v1 needs | Build a minimal `hunt_evidence_links` table (description + reference URL), deliberately not the full 13-type/graph-linked model — richer evidence tooling is a disclosed future item, not attempted here |
| Timeline reconstruction (merges audit trail + evidence + intelligence lifecycle events, cached) | Yes — `timeline-engine.js` | Yes, internal-analyst-only | **No** (same reasons); logic is bespoke to investigation-scoped Redis keys | Build `hunt_timeline` as a simple append-only log, mirroring the already-proven `siem_connector_audit_log`/`deployment_audit_log`/`watchlist_audit_log` pattern (capped, trimmed, `?`-placeholder inserts) rather than reconstructing a merged view |
| Entity-relationship graph + traversal + correlation + AI-Analyst suggestions | Yes — `graph-engine.js`/`graph-traversal.js`/`correlation-engine.js`/`ai-analyst.js` | Yes, internal-analyst-only | **No** as a graph engine (wrong tenancy/storage) — but confirms no separate hunt-specific graph is needed at all | Hunt hypothesis context comes from the existing canonical CTI accessors (`threat-graph.js` via `getDossierAPI`/`getActorDetailAPI`/`getIocDetailAPI`), not a new or reused graph traversal system |
| Structured-analytic findings (`AnalyticalFinding`: DRAFT→REVIEWED→APPROVED→PUBLISHED, confidence CONFIRMED/LIKELY/POSSIBLE/UNLIKELY/UNSUBSTANTIATED, evidence/reasoning/assumptions/limitations/alternative hypotheses) | Yes — `analysis-manager.js`/`analysis-models.js`, `api/v1/analysis/{findings,assessments}.js` | Yes, internal-analyst-only, scoped to internal `investigationId` | **Vocabulary reference only, not reusable as storage.** Confidence vocabulary answers a different question (epistemic: "how sure am I this statement is true") than a hunt finding's classification (security disposition: "what was this activity"). Adopting it wholesale would conflate two different axes. | New `hunt_findings.classification` uses the mandate's own security-disposition taxonomy (CONFIRMED_MALICIOUS/LIKELY_MALICIOUS/BENIGN/EXPECTED_ACTIVITY/INCONCLUSIVE/FALSE_POSITIVE/NO_EVIDENCE_FOUND); `confidence` field reuses `intelligence-object.js`'s existing, already-platform-wide HIGH/MEDIUM/LOW vocabulary (not a third new one) |
| Detection canonical store + release gate | Yes — `detection-rules.js`/`detection-intelligence.js` | Yes, customer-facing (paid tier) | **Yes, unchanged** | Reused exactly as PR #143 already does: `detection_id`/`detection_version` pinning, `RELEASED`-only gate |
| Customer defense-compatibility engine | Yes — `defense-compatibility.js` (`evaluateDetectionCompatibility`, `computeCustomerCoverage`) | Yes, customer-facing | **Yes, unchanged** | Hunt telemetry readiness computed live by calling this, never re-implemented or persisted |
| Detection deployment state machine | Yes — `deployment-store.js`/`deployment-engine.js`, `detection_deployments` (D1) | Yes, customer-facing (Beta) | **Yes, unchanged** | Hunt→deployment linkage joins on `detection_id` via `idx_deployments_detection`; DRIFTED/REVOKED states surfaced as-is, never re-derived |
| CVE/Campaign dossier accessor | Yes — `intel.js#getDossierAPI(type,id,tier)` | Yes, customer-facing | **Yes, unchanged** — but **only supports `cve`/`campaign`** | Actor/IOC hunt context uses the separate `getActorDetailAPI`/`getIocDetailAPI` functions instead (real gap in `getDossierAPI` itself, correctly worked around rather than widening that function's scope) |
| Detection feedback (TRUE_POSITIVE/FALSE_POSITIVE/tuning) | **No — confirmed absent anywhere in the repository** | N/A | N/A | Genuinely new capability; only two unrelated vocabularies to avoid colliding with (`detection-rules.js`'s rule-authoring `REVIEW_REQUIRED` lifecycle state, and free-text `reviewFeedback` strings in two internal analyst-approval workflows) |
| Router/route-table/vercel.json registration | Yes — 4-point pattern (`HANDLER_MODULES`, `DIRECT_API_HANDLERS`, `APEX_SUBPATH_HANDLERS` + matching `vercel.json` rewrite for any sub-path route, `vercel.json functions` block for memory/duration) | N/A (infrastructure) | **Yes, unchanged** | New `api/v1/hunts.js` registered following the exact existing 4-point pattern |
| D1 test-fixture extension pattern | Yes — `fake-d1.js`'s per-migration Map/array block + `exec()` branch pattern | N/A (test infra) | **Yes, unchanged** | New migration gets its own block, following the `0004` block's shape exactly |

---

## 3. What is genuinely new (justified, not a duplicate)

Per Reuse Priority Order (Principle 4): none of the new tables/logic below has an existing equivalent at the *customer-tenancy* layer, confirmed by the audit above, not assumed:

- `hunts`, `hunt_refs`, `hunt_queries`, `hunt_observations`, `hunt_evidence_links`, `hunt_findings`, `hunt_timeline` (D1, `sentinel-apex-core`, additive migration).
- `detection_feedback` (D1, same database) — has zero prior art anywhere in this codebase.
- A new composition module for coverage-maturity rollup (`AVAILABLE → ENVIRONMENT_COMPATIBLE → DEPLOYED → OBSERVED_SIGNAL → ANALYST_VALIDATED`) that **calls** `detection-intelligence.js`/`defense-compatibility.js`/`deployment-store.js` unchanged rather than being added to any of those already-certified, shared files directly (avoids blast radius on their existing consumers — Level 5 Minimal Change Surface).

**Deliberately NOT built, following the platform's own "computed, not stored" discipline** (Source-of-Truth Matrix's recurring pattern for Coverage/Customer Coverage/Watchable State/Search): a `hunt_telemetry_requirements` table and a persisted `REVIEW_REQUIRED` feedback-signal flag. Both are cheaper and safer to compute fresh at read time from `defense-compatibility.js` and `detection_feedback` respectively — a stored, separately-mutated copy of either would be exactly the kind of second-source-of-truth drift risk the Source-of-Truth Matrix exists to prevent.

---

## 4. D1 migration inventory (confirmed complete, all 4 files read)

| Migration | Tables |
|---|---|
| `0001_notification_delivery.sql` | `notification_preferences`, `notification_delivery_jobs`, `notification_delivery_log`, `notification_dead_letters`, `notification_audit_log` |
| `0002_watchlists_change_detection.sql` | `watchlists`, `watchlist_entities`, `watchlist_audit_log`, `entity_snapshots`, `change_events`, `owner_feed`, `watchlist_eval_state` |
| `0003_defense_profiles.sql` | `defense_profiles`, `defense_profile_technologies`, `defense_profile_telemetry`, `defense_profile_audit_log` |
| `0004_siem_deployment_gateway.sql` | `siem_connectors`, `siem_connector_audit_log`, `detection_deployments`, `deployment_approvals`, `deployment_attempts`, `deployment_audit_log`, `mock_siem_resources` |

Zero hunt/investigation/case/evidence/finding/disposition/observation/timeline/feedback/analyst_note/workbench tables exist today. `0005_threat_hunting_workspace.sql` is a wholly new, additive file.

---

## 5. Real, pre-existing latent findings surfaced incidentally (not this tranche's to fix, disclosed per this platform's own honesty discipline)

1. **`deployment-store.js`'s `NON_TERMINAL_STATES` array lists `'ROLLBACK_AVAILABLE'`**, a value that is not in `detection_deployments`'s actual `state` `CHECK` constraint (13 real values) and is never written anywhere — dead/inert, because rollback availability is (correctly) a derived boolean (`!!previous_intent_snapshot`) elsewhere in the same file. Pre-existing from PR #143, zero functional impact (the array is a superset; an inert extra entry doesn't change matching behavior), out of scope for this tranche (Zero Unnecessary Modification — unrelated to hunts). Recorded as a new Open Issue.
2. **`workers/lib/route-table.test.js:90`'s test title still reads "35-function parity check"**, stale since the PR #143 bump to 37 (only the assertion body was updated, not the title). Since this tranche must touch this exact file again to bump the count a second time, the title text is corrected in the same edit — a trivial, directly-adjacent fix, not opportunistic unrelated cleanup.

---

## 6. Explicit scoping decision: case/incident promotion

The mandate requires a hunt not be automatically an incident/case, with "PROMOTE TO CASE / LINK CASE only via explicit analyst action" if case management exists. It does (`case-manager.js`), but per §1 it is a completely separate identity domain (internal analyst, no `owner_id`) from the customer-owned hunt. Building a real cross-domain automated promotion bridge this tranche would mean granting either system knowledge of the other's identity model — a materially larger, riskier architectural change with no explicit mandate requirement forcing it now. **Decision:** v1 ships a plain, analyst-entered `linked_case_reference` free-text field on a hunt (a manual pointer an analyst fills in after opening an internal case through the existing, unmodified Workbench UI) — satisfies "explicit action, never automatic," discloses the real boundary rather than faking an integration, and can be upgraded to a real bridge later if a genuine cross-system workflow requirement emerges.

---

## 7. Query-execution scope (preliminary; finalized in the certification doc)

Neither `mock-siem-connector.js` nor `microsoft-sentinel-connector.js` implements ad-hoc log/query execution — both only implement lifecycle operations on a specific analytics-rule resource (`deploy`/`readBack`/`disable`/`deleteRemote`), scoped to the ARM management API and its OAuth resource (`https://management.azure.com/.default`). Real ad-hoc KQL execution against Sentinel's underlying Log Analytics workspace is a structurally different API (Azure Monitor Logs query endpoint), a different OAuth resource/scope, and a different Azure RBAC role (Log Analytics Reader, not the Sentinel-contributor-shaped role the current connector documents) — none of which this platform's connector implements, tests, or has credentials to verify. Consistent with the mandate's own instruction not to broaden OAuth scope to satisfy this tranche: remote query execution is **DEFERRED**. Hunt queries remain data (view/copy/download) only.

---

*CyberDudeBivash® Sentinel APEX — Threat Hunting Workspace Reuse-Before-Build Capability Inventory v1*
