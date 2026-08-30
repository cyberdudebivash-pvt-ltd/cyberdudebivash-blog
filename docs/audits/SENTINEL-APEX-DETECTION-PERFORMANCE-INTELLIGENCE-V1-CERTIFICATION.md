# SENTINEL APEX — Detection Performance Intelligence, Defensive Efficacy Fabric, Privacy-Safe Analyst Feedback Aggregation, Detection Review Prioritization & Closed-Loop Defense Quality Engine v1 — Certification

Branch: `claude/controlled-detection-deployment-auu51p`
Builds on: PR #143 (Controlled SIEM Deployment Gateway v1), PR #144 (Threat Hunting Workspace & Detection Feedback Intelligence v1)

---

## §1 — Executive Summary

This tranche answers one question: **what are we learning about a detection from real defensive use, and what should happen next?** It does so by adding exactly one new table (`detection_versions`, an immutable content-snapshot store) and a composition layer (`detection-performance-engine.js`) on top of two already-certified, unmodified systems: the canonical detection store (`detection-rules.js`/`detection-intelligence.js`) and Threat Hunting's own detection feedback (`detection-feedback-store.js`, PR #144).

The result is a deterministic **Quality State** (`INSUFFICIENT_EVIDENCE` / `HEALTHY` / `TUNING_RECOMMENDED` / `REVIEW_REQUIRED` / `TECHNICAL_FAILURE` / `REVOKED` / `DEPRECATED`) for every (detection, version) pair, always accompanied by an explicit, human-readable reason — never a score, never a probability, never a fabricated efficacy statistic. A privacy-safe, internal-only Review Queue prioritizes what needs attention. Nothing in this tranche can modify a detection's content, release a new version, or change a customer's deployed configuration — every action remains manual, going through the existing PR #143 approval/deployment control plane.

While building this, the tranche also closed a real, already-occurred defect: `detection-rules.js#storeRule()` has always overwritten a rule's content in place on every version bump, permanently destroying prior versions' content (confirmed: 3 of the 5 real canonical rules have already lost recoverable content for one or more historical versions). `detection_versions` now captures every future version immutably, plus the current content of all 5 existing rules via a one-time backfill.

## §2 — Prerequisite Gate Verification

Confirmed at the start of this tranche (Explore-agent audit + direct reads):
- PR #143/#144 architecture unchanged since merge; both live on `main`.
- `docs/architecture/PRODUCTION-RUNTIME-POLICY.md` — no new Redis dependency permitted for new capability (still respected: this tranche is D1-only).
- `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md` — current chain confirmed, extended in §44 of this PR's doc updates.
- `platform/open-issues.md` — Issues 30-32 (from PR #144) reviewed; Issue 31 ("validated defect" trigger not implemented) remains open and unaffected by this tranche (deliberately out of scope — no analyst-review workflow for feedback exists yet).
- `docs/audits/SENTINEL-APEX-GLOBAL-CTI-COMMERCIAL-TRANSFORMATION-V3-RESUME-CHECKPOINT.md` — round 12 (§18) reviewed as the resume point for this round.

## §3 — Reuse-Before-Build Audit Summary

A background research pass (Explore agent) inventoried every existing feedback/quality/performance concept before any code was written:
- `detection-feedback-store.js#computeFeedbackSignal()` — the ONE existing cross-tenant aggregate read (PR #144). Reused, unmodified, as the backbone of Quality State's feedback-derived tiers.
- `hunt-engine.js#resolveCanonicalDetection()` — the existing composition of `detectionRules.getRule()` + `detectionIntelligence.classifyAttackEvidence()` + `toCanonicalDetectionObject()`. Reused, unmodified, as the Validation axis's data source.
- `deployment-store.js` — existing `detection_deployments` table. Extended (one new function, `countDeploymentsByDetection`) rather than duplicated.
- The dead, unwired 43-file TypeScript `lib/` stack (`lib/governance/quality-gates.ts`, `confidence-engine.ts`, `reviewers.ts`, `workflow.ts`) — despite names that sound directly relevant, confirmed (again, independently) to have zero live-path overlap; not used. Already documented in `platform/open-issues.md` Issue 29.
- The internal Redis-backed SOC Workbench (`investigation-manager.js` et al.) — confirmed still inapplicable (no tenancy concept, and `PRODUCTION-RUNTIME-POLICY.md` bars new Redis dependency).

No overlapping/duplicate feedback taxonomy was introduced — the same 9 `FEEDBACK_CLASSIFICATIONS` from PR #144 are reused verbatim throughout.

## §4 — Safety Boundary Compliance

Explicitly verified NOT present anywhere in this tranche:
- No ML/statistical scoring model. `deriveQualityState()` is a pure, deterministic function of enum inputs.
- No single 0-100 "efficacy score." Every UI surface shows the four axes (Validation, Evidence Sufficiency, Quality State, Version History) separately, plus a tenant-private "Your Operational Feedback" section — never collapsed.
- No automatic rule rewriting, no automatic version release, no automatic redeployment. Confirmed by code inspection: `detection-performance-engine.js` has no write path into `detection-rules.js`'s content, `detection_deployments`, or any release/status field.
- No fake precision/recall/false-positive-rate statistic. See §11 (Statistical Truth Policy).
- No cross-customer raw data exposure. See §10 (Privacy Certification).

## §5 — The Detection Version Immutability Defect — Evidence & Fix

Confirmed by direct read of `api/_lib/detection-rules.js#storeRule()` (lines 76-144 before this tranche): every call — whether creating or updating a rule — computes a full `canonicalRule` object and, for an update, executes `store.rules[existingIdx] = canonicalRule` — an unconditional, total overwrite. `history[]` only ever recorded `{version, timestamp, change, author}` — metadata, never content.

Real-corpus evidence (read directly from `data/detection-rules-canonical.json` before any fix): of the 5 real canonical rules, 3 have multiple real version bumps (`65b906336880ed01` — 12 history entries, currently v1.0.9; `ac348bab79c7a3eb` — currently v1.0.8; `9a5467dc8ae03f68` — currently v1.0.9). For every one of these, content for every version before the current one is **already, permanently unrecoverable** — the overwrite already happened, repeatedly, before this tranche existed.

Fix: `migrations/0006_detection_performance_intelligence.sql`'s `detection_versions` table + `api/_lib/detection-version-store.js#snapshotVersion()`, called from `storeRule()` on every future version bump (see §7), plus a one-time backfill of the 5 existing rules' CURRENT content (see §8). Historical content from before this tranche is honestly marked unavailable, never invented (§25).

## §6 — Detection Version Snapshot Model

`detection_versions` (PK `(detection_id, version)`) stores, per version: `title, technique_id, level, description, data_source, platforms_json, suricata_json` (the actual defensive content), `governance_status_at_snapshot` + `confidence_at_snapshot` (a point-in-time capture, explicitly NOT live-tracking — a later `updateRuleStatus()` call does not retroactively change a past snapshot), a SHA-256 `content_hash` over a canonical (sorted-key) JSON serialization of exactly the content fields, `snapshot_source` (`LIVE_CAPTURE` | `BACKFILL_CURRENT_STATE`), `snapshot_reason`/`snapshot_author` (from `sourceMetadata`, when available), and `snapshotted_at`.

Deliberately NOT captured: `source.articles`/`source.campaigns`/`source.iocs` (evidence-linkage fields). This is a disclosed, deliberate scope boundary — see §14 for why this matters for historical validation-gate re-evaluation.

`snapshotVersion()` is idempotent by construction: `INSERT ... ON CONFLICT(detection_id, version) DO NOTHING`. A second call for a version that already has a row is a verified no-op — proven by `detection-version-store.test.js`'s "a repeat snapshot for the SAME (detection_id, version) is a no-op -- never overwrites" test, which submits a DIFFERENT title on the second call and asserts the ORIGINAL title survives.

## §7 — Fire-and-Forget Hook Design & Residual Risk Disclosure

`storeRule()` must remain fully synchronous: its one real production call site is `fetch-live-intel.js:1791`, inside the non-async `genMultiPlatformDetections(item, esc)`, called in a loop during live HTML-template generation. Making `storeRule()` async would cascade an async signature change through that function's own (numerous) callers — a materially larger blast radius than this tranche's scope.

The fix: `versionStore.snapshotVersion(canonicalRule, {...}).catch(err => console.warn(...))` — a floating promise, deliberately not awaited, added immediately after `saveCanonical(store)` and the `return`.

**Disclosed residual risk**: if the host process exits before this fire-and-forget write completes, that one version's snapshot is lost. This is judged low-risk in practice — `fetch-live-intel.js` is a long-running script with substantial work remaining after each `storeRule()` call, not a one-shot process — and is **strictly no worse than today's guaranteed, unconditional loss** on every version bump. Proven safe (never blocks, never throws) by `detection-rules-version-snapshot.test.js`'s "storeRule() itself never throws or blocks even when snapshotVersion() rejects" test.

## §8 — Backfill Mechanism & Real-Corpus Results

`scripts/backfill-detection-version-snapshots.js` — dry-run by default, `--apply` to write. Calls `detection-version-store.js#backfillCurrentVersions()`, which snapshots the CURRENT content of every rule with `snapshot_source: 'BACKFILL_CURRENT_STATE'`. Idempotent (safe to re-run). Live-verified against the real 5-rule canonical store via the QA server (§32): all 5 rules' current versions successfully backfilled; every prior version for the 3 multi-version rules correctly reports `content_available: false` (never fabricated) in the version-history API response.

## §9 — Tenant-Scoped Performance Record

`detection-feedback-store.js#computeTenantPerformance(ownerId, detectionId, detectionVersion)` — new, additive function (existing `computeFeedbackSignal`/`submitFeedback`/etc. untouched). Owner-scoped (matches every function in the file except the one deliberate cross-tenant exception). Computed on demand via one `GROUP BY classification` query — no materialized counts (see §26 for why). Returns `{total_feedback, classification_counts, last_feedback_at}` — the "Your Operational Feedback" section on the customer-facing detection detail page.

## §10 — Privacy-Safe Global Aggregation & Privacy Certification

`computeGlobalReviewMetrics()` composes `computeFeedbackSignal()` (unchanged) with one additional aggregate query (`COUNT(DISTINCT owner_id) AS global_owner_count, MAX(created_at)`), adding only `distinct_owners_total`/`last_feedback_at` to the existing `{signal, reason_codes, sample_size}` shape. `deployment-store.js#countDeploymentsByDetection()` is the same pattern for deployment reach.

**What remains tenant-private, always:** raw `detection_feedback.summary`, `owner_id`, `created_by`, `hunt_id`, `deployment_id` on any cross-tenant read path. `computeTenantPerformance()` is the only function that ever reads these for a specific tenant, and only ever with that tenant's own authenticated `ownerId`.

**What may be aggregated globally:** classification enum counts, distinct-owner counts, timestamps, and the canonical detection's own public fields (title, technique_id, level) — never anything identifying a customer.

**What is never exposed, anywhere in this tranche:** an owner_id, a hunt_id, a deployment_id, a connector_id, or free-text summary via any cross-tenant code path. Verified by dedicated `SAFETY CONTRACT` tests in `detection-feedback-store.test.js` and `detection-performance-engine.test.js` that submit feedback containing a realistic internal hostname string and assert it never appears in any aggregate response's serialized JSON.

**Suppression/cohort policy:** not yet implemented as a separate minimum-sample-size gate — at this platform's current scale (a handful of canonical detections, feedback counts in the single digits to low tens), a coarser per-classification distinct-owner threshold already exists (`REPEATED_REPORT_THRESHOLD = 3`, from PR #144, unchanged) for the two classifications where single-customer noise would otherwise mislead (TOO_BROAD/TOO_NARROW). No cross-tenant raw drill-down exists anywhere in this platform ("view feedback from Customer X" is not a capability that exists).

**Retention:** unchanged from PR #144 — `detection_feedback` has no automatic expiry; this tranche introduces no new retention policy decision.

## §11 — Statistical Truth Policy

`detection_feedback` rows are observations from hunts an analyst chose to run — not a random, unbiased sample. A ratio like `FALSE_POSITIVE_COUNT / HUNT_COUNT` is **not a real false-positive rate**: a customer who never hunts against a detection contributes zero signal either way, and hunts are themselves selected toward interesting activity. This tranche never computes, stores, or exposes such a ratio anywhere — not in the API, not in the UI, not in this document.

Evidence Sufficiency (§12) is deliberately binary for exactly this reason: it answers "does any real-world signal exist at all," not "how statistically confident are we" — a question this platform's current data does not support answering honestly.

## §12 — Evidence Sufficiency Model

`NO_OPERATIONAL_EVIDENCE` / `OPERATIONAL_EVIDENCE_PRESENT` — a deliberately simple 2-state model, not the finer LIMITED/MODERATE/STRONG gradient the mandate offered as an option. Justification: with a 5-rule corpus and zero prior calibration data, any finer threshold (e.g. "3+ reports = MODERATE") would be an arbitrary number dressed as a defensible one. The mandate's own fallback language explicitly sanctions this simpler model when no defensible finer threshold exists. `sample_size > 0` is the entire rule.

## §13 — Deterministic Quality State Engine — Priority Ordering & the Contextual-Gate Correction

`detection-performance-engine.js#deriveQualityState()` — priority order, first match wins:
1. **REVOKED / DEPRECATED** — a manual governance override (`detection-rules.js#updateRuleStatus()`, unchanged), always wins, independent of feedback, and applies to every version of that detection (not just the current one).
2. **TECHNICAL_FAILURE** — canonical gate status `BLOCKED` (current version only), OR ≥1 distinct customer reported `QUERY_ERROR`.
3. **REVIEW_REQUIRED** — ≥1 distinct customer reported `TELEMETRY_MISMATCH`.
4. **TUNING_RECOMMENDED** — 3+ distinct customers reported the same `TOO_BROAD` or `TOO_NARROW` (reusing PR #144's `REPEATED_REPORT_THRESHOLD` unchanged).
5. Floor: `INSUFFICIENT_EVIDENCE` (zero feedback) or `HEALTHY` (feedback exists, no trigger).

Every branch returns an explicit, human-readable reason string — verified by a dedicated test that every branch's reason is non-trivial prose, never "AI detected poor quality." The mandate's own example — "query invalid + 5 prior true positives → REVIEW_REQUIRED / TECHNICAL_FAILURE" — is satisfied by construction: technical-failure checks run before, and independent of, how positive the accumulated feedback looks.

**The contextual-gate correction (found via live QA, not assumed):** an earlier version of this engine also triggered REVIEW_REQUIRED from canonical gate status `REVIEW_REQUIRED`. Live-tested against the real canonical store (§32), this proved to be **near-universally true for every real detection**, not a genuine signal — because `resolveCanonicalDetection(id, [])` (no specific customer entity context available at this global level) always yields `attackEvidenceState: 'UNKNOWN'`, and `evaluateReleaseGate()` always adds `ATTACK_MAPPING_UNCERTAIN` whenever evidence is `UNKNOWN`, which alone produces gate status `REVIEW_REQUIRED`. This was corrected before certification: only gate status `BLOCKED` (which requires a genuine structural/telemetry/fixture hard-blocker — none of which depend on ATT&CK evidence state) feeds Quality State's technical-failure tier; the REVIEW_REQUIRED tier is now purely feedback-driven (`TELEMETRY_MISMATCH`). `canonical_status` (including the real, informative `REVIEW_REQUIRED` value) is still shown on the Validation axis for transparency — it simply no longer, by itself, drags Quality State down.

## §14 — Signal Attribution & the "Credit" Boundary

A hunt's `CONFIRMED_THREAT` disposition (PR #144) does not, by itself, mean any specific linked detection was a true positive — `hunt_findings` has no `detection_id` column, and the evidence/observation/query chain to a specific detection remains multi-hop and optional (confirmed unchanged from PR #144's own design). Detection feedback (`detection_feedback.classification`) is the ONLY mechanism that attributes a specific outcome to a specific `(detection_id, detection_version)` — an analyst must explicitly submit it; this tranche never infers or backfills feedback from a hunt's disposition alone.

## §15 — Review Priority Model

A TIER (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`), never an opaque numeric score — computed from exactly two auditable inputs: quality-state severity, and whether it currently affects live customer deployments (`deployment-store.js#countDeploymentsByDetection()`, global, count-only). `threat_relevance` (the detection's own `level`), `recency` (`last_feedback_at`), and `multiple_environments` (`distinct_owners > 1`) are reported as separate, transparent factors alongside the tier — deliberately not folded into the tier math, so the tier's meaning stays auditable.

## §16 — Tuning Recommendations

Deterministic, per-reason-code guidance text (`TUNING_RECOMMENDATIONS` map) — never an auto-generated replacement query. `QUERY_ERROR` → re-run structural/query validation; `TELEMETRY_MISMATCH` → review normalized field mapping; `REPEATED_TOO_BROAD`/`REPEATED_TOO_NARROW` → review conditions against fixtures. Mirrors `detection-intelligence.js#falsePositiveGuidanceFor()`'s own honesty discipline (general, defensible guidance, never a fabricated per-technique claim).

## §17 — No Automatic Rule Modification — Control Plane Boundary

Verified by code inspection: `detection-performance-engine.js` and `api/v1/detections/performance.js` contain zero write paths into `detection-rules.js`'s content, `governance.status`, `detection_deployments`, or any release/version field. Every output (Quality State, Review Priority, Tuning Recommendations) is read-only, advisory text for a human analyst. A new detection version continues to require an explicit `storeRule()` call (unchanged, Task pipeline); release continues to require the existing validation gate; deployment continues to require the existing PR #143 preview/approval/deploy flow.

## §18 — D1 Schema & Migration

`migrations/0006_detection_performance_intelligence.sql` — one new table, additive-only (`CREATE TABLE IF NOT EXISTS`). No `detection_performance_aggregates` or `detection_quality_history` table was added — see §26 for the evidence-based rationale (on-demand computation, matching this platform's recurring "coverage is never persisted" discipline).

## §19 — Store Layer (`detection-version-store.js`)

Exports: `SNAPSHOT_SOURCES`, `computeContentHash`, `snapshotVersion`, `getVersionSnapshot`, `listVersionSnapshots`, `backfillCurrentVersions`. Pure persistence + one deterministic hash function; no business logic. 21 dedicated tests (`detection-version-store.test.js`).

## §20 — Engine Layer (`detection-performance-engine.js`)

Composes `hunt-engine.js#resolveCanonicalDetection()` (unchanged), `detection-feedback-store.js#computeGlobalReviewMetrics()`/`computeTenantPerformance()` (new, additive), `detection-version-store.js` (new), and `deployment-store.js#countDeploymentsByDetection()` (new, additive) — never re-implements any of them. Exports: `deriveQualityState`, `computeDetectionQuality`, `getVersionHistory`, `computeReviewPriority`, `computeReviewQueueEntry`, `computeReviewQueue`.

## §21 — API Layer & Router Wiring

`api/v1/detections/performance.js` — new route (`api/v1/detections/rules`/`rules/[id]` already existed at this namespace; `performance` is a new sibling, no collision with the pre-existing, unrelated `api/v1/quality/index` route). Registered in `workers/lib/route-table.js`'s `DIRECT_API_HANDLERS`, `workers/lib/router.js`'s `HANDLER_MODULES`, and `vercel.json`'s `functions` block. Handler-count assertions bumped 38 → 39 in `route-table.test.js` (both the filesystem auto-discovery parity check and the `DIRECT_API_HANDLERS ∪ DYNAMIC_API_HANDLERS` count) — both still pass. `router.test.js`'s HANDLER_MODULES↔route-table parity check (fully dynamic, no hardcoded count) passes unmodified.

4 actions: `quality` (GET, authenticated, any tier), `version-history` (GET, authenticated), `my-performance` (GET, authenticated, owner-scoped), `review-queue` (GET, `X-Admin-Key` gated — reuses `security.js#verifyAdminKey()`/`adminIpRateLimit()` exactly as `api/v1/admin.js` already does, including the `auditLog('ADMIN_AUTH_FAIL', ...)` pattern on rejection).

## §22 — UI/UX — Detection Detail Page

`detection-quality.html` (new) — the four axes (Validation, Evidence Sufficiency, Quality State, Operational Evidence) as separate cards, never collapsed into one score; a reason box; tuning recommendations when present; a private "Your Operational Feedback" section; full version history. Linked from `hunts.html`'s detection-linkage view and `deployments.html`'s deployment list (one-line additive links, matching the established `hunts.html ↔ deployments.html` cross-linking precedent from PR #144). Dark Sentinel Apex theme, in-memory-only API key, `esc()`-escaped throughout.

## §23 — UI/UX — Internal Review Queue

`review-queue.html` (new) — admin-key-gated, filterable by priority tier, sortable table showing every canonical detection's current quality state and priority — explicitly not a "best detection" leaderboard (no ranking of healthy detections against each other; the empty/healthy end of the list carries no comparative ordering beyond "nothing to review").

## §24 — Version History UX & Honest Content-Availability

`getVersionHistory()` joins the live `history[]` metadata (always available) with `detection_versions` content snapshots. A version with no snapshot row is marked `content_available: false` — verified live (§32) against the real, 12-entry history of rule `65b906336880ed01`: only the current version (v1.0.9, post-backfill) shows `content_available: true`; all 11 prior versions honestly show unavailable, never fabricated.

## §25 — Idempotency, Replay-Safety & Revision Handling

No materialized counters exist anywhere in this tranche (see §26) — every aggregate is a fresh `SELECT` over raw `detection_feedback`/`detection_deployments` rows on every call. This makes "double counting" structurally impossible: there is no counter to increment twice. Proven by a dedicated test (`detection-feedback-store.test.js`) that computes the same aggregate twice with no writes in between and asserts byte-identical results.

A "revision" (an analyst correcting an earlier FALSE_POSITIVE report to TRUE_POSITIVE after further investigation) is handled the mandate's own preferred way — audit-preserving, never destructive: `detection_feedback` has no update/delete path (unchanged from PR #144; feedback is append-only). A revision is simply a new row; the aggregate correctly reflects both the original and the correction, proven by a dedicated test.

**Disclosed, pre-existing limitation, not introduced by this tranche**: `submitFeedback()` (PR #144) has no request-level idempotency key — a genuine network-retry duplicate submission would create two rows and be double-counted as two independent observations. This is a Task 2 characteristic, unchanged here; Task 3 introduces zero new feedback-write paths (all 4 of this tranche's new endpoints are read-only except the pre-existing `feedback-submit` action, untouched). Flagged in `platform/open-issues.md` (§44) rather than fixed opportunistically in an unrelated tranche.

## §26 — Aggregation Strategy Decision

Evidence-based: no materialized `detection_performance_aggregates` or `detection_quality_history` table was built. At this platform's current scale (5 canonical detections, feedback counts in the single/low-double digits), an on-demand `GROUP BY` query is milliseconds and requires zero reconciliation machinery, zero rebuild-drift risk, and zero second copy of state that could go stale. This matches the platform's own recurring, already-established "coverage/signal is never persisted, only recomputed" discipline (`hunt-engine.js`'s own header comments; `detection-feedback-store.js`'s `computeFeedbackSignal()` precedent). Revisit only with real evidence of read-volume or join-cost problems at genuine scale — not speculatively.

## §27 — Multi-Tenant Isolation Test Evidence

- `detection-performance-engine.test.js`: `computeDetectionQuality`'s SAFETY CONTRACT test (owner_id/summary never appear in a quality response).
- `detection-feedback-store.test.js`: `computeTenantPerformance` isolation test (two owners, two independent counts) + SAFETY CONTRACT test on `computeGlobalReviewMetrics`.
- `detections-performance.test.js` (HTTP layer): a real, non-mocked, end-to-end test submitting feedback as two different authenticated tenants and asserting each `my-performance` response reflects only its own caller — including an explicit adversarial case proving `ownerId` is always re-derived from `authenticate()`, never trusted from any client-controlled value.
- Live-verified (§32, workflow E): `sentinel_tenant_b`'s `my-performance` call correctly returns zero feedback for a detection only `sentinel_tenant_a` had submitted feedback on.
- Live-verified (§32): the real HTTP input-validation whitelist (`sec.assertFieldWhitelist`) rejects a client-supplied `detection_version` field on `feedback-submit` outright (`INVALID_FIELDS`) — confirming version-pinning is 100% server-derived, never client-controlled, at the validation layer, not merely "silently ignored."

## §28 — Security Threat Model

| Threat | Mitigation | Evidence |
|---|---|---|
| Cross-tenant feedback submission (Customer A submits for Customer B's hunt/deployment) | Unchanged from PR #144: `hunt-engine.js#submitDetectionFeedback()` independently re-verifies ownership of any supplied `hunt_id`/`deployment_id` before writing | Pre-existing PR #144 test coverage, re-verified unaffected |
| Global-aggregate poisoning (one tenant floods counts) | `REPEATED_REPORT_THRESHOLD = 3` distinct owners (PR #144, unchanged) already requires multiple independent tenants before TOO_BROAD/TOO_NARROW can trigger anything | `detection-feedback-store.test.js` |
| IDOR/BOLA on new endpoints | `quality`/`version-history` take only a `detection_id` (a shared, non-tenant-scoped resource by design — same exposure model as the pre-existing `detections/rules` endpoints); `my-performance` always re-derives `ownerId` from `authenticate()` | `detections-performance.test.js` |
| Admin-key bypass on `review-queue` | Reuses `security.js#verifyAdminKey()` unchanged (timing-safe compare, X-Admin-Key only, never Authorization) | `detections-performance.test.js`: wrong key, missing key, and a valid CUSTOMER key all rejected |
| Cache isolation | No caching layer exists anywhere in this tranche (on-demand computation only) — no shared-cache-key leak surface | By construction, §26 |
| Sandbox/test feedback contaminating production quality signal | Not separately distinguished in this tranche (no environment-tagging on `detection_feedback` exists platform-wide); disclosed limitation, §36 | N/A |
| XSS | `detection-quality.html`/`review-queue.html` use the same `esc()` escaping convention as every existing page | Code review |
| SQL injection | All new queries use `?` placeholders exclusively, matching `d1.js`'s established convention | Code review |
| Prototype pollution | No `Object.assign`/spread of unvalidated request-body keys into a lookup object anywhere in this tranche | Code review |
| DoS via unbounded reads | `review-queue` scans the full canonical rule set (currently 5 rules) — bounded by the corpus size itself; revisit with pagination only if the corpus grows materially (§26) | Code review |

## §29 — Test Suite Summary

| File | Tests | Focus |
|---|---|---|
| `api/_lib/__tests__/detection-version-store.test.js` | 21 | Content-hash determinism, snapshot idempotency/immutability, version isolation, backfill |
| `api/_lib/__tests__/detection-rules-version-snapshot.test.js` | 4 | Hook wiring on the REAL `storeRule()` function body (fs fully mocked — never touches the real canonical JSON file), fire-and-forget safety |
| `api/_lib/__tests__/detection-performance-engine.test.js` | 20 | `deriveQualityState`'s full deterministic priority ordering (pure-function), the contextual-gate correction, version immutability (requirement D), review queue sorting/privacy |
| `api/_lib/__tests__/detection-feedback-store.test.js` (extended) | 17 (8 new) | `computeTenantPerformance`/`computeGlobalReviewMetrics` isolation and safety contracts, replay-safety, revision handling |
| `api/_lib/__tests__/deployment-store.test.js` | 4 | `countDeploymentsByDetection` cross-tenant-safe counting |
| `api/v1/__tests__/detections-performance.test.js` | 13 | Full HTTP contract: auth requirements, param validation, admin-key gate, genuine end-to-end tenant isolation |

## §30 — Full Regression Results

`npx jest` (full suite, no path filter): **2576 passed, 0 failed, 60 skipped (1 pre-existing, unrelated suite), 86 of 87 suites passed.** Run both before this tranche's changes (baseline) and after (final) — identical pass count outside this tranche's own new/extended files, confirming zero regression.

## §31 — Browser QA: Six Required Workflows

A scratch Node server (not committed) wrapped the REAL `workers/lib/router.js#handleFetch` — the same dispatch code Cloudflare Workers runs — with the real fake-d1 fixture swapped in for D1 (safe, in-memory, no Cloudflare credentials involved) and a QA-only `authenticate()` swap mapping fixed test API keys to two distinct tenant identities (avoiding the need for a live/fake Redis just to prove tenant isolation). `detection-rules.js`'s real, unmodified, fs-backed canonical store was read **read-only** throughout — `storeRule()` (the one write path) was never invoked live, to guarantee zero risk to the real committed `data/detection-rules-canonical.json`; that write path is instead proven with the real function body via the fully-fs-mocked `detection-rules-version-snapshot.test.js` (§29).

- **A (real detection + hunt → performance → quality)**: Real rule `65b906336880ed01` ("Shadow Copy Deletion Preceding Ransomware Encryption", T1490). Before feedback: `INSUFFICIENT_EVIDENCE`. After submitting real `TRUE_POSITIVE` feedback via the unchanged `feedback-submit` action: `HEALTHY`, `evidence_sufficiency: OPERATIONAL_EVIDENCE_PRESENT`, `sample_size: 1`. `my-performance` correctly showed the submitting tenant's own count.
- **B (zero-feedback → INSUFFICIENT_EVIDENCE)**: Demonstrated above (pre-feedback state) and independently for `d3a50ec619c76f3f` (T1204.002), which has zero feedback and correctly reports `INSUFFICIENT_EVIDENCE`/`priority_tier: NONE`.
- **C (QUERY_ERROR → REVIEW_REQUIRED/TECHNICAL_FAILURE → tuning candidate, no auto-release)**: Submitted real `QUERY_ERROR` feedback against rule `ac348bab79c7a3eb`. Result: `quality_state: TECHNICAL_FAILURE`, reason correctly names the QUERY_ERROR trigger, `tuning_recommendations` correctly populated with the deterministic re-run-validation guidance text. `canonical_status`/`detection_version` were unchanged before and after — confirming no auto-release, no auto-mutation.
- **D (version immutability)**: Live-confirmed the HTTP-layer security property that makes this possible: attempting to POST an explicit `detection_version` on `feedback-submit` is rejected outright by the field whitelist (`INVALID_FIELDS`) — version-pinning is 100% server-derived. The full "v3 review-required → v4 candidate → v4 released → v3 immutable" lifecycle is proven at the store/engine level by `detection-performance-engine.test.js`'s dedicated "requirement D" integration test (real `feedbackStore.submitFeedback`/`computeDetectionQuality`, pinned to explicit historical vs. current versions) — not repeated live to avoid any live `storeRule()` call.
- **E (tenant isolation)**: `sentinel_tenant_b`'s `my-performance` call for a detection only `sentinel_tenant_a` had fed back on correctly returned `{total_feedback: 0, classification_counts: {}}`.
- **F (drift context)**: Verified by construction and live inspection: every `quality` response across all of the above never contains a deployment-state field (`state`, `DRIFTED`, etc.) — Quality State and deployment drift are cleanly separate concerns by design; drift itself remains PR #143/#144's own unchanged, already-certified `resolveDeploymentLinkage()` behavior.

Two full Playwright passes (Chromium, 1440×900) against `detection-quality.html` and `review-queue.html`: **zero real application console/page errors** across 4 checked page states (the only 2 console entries observed were (1) `googletagmanager.com`/`fonts.googleapis.com` being blocked by this sandbox's own network policy — confirmed via a direct `requestfailed` probe naming those exact external hosts, present identically on every pre-existing page in this codebase — and (2) the intentionally-tested wrong-admin-key 401, which is the correct rejection being exercised, not a defect). Screenshots captured for `detection-quality.html` (both a BLOCKED/TECHNICAL_FAILURE and a HEALTHY real detection) and `review-queue.html` (5 real detections, sorted HIGH→NONE, filter tabs with correct counts).

## §32 — Real Findings Surfaced By This Tranche

Building the Review Queue immediately surfaced a genuine, previously-invisible fact about the real production detection corpus: **2 of the 5 real canonical detection rules (`fbc0da003ab2d073` "Suspicious PowerShell Execution" and `9a5467dc8ae03f68` "Registry Run Key Persistence From User-Writable Path") are canonically `BLOCKED`** — a real structural/telemetry/query defect exists in their committed content today (`fbc0da003ab2d073`'s `lifecycle_reasons`: `INVALID_QUERY`, `INVALID_LOGSOURCE`, `UNSUPPORTED_TELEMETRY`), independent of any customer feedback. This tranche does not fix or modify that content — doing so is an unrelated, unrequested change outside this tranche's scope and would risk the real committed data file. It is disclosed here, and in `platform/open-issues.md` (§44), as a Day-1, actionable finding for an operator to address via the existing, unchanged `updateRuleStatus()`/manual-review governance path.

## §33 — No False Autonomy Compliance

Nothing in this tranche merges its own PR, exposes tenant-private data, generates fake production efficacy evidence, automatically rewrites a detection, automatically releases a version, automatically redeploys a customer's configuration, or performs any response action. Every capability built is read-only advisory intelligence for a human analyst or the platform operator.

## §34 — Performance & Bundle Impact

New client-side pages (`detection-quality.html`, `review-queue.html`) are static, vanilla-JS, no new third-party script dependency beyond the pre-existing gtag/fonts pattern already on every page. Server-side: `review-queue`'s full-corpus scan is O(5) at current scale; every other new endpoint is O(1) queries per call. No new build-time dependency. `scripts/build-cloudflare-assets.js`'s static-file allowlist extended by exactly 2 entries for the 2 new pages.

## §35 — Known Limitations & Honest Disclosures

1. **Pre-existing, unrelated asset-manifest gap discovered while extending it**: `scripts/build-cloudflare-assets.js`'s `PUBLIC_ROOT_FILES` allowlist was already missing `hunts.html`, `deployments.html`, `dossier.html`, `defense-profile.html`, and `workbench.html` before this tranche — meaning those pages are not served under the Cloudflare Workers static-asset path (`dist-public/`) today, independent of Vercel (which needs no such manifest and serves them directly). This tranche adds its own 2 new pages to the list but does not fix the pre-existing 5-page gap, which is unrelated to Detection Performance Intelligence — flagged in `platform/open-issues.md` (§44) rather than fixed as a side effect.
2. **Feedback submission has no request-level idempotency key** (§25) — a pre-existing PR #144 characteristic, not introduced or fixed here.
3. **No environment-tagging exists on `detection_feedback`** to distinguish sandbox/test feedback from production feedback at the platform level — this tranche's global aggregation therefore cannot yet reliably exclude non-production signal. Disclosed, not fixed (would require a schema change to a table this tranche deliberately did not modify beyond its own additive migration).
4. **A past version's canonical validation-gate status cannot be re-evaluated historically** — `detection_versions` does not capture evidence-linkage fields (`source.articles`/`campaigns`), so `computeDetectionQuality()` for a non-current version only ever applies the feedback-derived tiers, never the gate-derived ones (§13, §6). Disclosed as a deliberate scope boundary, not an oversight.
5. **Version content prior to this tranche's backfill is permanently unrecoverable** for the 3 real rules with multi-version history (§5) — this tranche stops future loss; it cannot undo past loss.
6. **Suppression/minimum-cohort-size policy is not a separately implemented gate** (§10) — the existing 3-distinct-owner threshold serves this purpose today at current scale; revisit with evidence if the corpus grows.

## §36 — Backward Compatibility & Zero Unnecessary Modification

Every existing exported function signature, API route, response shape, and D1 table is unchanged. The 4 modified existing files (`detection-rules.js`, `detection-feedback-store.js`, `deployment-store.js`, `fake-d1.js`) each received purely additive changes — new functions/hooks/branches, zero removed or altered existing behavior, confirmed by the zero-regression full-suite run (§30). `computeFeedbackSignal()`'s existing exact 3-key return shape (`{signal, reason_codes, sample_size}`) is verified unchanged by its own pre-existing strict-shape test, still passing.

## §37 — Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `computeFeedbackSignal`, `resolveCanonicalDetection`, `detection-rules.js#getRule/loadCanonical`, `feedback-submit` HTTP action, `security.js#verifyAdminKey/adminIpRateLimit`, `payment-utils.js#auditLog` |
| Existing API routes extended (not duplicated) | `api/v1/detections/*` namespace (new sibling `performance.js`, no collision) |
| Existing pages extended (not replaced) | `hunts.html`, `deployments.html` (one-line links each) |
| New components introduced (justified by gap analysis) | `detection-version-store.js`, `detection-performance-engine.js`, `api/v1/detections/performance.js`, `detection-quality.html`, `review-queue.html` — none pre-existed |
| Duplicate components introduced | **0** |
| Duplicate routes introduced | **0** |
| Backward compatibility preserved | **PASS** |
| Build passing with zero errors | **PASS** (full jest suite, §30) |

## §38 — Engineering Constitution Compliance Checklist

```
☑ Principle 1 — Zero Unnecessary Modification: 4 existing files touched, each purely additive.
☑ Principle 2 — Additive First Architecture: one new table, one new route, two new pages; nothing replaced.
☑ Principle 3 — Single Source of Truth: quality-state trigger math lives only in deriveQualityState(); computeGlobalReviewMetrics composes, never re-derives, computeFeedbackSignal.
☑ Principle 4 — Reuse Before Build: §3/§37.
☑ Principle 5 — Backward Compatibility: §36.
☑ Principle 6 — Production Stability First: §30, zero regressions.
☑ Principle 7 — Observable Everything: every quality-state branch carries an explicit reason; admin-auth failures audit-logged (existing mechanism, reused).
☑ Principle 8 — Commercial Readiness: surfaces real, actionable detection-quality findings (§32) directly supporting enterprise trust/credibility in the detection corpus.
☑ Principle 9 — Security First: §28.
☑ Principle 10 — Performance Before Features: §34.
☑ Proof Before Change / Blast Radius: applied at each of the 4 existing-file modifications above.
☑ Deprecation Instead of Deletion: nothing deprecated or removed this tranche.
☑ Reuse Report completed: §37.
```

## §39 — Next-Transformation Ranking

Recorded for the resume checkpoint, in priority order:
1. Controlled Read-Only SIEM Hunting Connectors (real ad-hoc query execution against a customer's SIEM — currently deferred, PR #144 §9).
2. Detection Tuning & Candidate Recommendation Engine (an analyst-facing workflow to turn a TUNING_RECOMMENDED signal into an actual v_next candidate — this tranche stops at recommending, never drafting).
3. MSSP Multi-Workspace Defense Operations.
4. Customer Exposure/Asset Relevance Context.
5. Executive Defense Posture/Coverage Intelligence.
6. Controlled SOAR Recommendation Layer — explicitly NOT to be implemented without separate, explicit authorization.

## §40 — Verdict

**CONDITIONAL GO.**

GO on: the core mission (deterministic, non-probabilistic Quality State + Evidence Sufficiency + Review Priority + Tuning Recommendations, privacy-safe throughout, zero automatic rule modification, zero regression, real live-data verification including a genuine self-correction found via that live testing).

Conditional on the operator: (1) reviewing the 2 real BLOCKED detections surfaced in §32 through the existing manual governance path; (2) being aware of the pre-existing Cloudflare asset-manifest gap (§35.1) affecting 5 unrelated pages, tracked separately; (3) running `scripts/backfill-detection-version-snapshots.js --apply` against the real production D1 database before relying on version-history content availability in production (this PR does not run it against production — only against the QA session's own isolated in-memory fixture).
