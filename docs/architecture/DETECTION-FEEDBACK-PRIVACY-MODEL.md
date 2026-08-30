# SENTINEL APEX — Detection Feedback Privacy Model

**Effective:** 2026-08-30
**Authority:** Established by the Detection Performance Intelligence v1 mandate's explicit privacy boundary requirement.
**Status:** Active policy governing every current and future consumer of `detection_feedback` and its derived aggregates.

---

## 1. The boundary, stated once

> **Raw customer hunt/feedback content never crosses tenants. Only approved, non-identifying derived signals may be globally aggregated.**
>
> Required flow: `CUSTOMER PRIVATE DATA → TENANT-SCOPED NORMALIZATION → PRIVACY-SAFE AGGREGATE COUNTER → GLOBAL DETECTION QUALITY SIGNAL`
>
> Never: `Customer A evidence → Customer B`.

This document exists so that every future function touching `detection_feedback` (or a table like it) can be checked against one explicit contract, rather than re-deriving privacy judgment call-by-call.

---

## 2. What is tenant-private, always

- `detection_feedback.owner_id`, `.created_by`, `.summary` (free text), `.hunt_id`, `.deployment_id`.
- `hunt_findings.summary`, `.evidence_refs`; `hunt_observations.summary`; `hunt_evidence_links.description`/`.reference_url` (all PR #144, unaffected by this tranche).
- Any raw row from `detection_feedback`, in full, for any owner other than the authenticated caller.

**Only ever read with the caller's own authenticated `ownerId`** (never a client-supplied value, never another tenant's): `detection-feedback-store.js#listFeedbackForOwner()`, `#computeTenantPerformance()` (new, this tranche).

## 3. What may be aggregated globally

Exactly these dimensions, and nothing else:

- Detection ID + detection version (the shared, canonically-authored resource the signal is *about* — not customer data).
- Feedback classification enum counts (`TRUE_POSITIVE`/`FALSE_POSITIVE`/.../`NO_SIGNAL` — a closed, pre-approved vocabulary, PR #144).
- Distinct-owner counts (`COUNT(DISTINCT owner_id)`) and total counts (`COUNT(*)`) — a count is not an identity.
- Timestamps (`MAX(created_at)`) — recency, not identity.
- The canonical detection's own public fields (title, technique_id, level) — already customer-visible elsewhere.
- Deployment reach (`COUNT(DISTINCT owner_id)` from `detection_deployments` with a live state) — again, a count only.

Implemented, unchanged since PR #144: `detection-feedback-store.js#computeFeedbackSignal()`.
Implemented, new this tranche (both compose the function above rather than re-deriving its logic): `computeGlobalReviewMetrics()`, `deployment-store.js#countDeploymentsByDetection()`.

## 4. What is never exposed, by any cross-tenant code path, under any circumstance

- An `owner_id`, `hunt_id`, `deployment_id`, or `connector_id`.
- A free-text `summary`/`description`/`reference_url`.
- A raw `detection_feedback`, `hunt_findings`, `hunt_observations`, or `hunt_evidence_links` row.
- A per-owner breakdown of the global aggregate (e.g. "Customer X reported Y") — there is no function anywhere in this platform that returns this, and this document forbids ever adding one. **"View feedback from Customer X" is not, and must never become, a capability.**

Enforced by test, not just convention: every function listed in §3 has a dedicated `SAFETY CONTRACT` test that submits feedback containing a realistic internal hostname string and a real owner ID, then asserts neither ever appears in that function's serialized JSON output (`api/_lib/__tests__/detection-feedback-store.test.js`, `api/_lib/__tests__/detection-performance-engine.test.js`).

## 5. Suppression / minimum cohort size

No dedicated minimum-cohort-size gate exists as a *separate* mechanism today. The existing threshold from PR #144 already serves this purpose for the two classifications where single-customer noise would otherwise mislead: `TOO_BROAD`/`TOO_NARROW` require reports from **3 or more distinct owners** (`REPEATED_REPORT_THRESHOLD`) before they contribute any signal at all — a single customer's opinion never globalizes. `QUERY_ERROR`/`TELEMETRY_MISMATCH` are treated as meaningful from a single report, deliberately, because these indicate the detection may be structurally broken for the environment it targets, not a matter of taste — see `detection-feedback-store.js`'s own header comment for this distinction, unchanged since PR #144.

This is judged sufficient at this platform's current scale (a handful of canonical detections, feedback counts in the single/low-double digits). **Revisit only with real evidence the corpus and feedback volume have grown enough that a dedicated, separately-tunable suppression gate is needed** — not speculatively.

## 6. Sandbox / test feedback

No environment tag exists on `detection_feedback` today to distinguish sandbox/test submissions from production ones. This means global aggregation (§3) cannot currently exclude non-production signal from a shared detection's Quality State. Disclosed as an open limitation (`platform/open-issues.md` Issue 33 item 3) — not fixed here, since it would require a schema change to a table this tranche deliberately scoped its own migration to leave alone (this tranche's only schema change is the additive `detection_versions` table).

## 7. Retention

Unchanged from PR #144: `detection_feedback` has no automatic expiry or retention policy. This document does not introduce one — a retention decision is a product/legal question, not an engineering default to set unilaterally.

## 8. Maintenance rule

Any new function that reads `detection_feedback` (or any future table carrying analyst-entered or customer-entered free text) across more than one `owner_id` must be checked against §3/§4 before merging, and must carry its own `SAFETY CONTRACT` test proving it. Update this document in the same commit that adds such a function — mirroring `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`'s own maintenance discipline.
