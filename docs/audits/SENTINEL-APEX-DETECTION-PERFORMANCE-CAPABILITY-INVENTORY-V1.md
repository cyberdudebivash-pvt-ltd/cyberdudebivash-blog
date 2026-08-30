# SENTINEL APEX — Detection Performance Intelligence: Reuse-Before-Build Capability Inventory v1

**Date:** 2026-08-30
**Scope:** Reuse-before-build audit preceding the Detection Performance Intelligence, Defensive Efficacy Fabric, Privacy-Safe Analyst Feedback Aggregation, Detection Review Prioritization & Closed-Loop Defense Quality Engine v1 tranche, per Principle 4 (Reuse Before Build) and Section 0 Level 4 (Reuse) of this repository's governance constitution. Performed via a combination of a dedicated research pass and direct reads of every candidate file — not assumed from names or prior-session memory.

---

## 1. Executive finding

No prior art exists anywhere in this repository for detection quality/efficacy/performance scoring, review prioritization, or tuning recommendation — this genuinely is new capability, not a rebuild of something that already exists. The audit's real value was instead **finding the one existing thing that DOES need extending, and finding a real, already-occurred defect that must be closed before the new capability can honestly claim its own core premise (that a detection version's feedback is meaningfully pinned)**:

1. **`detection-rules.js#storeRule()` overwrites content in place on every version bump** — `history[]` has only ever recorded metadata, never content. Confirmed directly against `data/detection-rules-canonical.json`: of the 5 real canonical rules, 3 have multiple real version bumps, and every one of them has already, permanently lost recoverable content for at least one historical version. A platform that pins operational feedback to `(detection_id, detection_version)` cannot honestly call that pinning meaningful without fixing this first — see the full evidence trail in the certification doc §5.
2. **`detection-feedback-store.js#computeFeedbackSignal()` (PR #144) is the exact right shape to extend, not replace.** It is already the one deliberate cross-tenant aggregate read in the platform, already proven safe by its own dedicated tests, and already implements the precise privacy contract (aggregate-only, never a raw row) this new tranche needs. The correct move is composing it, never re-deriving its trigger/threshold logic a second time.
3. **The dead, unwired 43-file TypeScript `lib/governance/*` stack** (`quality-gates.ts`, `confidence-engine.ts`, `reviewers.ts`, `workflow.ts`) has names that sound directly on-point for this exact tranche. Re-confirmed (independently, not trusting the prior audit's memory alone) that it has zero live-path overlap: nothing in the live `api/`/`workers/` tree imports from `lib/`, and `platform/open-issues.md` Issue 29/`platform/capabilities.md` already document this. Not used.
4. **The internal Redis-backed SOC Workbench** remains inapplicable for the same two reasons established in round 12's own audit (no `owner_id`/tenancy concept; `PRODUCTION-RUNTIME-POLICY.md` bars new Redis dependency for new capability) — re-confirmed, not re-litigated.

---

## 2. Capability matrix

| Capability | Existing? | Tenant scoped? | Aggregated? | Customer visible? | Gap / Decision |
|---|---|---|---|---|---|
| Detection feedback classification (TRUE_POSITIVE/FALSE_POSITIVE/USEFUL_SIGNAL/TOO_BROAD/TOO_NARROW/TELEMETRY_MISMATCH/QUERY_ERROR/TUNING_REQUIRED/NO_SIGNAL) | Yes — PR #144, `detection_feedback` table | Yes (storage) | No (storage) | Yes (own data) | Reuse unchanged. No overlapping/synonymous vocabulary invented. |
| Cross-tenant aggregate review signal | Yes — `computeFeedbackSignal()`, PR #144 | No (deliberate exception) | Yes (count-only) | Indirect (feeds a global signal) | Reuse unchanged, compose (not re-derive) for Quality State's feedback-derived tiers |
| Detection version content history | **No — confirmed absent.** `history[]` metadata only, content overwritten on every bump | N/A | N/A | Partially (current version only) | Genuinely new: `detection_versions` table + `detection-version-store.js` |
| Detection validation/release gate (RELEASED/BLOCKED/REVIEW_REQUIRED/REVOKED/DEPRECATED) | Yes — `detection-intelligence.js`, via `hunt-engine.js#resolveCanonicalDetection()` | No (shared resource) | N/A | Yes | Reuse unchanged as the Validation axis input — see §1.4 of the certification doc for the one correction needed (gate `REVIEW_REQUIRED` alone is not a genuine global signal without entity context) |
| Tenant-scoped detection performance counts ("your operational feedback") | **No — confirmed absent.** Only per-detection feedback *listing* existed (`listFeedbackForOwner`), never aggregated counts | N/A | N/A | N/A | Genuinely new: `computeTenantPerformance()`, additive to `detection-feedback-store.js` |
| Deployment reach (how many customers currently deploy a detection) | Partially — `detection_deployments` table exists (PR #143), but no cross-tenant COUNT function | N/A | No | No | Genuinely new: `countDeploymentsByDetection()`, additive to `deployment-store.js`, count-only |
| Quality state / efficacy scoring | **No — confirmed absent anywhere**, including the dead `lib/governance/quality-gates.ts` (zero live-path overlap) | N/A | N/A | N/A | Genuinely new: `detection-performance-engine.js#deriveQualityState()` — deterministic, never an ML score |
| Review queue / prioritization | **No — confirmed absent** | N/A | N/A | No (internal only) | Genuinely new: `computeReviewQueue()`, admin-key gated (reuses `security.js#verifyAdminKey()`/`adminIpRateLimit()` unchanged, same pattern `api/v1/admin.js` already uses) |
| Tuning recommendation text | **No — confirmed absent** | N/A | N/A | Yes | Genuinely new: deterministic, per-reason-code guidance map, mirroring `detection-intelligence.js#falsePositiveGuidanceFor()`'s own honesty discipline (general guidance, never a fabricated per-technique claim) |
| Admin-key authentication gate | Yes — `security.js#verifyAdminKey()`/`adminIpRateLimit()`, already used by `api/v1/admin.js` | N/A (operator-only) | N/A | No | Reuse unchanged for the new internal Review Queue endpoint |
| Router/route-table/vercel.json registration | Yes — established 3-point pattern (`HANDLER_MODULES`, `DIRECT_API_HANDLERS`, `vercel.json` functions block) | N/A (infrastructure) | N/A | N/A | New `api/v1/detections/performance.js` registered following the exact existing pattern — confirmed no collision with the pre-existing, unrelated `api/v1/quality/index` route |
| D1 test-fixture extension pattern | Yes — `fake-d1.js`'s per-migration Map/array block + `exec()` branch pattern | N/A (test infra) | N/A | N/A | New `detection_versions` Map + dispatch branches, following the `0005` block's shape exactly; one real substring-collision risk found and avoided during this extension (see §3) |
| Static-asset build manifest for new customer-facing pages | Yes — `scripts/build-cloudflare-assets.js`'s `PUBLIC_ROOT_FILES` allowlist | N/A (build infra) | N/A | N/A | Extended with the 2 new pages; a pre-existing gap (5 unrelated pages already missing) was discovered, not fixed, while doing so — see `platform/open-issues.md` Issue 33 item 1 |

---

## 3. What is genuinely new (justified, not a duplicate)

Per Reuse Priority Order (Principle 4): none of the new modules/tables below has an existing equivalent, confirmed by the audit above, not assumed:

- `detection_versions` (D1, `sentinel-apex-core`, additive migration `0006`) — has zero prior art anywhere in this codebase.
- `api/_lib/detection-version-store.js` — new module, pure persistence + one deterministic content-hash function.
- `api/_lib/detection-performance-engine.js` — new composition module, calls `hunt-engine.js`/`detection-feedback-store.js`/`detection-version-store.js`/`deployment-store.js` unchanged rather than being added to any of those already-certified, shared files directly (avoids blast radius on their existing consumers — Level 5 Minimal Change Surface).
- `api/v1/detections/performance.js` — new route file.

**One real near-collision caught and avoided while extending `fake-d1.js`**: a naive new SQL alias (`distinct_owners_total`) for a new aggregate query would have been wrongly dispatched by the existing `computeFeedbackSignal()` fixture branch, because that branch matches on the substring `COUNT(DISTINCT owner_id) AS distinct_owners` — which is itself a literal prefix of the naive new alias. Renamed to `global_owner_count` to avoid the collision outright, confirmed by test.

**Deliberately NOT built, following the platform's own "computed, not stored" discipline** (Source-of-Truth Matrix's recurring pattern for Coverage/Customer Coverage/Watchable State/Detection Feedback Signal): a `detection_performance_aggregates` table and a `detection_quality_history` table. Both would be a second, driftable copy of state this platform already knows how to derive fresh from `detection_feedback` + the canonical rule store — no evidence (read volume, join cost, or a genuine need for point-in-time quality-state history) justifies materializing either at this platform's current scale.
