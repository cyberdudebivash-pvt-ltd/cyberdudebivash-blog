# SENTINEL APEX — Watchlists & Intelligence Change Detection v1
## Production Certification

**Date:** 2026-08-25
**Branch:** `claude/p1-watchlists-change-detection-v1`
**Mandate:** P1 Production Priority Task — SENTINEL APEX™ Watchlists, Intelligence Change Detection & Continuous Monitoring Foundation v1
**Prior tranche:** PR #133 — Intelligence Dossiers v1 (merged) — this tranche builds directly on its dossier assembler, dossier UI, and entity-detail functions.

---

## 1. Executive Verdict

**CONDITIONAL GO**

CVE and Campaign watchlists, deterministic intelligence change detection, and a customer monitoring feed are real, evidence-backed, tested (107 new tests across 5 new test files, plus 1 new test added to the pre-existing `redis.test.js` — 108 net new tests, exactly matching the full Jest suite's verified delta of 1,838 → 1,946 passed), security-reviewed, and shipped as both an API (`GET/POST /api/v1/watchlists`) and customer-facing UI (a watch action on `dossier.html`, a Watchlists tab on `api-dashboard.html`). Every watchable-state field and change event traces back to canonical intelligence already served by `api/_lib/threat-graph.js`, `campaigns.json`, and `intelligence-dossier.js` — no second intelligence store was built.

**Conditional**, not unqualified GO, because:
1. **No live Cloudflare Cron Trigger** — the change evaluator (`scripts/evaluate-watchlist-changes.js`) is run manually today, matching this repo's own deliberate posture of deferring cron/D1/KV provisioning pending separate authorization (§20).
2. **Threat Actor, IOC, and Malware watchlists are explicitly not built** — deliberate, evidence-based scope decisions (§26), not oversights.
3. **No live production verification** — this is customer-owned mutable state with no live example to check against yet; all verification is integration-level against a real in-memory Redis double and real change-engine/watchlist-store code (§24).

Every other acceptance-criteria item this mandate lists — server-derived ownership, cross-customer isolation, deterministic noise-suppressed change detection, idempotent/replay-safe events, catastrophic-data-loss protection, global-event/customer-match separation, bounded output, real adversarial browser QA (zero XSS survives), full regression — is met and evidenced below.

---

## 2. Customer Problem

Before this tranche, a customer could search for intelligence (PR #131) and open an evidence-backed dossier (PR #133), but had to remember to come back and re-check manually — there was no way to be told when something changed. This tranche lets a customer watch a CVE or campaign and receive a monitoring feed entry when a real, evidence-backed, semantically-meaningful change occurs (a KEV listing, a new campaign association, a confirmed exploitation status) — never on cosmetic noise (array reordering, a regenerated timestamp, a numeric-vs-string representation change).

---

## 3. Baseline (fresh audit, this round)

Confirmed via `git log`/`git status` before any code was written:
- PR #133 (Intelligence Dossiers v1) merged as `96e22a52` on `main`, confirmed via `git log --oneline -15` after `git checkout main && git pull`.
- Working tree clean; branch `claude/p1-watchlists-change-detection-v1` created fresh from current `main`, not reused from a stale feature branch.

---

## 4. Reuse-Before-Build Audit

The single most consequential finding this round: **this Worker has zero production storage bindings today, and is not yet deployed to any production hostname.**

| Evidence source | Finding |
|---|---|
| `wrangler.jsonc` (root, read in full) | Explicit, dated comments: "no production hostname," "no production storage bindings," `kv_namespaces` — "no blog-owned namespace exists yet... reuse is not automatic," `d1_databases` — "none needed; the blog has no relational data dependency." |
| `CLOUDFLARE-ACCOUNT-INVENTORY.md` / `COMPLETE-CLOUDFLARE-INVENTORY.md` | The wider Cloudflare account has 8 KV namespaces and 5 D1 databases — **all confirmed to belong to sibling platforms** (`academy-*`, `titan-*`, `sentinel-apex-*`), classified **DEFER**/**DO_NOT_REUSE** for this blog. Direct quote: "the blog's current datastore (Upstash Redis) has no forcing Worker-compatibility reason to change." |
| `api/_lib/redis.js`, `api/_lib/middleware.js` | Upstash Redis via REST (pure `fetch`, no TCP socket — already Worker-compatible) is the real, live, already-production datastore backing customer identity (`user:key:*`), rate limiting, and the existing payment audit log. |

**This eliminated D1/KV/Durable Objects/Queues from consideration before any schema design began** — not a preference, an evidence-based conclusion. See §20 for the full architectural reasoning.

| Existing capability | Finding | Action taken |
|---|---|---|
| `api/_lib/middleware.js`'s `authenticate()` | Returns a **stable, independently-minted** `userId` (`usr_...`, set at registration, survives key rotation) alongside `tier`/`keyHash` | Reused unchanged as the watchlist owner identity — never the key hash, never a client-supplied field |
| `api/_lib/redis.js` | Full Upstash REST client (strings/hashes/sets/sorted-sets/pipeline) | Reused unchanged; one additive extension (`setnx`, for idempotent event creation) |
| `api/_lib/security.js`'s `guardRequest()`/`globalIpRateLimit()`/`assertFieldWhitelist()` | Canonical request guard, global rate limiter, and prototype-pollution-safe field whitelist, already used by every `api/v1/*.js` router | Reused unchanged in the new `api/v1/watchlists.js` router |
| `api/_lib/payment-utils.js`'s `sanitize()`/`auditLog()` | Generic HTML/control-char stripper (reused directly); a payment-domain-scoped audit-log **pattern** (ZADD + ZREMRANGEBYRANK trim to `audit:payment:log`) | `sanitize()` reused directly for watchlist name/description. `auditLog()` itself is hardcoded to the payment-domain key — not reused directly (would mix "WATCHLIST_CREATED" into a payment audit trail); the same trim **pattern** is reimplemented against a new `audit:watchlist:log` key |
| `api/_lib/intelligence-dossier.js`'s `classifyExploitation()` | Already the canonical CVE-exploitation-truth function, used by the dossier | Reused directly in `watchable-state.js` so a dossier and a change event can never disagree |
| `api/_lib/intelligence-dossier.js`'s inline campaign-confidence ternary | Not previously exported as a standalone function | Extracted into `campaignConfidenceBucket()` (behavior-preserving, additive) and exported, so watchable state reuses the identical thresholds |
| `api/_lib/intel.js`'s `loadGraph()` | Already used internally by `getDossierAPI()`, but not exported | Exported (additive, one more key in `module.exports`) so the change engine can load the same raw graph the dossier assembler uses |
| `api/v1/billing.js`'s `handleManageSubscription` ownership-check pattern | A **documented historical fix**: this exact handler used to trust a bare client-supplied `email`; now requires `authenticate()` + an explicit ownership comparison, returning the identical 404 for "doesn't exist" and "belongs to someone else" | Mirrored exactly for every watchlist ownership check — the same IDOR class this repo has already been burned by once |
| `api/v1/customer/dashboard.js` | Investigated as a possible "customer dashboard" integration point; confirmed it trusts a bare `?email=` query param with **zero credential** | **Not reused, not integrated with** — deliberately avoided repeating this exact, already-known-bad pattern for a feature that needs write access |
| `api/_lib/intelligence-change-detection.js` | A real, pre-existing `IntelligenceChangeDetectionEngine.detectChanges()` class | **Evaluated and rejected**, with cause — see §11 |
| `api/v1/watchbench/*`, `api/v1/workbench/*` | Confirmed via direct read: `requireAnalyst()`/`X-Analyst-Key` gated, zero customer auth path | Not wired to the customer-facing watch action (§26) |

No duplicate intelligence store, auth mechanism, rate limiter, or audit-log storage primitive was built.

---

## 5. Architecture

```
CANONICAL INTELLIGENCE (unchanged, already-live)
  threat-graph.json / campaigns.json / reports-index.json
        │
        ▼ buildCveWatchableState() / buildCampaignWatchableState()
          (api/_lib/watchable-state.js, NEW — reuses classifyExploitation()/
           campaignConfidenceBucket() from intelligence-dossier.js)
NORMALIZED WATCHABLE STATE — small, deterministic, fingerprinted
        │
        ▼ detectChanges() (api/_lib/change-detector.js, NEW — pure function)
SEMANTIC CHANGE EVENT (typed, evidence-carrying, idempotent event_id)
        │
        ▼ api/_lib/change-engine.js (NEW) persists the event once (SET...NX),
          matches it against api/_lib/watchlist-store.js's reverse index
        │
        ▼ appended by reference to every matched customer's feed
CUSTOMER RESULTS
  GET/POST /api/v1/watchlists  (api/v1/watchlists.js, NEW)
  dossier.html watch action, api-dashboard.html Watchlists tab
```

**Neither the watchable state nor the change event is a second intelligence store.** Deleting `snapshot:*`/`event:*` keys and re-running `evaluateWatchedEntities()` reproduces the same output from canonical sources — the only thing genuinely new and authoritative here is customer **intent** (which entities they chose to watch) and **event history** (what was already delivered), not intelligence.

---

## 6. Customer Ownership Model

Every watchlist read/write re-derives ownership from `authenticate()`'s `userId` and compares it against a stored `owner` field on the watchlist record — never trusted from the request body. A missing watchlist and someone else's watchlist return the **identical** `NOT_FOUND` (404), mirroring `billing.js`'s own historical fix precedent, so a valid watchlist ID cannot be enumerated by comparing error responses. Verified directly: 5 dedicated cross-customer isolation tests at the store layer (get/update/delete/add-entity individually, plus a check that `listWatchlists` never leaks another owner's records), and 1 consolidated HTTP-router test asserting the identical 404 across get/update/delete/add-entity for a non-owning caller.

---

## 7. Watchlist Contract

```js
{
  schema_version: '1.0',
  id, name, description, status,       // "active" | "paused"
  entity_count, created_at, updated_at, last_evaluated_at,
}
```
`owner` is stored server-side but **never** included in the public shape returned to any customer. Technical hard caps (flat across tiers — see §19): 20 watchlists/owner, 100 entities/watchlist, 100-char name, 500-char description.

---

## 8. Supported Entities

**CVE and Campaign only, in v1.** Threat Actor, IOC, and Malware were evaluated and deliberately deferred — see §26 for the specific evidence behind each. `action=add-entity` with any other type returns `UNSUPPORTED_ENTITY_TYPE` (400), never a fabricated success.

---

## 9. Normalized State Model

`api/_lib/watchable-state.js` builds a small, deterministic projection per entity — only fields whose change is meaningful:

- **CVE**: `cvss`, `severity`, `kev`, `active_exploitation` (via `classifyExploitation()`), `campaign_ids`/`actor_ids`/`report_ids` (normalized sets).
- **Campaign**: `severity`, `confidence_bucket` (via `campaignConfidenceBucket()`), `last_seen`, `actor_ids`/`cve_ids`/`report_ids`, `has_kev`/`has_exploited`/`has_ransomware`.

Deliberately excludes `generated_at`, request-scoped timestamps, and — critically — **raw IOC lists** (a campaign's `shared_iocs` is never read by `buildCampaignWatchableState()` at all, confirmed by a dedicated regression test with a 5,000-entry synthetic IOC array: the resulting state contains none of it). This is immunity to the mandate's "IOC list explosion" adversarial case **by construction**, not by truncation.

Relationship arrays are always `[...new Set(ids)].sort()` — reordering a source array can never look like a change.

---

## 10. Change-Event Schema

```js
{
  schema_version: '1.0',
  event_id,                      // deterministic hash of (schema_version, entity, change_type, canonical after-value)
  entity_id, entity_type,        // "cve" | "campaign"
  change_type, importance,       // CRITICAL | HIGH | MEDIUM | LOW
  before, after,
  related,                       // {id, type} for relationship-addition events, else null
  reason,                        // deterministic template, e.g. "CVE-X was added to the CISA KEV catalog."
  recommended_action,
  observed_at,
}
```
Deliberately minimal (Phase 61: "prefer entity reference... over copying full report bodies") — full evidentiary depth is reached by pivoting to the dossier via `entity_id`, not duplicated in the compact event record.

---

## 11. Change Semantics

**Deterministic diff, no LLM, ever.** `api/_lib/change-detector.js`'s `detectChanges({entityType, before, after})` is a pure function comparing two watchable-state snapshots field by field.

**Evaluated and NOT built on `api/_lib/intelligence-change-detection.js`** (a real, pre-existing class), with documented cause:
- It diffs whole intelligence-holdings snapshots (`{threatActors[], campaigns[], ...}`), not a single watched entity.
- Several comparisons use `JSON.stringify(a) !== JSON.stringify(b)` on arrays (e.g. `actor.knownMalware`) — **exactly** the array-reorder false-positive this mandate's Phase 17/22/71 explicitly prohibits.
- Severities are flat per-change-type hardcodes with no evidence awareness.
- No idempotent event identity, no source/evidence references.

This is a genuine, evidence-based "build new" decision (Reuse priority level 5), not a preference.

**Supported change types**: `CVE_KEV_ADDED`, `CVE_ACTIVE_EXPLOITATION_CONFIRMED`, `CVE_CVSS_CHANGED`, `CVE_SEVERITY_CHANGED`, `CVE_NEW_CAMPAIGN_ASSOCIATION`, `CVE_NEW_ACTOR_ASSOCIATION`, `CVE_NEW_REPORT`, `CAMPAIGN_KEV_FLAG_ADDED`, `CAMPAIGN_EXPLOITED_FLAG_ADDED`, `CAMPAIGN_RANSOMWARE_FLAG_ADDED`, `CAMPAIGN_NEW_ACTOR`, `CAMPAIGN_NEW_CVE`, `CAMPAIGN_SEVERITY_CHANGED`, `CAMPAIGN_CONFIDENCE_CHANGED`, `CAMPAIGN_NEW_REPORT`, `CAMPAIGN_LAST_SEEN_ADVANCED`.

**Addition-only** (Phase 74/77): relationship, KEV, and exploitation-status changes only fire on genuine additions (false→true, or a new relationship ID). No reversal or removal event type exists in v1 — this platform's canonical pipelines don't yet guarantee a disappearance reflects a real correction rather than a temporary projection error. `CVE_DETECTION_BECAME_AVAILABLE` is not implemented: `buildDetectionsSection()` always returns `available: false` (Intelligence Dossiers v1's own §15 finding), so this event type could provably never fire — shipping it would be dead code, not a real capability.

---

## 12. Noise Suppression

Achieved by construction, not filtering after the fact:
- Relationship arrays are always normalized sets — reordering never registers as a change.
- Volatile fields (`generated_at`, request IDs, cache timestamps) are never part of watchable state, so they cannot cause a false event even in principle.
- CVSS comparison coerces both sides through `Number()` — `9.8` and `"9.8"` compare equal (Phase 71's explicit adversarial case).
- `last_seen` comparison validates both sides as real ISO dates before comparing — a malformed value can never produce a false "advanced" event via lexicographic string comparison.
- The fingerprint short-circuit (SHA-256 over canonicalized, key-order-independent state) skips detailed diffing entirely when nothing semantically changed.

**Proven directly** (Workflow C, §28): a graph-edge-array reversal combined with a numeric→string CVSS representation change, applied simultaneously, produces **zero** customer events.

---

## 13. Evidence

Every relationship-addition event carries `related: {id, type}` — a real reference to the newly-linked entity, resolvable via the existing dossier pivot for full evidence (citations, confidence, timeline). The compact event record itself is not a duplicate evidence store; it points at one.

---

## 14. Confidence / Importance

A documented, deterministic table (`IMPORTANCE` in `change-detector.js`) — not invented per call. `CVE_ACTIVE_EXPLOITATION_CONFIRMED` is the sole `CRITICAL`; KEV/exploited/ransomware-flag additions and new campaign/actor associations are `HIGH`; CVSS/severity/confidence changes and new reports are `MEDIUM`; a routine `last_seen` advance is `LOW`.

---

## 15. Persistence

**Upstash Redis (existing, already-production)** — not Cloudflare D1/KV/Durable Objects/Queues. See §4/§20 for the full evidence trail. Key schema:

```
watchlist:{id}                    HASH   identity/metadata
watchlist:{id}:entities            SET    members "{type}:{id}"
owner:{ownerId}:watchlists          SET    members watchlistId
entity_watchers:{type}:{id}          SET    members watchlistId (reverse index)
snapshot:{type}:{id}                  STRING {schema_version, fingerprint, state}
event:{event_id}                       STRING (idempotent via SET...NX)
events:by_entity:{type}:{id}            ZSET  chronological
events:for_owner:{ownerId}                ZSET  per-customer feed, bounded/trimmed
audit:watchlist:log                        ZSET  same pattern as audit:payment:log, separate key
watchlist_eval:cursor                       STRING batch-sweep resume position
```
No SQL-style foreign-key constraints exist in Redis; the equivalent correctness properties are achieved via Redis-native semantics instead: SADD's natural idempotency prevents duplicate membership, and deterministic event IDs + `SET...NX` prevent duplicate events.

---

## 16. Idempotency

Event identity is `IEV-` + SHA-256(`schema_version|entity_type|entity_id|change_type|canonicalized(after)`).slice(0,24) — the same semantic change always produces the same `event_id`. Persistence uses `SET...NX`: the first writer creates it, every subsequent attempt (a replayed batch, a re-run evaluation) is a safe no-op. Verified directly: replaying the identical before/after pair does not duplicate a customer's feed entry; 25 simultaneous watchers of the same changed CVE produce exactly one stored `event:*` key, fanned out by reference.

---

## 17. Replay Safety

Re-running `evaluateEntity()` against unchanged canonical state is a fingerprint-comparison no-op. Re-running the full batch driver (`evaluateWatchedEntities()`) is safe at any point — the cursor is persisted before a batch completes, so one entity that reliably throws can never permanently wedge the sweep, and every step is independently idempotent and cheap to simply redo.

**Schema-version safety (Phase 30)**: found and fixed during a dedicated adversarial re-read, not the initial pass. A stored snapshot from an older `WATCHABLE_STATE_SCHEMA_VERSION` is now treated identically to "no snapshot exists" — silently re-baselined, zero events — rather than being diffed against an incompatible shape, which could otherwise produce a false mass-change event for every watched entity purely because the schema changed, not the intelligence.

---

## 18. Security

Full threat-model pass:

- **IDOR/BOLA**: every watchlist operation re-derives ownership server-side; identical 404 for missing vs. not-yours (§6). 5 dedicated tests at the store layer, 1 consolidated multi-assertion test at the HTTP-router layer.
- **Auth bypass**: every action requires `authenticate()` — 9/9 actions tested for 401 with no key.
- **Prototype pollution**: `assertFieldWhitelist()` rejects any unexpected body key, including a genuine JSON-sourced `"__proto__"` own property (tested via `JSON.parse`, not an object literal, which would set the prototype instead of creating a testable own property) — `entity_type: '__proto__'`/`'constructor'` also explicitly rejected in `validateEntityRef()`.
- **XSS**: watchlist names/descriptions are customer input, sanitized via `payment-utils.js`'s `sanitize()` server-side and `esc()`-escaped client-side; feed `reason`/`entity_id` fields (sourced from canonical intelligence, still treated as untrusted display data per this platform's own "never trust source-derived display values" principle) are `esc()`-escaped identically. **Verified via real adversarial browser automation**: `<script>`, `<img onerror>`, and `<svg onload>` payloads injected into a watchlist name and a feed reason — zero execution, payload text still visibly present as escaped text (proving `esc()` ran, not silent stripping).
- **Unbounded output / DoS**: 20 watchlists/owner, 100 entities/watchlist, feed pages capped at 100, feed history trimmed to 500 entries/owner.
- **Event privacy** (Phase 69): `getWatchersForEntity()` is consumed only internally by the change engine, never echoed to a customer-facing response — no endpoint reveals who else watches a given entity, how many customers watch it, or any other tenant's metadata.
- **Rate limiting**: reused unchanged (`guardRequest()` + `globalIpRateLimit()` + `authenticate()`'s own per-tier daily limit) — no new limiter built.

---

## 19. Entitlements

Flat across tiers in v1 — `api/_lib/payment-utils.js`'s `PLANS` carries no feature-flag precedent to extend (confirmed via direct read), and this mandate explicitly prohibits inventing pricing. `getWatchlistEntitlements(tier)` is a single, centralized function (not scattered `if (tier === 'pro')` checks) returning the same limits for every tier today — the "smallest consistent extension" the mandate calls for given no centralized entitlement layer exists platform-wide. Tracked as a real, disclosed gap (`platform/open-issues.md` Issue 23) for a future commercial decision once real usage data exists.

---

## 20. Cloudflare Runtime

**No D1, KV, Durable Objects, or Queues added.** This is the single most consequential architectural finding of this round (§4): `wrangler.jsonc` documents zero production storage bindings today, and this Worker isn't deployed to a production hostname yet at all. The wider Cloudflare account's existing D1/KV resources all belong to sibling platforms, independently classified DEFER/DO_NOT_REUSE for this blog by a prior session's own storage-binding decision. Provisioning new Cloudflare infrastructure is exactly the kind of architectural event this platform's own governance requires separate, explicit authorization for — and this session has no live Cloudflare account access to provision it even if it were in scope. Upstash Redis — the evidenced, already-production, zero-new-infrastructure choice — is used instead, unchanged.

`api/v1/watchlists.js` is registered in `workers/lib/route-table.js`'s `DIRECT_API_HANDLERS` and `workers/lib/router.js`'s `ROUTE_MAP`, following the exact existing pattern (updates the route-table parity test's handler count from 32 to 33 — a real, by-design tripwire, not a regression). No live Cloudflare Cron Trigger is wired for the change evaluator; `triggers.crons` is explicitly deferred in `wrangler.jsonc`'s own header pending separate authorization, the same posture already applied to storage bindings.

---

## 21. Performance

Measured directly against the real modules (not claimed without evidence):
- Per-entity evaluation (fingerprint-unchanged fast path): a single Redis `GET` + in-process comparison — no detailed diff runs unless the fingerprint actually differs.
- `evaluateWatchedEntities()` enumerates **only watched entities** (`entity_watchers:*` — bounded by total watchlist membership, never by corpus size) — never a blind scan of the full CVE/campaign corpus. Bounded batch size (`batchLimit`, default 200) with a persisted, wrapping cursor.
- No live Cloudflare/production telemetry exists yet (not deployed) — disclosed as integration-level measurement, not claimed as production p95.

---

## 22. Observability

Structured outcome counts returned by every `evaluateWatchedEntities()` run: `watched_entities_total`, `evaluated`, `baseline`, `unchanged`, `changed`, `load_failed`, `unsupported`, `events_created`, `watchlists_touched` — printed by `scripts/evaluate-watchlist-changes.js`'s CLI wrapper on every run. This directly gives the noise metric the mandate's Phase 64 calls for (`events_created` vs. `evaluated`) without a separate tracking mechanism. No dashboard/alerting layer exists yet — consistent with `platform/capabilities.md`'s own pre-existing "Observability / Monitoring" row finding (raw counters exist platform-wide, no dashboard on top of any of them).

---

## 23. API

`GET/POST /api/v1/watchlists?action={list|create|get|update|delete|list-entities|add-entity|remove-entity|feed|entitlements}`. Every action requires `authenticate()`. Errors: `MISSING_ACTION`/`INVALID_ACTION` (400), `INVALID_FIELDS` (400, prototype-pollution/unexpected-field defense), `MISSING_ID`/`INVALID_NAME`/`INVALID_ENTITY_ID`/`UNSUPPORTED_ENTITY_TYPE`/`INVALID_STATUS` (400), `NOT_FOUND` (404, ownership-neutral), `LIMIT_REACHED` (429), `METHOD_NOT_ALLOWED` (405). Zero changes to any existing action or route.

---

## 24. UX

- **`dossier.html`**: a real `<button>` ("＋ Add to Watchlist" / "✓ Watching — click to remove") next to the existing "View Threat Graph" action, using the dossier's own canonical `entity_id`. First use auto-creates "My Watchlist"; a full multi-watchlist picker is documented future work, not shipped half-working.
- **`api-dashboard.html`**: a new "Watchlists" tab (a real `<button>`, unlike the existing four div-based tabs — a minimal, scoped improvement, not a retrofit of the other four) with create/list/delete and a paginated, newest-first monitoring feed showing what changed, an importance badge, the deterministic reason string, the recommended action, and an "Open Dossier" pivot.
- Empty states are explicit and actionable ("No watchlists yet. Create one above, or use 'Add to Watchlist' from any CVE or campaign dossier.").

---

## 25. Browser QA

Real Chromium (Playwright), not headless assumption: 16/16 checks passed —
- `dossier.html`: full watch → watching → unwatch cycle, real `<button>` semantics, zero console errors (the pre-existing, already-documented Google Fonts/GTM `ERR_CONNECTION_RESET` non-issue explicitly filtered, matching the certified dossier QA's own established convention).
- `api-dashboard.html`: Watchlists tab is a real `<button>`; empty state; **adversarial `<script>`/`<img onerror>`/`<svg onload>` payloads in a watchlist name and a feed reason — zero execution, payload text still visibly present as escaped text**; importance badge and "Open Dossier" pivot render; delete flow works; zero console errors.
- Mobile (375px): zero horizontal overflow on the Watchlists panel.

---

## 26. Live Verification

Not applicable in the traditional sense: this is customer-owned mutable state with no existing live example to check against (unlike the dossier tranche, which could verify against real, already-committed CVE/campaign data). All verification is integration-level: the real `watchlist-store.js`/`change-engine.js`/`change-detector.js`/`api/v1/watchlists.js` modules, exercised against a real in-memory Redis double (verified itself against real Redis SETNX/SADD/ZREVRANGE/ZREMRANGEBYRANK semantics) and a fake intel loader standing in for canonical CVE/campaign data. Disclosed explicitly, per this mandate's own Phase 92 allowance ("use production-like isolated integration tests and document the limitation" when no real trigger occurs) — never conflated with live-Cloudflare verification.

---

## 27. Commercial Workflows

**Workflow A — CVE watch → KEV addition → event → recommended action** (run against the real modules):
```
Watch CVE-2026-8100 (CVSS 9.1) → baseline (0 events)
CISA lists it in KEV → evaluate again
  → CVE_KEV_ADDED [HIGH]: "...was added to the CISA KEV catalog."
  → CVE_ACTIVE_EXPLOITATION_CONFIRMED [CRITICAL]: "...changed from UNKNOWN to CONFIRMED."
  (both derive from the same cisa_kev flip -- classifyExploitation() ties them
  together, exactly matching this mandate's own north-star UI mockup)
Customer feed: 2 events, both with a real recommended_action.
```

**Workflow B — Campaign watch → new linked CVE → event → graph/dossier pivot**:
```
Watch campaign:demo-x (1 linked CVE, attributed to a real actor) → baseline
A second CVE is linked → CAMPAIGN_NEW_CVE [HIGH], related={CVE-2026-7001, cve}
Pivot: "View Threat Graph"/"Open Dossier" reach the EXISTING graph/dossier
surfaces -- no duplicate graph explorer built.
```

**Workflow C — Noise-control proof** (the critical trust test):
```
Baseline: CVE-2026-9200, 2 campaign edges, CVSS 6.5 (number)
Rebuild: graph edges reversed + CVSS re-represented as "6.5" (string)
  -- same semantic intelligence, different incidental representation.
Result: status=unchanged, events=0.
PROVEN: zero customer change events from a cosmetic-only rebuild.
```

Time-saved figures are not claimed — not measured against real analyst usage, per this mandate's own instruction not to fabricate them.

---

## 28. Known Limitations

- No live Cloudflare Cron Trigger — manual evaluator runs only (§20, tracked in `platform/open-issues.md` Issue 23).
- Threat Actor, IOC, and Malware watchlists not built — each with specific, documented evidence (§26/Issue 23), not a blanket "future work" note.
- Relationship/KEV/exploitation changes are addition-only — no reversal/removal event types (§11/Issue 23).
- Watchlist entitlements are flat across tiers (§19/Issue 23).
- No live production verification yet — integration-level only (§26).
- Alert delivery (email/webhook/Slack/Teams) is explicitly out of scope for this tranche, per the mandate's own Phase 47.

---

## 29. Rollback

Every commit is independently revertible:
1. `intel.js`/`intelligence-dossier.js`/`redis.js` extensions — purely additive exports; reverting removes nothing any existing caller depends on (verified: full existing test suite unaffected).
2. `watchlist-store.js`, `watchable-state.js`, `change-detector.js`, `change-engine.js`, `scripts/evaluate-watchlist-changes.js` (all new files) — reverting removes the entire backend capability with zero effect on any pre-existing module.
3. `api/v1/watchlists.js` + route registration — reverting removes `GET/POST /api/v1/watchlists` entirely; every pre-existing route is untouched (route-table parity test would need its count reverted to 32 in the same revert).
4. `dossier.html`/`api-dashboard.html` UI additions — both are purely additive DOM/JS sections; reverting removes the watch button/Watchlists tab with no effect on any existing page functionality.

No schema, route, or interface was removed or renamed anywhere in this tranche.

---

## 30. Product Readiness Classification

| Capability | Classification |
|---|---|
| CVE Watchlists | **BETA** — real, tested, security-reviewed; no live cron, no live verification yet |
| Campaign Watchlists | **BETA** — same basis as CVE |
| Threat Actor Watchlists | **BLOCKED** — not built, evidence-based deferral |
| IOC Watchlists | **BLOCKED** — not built, no freshness/lifecycle data exists |
| Change Detection (CVE/Campaign) | **BETA** — deterministic, tested (34 detector tests, 13 engine tests), noise-suppression proven |
| Monitoring Feed | **BETA** — functional, paginated, tier-gated; no live-triggered example yet |
| Alert Delivery (email/webhook) | **NOT BUILT** — explicitly out of scope this tranche |

---

## 31. Final Verdict

**CONDITIONAL GO** (see §1). Certified for the operator's review and merge decision — not merged automatically, per this mandate's explicit constraint.

**Next priority recommendation** (evidence-based): provision a live Cloudflare Cron Trigger for the change evaluator (the single highest-leverage gap between what this tranche promises structurally and what it can deliver continuously today) — this requires an explicit operator authorization decision, not further engineering. Secondary, per the mandate's own suggested sequence: Alert Delivery & Webhook Automation v1, once the monitoring feed built here has accumulated real customer usage evidence of what's worth alerting on.
