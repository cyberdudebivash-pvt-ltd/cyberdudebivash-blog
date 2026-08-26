# SENTINEL APEX™ — Customer Telemetry & Environment-Aware Defense Coverage Fabric v1 — Certification

Branch: `claude/p0-customer-telemetry-defense-context-v1` (task-assigned branch name: `claude/p1-customer-telemetry-defense-context-v1`)
Base: `main` @ `5bf05750` (PR #141, Threat-to-Defense Fabric v1, merged)
Date: 2026-08-26

## 1. Executive verdict

**CONDITIONAL GO.**

Everything this tranche built is real, tested against real production data (CVE-2023-27351's genuinely `RELEASED` T1490 detection), and demonstrably correct across every mandated coverage state (READY / PARTIALLY_READY / TELEMETRY_GAP / UNSUPPORTED_PLATFORM / UNKNOWN / NO_VALIDATED_DETECTION / UNKNOWN_PROFILE), verified through 51 new unit/route tests plus real-browser Playwright QA driving the actual production handler code.

Conditional because: (a) the underlying detection corpus is still thin (3 `RELEASED` detections total, inherited from PR #141, unchanged this round), so most techniques on most entities honestly show `NO_VALIDATED_DETECTION` regardless of environment — a corpus-size limitation, not a compatibility-engine defect; (b) provider-specific field-level telemetry mapping is documented at `confidence:"general"` (source-exists-only, no asserted field names) for every vendor except Microsoft (Defender XDR/Sentinel — verified against the real generator's own `FIELD_MAP`) and Sysmon/Windows Security Events (well-established public event-ID schemas) — CrowdStrike Falcon, SentinelOne, Splunk CIM, and cloud-provider telemetry are honestly disclosed as source-level-only, not field-verified; (c) no SIEM/EDR connector of any kind exists or was built — this tranche is read-only compatibility assessment, never deployment, exactly as scoped.

## 2. Customer problem

PR #141 answered "how can this threat be detected?" with global, environment-agnostic detection coverage. It could not answer "can *this* customer, with *their* SIEM/EDR/telemetry, actually use that detection?" A customer with Splunk and no Sysmon deployment had no way to know whether a `RELEASED` KQL detection was usable in their environment, or what specifically was missing to make it usable. This tranche closes that gap without touching global truth: same detection, same validation, now cross-referenced against an explicit, customer-declared Defense Profile.

## 3. Baseline (re-verified, not assumed)

Fresh `main` pulled and diffed against the working tree before any code was written (commit `5bf05750`, `d65e36e0` = PR #141's merge commit confirmed present in `git log`). `wrangler whoami` re-run once at task start: **still not authenticated** — recorded as the same external Cloudflare-credential blocker documented in every prior round's certification (`SENTINEL-APEX-CLOUDFLARE-LIVE-CUTOVER-V1-CERTIFICATION.md`); not re-litigated further, and this tranche proceeded entirely against verified code architecture with no live-deployment claim made anywhere in this document.

## 4. Reuse-before-build findings

Full detail: `docs/audits/SENTINEL-APEX-CUSTOMER-DEFENSE-CONTEXT-INVENTORY-V1.md`. Headline findings:

- **No workspace/tenant model exists anywhere in this codebase** (confirmed by direct grep, not assumed) — ruling out any multi-workspace Defense Profile design this round; one profile per authenticated `owner_id`, matching `watchlist-store.js`'s exact, already-proven ownership pattern.
- **The normalized telemetry vocabulary already exists**: `detection-intelligence.js#TELEMETRY_REQUIREMENTS`'s 4 keys (`process_creation`, `process_access`, `registry_set`, `network`) are imported directly into the new taxonomy module, not redeclared.
- **The field/format-mapping engine already exists**: `detection-engine.js#FIELD_MAP`'s `_kql_table`/`_splunk_dm`/`_osquery_table` values ARE the real vendor schema targets (`DeviceProcessEvents`, `DeviceEvents`, `DeviceRegistryEvents` for Microsoft; Splunk CIM data models for Splunk) the format generators already compile against. `FIELD_MAP` was not previously exported; this round adds it to `detection-engine.js`'s `module.exports` (one additive line) so the new compatibility engine reads the real values instead of re-declaring a driftable copy — verified identical via a dedicated test (`defense-taxonomy.test.js`: "microsoft-defender-xdr ... source labels match the real generator's FIELD_MAP._kql_table values exactly").
- **A customer-owned, D1-backed CRUD router pattern already exists** (`api/v1/watchlists.js`) and is followed exactly for the new `api/v1/defense-profile.js`, rather than being bolted onto `intel.js`'s GET-only convention.

## 5. Defense Profile model

```
defense_profiles                 -- id, owner_id (UNIQUE), name, schema_version, timestamps
defense_profile_technologies     -- profile_id, category, technology_id, custom_label
defense_profile_telemetry        -- profile_id, data_source, status (AVAILABLE/PARTIALLY_AVAILABLE/NOT_AVAILABLE only)
defense_profile_audit_log        -- best-effort, capped at 10,000 rows
```

One profile per owner in v1 (mandate Phase 52; no multi-workspace foundation exists to scope multiple profiles under — confirmed in §4). `UNKNOWN` telemetry status is never a stored row value — a data source with no row IS "unknown" (see migration file's design note); setting a field back to unconfigured deletes its row rather than writing a third status string, so "missing" and "explicitly unknown" cannot represent two different stored facts.

## 6. Ownership and isolation

Every read/write derives `owner_id` exclusively from `authenticate()`'s server-issued `userId` — never from the request body (`api/v1/defense-profile.js` never accepts an `owner_id`/`profile_id` field; `FIELDS.save = ['name','technologies','telemetry']`, enforced by `sec.assertFieldWhitelist`). A missing profile and another owner's profile are indistinguishable to the caller (`getProfile()` scopes its query to the caller's own `owner_id`; there is no cross-owner read path at all, not even a 404-vs-403 distinction to leak). Verified by 5 dedicated isolation tests in `defense-profile-store.test.js` + 2 in `defense-profile.test.js` (router-level, through the real authenticated path) + 1 in `intel-defense-coverage.test.js` (customer A's profile never leaks into customer B's coverage computation).

## 7. Technology taxonomy

`api/_lib/defense-taxonomy.js`. Five categories (SIEM, EDR/XDR, Cloud, Endpoint Telemetry, Operating Systems), each with a `CUSTOM_UNMAPPED` ("Other / Not listed") escape hatch that never claims compatibility. SIEMs with no validated generator in this platform (Elastic Security, IBM QRadar, Google SecOps) are explicitly modeled with `detection_format: null` — selectable, honestly incapable of ever reaching `READY` natively (verified by test).

## 8. Telemetry taxonomy

Reused verbatim from `detection-intelligence.js` (§4). Only 3 of the 4 documented data sources (`process_creation`, `process_access`, `registry_set`) are exercised by any real buildable technique today — `network` has no buildable technique in `detectionEngine.REGISTRY` yet, disclosed here rather than silently unused.

## 9. Field mapping

Reused, not duplicated (§4). Provider entries are honestly two-tiered: `confidence: "documented"` (Microsoft Defender XDR via `FIELD_MAP`, Sysmon Event IDs 1/10/13, Windows Security Event 4688, Linux auditd execve) carry real field names; `confidence: "general"` (CrowdStrike Falcon, SentinelOne, Splunk CIM data models, cloud network logs, Windows Security 4657) carry only a source label, `fields: null` — verified by a dedicated test that every `fields: null` entry is labeled `"general"` and every `"documented"` entry has a real array.

## 10. Detection requirements

Not re-derived from a generic per-data-source template. `defense-compatibility.js#requirementsFor()` reads each canonical detection's own `attack[].id` and looks up `detectionEngine.REGISTRY[id].data_source` — the exact same source-of-truth the generator itself used to build that detection. Required *fields* (as opposed to data source) come from `detection-intelligence.js`'s own `runValidation().telemetry.fields_referenced` — the rule's real, parsed Sigma selection logic, not a guess.

## 11. Compatibility algorithm

`evaluateDetectionCompatibility(canonicalDetection, profile)`, fully deterministic, zero LLM involvement:

1. Non-`RELEASED` detections are never evaluated as compatible (`NO_VALIDATED_DETECTION`).
2. **Format gate first**: if the caller has no SIEM technology declared → `UNKNOWN` (never a guessed incompatibility). If a SIEM is declared but none of its preferred formats exist among the detection's `RELEASED` formats → `UNSUPPORTED_PLATFORM`, with `sigma_portable` disclosed but never auto-upgraded to a match (mandate Phase 26).
3. **Telemetry gate second**, only once a format matched: `rollupTelemetryStatus()` collapses one-or-more per-data-source declarations into `FULLY_AVAILABLE → READY`, `PARTIALLY_AVAILABLE → PARTIALLY_READY`, all-`UNKNOWN → UNKNOWN`, any `NOT_AVAILABLE` (with the rest not fully available) `→ TELEMETRY_GAP` — verified against the mandate's own two worked examples (Phase 21/22) as literal unit tests.

## 12. Coverage states

Six states used at the per-technique customer level: `READY`, `PARTIALLY_READY`, `TELEMETRY_GAP`, `UNSUPPORTED_PLATFORM`, `UNKNOWN`, `NO_VALIDATED_DETECTION`, plus `UNKNOWN_PROFILE` when no Defense Profile exists at all. Never compressed to covered/uncovered (mandate Phase 28).

## 13. READY semantics

Proven against real data: CVE-2023-27351's `RELEASED` T1490 detection + a profile declaring Microsoft Sentinel + `process_creation: AVAILABLE` → `READY`, `format_used: "kql"` (`defense-compatibility.test.js`, `intel-defense-coverage.test.js`, and the Playwright browser QA screenshot — real rendered UI, not a mock).

## 14. TELEMETRY_GAP semantics

Same detection, same SIEM, `process_creation: NOT_AVAILABLE` → `TELEMETRY_GAP`, never `READY`, with the exact missing data source and vendor-scoped suggested sources named. Proven real-data + route-level + synthetic unit tests.

## 15. UNKNOWN semantics

Same detection, same SIEM, `process_creation` never declared → `UNKNOWN`, never `TELEMETRY_GAP` (mandate Phase 16/23's central distinction). Proven at every layer (rollup unit test, compatibility unit test, real-data truth table, route test).

## 16. Unsupported platform semantics

Real IBM QRadar profile (a technology with `detection_format: null`, genuinely no validated generator in this platform) against the same real `RELEASED` T1490 detection → `UNSUPPORTED_PLATFORM`, `sigma_portable: true`, `format_used: null` — no fabricated QRadar query language, ever. This is the honest, real-data substitute for the mandate's "Splunk-only-with-KQL-only-detection" example: because every currently `RELEASED` detection is generated with sigma+kql+splunk+osquery *simultaneously* (confirmed by reading `detectionEngine.buildForTechnique()`), no real detection today is missing a native Splunk format to demonstrate that literal scenario — QRadar (a real SIEM with zero validated generator support) demonstrates the identical `UNSUPPORTED_PLATFORM` code path with real, not synthetic, data. The literal single-format-missing branch is still verified, via a clearly-labeled synthetic fixture in `defense-compatibility.test.js`, since it is a real, reachable code path for a future detection with a narrower format set.

## 17. Recommendation ranking

`recommendationFor()` and the per-technique `best` detection selection in `computeCustomerCoverage()` follow a fixed priority (`READY > PARTIALLY_READY > TELEMETRY_GAP > UNKNOWN > UNSUPPORTED_PLATFORM`) — deterministic, no ML/LLM ranking signal anywhere. Every recommendation states *why* (mandate Phase 62): "Deploy-ready: use the kql format from detection …", "Configure an available telemetry source … (e.g. DeviceProcessEvents, Sysmon Event ID 1 …)".

## 18. Dossier integration

`dossier.html` gains a "Your Defense Coverage" card, fetched independently and in parallel with the pre-existing "Detection Coverage" card (`refreshDefenseCoverage()`, mirroring `refreshDetectionCoverage()`'s exact async-enhancement pattern). Zero changes to the existing dossier contract, existing detection-coverage panel, or `intelligence-dossier.js` itself. Safe with no profile configured (renders a setup prompt, never an error) — verified live via Playwright.

## 19. API

Two additions, both additive:
- `api/v1/intel.js`: new `case 'defense-coverage':` (GET, `?type=cve|campaign&id=...`), following every sibling action's exact shape. Zero changes to any pre-existing action's response contract (full existing `intel.js`/`intel-detections.js`/`intel-dossier.js` test suites re-run, all green).
- `api/v1/defense-profile.js` (new file): `get` / `save` / `delete` / `taxonomy` / `entitlements`, mirroring `watchlists.js`'s router convention exactly. Registered in `workers/lib/router.js`'s `HANDLER_MODULES` and `vercel.json`'s `functions` block, and in `workers/lib/route-table.js`'s `DIRECT_API_HANDLERS` — the pre-existing 34-handler filesystem-parity governance test now correctly asserts 35 (updated in the same commit, not worked around).

## 20. UX

`defense-profile.html` (new page): a compact, single-page wizard — checkbox chips per category (SIEM/EDR-XDR/Cloud/Endpoint Telemetry/OS), a select-per-data-source telemetry panel defaulting to "Unknown / Not configured", Save/Delete. Same design tokens, same in-memory-only API-key discipline, same `esc()` XSS-safe rendering convention as `dossier.html`. No feature is added without an explanation of what it does with the customer's declaration (privacy notice at the top of the page, mandate Phase 45).

## 21. Privacy

Defense Profile data is never included in any public report, social card, sitemap, or public API response (grep-verified: no `og.js`/report/sitemap code path references `defense-profile-store` or `defense-taxonomy`). Operational logs (`defense_profile_audit_log`) record `profile_id`/`owner_id`/action/field-count only — never a full technology or telemetry dump (mandate Phase 47).

## 22. Security

- **SQL injection**: every D1 statement uses `?` placeholders exclusively; grep-verified zero string-interpolated SQL across `defense-profile-store.js`.
- **IDOR/BOLA/cross-tenant**: §6.
- **XSS**: `sanitize()` strips HTML/dangerous characters from `name`/`custom_label` at write time (verified by unit test); `esc()` HTML-escapes every rendered value client-side. Verified live in Playwright: a `<img src=x onerror=...>` payload in a custom SIEM label never executes and never appears as live markup after re-render.
- **Prototype pollution**: category/technology-id/data-source keys are blocklisted (`__proto__`/`constructor`/`prototype`), verified against a REAL `JSON.parse()`-constructed attacker payload (not a JS object literal, which does not reproduce the real vulnerability shape) — confirms `Object.prototype` is never touched.
- **Entitlement/tier bypass**: `getDefenseProfileEntitlements()` is flat across tiers, matching the pre-existing, documented `watchlist-store.js` precedent (no new bypass surface introduced).
- **Oversized-profile DoS**: `MAX_TECHNOLOGIES_PER_CATEGORY = 10`, `MAX_NAME_LENGTH`/`MAX_CUSTOM_LABEL_LENGTH` bound every string, request body capped at 20KB (`guardRequest`).
- **Coverage-computation DoS**: bounded by the dossier's own already-bounded `attack_context.techniques[]`; no unbounded loop introduced.

## 23. Entitlements

`defense_profile.enabled`, `max_profiles: 1`, `max_technologies_per_category: 10` — flat, non-tier-differentiated, matching the existing documented gap (`platform/open-issues.md`) rather than inventing new pricing logic in code (mandate Phase 50).

## 24. D1

`migrations/0003_defense_profiles.sql`, additive-only, same `sentinel-apex-core` database. No destructive migration; `CREATE TABLE IF NOT EXISTS` throughout, consistent with `0001`/`0002`.

## 25. Cloudflare architecture

No `fs`, `child_process`, or Node-server-only module used anywhere in the new code. D1 access goes exclusively through the existing `api/_lib/d1.js` abstraction (native `env.DB` binding on Workers, REST fallback on Node/Vercel) — zero new runtime primitives. No Redis, no Upstash, no new GitHub-Actions-as-scheduler introduced (governance tests `tests/governance-cloudflare-runtime.test.js`/`tests/governance.test.ts` re-run, both green).

## 26. Performance

Not independently load-tested (no production traffic-shape data available in this sandbox — consistent with every prior round's honest disclosure). `computeCustomerCoverage()` is O(techniques × rules-per-technique), the same complexity class as the pre-existing global `computeCoverage()` it wraps — no new N+1 pattern introduced (verified by code review: one `getRule()` call per rule id already collected by the unmodified global engine, no per-technique D1 round trip).

## 27. Tests

- `api/_lib/__tests__/defense-taxonomy.test.js` — 14 tests
- `api/_lib/__tests__/defense-profile-store.test.js` — 21 tests
- `api/_lib/__tests__/defense-compatibility.test.js` — 31 tests
- `api/v1/__tests__/defense-profile.test.js` — 19 tests
- `api/v1/__tests__/intel-defense-coverage.test.js` — 9 tests

**94 new tests, all passing.** Full regression: **Jest 70/71 suites passing (1 pre-existing, unrelated skip), 2339/2399 tests passing (60 pre-existing skips), 0 failures.** `pytest`: **1739/1739 passing.** `node --test` (renderer + engine-node + workers/lib): **290/290 passing.** Zero regressions in any pre-existing suite.

## 28. Browser QA

Real Chromium (Playwright, pre-installed binary), real production handler code (`defense-profile.js`/`intel.js`/`watchlists.js` invoked in-process, intercepted at the network layer — not hand-written JSON mocks), real committed CVE-2023-27351 data, a real in-memory D1 fixture. 12/12 checks passed at both 1440px and 375px: wizard load/save/reload persistence, technology/telemetry state round-trips correctly, XSS payload in a custom label never executes, no horizontal overflow at 375px on either page, workflow D (no profile → setup prompt) and workflow A (configured profile → `READY` badge) both rendered correctly end-to-end. Zero uncaught page errors. The only console noise is expected external-network denials (Google Fonts/gtag, blocked in this sandbox) and a `file://`-protocol-relative favicon 404 — both pre-existing on every page in this site, not introduced by this round.

## 29. Real-data workflows

- **Workflow A** (Microsoft customer, real Campaign/CVE, real `RELEASED` KQL detection, `DeviceProcessEvents`-equivalent telemetry available) → `READY`. Proven in `intel-defense-coverage.test.js` and live in the browser QA screenshot.
- **Workflow B** (same detection, telemetry explicitly missing) → `TELEMETRY_GAP` with the exact missing source named.
- **Workflow C** (SIEM with no validated generator — real QRadar, substituting for the literal Splunk-only scenario per §16's honest disclosure) → `UNSUPPORTED_PLATFORM`, no fabricated query language.
- **Workflow D** (no Defense Profile at all) → dossier remains fully usable, global coverage unaffected, customer panel shows a setup prompt. Proven live in the browser QA run.

## 30. Known limitations

- Detection corpus is still thin (3 `RELEASED` detections, unchanged from PR #141) — most techniques on most entities show `NO_VALIDATED_DETECTION` regardless of environment, honestly, not a compatibility-engine defect.
- Provider field-level mapping beyond Microsoft/Sysmon/Windows-Security-Events/Linux-auditd is source-label-only (`confidence: "general"`), disclosed, never asserted as verified.
- No automated accessibility scanner (axe-core) run — native semantic HTML (`<label>`, `<button>`, `<select>`, `<input type="checkbox">`) used throughout, matching the pre-existing `dossier.html`'s own (undocumented-tool) precedent; not independently audited this round.
- No SIEM/EDR connector, no automated telemetry verification, no deployment path — entirely out of scope by mandate, not attempted.
- No production load/performance measurement (sandbox limitation, consistent with every prior round).
- Cloudflare live-cutover blocker remains open (`wrangler whoami`: not authenticated), unchanged, external to this platform's own work.

## 31. Rollback

Every change is additive: two new database tables (empty until a customer saves a profile — dropping them is a no-op for every other subsystem), one new router file, one new UI page, one new dossier card (behind its own independent fetch, degrading to an empty state on failure), one new `intel.js` action, one additive export from `detection-engine.js`. Reverting this branch's commits restores the exact PR #141 baseline with zero data loss (no existing table, route, or exported symbol was altered).

## 32. Final verdict

**CONDITIONAL GO.** Ship it: the engine is correct, tested at unit/route/real-browser layers against real production data, secure against the adversarial matrix the mandate specified, and architecturally additive with zero regressions across 2339+1739+290 pre-existing tests. Conditional only on the honestly-disclosed, pre-existing corpus-thinness and the intentionally-scoped absence of any deployment/connector capability — both explicit mandate boundaries, not gaps in this tranche's own execution.
