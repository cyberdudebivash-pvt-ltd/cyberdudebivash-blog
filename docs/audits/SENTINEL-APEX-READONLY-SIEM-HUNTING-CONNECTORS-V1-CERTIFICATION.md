# SENTINEL APEX — Controlled Read-Only SIEM Hunting Connectors & Remote Observation Ingestion v1
## Production Certification

**Date:** 2026-08-30
**Branch:** `claude/p0-readonly-siem-hunting-v1`
**Mandate:** P0/P1 Master Production Transformation Task — Detection Integrity Remediation + Controlled Read-Only SIEM Hunting Connectors + Remote Observation Ingestion v1

---

## 1. Executive Verdict

**GO**, Beta-scoped, matching the Beta scoping every prior tranche in this lineage (Controlled SIEM Deployment Gateway v1, Threat Hunting Workspace v1, Detection Performance Intelligence v1) has honestly carried. Both P0 blocked detections received an explicit, evidence-based disposition (one fixed via a new immutable version, one revoked) before any hunting-connector code was written, per the mandate's own non-negotiable dependency order. Exactly one live hunting connector (Microsoft Sentinel) plus the deterministic Sandbox connector were built, both gated behind a new, separate `hunt_query_supported` capability flag never assumed equal to `deploy_supported`. Vendor sandbox execution against a real Azure tenant remains unverified, same disclosed limitation as the deploy path.

---

## 2. Baseline (Section 4 of the mandate)

Branch created fresh from `main` after confirming PR #145 merged (`pull_request.closed` webhook, `outcome: merged`), per `git log`/`git status` at session start. This certification's branch (`claude/p0-readonly-siem-hunting-v1`) does not continue PR #145's own branch.

Required reading completed before any code was written: `SENTINEL-APEX-CONTROLLED-SIEM-DEPLOYMENT-GATEWAY-V1-CERTIFICATION.md`, `SENTINEL-APEX-THREAT-HUNTING-DETECTION-FEEDBACK-V1-CERTIFICATION.md`, `SENTINEL-APEX-DETECTION-PERFORMANCE-INTELLIGENCE-V1-CERTIFICATION.md`, `DETECTION-FEEDBACK-PRIVACY-MODEL.md`, `INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`, `platform/capabilities.md`, `platform/open-issues.md`.

---

## 3. Blocked Detection Remediation (P0)

Queried directly against the real canonical detection store (`detection-rules.js#loadCanonical()` + `detection-intelligence.js#toCanonicalDetectionObject()`), not prose memory. Exactly two `BLOCKED` real detections found, matching the count Detection Performance Intelligence v1's Review Queue had already surfaced (Issue 33 item 7).

| Detection | Version | Failure | Root cause | Customer impact | Remediation |
|---|---|---|---|---|---|
| `9a5467dc8ae03f68` — "Registry Run Key Persistence From User-Writable Path" (T1547.001) | v1.0.9 | `BLOCKED`, `UNSUPPORTED_TELEMETRY` | `data_source` metadata stored as `process_creation`, but the rule's own Sigma content has always declared `logsource.category: registry_set` and references `TargetObject` (a registry field, absent from `process_creation`'s known fields, present in `registry_set`'s). A genuine, provable metadata defect at generation time — never a content defect. Real CVE-2026-54550 backing; structurally valid; fixtures pass. | Zero deployments at any point (`deployment-store.js#listDeployments()` — zero matches for this detection_id, verified directly). Never customer-visible as deployed content. | **FIXED_IN_NEW_VERSION.** `scripts/remediate-blocked-detections.js` reconstructed the FULL existing `ruleSpec` (all platform formats, description, level, suricata) verbatim from the live rule and corrected only `data_source` to `registry_set`, then called the existing, unmodified `storeRule()` — producing immutable v1.0.10. New canonical status: not `BLOCKED` (remaining reason: `ATTACK_MAPPING_UNCERTAIN`, expected without entity-specific evidence context — never claimed `RELEASED` without it). The historical v1.0.9 snapshot is untouched; both versions exist side-by-side in `detection_versions`. |
| `fbc0da003ab2d073` — "Suspicious PowerShell Execution" (T1059.001) | v1.0.0 | `BLOCKED`, `INVALID_QUERY`/`INVALID_LOGSOURCE`/`UNSUPPORTED_TELEMETRY` | Incomplete test/seed content with zero real evidentiary backing: `source.articles` references `TEST-001`, confirmed absent from the entire real intelligence corpus (exhaustive grep across `api/intel/**`, `reports-index.json`, `threat-graph.json` — 0 matches); `source.iocs` is an RFC1918 placeholder (`10.0.0.1`); Sigma content is missing 3 mandatory fields (title, a properly-shaped `logsource` object, `detection.condition`); `data_source` is an empty string. No genuine detection logic exists to correct. | Zero deployments at any point (same verification as above). | **REVOKED.** `updateRuleStatus(id, 'REVOKED', {author, comment})` — the existing, unmodified mechanism: no content change, no version bump. Fabricating a "corrected" Sigma rule for content with no real evidentiary backing would itself be the fabrication this platform's own governance forbids. |

Both dispositions are permanently pinned by frozen regression fixtures (`api/_lib/__tests__/detection-integrity-remediation.test.js`) that reproduce the EXACT historical failure from literal, frozen copies of the pre-remediation content — never dependent on the live, now-mutated canonical store — so both the original defect and the fix stay provable even if the store changes again.

No performance-state reset was needed: neither detection had any prior deployment, hunt link, or feedback history to reconcile.

---

## 4. Detection Version Integrity

Both the broken historical release (v1.0.9 for `9a5467dc8ae03f68`) and the new corrected release (v1.0.10) exist in `detection_versions`, captured by the pre-existing, unmodified snapshot hook (Detection Performance Intelligence v1). History was never rewritten. The new version starts at `INSUFFICIENT_EVIDENCE`/fresh validation — no operational evidence was transferred from the old version.

---

## 5. Asset-Manifest Disposition

Classified as **CUSTOMER_VISIBLE_RUNTIME_DEFECT** for the specific case of `hunts.html`, since Hunt Workspace is central to this very tranche's own new remote-hunting UI (satisfying the mandate's own "fix if it affects Hunt Workspace or SIEM connector UI" test). Fixed: `scripts/build-cloudflare-assets.js`'s `PUBLIC_ROOT_FILES` allowlist gained all 5 previously-missing pages (`hunts.html`, `deployments.html`, `dossier.html`, `defense-profile.html`, `workbench.html`) in one change — bundling only the fix this tranche's own scope required, not a larger unrelated migration. `dist-public/` rebuilt and verified: 11,066 files (up from 11,029), all 5 new HTML files present. `platform/open-issues.md` Issue 33 item 1 updated to RESOLVED, not silently dropped.

---

## 6. Reuse-Before-Build

Full detail: `docs/audits/SENTINEL-APEX-READONLY-SIEM-HUNTING-INVENTORY-V1.md`. Summary: 8 of 9 required D1 tables already existed; only `hunt_query_executions` (metadata-only) is new. No second query-template store, no raw-telemetry table, no second credential vault, no second feedback-writing path.

---

## 7. Connector Selection

Microsoft Sentinel selected as the one primary live hunting connector, with real, live-verified evidence (endpoint, OAuth scope, RBAC role, response schema) — see the inventory doc §3. Splunk/Elastic/QRadar/Google SecOps remain `hunt_query_supported: false`, matching their pre-existing `deploy_supported: false`.

---

## 8. Connector Architecture

`connector-contract.js` extended with 3 new optional methods (`testHuntQueryConnection`/`executeHuntQuery`/`normalizeResults`), gated by `capabilities.hunt_query_supported` — a connector never required to implement them. Both `mock-siem-connector.js` and `microsoft-sentinel-connector.js` implement all 3. `normalizeResults()` on both connectors delegates to one shared, single-source-of-truth implementation (`connector-contract.js#normalizeObservationRows()`) rather than duplicating sanitization logic per connector.

---

## 9. Least Privilege

Microsoft Sentinel hunting requires the built-in **Reader** role, scoped to the target Log Analytics workspace only (never subscription- or tenant-wide) — additive to, and independent of, the deploy path's "Microsoft Sentinel Contributor" role. Documented in `siem-connector-taxonomy.js`'s `least_privilege_role` string for the platform.

---

## 10. Credential Model

Reused unchanged: `getConnectorWithCredential()` decrypts for the duration of one operation, same as the deploy path — no second vault, no plaintext D1 secret, no frontend exposure. `workspace_id` (the one new field hunting needs) is stored as a plain, non-secret `target_config` field (a workspace identifier, not a credential) — genuinely optional, so no existing deploy-only connector's validation is broken by this tranche (verified: `validateTargetConfig()`'s new `optional_target_fields` loop iterates zero times for every platform except `microsoft-sentinel`, identical behavior to before for all others).

---

## 11. Query Templates

`hunt_queries` (existing, PR #144) IS the trusted, versioned query-template registry for the one query source v1 supports — a RELEASED detection's own snapshotted content, added via the existing, unmodified `addQuery()`. No new table.

---

## 12. Query Safety

Read-only enforced by the remote API's own semantics, not just a UI label: the Log Analytics Query API is a documented data-plane read operation, structurally distinct from the alertRules control-plane the deploy path uses. `read_only: true` in `previewQuery()`'s response is only ever set for a `hunt_query_supported` connector, never inferred.

---

## 13. Parameterization

Exactly one parameter type in v1: time range, passed as Microsoft's own native `timespan` API field — never string-concatenated into query text, so this parameter type is inherently immune to injection by construction. IOC/hostname/username/entity-id parameterization deliberately deferred (Issue 34 item 3) — no real canonical detection content has such placeholders today.

---

## 14. Time Bounds

Explicit `time_start`/`time_end`, validated by `hunt-query-engine.js#runQuery()`: both required, `time_end` must be after `time_start`, and the range must not exceed `MAX_TIME_RANGE_MS` (30 days) — never an unbounded historical query.

---

## 15. Result Bounds

`DEFAULT_ROW_LIMIT` (100) and `MAX_ROW_LIMIT` (1,000) are v1 technical ceilings, documented as separate from any commercial entitlement (none exists yet for hunt-query result size — Issue 34 item 7). Both connectors enforce the bound and report `truncated: true` rather than silently returning more rows than requested — proven by test (`OVER_LIMIT`/`HUNDRED_RESULTS` simulate scenarios, and a real 300-row Sentinel mock response bounded to 50).

---

## 16. Execution Model

`hunt_query_executions` states: `RUNNING`/`SUCCEEDED`/`PARTIAL`/`TIMED_OUT`/`RATE_LIMITED`/`FAILED`. Explicit two-step flow: `previewQuery()` (VIEW QUERY → PREVIEW PARAMETERS, no remote call, no execution record) then `runQuery()` (the explicit RUN QUERY action) — no auto-run on page open, proven by the browser QA driver never invoking Run except via an explicit click. One in-flight execution per hunt (D1-backed check against a `RUNNING` row younger than 60s) — a simple, documented v1 concurrency bound, not a rate-limiter (Issue 34 item 6).

---

## 17. Result Normalization

`connector-contract.js#normalizeObservationRows()` — the one shared implementation both connectors' `normalizeResults()` delegate to. Output is always `{fields, source_row_index}`; `fields` values are always primitives (string/number/boolean/null, each capped at 2,000 characters); `__proto__`/`constructor`/`prototype` keys are always dropped, never merely overwritten; a structurally malformed row (not an object, or null) is dropped entirely rather than guessed at. Deliberately does NOT force every SIEM's field names into one identical schema — only the envelope and the sanitization discipline are shared.

---

## 18. Privacy

Remote telemetry is tenant-private, never exposed via public CTI/API/global quality page/other tenants/social previews/analytics. Structurally enforced, not merely conventional: `hunt_query_executions` carries no code path into `detection_feedback`/`computeGlobalReviewMetrics()`/`computeFeedbackSignal()` — the only way data enters the global aggregate is via `submitDetectionFeedback()`, which accepts only `classification`/`summary` text, never raw result rows. Proven by test (`hunt-query-privacy-security.test.js`): a result row containing sandbox-host/sandbox-user values never appears anywhere in the global aggregate's serialized output, even after that exact data was persisted as a real hunt observation and used as the basis for real detection feedback. Full model update: `DETECTION-FEEDBACK-PRIVACY-MODEL.md` §9 (new).

Raw remote telemetry is never persisted by default — only execution metadata (state/row count/error code/classification) plus analyst-selected observations/evidence persist, matching the mandate's "never become a telemetry lake" requirement by construction (no raw-result table exists at all).

---

## 19. Observation Selection

Analyst-explicit only: `runQuery()` returns ephemeral, bounded results in the API response; the UI never auto-selects a row. `selectHuntObservation()` (hunts.html) persists exactly the one row an analyst clicks "Select as Observation" on, via the existing, additively-extended `addObservation()` — carrying `execution_id` (connector/time-bounds provenance via the execution row) and `selected_fields_json` (the one normalized row's field subset, already sanitized upstream, capped again at 8,000 bytes total as defense in depth). `created_by`/`created_at` already supplied analyst identity + creation time.

---

## 20. Hunt Integration

Hunt detail UI (`hunts.html`) extended per-query with: connector selector → time range/row limit inputs → Preview → Run Query → bounded results table → Select as Observation, directly beneath the existing query-snapshot view — no disconnected query console. RUN is disabled until Preview confirms `readiness.ready === true`; a DRIFTED deployment for the query's source detection is surfaced as a warning before Run, never silently hidden.

---

## 21. Detection Feedback Integration

`hunt-query-engine.js#runQuery()` calls `hunt-engine.js#submitDetectionFeedback()` unchanged — classification `QUERY_ERROR` fires only when the connector's failure classifies as `QUERY_DEFECT` (see §22). No new feedback-writing code path was created.

---

## 22. Query-Error Attribution

`classifyExecutionFailure()` (hunt-query-engine.js) maps a `ConnectorError` code to `{state, errorClassification}`: `QUERY_REJECTED` → `QUERY_DEFECT` (the only classification that ever creates a `QUERY_ERROR` feedback row); `AUTH_FAILED`/`PERMISSION_DENIED` → `AUTH_ISSUE`; `RATE_LIMITED`/`TIMEOUT`/anything else → `PROVIDER_ISSUE`. A genuine real-world path to `QUERY_REJECTED` was verified and added: a 400 response from the Log Analytics API (well-documented as meaning invalid KQL or an unknown table/column) is classified `QUERY_REJECTED` — a real fix found and applied this session, since without it every remote query defect would have fallen through to the generic `REMOTE_ERROR`/`PROVIDER_ISSUE` bucket and the whole `QUERY_ERROR` feedback pathway would never fire for a real vendor call. Proven never to misfire: a provider outage (simulated 500/AUTH_FAILED) never creates a `QUERY_ERROR` row (tested at connector, engine, API-router, and browser-QA levels).

---

## 23. Tenant Isolation

Every hunt-query action re-derives ownership from `hunt_id`/`query_id`/`connector_id`/`execution_id` against the authenticated caller's `userId` — never trusted from the request body. `resolveContext()` (hunt-query-engine.js) checks all three together; a queryId or connectorId belonging to another tenant is `NOT_FOUND`, identical to every other store in this platform. Proven at 4 levels: unit (`hunt-query-store.test.js`, `hunt-query-engine.test.js`), HTTP-router (`hunts.test.js`), and real-browser (`Workflow F`).

---

## 24. SSRF

Microsoft Sentinel's hunting URL is built ONLY from a fixed hostname (`api.loganalytics.azure.com`) plus `encodeURIComponent(workspaceId)` — never a customer-supplied hostname. Proven by test: a hostile `workspace_id` value containing a URL/host-like payload is percent-encoded into the path, never interpreted as a redirect target; the request's actual hostname is always `api.loganalytics.azure.com` regardless of `workspace_id` content.

---

## 25. OAuth

A genuinely separate OAuth token request for hunting (`getHuntAccessToken()`), scope `https://api.loganalytics.io/.default`, never assumed granted by the deploy path's own token (scope `https://management.azure.com/.default`) — verified live against current Microsoft documentation. Never cached across calls, matching the deploy path's own documented simplicity choice. Never exposed to the browser or logged.

---

## 26. Cloudflare Runtime

No Node-only API introduced (`fs`/`child_process`/raw sockets) — `fetch()`/Web Crypto only, matching every existing connector. `vercel.json`'s `hunts.js` entry bumped `maxDuration` 20→25 to match `deployments.js`'s existing precedent for the identical worst-case shape (10s token acquisition + 15s query fetch, sequential) — a genuine latent risk this tranche's own new outbound network calls introduced into a file that never made one before, found and fixed, not a speculative change.

---

## 27. D1

One new table, `hunt_query_executions` (`migrations/0007_readonly_siem_hunting.sql`), plus two nullable, additive columns on the existing `hunt_observations` table (`execution_id`, `selected_fields_json`). Additive-only (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ADD COLUMN`), tested against both a fresh and an already-populated fake-d1 fixture.

---

## 28. Queue Decision

**QUEUE NOT REQUIRED.** An interactive, bounded, single-remote-call query (max 25s worst-case, per §26) fits entirely within one request/response cycle — no async vendor-query polling model was needed or built.

---

## 29. Entitlements

No new entitlement dimension was invented. `getSiemConnectorEntitlements()` (unchanged) already gates whether a customer can create a live connector at all; hunting reuses that same connector, so no separate `hunting.remote_query` gate exists yet — a disclosed, deliberate v1 simplicity choice (Issue 34 item 7), not an oversight.

---

## 30. Observability

`hunt_timeline` gains one new `event_type` (`QUERY_EXECUTED`), matching every other hunt lifecycle event's exact pattern — no new audit table. `hunt_query_executions` itself is the structured, queryable record of every execution's outcome (state/error_code/error_classification/row_count/timestamps).

---

## 31. Security

Prototype pollution: proven at the connector level (a hostile `__proto__` own-property, constructed via a computed key exactly matching what `JSON.parse()` of a hostile remote payload would produce) and end-to-end through the real engine — `({}).polluted` never becomes defined. XSS: hostile field values (e.g. `<script>` strings) are carried through as inert data by `esc()` at render time, matching this platform's existing escaping discipline everywhere else. IDOR/BOLA: see §23. SSRF: see §24. Query injection: see §13.

---

## 32. Performance

No new synchronous blocking work added to any existing hot path. The one new outbound-network-capable file (`hunts.js`) has its Vercel duration budget corrected (§26).

---

## 33. Tests

164 new/extended tests this tranche (37 mock-connector, 45 Sentinel-connector, 40 hunt-query-engine, 8 hunt-query-store, 4 privacy/security, 5 detection-integrity-remediation, 21 in hunts.js's HTTP-router suite, 4 hunt-store provenance). Full regression suite: 2,690 non-skipped Jest tests passing, zero regressions across the entire pre-existing suite.

---

## 34. Browser QA

Real Chromium (Playwright), driven against the real `hunts.html` frontend code and the real backend engine/store/connector code (an in-memory D1 substitute standing in for a live Cloudflare D1 database — the same class of disclosed limitation every prior tranche in this lineage has carried; ad hoc, non-committed harness, matching this repository's own established precedent). 21/21 checks passed across all required workflows (A: happy path through to feedback submission; B: zero-result, no auto-finding; C: genuine query error → QUERY_ERROR feedback; D: provider failure → no feedback signal; E: telemetry gap blocks Run before any remote call; F: cross-tenant isolation on preview AND run; G: bounded results at a small explicit row limit), plus a dedicated Select-as-Observation pass (real provenance persisted) and a 375px mobile viewport smoke check. One real bug found and fixed during this pass: `renderHuntResultStatus()` crashed (`Cannot read properties of undefined (reading 'length')`) on a FAILED/TIMED_OUT/RATE_LIMITED execution outcome, since that response shape carries no `results` array — fixed to branch on `state` before ever touching `results`.

---

## 35. Vendor Sandbox Verification

**NOT VERIFIED**, same disclosed limitation as the deploy path. No Azure tenant, subscription, or credentials exist in this sandbox. Every Sentinel hunting code path is verified against Microsoft's current published API contract (fetched live this session) and covered by unit tests against a mocked `fetch` — never claimed as proven against a live workspace.

---

## 36. Real-Data Workflows

See §34. All 7 named workflows (A–G) plus the Select-as-Observation and mobile checks ran against real production handler code, the real committed canonical detection store's remediated content, and real (in-memory-backed) D1 persistence — not a scripted mock of the application layer itself.

---

## 37. Known Limitations

See `platform/open-issues.md` Issue 34 for the full, itemized list (12 items): single live connector; vendor sandbox unverified; one parameter type only; no internal query-template source; credential-scope non-assumption; one-in-flight-per-hunt concurrency bound; technical (not commercial) result/time bounds; no export surface; no environment-tagging; no `Object.freeze()` on returned field objects; no Lighthouse measurement; all pre-existing platform limitations inherited.

---

## 38. Rollback

Every change is additive: two new files (`hunt-query-store.js`, `hunt-query-engine.js`), one new migration, new optional connector methods, new optional taxonomy fields, new nullable columns, new router actions, new UI panel. Reverting this tranche's commits restores the prior state exactly — no existing table, column, capability flag, or route was renamed, removed, or given new required semantics. The one exception requiring care on rollback: the two remediated detection rules (`9a5467dc8ae03f68` new version, `fbc0da003ab2d073` revoked status) are governance actions on the canonical store, not code — reverting the CODE does not undo the remediation, which is correct and intentional (the remediation is independently justified P0 work, not something this tranche's own rollback should ever silently reverse).

---

## 39. Final Verdict

**GO, Beta-scoped.** Both P0 blocked detections resolved with full evidence before any P1 hunting code was written. Exactly one live connector (Microsoft Sentinel) plus the deterministic Sandbox connector, both gated behind a capability flag never assumed equal to deploy support. Read-only enforced structurally, not just labeled. Privacy boundary proven by test, not merely documented. Zero regressions across 2,690 non-skipped tests. Real browser QA found and fixed one genuine bug. Vendor sandbox execution against a live Azure tenant remains the one disclosed, unverified gap — identical in kind to every prior tranche in this lineage.

---
*CyberDudeBivash® Sentinel APEX — Controlled Read-Only SIEM Hunting Connectors & Remote Observation Ingestion v1 Certification*
