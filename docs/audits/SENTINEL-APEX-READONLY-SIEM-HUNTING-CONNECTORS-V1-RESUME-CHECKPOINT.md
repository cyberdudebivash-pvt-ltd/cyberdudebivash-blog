# SENTINEL APEX — Controlled Read-Only SIEM Hunting Connectors v1 — Resume Checkpoint

**Date:** 2026-08-30
**Branch:** `claude/p0-readonly-siem-hunting-v1` (base SHA `5d687f96f04c84bec8c4a72d9d37274f5d63899d`, forked fresh from `main` after PR #145 merged)
**Status:** Complete, uncommitted work ready for the commit sequence.

---

## What this tranche did

**P0**: Queried the real canonical detection store directly, found the exact same 2 `BLOCKED` detections Detection Performance Intelligence v1's Review Queue had already surfaced (`9a5467dc8ae03f68`, `fbc0da003ab2d073`), root-caused both with real evidence, and disposed of both BEFORE writing any hunting-connector code:
- `9a5467dc8ae03f68` — **FIXED_IN_NEW_VERSION** (v1.0.10, corrected `data_source` metadata from `process_creation` to `registry_set`, matching the rule's own always-correct Sigma content). Historical v1.0.9 preserved unmodified.
- `fbc0da003ab2d073` — **REVOKED** (fabricated test-seed content, no genuine detection logic to correct).

Also fixed the pre-existing Cloudflare asset-manifest gap (`hunts.html` + 4 other pages now servable under Cloudflare Workers' static-asset path), since it directly affects this tranche's own new UI.

**P1**: Built a controlled, read-only, bounded remote SIEM hunting capability:
- New capability flag `hunt_query_supported`, separate from `deploy_supported`, on both connectors (`mock-siem`, `microsoft-sentinel`); the 4 unimplemented platforms get `hunt_query_supported: false` too.
- `executeHuntQuery()`/`testHuntQueryConnection()`/`normalizeResults()` added to both connectors, sharing one connector-contract-level sanitization/envelope implementation.
- One new D1 table (`hunt_query_executions`, metadata only) + 2 additive columns on `hunt_observations` (`execution_id`, `selected_fields_json`).
- New `hunt-query-store.js`/`hunt-query-engine.js` orchestration: readiness gating (telemetry must be exactly `READY`), time/row bounds, one-in-flight-per-hunt concurrency, query-defect → `QUERY_ERROR` feedback routing (never for a provider outage/rate limit).
- 3 new actions on the existing `api/v1/hunts.js` router: `query-preview`/`query-run`/`query-executions`.
- `hunts.html` extended per-query with a full Preview → Run → bounded results → Select as Observation panel.
- Real browser QA (Chromium/Playwright, ad hoc, not committed) — 21/21 checks, 1 real bug found and fixed.

---

## Real Microsoft API research (live, this session)

- Endpoint: `POST https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query`
- OAuth scope for hunting: `https://api.loganalytics.io/.default` (genuinely different from the deploy path's `https://management.azure.com/.default`)
- RBAC role: built-in **Reader**, scoped to the target Log Analytics workspace
- `timespan` is the API's own native time-range field (never embedded in query text) — inherently injection-safe
- Response: `{"tables":[{"name","columns":[{"name","type"}],"rows":[[...]]}]}`
- A 400 response is a genuine query/field defect (invalid KQL / unknown table-column) — classified `QUERY_REJECTED` → `QUERY_DEFECT`, the one real path to a `QUERY_ERROR` feedback signal for a live vendor call.

---

## Query safety / result limits

- Exactly one parameterization type: time range, via `timespan` — no IOC/hostname/username support yet.
- `DEFAULT_ROW_LIMIT=100`, `MAX_ROW_LIMIT=1000`, `MAX_TIME_RANGE_MS=30 days` — technical ceilings, not commercial tiers.
- One in-flight execution per hunt (D1-backed, 60s staleness window).

---

## Test / QA totals

164 new/extended tests this tranche. Full suite: **2,690 non-skipped Jest tests passing, zero regressions.** Browser QA: 21/21 real-browser checks (workflows A–G + select-observation + mobile viewport), 1 real bug found and fixed (`renderHuntResultStatus()` crash on a FAILED/TIMED_OUT/RATE_LIMITED result shape with no `results` array).

---

## Vendor live verification

**NOT VERIFIED.** No Azure tenant/credentials in this sandbox — identical, disclosed limitation to the Controlled SIEM Deployment Gateway v1 tranche's own deploy-path gap.

---

## Known limitations (full list: `platform/open-issues.md` Issue 34)

Single live hunting connector; one parameter type; no internal (non-detection-derived) query template source; one-in-flight-per-hunt concurrency bound only; technical (not commercial) bounds; no export surface; no environment-tagging on execution metadata; no `Object.freeze()` hardening on returned field objects.

---

## Files changed/added (uncommitted at time of writing)

New: `api/_lib/hunt-query-store.js`, `api/_lib/hunt-query-engine.js`, `migrations/0007_readonly_siem_hunting.sql`, `scripts/remediate-blocked-detections.js`, `api/_lib/__tests__/detection-integrity-remediation.test.js`, `api/_lib/__tests__/hunt-query-store.test.js`, `api/_lib/__tests__/hunt-query-engine.test.js`, `api/_lib/__tests__/hunt-query-privacy-security.test.js`, `docs/audits/SENTINEL-APEX-READONLY-SIEM-HUNTING-INVENTORY-V1.md`, `docs/audits/SENTINEL-APEX-READONLY-SIEM-HUNTING-CONNECTORS-V1-CERTIFICATION.md`, this checkpoint.

Modified: `api/_lib/connectors/connector-contract.js`, `api/_lib/connectors/mock-siem-connector.js`, `api/_lib/connectors/microsoft-sentinel-connector.js`, `api/_lib/connectors/__tests__/mock-siem-connector.test.js`, `api/_lib/connectors/__tests__/microsoft-sentinel-connector.test.js`, `api/_lib/siem-connector-taxonomy.js`, `api/_lib/siem-connector-store.js`, `api/_lib/hunt-store.js`, `api/_lib/__tests__/hunt-store.test.js`, `api/_lib/__fixtures__/fake-d1.js`, `api/v1/hunts.js`, `api/v1/__tests__/hunts.test.js`, `hunts.html`, `scripts/build-cloudflare-assets.js`, `vercel.json`, `data/detection-rules-canonical.json` (real remediation), `platform/capabilities.md`, `platform/open-issues.md`, `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`, `docs/architecture/DETECTION-FEEDBACK-PRIVACY-MODEL.md`.

---

## Next transformation ranking (per the mandate)

1. Detection Tuning & Candidate Recommendation Engine
2. MSSP Multi-Workspace Operations
3. Customer Exposure/Asset Context
4. Executive Defense Posture Intelligence
5. Additional Read-Only SIEM Connectors
6. Controlled SOAR Recommendation Layer — **explicitly not to be implemented**

---

## Remaining steps

Commit in the suggested logical sequence, push, open a draft PR, subscribe to its activity, and monitor/respond to CI + review as it comes in — matching the exact operating discipline every prior tranche in this lineage has followed.

---
*CyberDudeBivash® Sentinel APEX — Controlled Read-Only SIEM Hunting Connectors v1 Resume Checkpoint*
