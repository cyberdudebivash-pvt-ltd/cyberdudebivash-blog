# SENTINEL APEX — Controlled Read-Only SIEM Hunting Connectors v1
## Reuse-Before-Build Inventory & Connector Selection Evidence

**Date:** 2026-08-30
**Scope:** what already exists in this platform that a read-only, bounded, explicit remote hunt-query capability can extend, and the evidence trail for selecting Microsoft Sentinel as the one primary live connector this tranche builds.

---

## 1. What already exists (and is reused unchanged)

| Capability need | Existing component | Disposition |
|---|---|---|
| Connector ownership, credential storage, entitlements | `api/_lib/siem-connector-store.js`, `api/_lib/connector-crypto.js` | Reused unchanged. `getConnectorWithCredential()` is the one function every hunting call reuses to obtain a decrypted credential for the duration of one operation — no second vault, no plaintext D1 secret. |
| Connector capability taxonomy | `api/_lib/siem-connector-taxonomy.js` | Extended additively: `hunt_query_supported` boolean added per platform, `optional_target_fields` added for `microsoft-sentinel`'s `workspace_id`. Zero existing fields renamed or removed. |
| Connector module interface contract | `api/_lib/connectors/connector-contract.js` | Extended additively: `testHuntQueryConnection`/`executeHuntQuery`/`normalizeResults` documented as optional methods, gated by the new capability flag, alongside the existing deploy-oriented methods. `normalizeObservationRows()` added as the one shared, single-source-of-truth sanitization/envelope implementation both connectors now delegate to. |
| Sandbox/mock connector | `api/_lib/connectors/mock-siem-connector.js` | Extended additively with hunting methods, reusing its existing `simulate` vocabulary for connector-level failures and adding one new, query-content-driven `__SIMULATE_HUNT__:` marker convention for result-shape scenarios. |
| Real live connector | `api/_lib/connectors/microsoft-sentinel-connector.js` | Extended additively with hunting methods on the SAME connector module (not a second Sentinel-hunting-only module) — same platform id, same credential, a second OAuth scope. |
| Detection lifecycle / RELEASED-only gate | `detection-rules.js` / `detection-intelligence.js` | Reused unchanged, via `hunt-engine.js#resolveCanonicalDetection()`. |
| Telemetry-compatibility readiness | `defense-compatibility.js` / `defense-profile-store.js` | Reused unchanged, via a new `hunt-query-engine.js#checkDetectionReadiness()` that composes them exactly like `hunt-engine.js#computeHuntReadiness()` already does — never a second compatibility computation. |
| Deployment linkage / drift surfacing | `deployment-store.js` | Reused unchanged, via `hunt-engine.js#resolveDeploymentLinkage()`. |
| Hunt query storage (the trusted query template registry) | `hunt-store.js`'s `hunt_queries` table / `addQuery()` | **This is the trusted hunt-query template registry the mandate asked for** — one row per (source_detection_id, source_detection_version), content snapshotted at add-time, format and validation_status already captured. No second `hunt_query_templates` table is built; inventing one would duplicate an existing, adequate store. |
| Observation persistence | `hunt-store.js`'s `hunt_observations` table / `addObservation()` | Extended additively with two nullable columns (`execution_id`, `selected_fields_json`) for provenance — every pre-existing and manually-authored observation is unaffected (both columns NULL). |
| Hunt audit trail | `hunt-store.js`'s `hunt_timeline` table / `appendTimeline()` | Reused unchanged, with one new `event_type` value (`QUERY_EXECUTED`). |
| Detection feedback routing | `hunt-engine.js#submitDetectionFeedback()` / `detection-feedback-store.js` | Reused unchanged. A genuine query defect creates a `QUERY_ERROR` row through the exact same function every other feedback path already uses — no second feedback-writing code path. |
| Hunt/query/connector API router | `api/v1/hunts.js` | Extended additively with 3 new actions (`query-preview`/`query-run`/`query-executions`) on the SAME file — no second route file, no `vercel.json`/`route-table.js` change needed (the file was already registered). |
| Cloudflare asset manifest | `scripts/build-cloudflare-assets.js` | Fixed a pre-existing gap (Issue 33 item 1) as part of this tranche, since it directly affects this tranche's own new Hunt Workspace UI — see the certification doc §5. |

**Reuse ratio**: of the 9 D1 tables this tranche's data model needs, 8 already existed (`hunts`, `hunt_refs`, `hunt_queries`, `hunt_observations`, `hunt_evidence_links`, `hunt_findings`, `hunt_timeline`, `detection_feedback`, `siem_connectors`) — only ONE new table (`hunt_query_executions`) was added, and it stores metadata only.

---

## 2. What was deliberately NOT built

- **A second query-template store.** `hunt_queries` already is one.
- **A raw-telemetry/result-row table.** Results are bounded, normalized, and returned ephemerally in the API response only. An analyst-selected row persists via the existing `hunt_observations` table — never automatically.
- **A generic multi-SIEM hunting layer.** Only Microsoft Sentinel (real) and the Sandbox connector (deterministic, CI-required) implement `hunt_query_supported`. Splunk/Elastic/QRadar/Google SecOps are declared `hunt_query_supported: false`, matching their pre-existing `deploy_supported: false` — honest, not silently omitted.
- **Ad-hoc/arbitrary analyst-authored query execution.** Query sources remain limited to a RELEASED detection's own snapshotted content.
- **IOC/hostname/username/entity-id parameterization.** No real canonical detection content has such placeholders today; building the mechanism ahead of real demand would be speculative.
- **A second connector-credential vault or a second decrypt-for-hunting code path.** `getConnectorWithCredential()` is reused as-is.

---

## 3. Connector selection evidence: why Microsoft Sentinel

Same evidence class the Controlled SIEM Deployment Gateway v1 audit already established for the DEPLOY path (`docs/audits/SENTINEL-APEX-SIEM-CONNECTOR-INVENTORY-V1.md`), independently re-verified for the HUNTING path specifically, since deploy and hunt are proven to require different Azure resources/scopes (Section 18 of the mandate):

1. **A real, released detection format this platform already generates** targets Microsoft's own Advanced Hunting table names (`DeviceProcessEvents`/`DeviceEvents`/`DeviceRegistryEvents`, `detection-engine.js`'s `FIELD_MAP`) — the KQL this tranche would execute is already the most field-verified content this platform produces.
2. **A real, currently-documented data-plane query API** exists: `POST https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query` (learn.microsoft.com/azure/azure-monitor/logs/api/access-api, fetched live 2026-08-30; the older `api.loganalytics.io` host is documented as supported "for the foreseeable future").
3. **A real, least-privilege, built-in RBAC role** exists for read-only data-plane query access: **Reader**, scoped to the target Log Analytics workspace — verified via Microsoft's own Sentinel/Log Analytics RBAC documentation, distinct from "Microsoft Sentinel Contributor" (which the deploy path already uses and which grants no data-plane query access at all).
4. **The time-range parameter is native to the API**, not embedded in query text (`timespan`, ISO 8601 interval) — meaning the one parameter type v1 supports is inherently immune to injection by construction, not by escaping discipline alone.
5. **The response schema is real and documented**: `{"tables":[{"name","columns":[{"name","type"}],"rows":[[...]]}]}` — directly maps onto this tranche's `normalizeResults()` contract.

Splunk/Elastic/QRadar/Google SecOps remain audited-but-undeveloped for the SAME reasons the deploy-path audit found: no validated generator/format exists for 3 of them, and Splunk Cloud vs. Enterprise on-prem's materially different saved-search/auth semantics were not verified against current official documentation this round either. Building five shallow hunting connectors instead of one deep one would be against this mandate's own stated priority.

---

## 4. Maintenance rule

Update this document in the same commit that adds a second hunting connector, a new query parameter type, or a new query source — mirroring every other audit/inventory doc's own stated discipline in this repository.

---
*CyberDudeBivash® Sentinel APEX — Controlled Read-Only SIEM Hunting Connectors v1 Reuse-Before-Build Inventory*
